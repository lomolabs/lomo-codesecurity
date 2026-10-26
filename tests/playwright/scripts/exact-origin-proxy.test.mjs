import assert from 'node:assert/strict';
import { Agent, createServer, request } from 'node:http';
import { createConnection } from 'node:net';
import test from 'node:test';

import { startExactOriginProxy } from './exact-origin-proxy.mjs';

async function waitFor(predicate) {
  const deadline = performance.now() + 1000;
  while (!predicate()) {
    assert.ok(performance.now() < deadline, 'owned connection state did not settle');
    await new Promise((resolve) => setImmediate(resolve));
  }
}

async function fixture(handler) {
  const server = createServer(handler);
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const proxy = await startExactOriginProxy(origin);
  return { origin, proxy, async close() {
    let failed = false;
    let primaryError;
    try { await proxy.close(); }
    catch (error) { failed = true; primaryError = error; }
    try {
      const closed = [...sockets].map((socket) => new Promise((resolve) => socket.once('close', resolve)));
      const stopped = new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections();
      await Promise.all([stopped, ...closed]);
    } catch (error) { if (!failed) throw error; }
    if (failed) throw primaryError;
  } };
}

async function idleClient(proxyUrl) {
  const address = new URL(proxyUrl);
  const socket = createConnection({ host: '127.0.0.1', port: Number(address.port) });
  socket.on('error', () => {});
  await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
  return socket;
}

function proxiedRequest(owned, agent) {
  const proxy = new URL(owned.proxy.url);
  return request({ hostname: '127.0.0.1', port: Number(proxy.port), method: 'GET',
    path: `${owned.origin}/control`, headers: { Host: new URL(owned.origin).host }, agent });
}

async function assertListenerClosed(proxyUrl) {
  const address = new URL(proxyUrl);
  const socket = createConnection({ host: '127.0.0.1', port: Number(address.port) });
  try {
    const code = await new Promise((resolve, reject) => {
      socket.once('connect', () => reject(new Error('closed proxy unexpectedly accepted a connection')));
      socket.once('error', (error) => resolve(error.code));
      socket.setTimeout(1000, () => { socket.destroy(); reject(new Error('closed-listener observation timed out')); });
    });
    assert.equal(code, 'ECONNREFUSED');
  } finally { socket.destroy(); }
}

test('proxy close awaits idle and keepalive socket events for every concurrent caller', { timeout: 10000 }, async () => {
  const owned = await fixture((_request, response) => response.end('control'));
  const agent = new Agent({ keepAlive: true });
  const clients = [];
  try {
    clients.push(await idleClient(owned.proxy.url), await idleClient(owned.proxy.url));
    await new Promise((resolve, reject) => {
      const outgoing = proxiedRequest(owned, agent);
      outgoing.once('error', reject);
      outgoing.once('response', (response) => { response.resume(); response.once('end', resolve); response.once('error', reject); });
      outgoing.end();
    });
    await waitFor(() => owned.proxy.snapshot().activeSockets === 3 && owned.proxy.snapshot().activeUpstreams === 0);
    const first = owned.proxy.close().then(() => owned.proxy.snapshot());
    const second = owned.proxy.close().then(() => owned.proxy.snapshot());
    for (const snapshot of await Promise.all([first, second])) {
      assert.equal(snapshot.closed, true);
      assert.equal(snapshot.activeSockets, 0, 'close must await tracked socket close events, not only server close');
      assert.equal(snapshot.activeUpstreams, 0);
    }
    await owned.proxy.close();
    await assertListenerClosed(owned.proxy.url);
  } finally {
    for (const client of clients) client.destroy();
    agent.destroy();
    await owned.close();
  }
});

test('proxy close also terminates an owned active upstream without premature completion', { timeout: 10000 }, async () => {
  const owned = await fixture((_request, response) => { response.writeHead(200); response.write('control'); });
  const agent = new Agent({ keepAlive: true });
  let outgoing;
  try {
    await new Promise((resolve, reject) => {
      outgoing = proxiedRequest(owned, agent);
      outgoing.on('error', () => {});
      outgoing.once('response', (response) => {
        response.on('error', () => {});
        response.once('data', resolve);
      });
      outgoing.once('error', reject);
      outgoing.end();
    });
    await waitFor(() => owned.proxy.snapshot().activeSockets === 1 && owned.proxy.snapshot().activeUpstreams === 1);
    const first = owned.proxy.close().then(() => owned.proxy.snapshot());
    const second = owned.proxy.close().then(() => owned.proxy.snapshot());
    for (const snapshot of await Promise.all([first, second])) {
      assert.equal(snapshot.closed, true);
      assert.equal(snapshot.activeSockets, 0);
      assert.equal(snapshot.activeUpstreams, 0);
    }
    await assertListenerClosed(owned.proxy.url);
  } finally { outgoing?.destroy(); agent.destroy(); await owned.close(); }
});
