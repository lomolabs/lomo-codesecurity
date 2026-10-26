import { expect, test, type BrowserContext, type CDPSession, type Frame } from '@playwright/test';
import { createServer, type Server } from 'node:http';
import { createRequire } from 'node:module';
import { createConnection } from 'node:net';
import { exactProxyContextOptions, startExactOriginProxy } from '../scripts/exact-origin-proxy.mjs';

test.use({ trace: 'off', screenshot: 'off', video: 'off' });

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Owned sentinel listener unavailable.');
  return address.port;
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  if (server.listening) await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

test('context proxy exact-origin HTTP conformance is enforced across verified opaque frame targets', async ({ browser, request }, testInfo) => {
  expect(testInfo.project.name).toBe('desktop-1440');
  expect(createRequire(import.meta.url)('@playwright/test/package.json').version).toBe('1.61.1');
  expect(browser.version()).toBe('149.0.7827.55');
  // No unsupported ambient bypass override may silently weaken this mechanism.
  expect(process.env.PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK).toBeUndefined();
  let primaryOrigin = '';
  let secondaryOrigin = '';
  let wireAllowed = 0;
  let wireDenied = 0;
  let unexpectedWire = false;
  let context: BrowserContext | undefined;
  let proxy: Awaited<ReturnType<typeof startExactOriginProxy>> | undefined;
  let failureImageCaptured = false;
  let cleanupComplete = false;
  let proxyClosedFailure: Record<string, unknown> | null = null;
  const rows: Array<Record<string, unknown>> = [];
  const childSessions: CDPSession[] = [];
  const makeServer = (secondary: boolean) => createServer((incoming, response) => {
    const pathname = new URL(incoming.url ?? '/', 'http://127.0.0.1').pathname;
    if (!['/frame', '/favicon.ico', '/allowed', '/denied', '/redirect', '/redirect-target', '/credential', '/closed-control'].includes(pathname)
      || incoming.method !== 'GET' || wireAllowed + wireDenied >= 256) unexpectedWire = true;
    if (pathname !== '/frame' && pathname !== '/favicon.ico') {
      if (secondary || incoming.headers.host !== new URL(primaryOrigin).host) wireDenied += 1;
      else wireAllowed += 1;
    }
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Access-Control-Allow-Origin', '*');
    if (pathname === '/redirect') {
      response.writeHead(302, { Location: `${secondaryOrigin}/redirect-target` });
      response.end();
    } else if (pathname === '/frame') {
      response.setHeader('Content-Type', 'text/html; charset=utf-8');
      response.end('<!doctype html><title>Owned proxy conformance fixture</title><p>Local fixture</p>');
    } else response.end('owned-fixture');
  });
  const primary = makeServer(false);
  const secondary = makeServer(true);
  const fetchFrom = (frame: Frame, url: string) => frame.evaluate(async (target) => {
    try {
      const response = await fetch(target, { cache: 'no-store', signal: AbortSignal.timeout(1500) });
      await response.text();
      return response.status === 200 ? 'received' : response.status === 403 ? 'denied' : 'http-error';
    } catch (error) { return error instanceof DOMException && error.name === 'TimeoutError' ? 'timeout' : 'rejected'; }
  }, url);
  const captureFailure = async () => {
    if (failureImageCaptured || !context?.pages()[0]) return;
    try {
      await context.pages()[0].screenshot({ path: testInfo.outputPath('proxy-conformance-failure.png'), timeout: 1000 });
      failureImageCaptured = true;
    } catch { /* Missing imagery remains a maintained runner failure. */ }
  };
  try {
    primaryOrigin = `http://127.0.0.1:${await listen(primary)}`;
    secondaryOrigin = `http://127.0.0.1:${await listen(secondary)}`;
    const wrongHostOrigin = primaryOrigin.replace('127.0.0.1', 'localhost');
    // Controller-owned local controls prove denied listeners actually work.
    expect((await request.get(`${secondaryOrigin}/denied`)).status()).toBe(200);
    expect((await request.get(`${wrongHostOrigin}/denied`)).status()).toBe(200);
    proxy = await startExactOriginProxy(primaryOrigin);
    const deniedProtocol = (method: 'CONNECT' | 'UPGRADE') => new Promise<void>((resolve, reject) => {
      const endpoint = new URL(proxy!.url);
      const socket = createConnection({ host: '127.0.0.1', port: Number(endpoint.port) });
      const timer = setTimeout(() => { socket.destroy(); reject(new Error('Owned proxy protocol denial timed out.')); }, 1500);
      socket.once('error', () => { /* Closed/reset is checked with proxy denial counters. */ });
      socket.once('close', () => { clearTimeout(timer); resolve(); });
      socket.once('connect', () => socket.end(method === 'CONNECT'
        ? `CONNECT ${new URL(secondaryOrigin).host} HTTP/1.1\r\nHost: ${new URL(secondaryOrigin).host}\r\n\r\n`
        : `GET ${secondaryOrigin}/denied HTTP/1.1\r\nHost: ${new URL(secondaryOrigin).host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`));
    });
    const deniedBeforeProtocols = wireDenied;
    await deniedProtocol('CONNECT');
    await deniedProtocol('UPGRADE');
    expect(proxy.snapshot().tunnelDenied).toBe(1);
    expect(proxy.snapshot().upgradeDenied).toBe(1);
    expect(wireDenied).toBe(deniedBeforeProtocols);
    context = await browser.newContext({ serviceWorkers: 'block', proxy: exactProxyContextOptions(proxy.url) });
    const page = await context.newPage();
    const session = await context.newCDPSession(page);
    await session.send('Network.enable');
    await session.send('Network.setCacheDisabled', { cacheDisabled: true });
    let credentialObservations = 0;
    let unexpectedDestination = false;
    page.on('request', (observed) => {
      const url = new URL(observed.url());
      if (/^https?:$/.test(url.protocol) && ![primaryOrigin, secondaryOrigin, wrongHostOrigin].includes(url.origin)) unexpectedDestination = true;
      if ([...url.searchParams.keys()].some((key) => /token|secret|password|credential|authorization|api[_-]?key/i.test(key))) credentialObservations += 1;
    });
    await page.goto(`${primaryOrigin}/frame`);
    const createOpaqueFrame = async (name: string) => {
      await page.evaluate(({ src, name }) => new Promise<void>((resolve, reject) => {
        const iframe = document.createElement('iframe');
        iframe.name = name;
        iframe.sandbox.add('allow-scripts');
        iframe.onload = () => resolve();
        iframe.onerror = () => reject(new Error('Owned opaque frame failed.'));
        iframe.src = src;
        document.body.append(iframe);
      }), { src: `${primaryOrigin}/frame`, name });
      const frame = page.frame({ name });
      if (!frame) throw new Error('Owned opaque frame is missing.');
      // Fail rather than manufacturing an OOPIF with a broadened policy/route.
      const childSession = await context!.newCDPSession(frame);
      childSessions.push(childSession);
      const childTarget = await childSession.send('Target.getTargetInfo');
      const parentTarget = await session.send('Target.getTargetInfo');
      expect(childTarget.targetInfo.type).toBe('iframe');
      expect(childTarget.targetInfo.targetId).not.toBe(parentTarget.targetInfo.targetId);
      expect(await frame.evaluate(() => self.origin)).toBe('null');
      await childSession.send('Network.enable');
      await childSession.send('Network.setCacheDisabled', { cacheDisabled: true });
      return frame;
    };
    const existingFrame = await createOpaqueFrame('existing-opaque');
    // Settle the initial document/favicon outside every counter observation.
    await page.waitForLoadState('networkidle');
    for (const surface of ['main', 'existing-oopif', 'new-oopif'] as const) {
      const frame = surface === 'main' ? page.mainFrame() : surface === 'existing-oopif' ? existingFrame : await createOpaqueFrame('new-opaque');
      const results: Array<Record<string, unknown>> = [];
      for (const [caseId, origin, pathname] of [
        ['allowed', primaryOrigin, '/allowed'], ['wrong-port', secondaryOrigin, '/denied'],
        ['wrong-host', wrongHostOrigin, '/denied'], ['redirect', primaryOrigin, '/redirect'],
        ['credential', primaryOrigin, '/credential?token=synthetic'],
      ] as const) {
        const beforeAllowed = wireAllowed;
        const beforeDenied = wireDenied;
        const before = proxy.snapshot();
        const outcome = await fetchFrom(frame, `${origin}${pathname}`);
        const after = proxy.snapshot();
        const allowedArrivals = wireAllowed - beforeAllowed;
        const deniedArrivals = wireDenied - beforeDenied;
        const proxyDenials = after.denied - before.denied;
        results.push({ caseId, outcome, allowedArrivals, deniedArrivals, proxyDenials });
        expect.soft(outcome).not.toBe('timeout');
        expect.soft(deniedArrivals, `${surface}/${caseId} no denied wire arrival`).toBe(0);
        if (caseId === 'allowed' || caseId === 'credential') {
          expect.soft(outcome).toBe('received');
          expect.soft(allowedArrivals).toBe(1);
          expect.soft(after.forwarded - before.forwarded, 'forced loopback proxy path').toBe(1);
        } else {
          expect.soft(outcome).toBe('denied');
          expect.soft(proxyDenials).toBe(1);
        }
      }
      rows.push({ surface, verifiedOpaqueOopif: surface !== 'main', cacheDisabledSessionRetained: true, results });
    }
    const beforeCloseAllowed = wireAllowed;
    const beforeCloseDenied = wireDenied;
    await proxy.close();
    const closedOutcome = await fetchFrom(page.mainFrame(), `${primaryOrigin}/closed-control`);
    proxyClosedFailure = { outcome: closedOutcome, wireArrivals: wireAllowed + wireDenied - beforeCloseAllowed - beforeCloseDenied };
    expect(closedOutcome).toBe('rejected');
    expect(proxyClosedFailure.wireArrivals).toBe(0);
    expect(credentialObservations).toBe(3);
    expect(unexpectedDestination).toBe(false);
    expect(unexpectedWire).toBe(false);
    expect(context.pages()).toHaveLength(1);
    expect(page.frames()).toHaveLength(3);
    expect(page.workers()).toHaveLength(0);
    expect(proxy.snapshot().limitExceeded).toBe(false);
    expect(proxy.snapshot().timedOut).toBe(0);
    expect(proxy.snapshot().upstreamFailed).toBe(0);
    if (testInfo.errors.length) await captureFailure();
  } finally {
    if (rows.length !== 3 || !proxyClosedFailure) await captureFailure();
    const cleanup = await Promise.allSettled([context?.close(), proxy?.close(), close(primary), close(secondary)]);
    const finalProxy = proxy?.snapshot();
    cleanupComplete = cleanup.every((result) => result.status === 'fulfilled')
      && (!finalProxy || (finalProxy.closed && finalProxy.activeSockets === 0 && finalProxy.activeUpstreams === 0));
    await testInfo.attach('proxy-isolation-conformance.json', { contentType: 'application/json', body: Buffer.from(JSON.stringify({
      schema: 'lomo-proxy-isolation-conformance/v1', diagnostic: true, qualification: false,
      playwright: '1.61.1', chromium: '149.0.7827.55', rows, proxyClosedFailure,
      proxy: proxy?.snapshot() ?? null, cleanupComplete, failureImageCaptured,
      conformancePassed: rows.length === 3 && proxyClosedFailure?.outcome === 'rejected' && testInfo.errors.length === 0 && cleanupComplete,
      limits: ['HTTP GET/HEAD only; no tunneling or WebSocket support.', 'Sandbox OOPIF must be observed; unsupported separation fails without fallback.', 'No navigation performance or release qualification claim.'],
    })) });
    expect(cleanupComplete).toBe(true);
  }
});
