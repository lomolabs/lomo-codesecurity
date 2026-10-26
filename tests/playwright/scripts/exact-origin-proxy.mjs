import { Agent, createServer, request as httpRequest } from 'node:http';

const limits = Object.freeze({ requests: 1024, sockets: 64, responseBytes: 8 * 1024 * 1024, totalBytes: 128 * 1024 * 1024, timeoutMs: 5000 });
const hopHeaders = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);

export function exactProxyOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Proxy fixture origin is invalid.'); }
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port
    || Number(url.port) < 1024 || Number(url.port) > 65535 || url.origin !== value
    || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('Proxy requires one exact explicit-port IPv4-loopback HTTP origin.');
  }
  return url;
}

export function proxyTargetPath(origin, target, method, headers) {
  const approved = exactProxyOrigin(origin);
  if (typeof target !== 'string' || target.length > 8192 || /[\u0000-\u0020\u007f]/.test(target)
    || !['GET', 'HEAD'].includes(method) || headers.host !== approved.host
    || headers.upgrade || headers['transfer-encoding']
    || (headers['content-length'] !== undefined && headers['content-length'] !== '0')) return null;
  let url;
  try { url = new URL(target); } catch { return null; }
  if (url.origin !== approved.origin || url.href !== target || url.username || url.password || url.hash) return null;
  return `${url.pathname}${url.search}`;
}

export function exactProxyContextOptions(proxyUrl, environment = process.env) {
  if (environment.PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK !== undefined) {
    throw new Error('Conformance refuses the forced-loopback proxy override.');
  }
  exactProxyOrigin(proxyUrl);
  // Pinned Chromium subtracts its implicit loopback bypass with this exact rule.
  return { server: proxyUrl, bypass: '<-loopback>' };
}

function endToEndHeaders(headers) {
  const excluded = new Set([...hopHeaders, ...(headers.connection ?? '').toLowerCase().split(',').map((name) => name.trim())]);
  return Object.fromEntries(Object.entries(headers).filter(([name]) => !excluded.has(name)));
}

/** Test-only read proxy: no arbitrary upstream, tunnels, payload storage or logs. */
export async function startExactOriginProxy(origin) {
  const approved = exactProxyOrigin(origin);
  const agent = new Agent({ keepAlive: true, maxSockets: 32, maxTotalSockets: 32 });
  const sockets = new Set();
  const upstreams = new Set();
  let closing;
  const stats = { requests: 0, forwarded: 0, denied: 0, tunnelDenied: 0, upgradeDenied: 0, socketLimit: 0, limitExceeded: false, upstreamFailed: 0, timedOut: 0, responseBytes: 0, closed: false };
  const server = createServer({ maxHeaderSize: 16384, requestTimeout: limits.timeoutMs, headersTimeout: limits.timeoutMs, keepAliveTimeout: 1000 }, (request, response) => {
    if (stats.requests >= limits.requests) { stats.limitExceeded = true; request.socket.destroy(); return; }
    stats.requests += 1;
    const path = proxyTargetPath(origin, request.url, request.method, request.headers);
    if (path === null || stats.closed) {
      stats.denied += 1;
      response.writeHead(403, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' });
      response.end('Blocked by owned conformance proxy.');
      return;
    }
    stats.forwarded += 1;
    // Only path and opaque end-to-end headers are taken from the request. The
    // connection destination never comes from its absolute URL or Host header.
    const upstream = httpRequest({ hostname: '127.0.0.1', port: Number(approved.port), path,
      method: request.method, headers: { ...endToEndHeaders(request.headers), host: approved.host }, agent });
    upstreams.add(upstream);
    const timer = setTimeout(() => { stats.timedOut += 1; upstream.destroy(); response.destroy(); }, limits.timeoutMs);
    const finish = () => { clearTimeout(timer); upstreams.delete(upstream); };
    response.once('close', () => { finish(); upstream.destroy(); });
    upstream.once('error', () => {
      stats.upstreamFailed += 1;
      if (!response.headersSent) response.writeHead(502, { 'Cache-Control': 'no-store' });
      response.end();
      finish();
    });
    upstream.once('response', (incoming) => {
      let bytes = 0;
      response.writeHead(incoming.statusCode ?? 502, endToEndHeaders(incoming.headers));
      incoming.on('data', (chunk) => {
        bytes += chunk.length;
        stats.responseBytes += chunk.length;
        if (bytes > limits.responseBytes || stats.responseBytes > limits.totalBytes) {
          stats.limitExceeded = true; incoming.destroy(); upstream.destroy(); response.destroy();
        }
      });
      incoming.once('error', () => { stats.upstreamFailed += 1; response.destroy(); finish(); });
      incoming.once('end', finish);
      incoming.pipe(response);
    });
    upstream.end();
  });
  server.on('connection', (socket) => {
    if (sockets.size >= limits.sockets) { stats.socketLimit += 1; socket.destroy(); return; }
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.setTimeout(limits.timeoutMs, () => socket.destroy());
  });
  const denyProtocol = (field, socket) => {
    if (stats.requests >= limits.requests) stats.limitExceeded = true;
    else { stats.requests += 1; stats[field] += 1; }
    socket.destroy();
  };
  server.on('connect', (_request, socket) => denyProtocol('tunnelDenied', socket));
  server.on('upgrade', (_request, socket) => denyProtocol('upgradeDenied', socket));
  server.on('clientError', (_error, socket) => socket.destroy());
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
    });
  } catch (error) { agent.destroy(); throw error; }
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Owned proxy listener unavailable.');
  return {
    url: `http://127.0.0.1:${address.port}`,
    snapshot: () => ({ ...stats, limits, activeSockets: sockets.size, activeUpstreams: upstreams.size }),
    close() {
      if (closing) return closing;
      stats.closed = true;
      closing = (async () => {
        let timer;
        try {
          // Server.close can precede socket close events. Observe each actual
          // close before destroying resources; never clear their tracked Sets.
          const resourcesClosed = [...sockets, ...upstreams].map((resource) =>
            new Promise((resolve) => resource.once('close', resolve)));
          const serverClosed = new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
          for (const upstream of upstreams) upstream.destroy();
          for (const socket of sockets) socket.destroy();
          agent.destroy();
          server.closeAllConnections();
          await Promise.race([
            Promise.all([serverClosed, ...resourcesClosed]),
            new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Owned proxy close deadline exceeded.')), limits.timeoutMs); }),
          ]);
          if (sockets.size || upstreams.size) throw new Error('Owned proxy close observations are incomplete.');
        } finally { clearTimeout(timer); }
      })();
      return closing;
    },
  };
}
