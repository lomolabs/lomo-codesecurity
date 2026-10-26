import { expect, test, type BrowserContext, type CDPSession, type Frame } from '@playwright/test';
import { createServer, type Server } from 'node:http';
import { createRequire } from 'node:module';

import { installRuntimeGuards } from './support/quality.js';

// Supporting HTTP conformance only. No navigation measurements or policy fallback.
// All URLs are constructed here from two run-owned IPv4-loopback listeners.
test.use({ trace: 'off', screenshot: 'off', video: 'off' });
const expectedBrowser = '149.0.7827.55';
const surfaces = ['main', 'same-process-frame', 'oopif'] as const;
const policies = ['page-route', 'native-main-target'] as const;
type WireRecord = { sentinel: 'primary' | 'secondary'; caseId: string; methodIsGet: boolean; hostIsAllowed: boolean };

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Owned loopback listener has no TCP port.');
  return address.port;
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

test('native exact-origin HTTP conformance diagnostic preserves page-route frame denial', async ({ browser }, testInfo) => {
  expect(testInfo.project.name).toBe('desktop-1440');
  expect(createRequire(import.meta.url)('@playwright/test/package.json').version).toBe('1.61.1');
  expect(browser.version()).toBe(expectedBrowser);
  const wire: WireRecord[] = [];
  const evidence: Array<Record<string, unknown>> = [];
  const contexts = new Set<BrowserContext>();
  let primaryOrigin = '';
  let secondaryOrigin = '';
  let wrongHostOrigin = '';
  let invalidRequest = false;
  let cleanupComplete = false;
  let failureImageCaptured = false;
  const captureFailureImage = async () => {
    if (failureImageCaptured) return;
    const ownedPage = [...contexts].at(-1)?.pages()[0];
    if (!ownedPage) return;
    try {
      // Only the inert owned fixture is visible; no browser chrome or fetch URL.
      await ownedPage.screenshot({ path: testInfo.outputPath('network-conformance-failure.png'), timeout: 1_000 });
      failureImageCaptured = true;
    } catch { /* The runner separately records missing required failure imagery. */ }
  };
  const makeServer = (sentinel: WireRecord['sentinel']) => createServer((request, response) => {
    // Never retain a request target, query, header value, body or credential.
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    const caseId = /^\/probe\/([a-z-]+)$/.exec(url.pathname)?.[1];
    const permitted = url.pathname === '/frame' || url.pathname === '/favicon.ico' || caseId !== undefined;
    if (!permitted || request.method !== 'GET' || wire.length >= 256) invalidRequest = true;
    if (caseId && wire.length < 256) wire.push({
      sentinel, caseId, methodIsGet: request.method === 'GET',
      hostIsAllowed: request.headers.host === new URL(primaryOrigin).host,
    });
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Access-Control-Allow-Origin', '*');
    if (caseId === 'redirect') {
      response.writeHead(302, { Location: `${secondaryOrigin}/probe/redirect-target` });
      response.end();
    } else if (url.pathname === '/frame') {
      response.setHeader('Content-Type', 'text/html; charset=utf-8');
      response.end('<!doctype html><title>Owned HTTP conformance fixture</title><p>Local fixture</p>');
    } else {
      response.setHeader('Content-Type', 'text/plain');
      response.end('owned-fixture');
    }
  });
  const primary = makeServer('primary');
  const secondary = makeServer('secondary');
  const fetchFrom = (frame: Frame, url: string) => frame.evaluate(async (target) => {
    try {
      const response = await fetch(target, { cache: 'no-store', signal: AbortSignal.timeout(1_500) });
      await response.text();
      return response.status === 200 ? 'received' : 'http-error';
    } catch (error) {
      return error instanceof DOMException && error.name === 'TimeoutError' ? 'timeout' : 'rejected';
    }
  }, url);
  try {
    primaryOrigin = `http://127.0.0.1:${await listen(primary)}`;
    secondaryOrigin = `http://127.0.0.1:${await listen(secondary)}`;
    wrongHostOrigin = primaryOrigin.replace('127.0.0.1', 'localhost');
    for (const policy of policies) for (const surface of surfaces) {
      const context = await browser.newContext({ serviceWorkers: 'block' });
      contexts.add(context);
      const page = await context.newPage();
      const session = await context.newCDPSession(page);
      await session.send('Network.enable');
      await session.send('Network.setCacheDisabled', { cacheDisabled: true });
      await page.goto(`${primaryOrigin}/frame`);
      // Prove both negative sentinels are reachable before installing either policy.
      // These controls use only owned loopback URLs and contain no credentials.
      expect(await fetchFrom(page.mainFrame(), `${secondaryOrigin}/probe/control-port`)).toBe('received');
      expect(await fetchFrom(page.mainFrame(), `${wrongHostOrigin}/probe/control-host`)).toBe('received');
      let frame = page.mainFrame();
      let separateTarget = false;
      let childSession: CDPSession | null = null;
      if (surface !== 'main') {
        const frameOrigin = surface === 'oopif' ? wrongHostOrigin : primaryOrigin;
        await page.evaluate((src) => new Promise<void>((resolve, reject) => {
          const iframe = document.createElement('iframe');
          iframe.name = 'owned-conformance-frame';
          iframe.onload = () => resolve();
          iframe.onerror = () => reject(new Error('Owned fixture frame failed.'));
          iframe.src = src;
          document.body.append(iframe);
        }), `${frameOrigin}/frame`);
        const child = page.frame({ name: 'owned-conformance-frame' });
        if (!child) throw new Error('Owned child frame is missing.');
        frame = child;
        // Pinned Playwright refuses a frame CDP session for same-process frames.
        // A successful distinct iframe target proves OOPIF coverage, not merely a URL.
        try {
          childSession = await context.newCDPSession(frame);
          const childTarget = await childSession.send('Target.getTargetInfo');
          const mainTarget = await session.send('Target.getTargetInfo');
          separateTarget = childTarget.targetInfo.type === 'iframe'
            && childTarget.targetInfo.targetId !== mainTarget.targetInfo.targetId;
          await childSession.send('Network.enable');
          await childSession.send('Network.setCacheDisabled', { cacheDisabled: true });
        } catch (error) {
          if (!(error instanceof Error) || !error.message.includes('does not have a separate CDP session')) throw error;
        }
        expect(separateTarget, `${surface} process boundary`).toBe(surface === 'oopif');
      }
      let credentialObservations = 0;
      let unexpectedDestination = false;
      page.on('request', (request) => {
        const url = new URL(request.url());
        if (/^https?:$/.test(url.protocol) && ![primaryOrigin, secondaryOrigin, wrongHostOrigin].includes(url.origin)) unexpectedDestination = true;
        if ([...url.searchParams.keys()].some((name) => /token|secret|password|credential|authorization|api[_-]?key/i.test(name))) credentialObservations += 1;
      });
      if (policy === 'page-route') {
        await installRuntimeGuards(page, primaryOrigin);
      } else {
        // Ordered native allow, then wildcard deny. No route or Fetch.enable.
        await session.send('Network.setBlockedURLs', {
          urlPatterns: [{ urlPattern: `${primaryOrigin}/*`, block: false }], urls: ['*'],
        });
      }
      const results: Array<Record<string, unknown>> = [];
      for (const [caseId, origin] of [
        ['allowed', primaryOrigin], ['wrong-port', secondaryOrigin],
        ['wrong-host', wrongHostOrigin], ['redirect', primaryOrigin],
        ['credential', primaryOrigin],
      ] as const) {
        const before = wire.length;
        // Public, deliberately nonsecret marker tests the existing observational guard.
        const outcome = await fetchFrom(frame, `${origin}/probe/${caseId}${caseId === 'credential' ? '?token=synthetic' : ''}`);
        const arrived = wire.slice(before);
        const deniedArrivals = arrived.filter((row) => row.sentinel === 'secondary' || !row.hostIsAllowed).length;
        results.push({ caseId, outcome, wireArrivals: arrived.length, deniedArrivals });
        expect.soft(outcome, `${policy}/${surface}/${caseId} bounded request`).not.toBe('timeout');
        if (caseId === 'allowed' || caseId === 'credential') {
          expect.soft(outcome, `${policy}/${surface}/${caseId} positive control`).toBe('received');
          expect.soft(arrived.length).toBe(1);
        } else if (caseId !== 'redirect' || policy === 'native-main-target') {
          expect.soft(deniedArrivals, `${policy}/${surface}/${caseId} pre-wire denial`).toBe(0);
          expect.soft(outcome).toBe('rejected');
        }
        // page.route documents no redirect-follow-up interception; record its
        // actual behavior without inventing a comparator guarantee.
      }
      expect.soft(credentialObservations, `${policy}/${surface} credential observation`).toBe(1);
      expect.soft(unexpectedDestination).toBe(false);
      expect.soft(context.pages()).toHaveLength(1);
      expect.soft(page.frames()).toHaveLength(surface === 'main' ? 1 : 2);
      expect.soft(page.workers()).toHaveLength(0);
      evidence.push({ policy, surface, separateTarget, cacheDisabled: true, credentialObservations, unexpectedDestination, results });
      if (testInfo.errors.length > 0) await captureFailureImage();
      // Keep the cache-control agent alive through every request observation.
      // A thrown assertion instead closes its owning context in the outer finally.
      if (childSession) await childSession.detach();
      await context.close();
      contexts.delete(context);
    }
    expect(invalidRequest).toBe(false);
    expect(evidence).toHaveLength(6);
  } finally {
    if (contexts.size > 0) await captureFailureImage();
    const cleanup = await Promise.allSettled([...contexts].map((context) => context.close()));
    const servers = await Promise.allSettled([close(primary), close(secondary)]);
    cleanupComplete = [...cleanup, ...servers].every((result) => result.status === 'fulfilled');
    await testInfo.attach('network-isolation-conformance.json', {
      contentType: 'application/json',
      body: Buffer.from(JSON.stringify({
        schema: 'lomo-network-isolation-conformance/v1', diagnostic: true, qualification: false,
        playwright: '1.61.1', chromium: expectedBrowser, completedSurfaces: evidence.length,
        conformancePassed: evidence.length === 6 && testInfo.errors.length === 0 && !invalidRequest && cleanupComplete,
        cleanupComplete, failureImageCaptured, invalidRequest, evidence,
        limits: ['HTTP only; no popup, worker or WebSocket pre-wire claim.', 'Existing frames are prepared before policy installation; no new-target lifecycle guarantee.', 'No navigation performance result or timing-budget change.'],
      })),
    });
    expect(cleanupComplete, 'owned context and sentinel cleanup').toBe(true);
  }
});
