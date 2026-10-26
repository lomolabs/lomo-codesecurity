import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { createServer } from 'vite';

test('history requests retain cancellation while exact scan reads request full evidence', async (context) => {
  const vite = await createServer({
    root: fileURLToPath(new URL('..', import.meta.url)), configFile: false,
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { api } = await vite.ssrLoadModule('/src/api.ts') as typeof import('../src/api.ts');
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; });
  const calls: { path: string; signal: AbortSignal | null | undefined }[] = [];
  globalThis.fetch = async (path, init) => {
    calls.push({ path: String(path), signal: init?.signal });
    return new Response(JSON.stringify([]), { status: 200 });
  };
  const controller = new AbortController();
  await api.scans(controller.signal);
  await api.scan(42, controller.signal);
  assert.deepEqual(calls, [
    { path: '/v1/scans?view=history', signal: controller.signal },
    { path: '/v1/scans/42', signal: controller.signal },
  ]);
});


test('invalid browser invitation does not broadcast loss of a retained browser member', async (context) => {
  const webRoot = fileURLToPath(new URL('..', import.meta.url));
  const vite = await createServer({
    root: webRoot,
    configFile: false,
    appType: 'custom',
    logLevel: 'silent',
    server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { api, onAuthRequired } = await vite.ssrLoadModule('/src/api.ts') as typeof import('../src/api.ts');
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; });
  let broadcasts = 0;
  const unsubscribe = onAuthRequired(() => { broadcasts += 1; });
  context.after(unsubscribe);
  globalThis.fetch = async () => new Response(JSON.stringify({
    detail: {
      code: 'ide_browser_invitation_unavailable',
      message: 'This one-time IDE browser invitation is not available.',
    },
  }), { status: 401, headers: { 'Content-Type': 'application/json' } });

  await assert.rejects(api.bootstrap(`kbi1.${'i'.repeat(24)}.${'s'.repeat(43)}`));
  assert.equal(broadcasts, 0);

  await assert.rejects(api.authSession());
  assert.equal(broadcasts, 1);
});

test('cache outcome check sends one exact CSRF-protected idempotent command for the failed revision', async (context) => {
  const vite = await createServer({
    root: fileURLToPath(new URL('..', import.meta.url)), configFile: false,
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { api, setCsrfToken, ApiError } = await vite.ssrLoadModule('/src/api.ts') as typeof import('../src/api.ts');
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; setCsrfToken(''); });
  const calls: { path: string; init: RequestInit }[] = [];
  const response = { original_job_id: 42, job: { id: 43, kind: 'scanner_cache_reconcile', status: 'queued' },
    lifecycle: { scope: 'cache', job_id: 43, status: 'queued' } };
  setCsrfToken('synthetic-csrf');
  globalThis.fetch = async (path, init) => {
    calls.push({ path: String(path), init: init || {} });
    return new Response(JSON.stringify(response), { status: 202, headers: { 'Content-Type': 'application/json' } });
  };
  assert.deepEqual(await api.reconcileScannerCacheJob(42, 7), response);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, '/v1/jobs/42/reconcile');
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.credentials, 'same-origin');
  assert.deepEqual(JSON.parse(String(calls[0].init.body)), { expected_revision: 7 });
  const headers = calls[0].init.headers as Record<string, string>;
  assert.equal(headers['X-CSRF-Token'], 'synthetic-csrf');
  assert.match(headers['Idempotency-Key'], /^web-[a-f0-9-]{36}$/u);
  for (const [id, revision] of [[0, 7], [42, 0], [42, Number.NaN], [1.1, 7]]) {
    assert.throws(() => api.reconcileScannerCacheJob(id, revision), /exact failed job/u);
  }
  assert.equal(calls.length, 1, 'invalid identities cannot send a command');
  globalThis.fetch = async (path, init) => {
    calls.push({ path: String(path), init: init || {} });
    return new Response(JSON.stringify({ detail: { code: 'job_revision_changed', message: 'Reload the original job before reconciling.' } }),
      { status: 409, headers: { 'Content-Type': 'application/json' } });
  };
  await assert.rejects(api.reconcileScannerCacheJob(42, 7), error => error instanceof ApiError && error.code === 'job_revision_changed');
  assert.equal(calls.length, 2, 'conflicts do not automatically repeat the command');
});

test('provider read and write validation preserves one request, cancellation, CSRF and typed rejections', async context => {
  const vite = await createServer({
    root: fileURLToPath(new URL('..', import.meta.url)), configFile: false,
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { api, setCsrfToken, ApiError } = await vite.ssrLoadModule('/src/api.ts') as typeof import('../src/api.ts');
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; setCsrfToken(''); });
  const controller = new AbortController();
  const calls: { path: string; init: RequestInit }[] = [];
  let body = '{}';
  let status = 200;
  globalThis.fetch = async (path, init) => {
    calls.push({ path: String(path), init: init || {} });
    return new Response(body, { status, headers: { 'Content-Type': 'application/json' } });
  };
  const provider = { id: 'local', name: 'Local', transport: 'local' as const, priority: 0, enabled: true,
    base_url: null, model: 'fixture', model_digest: 'a'.repeat(64), ssh_host: null, ssh_port: null, ssh_user: null };
  setCsrfToken('synthetic-csrf');
  for (const payload of ['{}', '{']) {
    body = payload;
    await assert.rejects(api.advisorProviders(controller.signal), /provider state could not be verified/u);
    await assert.rejects(api.createAdvisorProvider(3, provider), /provider change could not be confirmed/u);
    await assert.rejects(api.updateAdvisorProvider('local', 3, provider), /provider change could not be confirmed/u);
    await assert.rejects(api.deleteAdvisorProvider('local', 3), /provider change could not be confirmed/u);
  }
  assert.equal(calls.length, 8, 'invalid responses do not repeat requests');
  assert.deepEqual(calls.map(call => [call.path, call.init.method || 'GET']), Array(2).fill([
    ['/v1/advisor/providers', 'GET'], ['/v1/advisor/providers', 'POST'],
    ['/v1/advisor/providers/local', 'PUT'], ['/v1/advisor/providers/local', 'DELETE'],
  ]).flat());
  for (const call of calls) {
    assert.equal(call.init.credentials, 'same-origin');
    if (call.init.method) {
      assert.equal((call.init.headers as Record<string, string>)['X-CSRF-Token'], 'synthetic-csrf');
      assert.equal(JSON.parse(String(call.init.body)).expected_revision, 3);
    } else assert.equal(call.init.signal, controller.signal);
  }
  status = 409;
  body = JSON.stringify({ detail: { code: 'advisor_provider_revision_changed', message: 'Provider configuration changed.' } });
  await assert.rejects(api.updateAdvisorProvider('local', 3, provider),
    error => error instanceof ApiError && error.status === 409 && error.code === 'advisor_provider_revision_changed');
  const transportFailure = new TypeError('Failed to fetch');
  globalThis.fetch = async () => { throw transportFailure; };
  await assert.rejects(api.createAdvisorProvider(3, provider), error => error === transportFailure);
});
