import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import type { ScannerCacheVerification, ScannerLifecycleScope, ScannerPreflight, ScannerTool } from '../src/api.ts';
import { scannerDataCatalogSelection } from '../src/scannerPreparation.ts';

test('scanner data selection never converts missing signed identity into bundled trust', () => {
  const scope = (result: unknown) => ({ status: 'completed', receipt: { result } }) as ScannerLifecycleScope;
  assert.deepEqual(scannerDataCatalogSelection(scope({ catalog_mode: 'signed', catalog_digest: 'a'.repeat(64) })), {
    mode: 'signed', digest: 'a'.repeat(64),
  });
  assert.deepEqual(scannerDataCatalogSelection(scope({ catalog_mode: 'source-reviewed/bundled', catalog_digest: null })), {
    mode: 'source-reviewed/bundled', digest: null,
  });
  for (const result of [
    { catalog_mode: 'signed', catalog_digest: null },
    { catalog_mode: 'signed', catalog_digest: 'invalid' },
    { catalog_mode: 'source-reviewed/bundled', catalog_digest: 'a'.repeat(64) },
    { catalog_mode: 'unverified' },
  ]) assert.equal(scannerDataCatalogSelection(scope(result)), null);
  assert.equal(scannerDataCatalogSelection(null), null);
});

test('cache activation invalidates stale catalog selection without inventing current readiness', async (context) => {
  const vite = await createServer({ root: fileURLToPath(new URL('..', import.meta.url)),
    configFile: false, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { Tools } = await vite.ssrLoadModule('/src/App.tsx') as typeof import('../src/App.tsx');
  const { catalogComponentState, scannerCacheComponents } = await vite.ssrLoadModule('/src/scannerPreparation.ts') as typeof import('../src/scannerPreparation.ts');
  const cache: ScannerLifecycleScope = {
    scope: 'cache', status: 'completed', revision: 3, job_id: 15, job_url: '/v1/jobs/15',
    active_generation: 'a'.repeat(64), previous_generation: null, receipt: {}, error_code: null, error_detail: null,
    started_at: '2026-09-07T12:00:00Z', completed_at: '2026-09-07T12:10:00Z', updated_at: '2026-09-07T12:10:00Z',
  };
  const catalog: ScannerLifecycleScope = { ...cache, scope: 'catalog', job_id: 14, job_url: '/v1/jobs/14',
    active_generation: null, started_at: '2026-09-07T11:59:00Z', completed_at: '2026-09-07T11:59:05Z',
    receipt: { result: { kind: 'catalog', checked_at: '2026-09-07T11:59:04Z', components: scannerCacheComponents.map(({ id }) => ({
      component_id: id, state: 'candidate_available',
    })) } },
  };
  const tool: ScannerTool = {
    id: 'grype', name: 'Grype', category: 'sca', lifecycle: 'scan', source: 'external', output_format: 'json',
    description: 'Synthetic tool state.', enabled: true, current_version: '0.117.0', latest_version: '0.117.0',
    installed_version: '0.117.0', available: true, status: 'ready', update_available: false, findings_count: 0, artifacts_count: 0,
  };
  const preflight: ScannerPreflight = {
    schema_version: 1, revision: 'b'.repeat(64), ready: true, enabled_tool_ids: ['grype'], ready_tool_ids: ['grype'],
    blocked_tools: [], required_component_ids: [], preparation_available: false, active_generation: cache.active_generation,
    catalog_revision: 2, cache_revision: 3, recommended_action: 'scan',
    cache_rollback: { eligible: false, reason_code: 'no_previous_generation', reason: 'No previous-good generation.', target_generation: null },
  };
  const render = (checked: ScannerLifecycleScope, cached = cache, scanner = tool) => renderToStaticMarkup(createElement(Tools, {
    surface: { 'data-route-surface': 'tools', inert: false }, tools: [scanner], lifecycle: { catalog: checked, cache: cached },
    preflight, jobs: [], busy: false, dashboardSettled: true,
    prepareScanners() {}, checkTools() {}, updateScannerCache() {}, rollbackScannerCache() {}, selectToolCandidate() {},
    toggleTool() {}, cancelJob() {}, retryJob() {}, viewJob() {}, refreshScannerStatus() {}, retryScannerVerification() {},
  }));
  const historicalReceipt = JSON.stringify(catalog.receipt);
  const withCheckedAt = (checkedAt: unknown): ScannerLifecycleScope => ({ ...catalog,
    started_at: '2026-09-07T12:11:00Z', completed_at: '2026-09-07T12:12:00Z',
    receipt: { result: { ...(catalog.receipt.result as Record<string, unknown>), checked_at: checkedAt } },
  });
  for (const stale of [
    catalog,
    { ...catalog, completed_at: '2026-09-07T12:12:00Z' }, // Started before activation, even if persisted later.
    { ...catalog, started_at: '2026-09-07T12:10:00Z' },
    { ...catalog, started_at: null },
    { ...catalog, started_at: '2026-02-30T12:11:00Z' },
    withCheckedAt(undefined),
    withCheckedAt('not-a-timestamp'),
    withCheckedAt('2026-02-30T12:11:30Z'),
    withCheckedAt('2026-09-07T12:09:00Z'), // Started after activity, but checked before it.
    withCheckedAt('2026-09-07T12:10:30Z'), // Checked after activity, but before its own start.
  ]) {
    assert.equal(catalogComponentState(stale, 'grype-db', cache), 'catalog_needs_refresh');
    const html = render(stale);
    assert.match(html, /Ready to Scan/u);
    assert.match(html, /Check curated catalog/u);
    assert.match(html, /this does not download scanner data/u);
    assert.equal([...html.matchAll(/<input[^>]*type="checkbox"[^>]*disabled=""/gu)].length, 6);
    assert.doesNotMatch(html, /pill-candidate_available|pill-current/u);
    assert.match(html, /pill-not_checked">Catalog needs refresh/u);
    assert.match(html, /No newer reviewed scanner image candidate is available/u);
    assert.doesNotMatch(html, /An admitted candidate manifest is required/u);
  }
  const fresh = { ...catalog, started_at: '2026-09-07T12:11:00Z', completed_at: '2026-09-07T12:12:00Z',
    receipt: { result: { kind: 'catalog', checked_at: '2026-09-07T12:11:30Z', components: scannerCacheComponents.map(({ id }) => ({
      component_id: id, state: 'current',
    })) } },
  };
  assert.equal(catalogComponentState(fresh, 'grype-db', cache), 'current');
  assert.match(render(fresh), /pill-current/u);
  assert.doesNotMatch(render(fresh), /Catalog needs refresh/u);
  assert.equal(catalogComponentState(fresh, 'grype-db', { ...cache, active_generation: 'c'.repeat(64), completed_at: '2026-09-07T12:13:00Z' }), 'catalog_needs_refresh', 'rollback invalidates an older catalog too');
  for (const status of ['queued', 'leased', 'running', 'cancelling'] as const) {
    assert.equal(catalogComponentState(catalog, 'grype-db', { ...cache, status, completed_at: null }), 'catalog_needs_refresh');
  }
  for (const status of ['failed', 'cancelled'] as const) {
    const laterAttempt: ScannerLifecycleScope = { ...cache, status, job_id: 18, revision: 4, receipt: {},
      started_at: '2026-09-07T12:13:00Z', completed_at: '2026-09-07T12:14:00Z' };
    assert.equal(laterAttempt.active_generation, cache.active_generation);
    assert.equal(catalogComponentState(catalog, 'grype-db', laterAttempt), 'catalog_needs_refresh', 'a failed/cancelled attempt cannot reopen old candidates');
    assert.equal(catalogComponentState(fresh, 'grype-db', laterAttempt), 'catalog_needs_refresh');
    const html = render(catalog, laterAttempt);
    assert.equal([...html.matchAll(/<input[^>]*type="checkbox"[^>]*disabled=""/gu)].length, 6);
    assert.match(html, /Catalog needs refresh after cache activity/u);
    assert.doesNotMatch(html, /Catalog needs refresh after cache activation/u);
    const rechecked = { ...withCheckedAt('2026-09-07T12:16:00Z'), started_at: '2026-09-07T12:15:00Z', completed_at: '2026-09-07T12:17:00Z' };
    assert.equal(catalogComponentState(rechecked, 'grype-db', laterAttempt), 'candidate_available', 'an actual new catalog can admit its own candidates');
  }
  assert.equal(catalogComponentState(catalog, 'grype-db'), 'candidate_available', 'initial preparation retains real candidates');
  assert.equal(catalogComponentState(catalog, 'grype-db', { ...cache, status: 'idle', completed_at: null }), 'candidate_available');
  assert.equal(catalogComponentState(fresh, 'grype-db', { ...cache, completed_at: null }), 'catalog_needs_refresh');
  assert.match(render(fresh, cache, { ...tool, update_available: true }), /An admitted candidate manifest is required/u);
  assert.match(render(fresh, cache, { ...tool, status: 'host_confirmation_required' }), /already selected; host confirmation is still required/u);
  assert.equal(JSON.stringify(catalog.receipt), historicalReceipt, 'historical catalog receipt is unchanged');
  assert.equal(preflight.ready, true);
});

test('scanner verification renders truthful controls and accepts matching live preflight receipts', async (context) => {
  const vite = await createServer({ root: fileURLToPath(new URL('..', import.meta.url)),
    configFile: false, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { ScannerCacheVerificationPanel, validScannerPreflight } = await vite.ssrLoadModule('/src/App.tsx') as typeof import('../src/App.tsx');
  const verification: ScannerCacheVerification = {
    state: 'verifying', target: 'active', generation_id: 'a'.repeat(64), phase: 'hashing', component_id: 'grype-db',
    started_at: new Date().toISOString(), last_activity_at: new Date().toISOString(), bytes_verified: 1024, bytes_total: 4096,
  };
  const render = (entry: ScannerCacheVerification) => renderToStaticMarkup(createElement(ScannerCacheVerificationPanel,
    { verification: entry, busy: false, onRetry: () => {}, onRefresh: () => {} }));
  const html = render(verification);
  assert.match(html, /data-testid="scanner-cache-verification-active"/u);
  assert.match(html, /Verifying scanner cache/u);
  assert.match(html, /Grype vulnerability DB/u);
  assert.match(html, /last activity/u);
  assert.match(html, /Refresh readiness/u);
  assert.doesNotMatch(html, /Retry verification|progressbar|[0-9]%/u);
  assert.match(render({ ...verification, state: 'timed_out' }), /Retry verification/u);
  const previousHtml = render({ ...verification, target: 'previous_good', state: 'failed' });
  assert.match(previousHtml, /Retry rollback verification/u);
  assert.match(previousHtml, /already-verified active cache remains available/u);

  const active: ScannerPreflight = {
    schema_version: 1, revision: 'b'.repeat(64), ready: false, enabled_tool_ids: ['grype'], ready_tool_ids: [],
    blocked_tools: [{ id: 'grype', name: 'Grype', blocking_reasons: ['scanner cache verification is in progress'],
      required_component_ids: ['grype-db'], preparation_blocking_reasons: ['scanner cache verification is in progress'] }],
    required_component_ids: ['grype-db'], preparation_available: false, active_generation: null,
    catalog_revision: null, cache_revision: null, cache_verification: verification,
    cache_rollback: { eligible: false, reason_code: 'no_previous_generation', reason: 'No previous-good generation.', target_generation: null },
    recommended_action: 'wait_for_scanner_verification',
  };
  assert.equal(validScannerPreflight(active), true);
  assert.equal(validScannerPreflight({ ...active, cache_verification: { ...verification, state: 'timed_out' }, recommended_action: 'retry_scanner_verification' }), true);
  assert.equal(validScannerPreflight({ ...active, preparation_available: true }), false);
  assert.equal(validScannerPreflight({ ...active, cache_verification: undefined }), false);
  assert.equal(validScannerPreflight({ ...active, enabled_tool_ids: ['grype', 'sast-lite'], ready_tool_ids: ['sast-lite'] }), true);
  const previous: ScannerPreflight = { ...active, cache_verification: undefined, ready: true, ready_tool_ids: ['grype'],
    blocked_tools: [], required_component_ids: [], active_generation: 'c'.repeat(64), recommended_action: 'scan',
    cache_rollback: { eligible: false, reason_code: 'previous_generation_verifying', reason: 'Verifying rollback.',
      target_generation: verification.generation_id, verification: { ...verification, target: 'previous_good' } },
  };
  assert.equal(validScannerPreflight(previous), true);

  const appSource = await readFile(fileURLToPath(new URL('../src/App.tsx', import.meta.url)), 'utf8');
  assert.match(appSource, /scannerVerificationPollRequired\(scannerPreflight\)/u);
  assert.match(appSource, /JSON\.stringify\(preflight\.cache_verification\)/u);
  assert.match(appSource, /const canRunLimited = Boolean\(preflight\?\.ready_tool_ids\.length\)/u);
  assert.match(appSource, /if \(verificationReason && coverage === 'complete'\)/u);
  assert.match(appSource, /if \(actionableSelectedComponents\.length && !cacheUpdateDisabledReason && catalogSelection\)/u);
});

test('scanner verification retry is one explicit authenticated request for the exact target', async (context) => {
  const vite = await createServer({ root: fileURLToPath(new URL('..', import.meta.url)),
    configFile: false, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { api, setCsrfToken } = await vite.ssrLoadModule('/src/api.ts') as typeof import('../src/api.ts');
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; });
  const requests: { url: string; init?: RequestInit }[] = [];
  globalThis.fetch = async (url, init) => {
    requests.push({ url: String(url), init });
    return new Response(JSON.stringify({}), { status: init?.method === 'POST' ? 202 : 200,
      headers: { 'Content-Type': 'application/json' } });
  };
  setCsrfToken('synthetic-csrf');
  await api.scannerPreflight();
  await api.scannerPreflight();
  assert.equal(requests.length, 2);
  assert.equal(requests.every(({ init }) => init?.method !== 'POST'), true);
  await api.retryScannerVerification('previous_good', 'a'.repeat(64));
  assert.equal(requests.length, 3);
  const command = requests[2];
  assert.equal(command.url, '/v1/scanner/cache/verification/retry');
  assert.equal(command.init?.method, 'POST');
  assert.equal(command.init?.credentials, 'same-origin');
  assert.equal(new Headers(command.init?.headers).get('X-CSRF-Token'), 'synthetic-csrf');
  assert.deepEqual(JSON.parse(String(command.init?.body)), { target: 'previous_good', expected_generation: 'a'.repeat(64) });
});

test('accepted scanner verification retry remains visible and polling after a dashboard refresh failure', async (context) => {
  const vite = await createServer({ root: fileURLToPath(new URL('..', import.meta.url)),
    configFile: false, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { applyAcceptedScannerVerification, scannerVerificationPollRequired } = await vite.ssrLoadModule('/src/scannerPreparation.ts') as typeof import('../src/scannerPreparation.ts');
  const { ScannerCacheVerificationPanel, validScannerPreflight } = await vite.ssrLoadModule('/src/App.tsx') as typeof import('../src/App.tsx');
  const failed: ScannerCacheVerification = {
    state: 'timed_out', target: 'active', generation_id: 'a'.repeat(64), phase: 'validating',
    component_id: 'grype-db', bytes_verified: null, bytes_total: null,
    started_at: '2026-09-07T12:00:00Z', last_activity_at: '2026-09-07T12:15:00Z',
  };
  const previous = { ...failed, target: 'previous_good' as const };
  const before: ScannerPreflight = {
    schema_version: 1, revision: 'b'.repeat(64), ready: false, enabled_tool_ids: ['grype'], ready_tool_ids: [],
    blocked_tools: [{ id: 'grype', name: 'Grype', blocking_reasons: ['scanner cache verification timed out'],
      required_component_ids: ['grype-db'], preparation_blocking_reasons: ['scanner cache verification timed out'] }],
    required_component_ids: ['grype-db'], preparation_available: false, active_generation: null,
    catalog_revision: null, cache_revision: null, cache_verification: failed,
    cache_rollback: { eligible: false, reason_code: 'previous_generation_verification_timeout', reason: 'Verification timed out.',
      target_generation: previous.generation_id, verification: previous },
    recommended_action: 'retry_scanner_verification',
  };
  for (const requested of [failed, previous]) {
    const accepted = { ...requested, state: 'verifying' as const, phase: 'queued' as const,
      started_at: '2026-09-07T12:16:00Z', last_activity_at: '2026-09-07T12:16:00Z' };
    const displayed = applyAcceptedScannerVerification(before, requested, accepted)!;
    await assert.rejects(async () => { throw new Error('Dashboard refresh unavailable'); });
    assert.equal(scannerVerificationPollRequired(displayed), true);
    assert.equal(displayed.revision, before.revision, 'the command receipt cannot invent an admission revision');
    assert.equal(validScannerPreflight(displayed), true);
    const observed = requested.target === 'active' ? displayed.cache_verification! : displayed.cache_rollback.verification!;
    const html = renderToStaticMarkup(createElement(ScannerCacheVerificationPanel,
      { verification: observed, busy: false, onRetry: () => {}, onRefresh: () => {} }));
    assert.match(html, /Verifying (?:scanner|rollback) cache/u);
    assert.doesNotMatch(html, /Retry verification|Retry rollback verification/u);
    assert.equal(displayed.ready, before.ready);
    if (requested.target === 'previous_good') assert.equal(displayed.cache_verification, before.cache_verification);
    else assert.equal(displayed.cache_rollback, before.cache_rollback);
    assert.equal(applyAcceptedScannerVerification(displayed, requested, accepted), displayed, 'an older response cannot overwrite a newer state');
    assert.equal(applyAcceptedScannerVerification(before, { ...requested, started_at: '2026-09-07T11:00:00Z' }, accepted), before);
    assert.equal(applyAcceptedScannerVerification(before, { ...requested, last_activity_at: '2026-09-07T12:14:00Z' }, accepted), before);
    assert.equal(applyAcceptedScannerVerification(before, requested, { ...accepted, generation_id: 'c'.repeat(64) }), before);
    assert.equal(applyAcceptedScannerVerification(before, requested, { ...accepted, state: 'failed' }), before);
  }
  assert.equal(scannerVerificationPollRequired(before), false, 'a subsequent terminal preflight stops polling');
  const appSource = await readFile(fileURLToPath(new URL('../src/App.tsx', import.meta.url)), 'utf8');
  const handler = appSource.slice(appSource.indexOf('async function retryScannerVerification('), appSource.indexOf('async function rollbackScannerCache('));
  assert.match(handler, /refreshGenerationRef\.current \+= 1;[\s\S]*refreshControllerRef\.current\?\.abort\(\);/u);
  assert.match(handler, /scannerPreflight: \[\]/u);
  assert.ok(handler.indexOf('applyAcceptedScannerVerification(current, verification, accepted)') < handler.indexOf("await refresh(undefined, 'mutation')"));
});

test('one primary scanner action truthfully starts with catalog-only admission', async (context) => {
  const appSource = await readFile(fileURLToPath(new URL('../src/App.tsx', import.meta.url)), 'utf8');
  const apiSource = await readFile(fileURLToPath(new URL('../src/api.ts', import.meta.url)), 'utf8');
  const policySource = await readFile(fileURLToPath(new URL('../src/scannerPreparation.ts', import.meta.url)), 'utf8');

  assert.match(appSource, /const command = await api\.prepareScanners\(\);/u);
  assert.match(appSource, /recordScannerLifecycleCommand\(command\.catalog\.job, command\.catalog\.lifecycle\);/u);
  assert.match(appSource, /if \(command\.cache\) \{[\s\S]{0,160}recordScannerLifecycleCommand\(command\.cache\.job, command\.cache\.lifecycle\);/u);
  assert.match(appSource, /'Prepare all scanners'/u);
  assert.match(appSource, /Starts only after the catalog passes/u);
  assert.match(appSource, /The last scanner check requires a source update\./u);
  assert.match(appSource, /Each attempt checks the catalog before any download\./u);
  assert.match(appSource, /Downloading the same data again will not make it current\./u);
  assert.match(appSource, /Get refreshed reviewed CodeSecurity source/u);
  assert.match(appSource, /requiredLockRefreshComponents\(preflight, lifecycle\?\.catalog \|\| null\)/u);
  assert.match(appSource, /scannerPreparationDisabledReason\(/u);
  assert.match(appSource, /aria-describedby=\{preparationDisabledReason \? 'scanner-preparation-disabled-reason'/u);
  assert.match(appSource, /<DisabledReason id="scanner-preparation-disabled-reason" reason=\{activeVerification \? null : preparationDisabledReason\}/u);
  assert.match(appSource, /Scanner runtime recovery steps/u);
  assert.match(appSource, /--no-deps --no-build --force-recreate --wait --wait-timeout 120 scanner/u);
  assert.match(appSource, /Copy recovery command/u);
  assert.match(appSource, /Refresh readiness/u);
  assert.match(appSource, /refreshScannerStatus=\{\(\) => void refresh\(undefined, 'manual'\)\}/u);
  assert.doesNotMatch(appSource, /scannerRuntimeRecoveryCommand[\s\S]{0,500}(?:--build|docker pull|down -v)/u);
  assert.doesNotMatch(appSource, /requiredCandidateComponents\.length[\s\S]{0,300}stableUpdateScannerCache/u);
  assert.match(apiSource, /cache\?: ScannerLifecycleCommandOut \| null/u);
  assert.match(apiSource, /prepareScanners: \(\) => request<ScannerPreparationCommandOut>\('\/v1\/scanner\/prepare'/u);
  assert.match(policySource, /Verified cache work will be created only if that catalog check passes\./u);

  const vite = await createServer({ root: fileURLToPath(new URL('..', import.meta.url)),
    configFile: false, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { Tools } = await vite.ssrLoadModule('/src/App.tsx') as typeof import('../src/App.tsx');
  const scope: ScannerLifecycleScope = {
    scope: 'catalog', status: 'idle', revision: 0, job_id: null, job_url: null,
    active_generation: null, previous_generation: null, receipt: {}, error_code: null, error_detail: null,
    started_at: null, completed_at: null, updated_at: '2026-09-20T08:00:00Z',
  };
  const preflight: ScannerPreflight = {
    schema_version: 1, revision: 'b'.repeat(64), ready: false,
    enabled_tool_ids: ['trivy', 'grype', 'opengrep', 'bearer'], ready_tool_ids: [],
    blocked_tools: ['trivy', 'grype', 'opengrep', 'bearer'].map((id) => ({
      id, name: id, blocking_reasons: [`${id} data must be prepared.`],
      required_component_ids: [], preparation_blocking_reasons: [],
    })),
    required_component_ids: ['grype-db'], preparation_available: true, active_generation: 'a'.repeat(64),
    catalog_revision: 0, cache_revision: 0, recommended_action: 'prepare_scanners',
    cache_rollback: { eligible: false, reason_code: 'no_previous_generation', reason: 'No previous-good generation.', target_generation: null },
  };
  const render = (busy: boolean) => renderToStaticMarkup(createElement(Tools, {
    surface: { 'data-route-surface': 'tools', inert: false }, tools: [],
    lifecycle: { catalog: scope, cache: { ...scope, scope: 'cache' } }, preflight,
    jobs: [], busy, dashboardSettled: true,
    prepareScanners() {}, checkTools() {}, updateScannerCache() {}, rollbackScannerCache() {}, selectToolCandidate() {},
    toggleTool() {}, cancelJob() {}, retryJob() {}, viewJob() {}, refreshScannerStatus() {}, retryScannerVerification() {},
  }));
  for (const busy of [false, true]) {
    const html = render(busy);
    const label = busy ? 'Preparation in progress' : 'Prepare all scanners';
    const buttons = [...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/gu)]
      .map(([button]) => button).filter((button) => button.includes(label));
    assert.equal(buttons.length, 1, 'the primary action remains a single native button');
    const actionOffset = html.indexOf(buttons[0]);
    assert.ok(actionOffset < html.indexOf('class="preparation-steps"'), 'the primary action precedes preparation steps');
    assert.ok(actionOffset < html.indexOf('class="preflight-blocked-tools"'), 'the primary action precedes every blocked-scanner explanation');
    assert.match(html, /Validated runtime generation aaaaaaaaaaaa/u);
    assert.match(html, /4 blocked scanners/u);
    for (const tool of preflight.blocked_tools) assert.ok(html.includes(tool.blocking_reasons[0]));
    if (busy) {
      assert.match(buttons[0], /aria-describedby="scanner-preparation-disabled-reason"[^>]*disabled=""/u);
      assert.match(html, /id="scanner-preparation-disabled-reason" role="status">Scanner preparation is already processing or reconciling durable work\./u);
      assert.ok(html.indexOf('id="scanner-preparation-disabled-reason"') < html.indexOf('class="preparation-steps"'));
    } else assert.doesNotMatch(buttons[0], /aria-describedby|disabled=/u);
  }

  const styles = await readFile(fileURLToPath(new URL('../src/styles.css', import.meta.url)), 'utf8');
  const summary = styles.match(/\.workbench-summary\s*\{(?<body>[^}]*)\}/u)?.groups?.body;
  const summaryValue = styles.match(/\.workbench-summary > div\s*\{(?<body>[^}]*)\}/u)?.groups?.body;
  assert.ok(summary && summaryValue, 'scanner metadata uses the shared semantic summary');
  assert.match(summary, /flex-wrap:\s*wrap/u);
  assert.match(summaryValue, /min-width:\s*0/u);
  assert.match(summaryValue, /overflow-wrap:\s*anywhere/u);
  assert.doesNotMatch(summaryValue, /overflow:\s*hidden|text-overflow:\s*ellipsis/u);
  assert.match(render(false), /<dl class="workbench-summary" aria-label="Scanner summary">/u);
  const statText = styles.match(/\.stat > div\s*\{(?<body>[^}]*)\}/u)?.groups?.body;
  assert.ok(statText);
  assert.match(statText, /min-width:\s*0/u);
  assert.match(statText, /overflow-wrap:\s*anywhere/u);
  assert.doesNotMatch(statText, /overflow:\s*hidden|text-overflow:\s*ellipsis/u);
});

test('scanner work keeps advanced maintenance secondary to primary readiness', async () => {
  const appSource = await readFile(fileURLToPath(new URL('../src/App.tsx', import.meta.url)), 'utf8');

  assert.match(appSource, /const \[maintenanceOpen, setMaintenanceOpen\] = useState\(false\);/u);
  assert.match(appSource, /<details[\s\S]{0,160}open=\{maintenanceOpen\}[\s\S]{0,160}onToggle=/u);
  assert.doesNotMatch(appSource, /lifecycleActive[\s\S]{0,300}setMaintenanceOpen\(true\)/u);
});
