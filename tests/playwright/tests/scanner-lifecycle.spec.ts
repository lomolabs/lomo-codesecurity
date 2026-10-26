import { referenceTest } from './support/reference-viewport.js';
import { expect, Page } from '@playwright/test';

import { installRuntimeGuards } from './support/quality.js';

async function openTools(page: Page, openMaintenance = true) {
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await page.goto('/?view=overview');
  await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
  await expect(page.getByRole('status', { name: 'Control plane healthy', exact: true })).toBeVisible();
  await page.getByRole('navigation').getByRole('button', { name: 'Tools', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Tools', exact: true })).toBeVisible();
  const surface = page.locator('section[data-route-surface="tools"]');
  await expect(surface).toHaveAttribute('data-tools-render-stage', 'ready');
  await expect(surface).not.toHaveAttribute('aria-hidden', 'true');
  await expect(surface.locator('.tool-card').first()).toBeVisible();
  if (openMaintenance) {
    const maintenance = surface.locator('details.scanner-maintenance');
    if (await maintenance.getAttribute('open') === null) {
      await maintenance.getByText('Advanced scanner maintenance', { exact: true }).click();
    }
    await expect(maintenance).toHaveAttribute('open', '');
  }
  return surface;
}

referenceTest('Tools keeps one-click preparation primary and manual maintenance progressively disclosed', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await request.post('/__test/reset', { data: { profile: 'scanner-preparation', generation: 1 } });
  let surface = await openTools(page, false);
  let maintenance = surface.locator('details.scanner-maintenance');
  // A catalog-ready binary can still lack required rules. Present one
  // authoritative readiness summary, not a contradictory generic "ready".
  const blockedTool = surface.locator('.tool-card', { hasText: 'OpenGrep' });
  await expect(blockedTool.locator('.readiness-head strong')).toHaveText('not ready');
  await expect(blockedTool.locator('.kv dt').getByText('Status', { exact: true })).toHaveCount(0);
  await expect(blockedTool.getByLabel('OpenGrep runtime readiness')).toContainText('No validated active or previous-good OpenGrep rules generation exists.');
  await testInfo.attach('blocked-tool-truthful-readiness.png', {
    body: await blockedTool.screenshot(), contentType: 'image/png',
  });
  await expect(surface.getByRole('button', { name: 'Prepare all scanners', exact: true })).toBeVisible();
  await expect(maintenance).not.toHaveAttribute('open', '');
  await expect(maintenance.getByRole('button', { name: 'Check curated catalog', exact: true })).toBeHidden();
  await maintenance.getByText('Advanced scanner maintenance', { exact: true }).click();
  await expect(maintenance.getByRole('button', { name: 'Check curated catalog', exact: true })).toBeVisible();

  await request.post('/__test/reset', { data: { profile: 'scanner-readiness-missing', generation: 2 } });
  surface = await openTools(page, false);
  await expect(surface.getByRole('button', { name: 'Prepare all scanners', exact: true })).toHaveCount(0);
  await expect(surface.getByRole('alert')).toContainText('Preparing databases and rules cannot repair a missing binary or offline execution path.');
  await expect(surface).toContainText('Scanner runtime required: Runtime readiness was not reported.');
  guards.assertClean();
});

referenceTest('Tools queues durable catalog and explicit cache commands without claiming installation', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'scanner-readiness-missing', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openTools(page);

  const catalog = surface.getByLabel('Curated catalog lifecycle');
  const cache = surface.getByLabel('Offline cache lifecycle');
  await expect(catalog.locator('.pill')).toHaveText('completed');
  await expect(cache.locator('.pill')).toHaveText('idle');

  const updateCache = surface.getByRole('button', { name: 'Update selected cache', exact: true });
  await expect(updateCache).toBeDisabled();
  await expect(updateCache).toHaveAttribute('aria-describedby', 'scanner-cache-update-disabled-reason');
  await expect(surface.locator('#scanner-cache-update-disabled-reason')).toHaveText('Select at least one attested cache candidate to update.');

  const readiness = surface.getByLabel('OpenGrep runtime readiness');
  await expect(readiness.getByText('Binary', { exact: true })).toBeVisible();
  await expect(readiness.getByText('Data', { exact: true })).toBeVisible();
  await expect(readiness.getByText('Rules', { exact: true })).toBeVisible();
  await expect(readiness.getByText('Execution', { exact: true })).toBeVisible();
  await expect(surface.getByRole('button', { name: 'Apply Latest' })).toHaveCount(0);

  const checkov = surface.locator('.tool-card', { hasText: 'Checkov' });
  await expect(checkov.getByLabel('Checkov runtime readiness').locator('.readiness-not_reported')).toHaveCount(4);
  await checkov.getByRole('button', { name: 'Select candidate', exact: true }).click();
  await expect(checkov.getByText(/Host confirmation is required to replace the immutable scanner image/)).toBeVisible();
  await expect(checkov.getByRole('button', { name: 'Candidate selected', exact: true })).toBeDisabled();

  const trivyDb = surface.getByRole('checkbox', { name: /Trivy vulnerability DB/ });
  const opengrepRules = surface.getByRole('checkbox', { name: /OpenGrep reviewed rules/ });
  await expect(trivyDb).toBeEnabled();
  await expect(surface.getByRole('checkbox', { name: /Trivy Java DB/ })).toBeDisabled();
  await trivyDb.check();
  await opengrepRules.check();
  await surface.getByRole('button', { name: 'Update selected cache', exact: true }).click();
  await expect(page.getByText('Queuing verified cache update', { exact: true })).toBeVisible();
  await expect(cache.locator('.pill')).toHaveText('queued');
  await expect(cache.getByRole('button', { name: /View job #/ })).toBeVisible();

  await surface.getByRole('button', { name: 'Check curated catalog', exact: true }).click();
  await expect(page.getByText('Queuing curated catalog check', { exact: true })).toBeVisible();
  await expect(catalog.locator('.pill')).toHaveText('queued');

  const commands = await (await request.get('/__test/commands')).json() as Array<{
    route: string;
    idempotency_key: string;
    input: Record<string, unknown>;
  }>;
  const lifecycleCommands = commands.filter((command) => command.route.startsWith('scanner-'));
  expect(lifecycleCommands.map((command) => command.route)).toEqual(['scanner-cache-update', 'scanner-catalog-check']);
  expect(lifecycleCommands[0].input).toEqual({ component_ids: ['opengrep-reviewed-rules', 'trivy-db'], catalog_digest: null });
  expect(lifecycleCommands.every((command) => /^web-[0-9a-f-]{36}$/.test(command.idempotency_key))).toBe(true);
  expect(new Set(lifecycleCommands.map((command) => command.idempotency_key)).size).toBe(2);
  guards.assertClean();
});

referenceTest('Tools rechecks a historical source-update catalog before any download', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'scanner-lock-refresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openTools(page);

  const grype = surface.locator('.cache-component', { hasText: 'Grype vulnerability DB' });
  await expect(grype.locator('.pill')).toHaveText('requires_lock_refresh');
  await expect(grype.getByRole('checkbox')).toBeDisabled();

  const guidance = surface.getByRole('status').filter({ hasText: 'The last scanner check requires a source update.' });
  await expect(guidance).toContainText('Get refreshed reviewed CodeSecurity source');
  await expect(guidance).toContainText('existing state and editor options');
  await expect(guidance).toContainText('After updating, choose Prepare all scanners to check the refreshed source.');
  await expect(guidance).toContainText('Each attempt checks the catalog before any download.');
  await expect(guidance).toContainText('Downloading the same data again will not make it current');
  const prepare = surface.getByRole('button', { name: 'Prepare all scanners', exact: true });
  await expect(prepare).toBeEnabled();
  await expect(guidance.getByRole('button')).toHaveCount(0);
  await testInfo.attach('historical-source-update-guidance.png', { body: await guidance.screenshot(), contentType: 'image/png' });

  const before = await request.get('/v1/scanner/lifecycle').then((response) => response.json());
  expect(before.catalog.status).toBe('completed');
  expect(before.cache.status).toBe('idle');
  const jobsBefore = await request.get('/v1/jobs').then((response) => response.json()) as Array<{ id: number }>;
  const previousIds = new Set(jobsBefore.map(({ id }) => id));
  const responsePending = page.waitForResponse((response) => (
    new URL(response.url()).pathname === '/v1/scanner/prepare' && response.request().method() === 'POST'
  ));
  await prepare.click();
  const response = await responsePending;
  expect(response.status()).toBe(202);
  const prepared = await response.json();
  expect(prepared).toMatchObject({
    catalog: { job: { kind: 'scanner_catalog_check', status: 'queued' }, lifecycle: { scope: 'catalog', status: 'queued' } },
    cache: null,
    required_component_ids: ['grype-db'],
  });
  await expect(surface.getByLabel('Curated catalog lifecycle').locator('.pill')).toHaveText('queued');
  await expect(surface.getByLabel('Offline cache lifecycle').locator('.pill')).toHaveText('idle');
  await expect(surface.getByRole('button', { name: 'Preparation in progress', exact: true })).toBeDisabled();
  await expect(grype.getByRole('checkbox')).toBeDisabled();
  await page.waitForLoadState('networkidle');

  const commands = await request.get('/__test/commands').then((reply) => reply.json()) as Array<{ route: string; input: Record<string, unknown> }>;
  expect(commands).toHaveLength(1);
  expect(commands[0]).toMatchObject({ route: 'scanner-prepare', input: {} });
  const after = await request.get('/v1/scanner/lifecycle').then((reply) => reply.json());
  expect(after.cache).toEqual(before.cache);
  const jobsAfter = await request.get('/v1/jobs').then((reply) => reply.json()) as Array<{ id: number; kind: string }>;
  expect(jobsAfter.filter(({ id }) => !previousIds.has(id))).toEqual([prepared.catalog.job]);
  await testInfo.attach('historical-source-update-catalog-only-command.json', {
    body: Buffer.from(JSON.stringify({ prepared, commands, unchanged_cache: after.cache }, null, 2)), contentType: 'application/json',
  });
  guards.assertClean();
});

referenceTest('Tools advanced cache update excludes stale immutable candidates', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'scanner-lock-refresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openTools(page);
  const grype = surface.locator('.cache-component', { hasText: 'Grype vulnerability DB' });
  await expect(grype.locator('.pill')).toHaveText('requires_lock_refresh');
  await expect(grype.getByRole('checkbox')).toBeDisabled();

  const acquisitionRelative = surface.getByRole('checkbox', { name: /Trivy checks/ });
  await expect(acquisitionRelative).toBeEnabled();
  await acquisitionRelative.check();
  await surface.getByRole('button', { name: 'Update selected cache', exact: true }).click();

  const commands = await (await request.get('/__test/commands')).json() as Array<{
    route: string;
    input: Record<string, unknown>;
  }>;
  expect(commands).toHaveLength(1);
  expect(commands[0]).toMatchObject({
    route: 'scanner-cache-update',
    input: { component_ids: ['trivy-checks'] },
  });
  guards.assertClean();
});

referenceTest('Tools exposes lifecycle cancel and retry through the associated durable jobs', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'scanner-lifecycle-failures', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openTools(page);

  const catalog = surface.getByLabel('Curated catalog lifecycle');
  const cache = surface.getByLabel('Offline cache lifecycle');
  await expect(catalog.locator('.pill')).toHaveText('running');
  await expect(cache.locator('.pill')).toHaveText('failed');
  await expect(cache).toContainText('candidate_validation_failed');
  const checkCatalog = surface.getByRole('button', { name: 'Check curated catalog', exact: true });
  await expect(checkCatalog).toBeDisabled();
  await expect(checkCatalog).toHaveAttribute('aria-describedby', 'scanner-catalog-disabled-reason');
  await expect(surface.locator('#scanner-catalog-disabled-reason')).toHaveText('A curated catalog check is already in progress.');

  await catalog.getByRole('button', { name: 'Cancel', exact: true }).click();
  const cancellation = page.locator('dialog.confirmation-dialog');
  await expect(cancellation).toBeVisible();
  expect(await cancellation.locator('p').innerText()).toContain('The source-blind updater will stop at a safe boundary.');
  await cancellation.getByRole('button', { name: 'Cancel job', exact: true }).click();
  await expect(page.getByText('The durable worker will cancel the exact updater operation and wait for its terminal receipt.', { exact: true })).toBeVisible();
  await expect(catalog.locator('.pill')).toHaveText('cancelling');
  await expect(catalog).toContainText('waiting for updater confirmation');

  await cache.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(cache.locator('.pill')).toHaveText('queued');
  await expect(cache).toContainText('Persisted and waiting for the durable worker');

  await catalog.getByRole('button', { name: 'View job #95' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Jobs', exact: true })).toBeVisible();
  const catalogJob = page.locator('.job-row', { hasText: 'Running curated catalog check' });
  await expect(catalogJob).toContainText('cancelling');
  await expect(catalogJob).toContainText("Updater cancellation is persisted; waiting for the updater's terminal receipt.");
  guards.assertClean();
});

referenceTest('Tools loads and focuses an exact durable job omitted from recent history before retrying it', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'scanner-lifecycle-failures', generation: 1 } });
  let exactJobRequests = 0;
  let failExactJobRefresh = false;
  page.on('request', (candidate) => {
    const url = new URL(candidate.url());
    if (candidate.method() === 'GET' && url.pathname === '/v1/jobs/96') exactJobRequests += 1;
  });
  await page.route('**/v1/jobs/96', async (route) => {
    if (route.request().method() !== 'GET' || !failExactJobRefresh) {
      await route.continue();
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', json: { id: 97 } });
  });
  await page.route('**/v1/jobs*', async (route) => {
    const requestUrl = new URL(route.request().url());
    if (
      route.request().method() !== 'GET'
      || requestUrl.pathname !== '/v1/jobs'
      || requestUrl.searchParams.has('status')
    ) {
      await route.continue();
      return;
    }
    const response = await route.fetch();
    const recentJobs = await response.json() as Array<{ id: number }>;
    await route.fulfill({ response, json: recentJobs.filter((job) => job.id !== 96) });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const tools = await openTools(page);
  const cache = tools.getByLabel('Offline cache lifecycle');

  await expect(cache.getByRole('button', { name: 'Retry', exact: true })).toHaveCount(0);
  await cache.getByRole('button', { name: 'View job #96', exact: true }).click();

  await expect(page.getByRole('heading', { level: 1, name: 'Jobs', exact: true })).toBeVisible();
  await expect(page.getByText('Showing exact durable job #96', { exact: true })).toBeVisible();
  const exactJob = page.getByLabel('Job #96: Failed verified cache update', { exact: true });
  await expect(exactJob).toBeVisible();
  await expect(exactJob).toBeFocused();
  await expect(exactJob).toHaveAttribute('aria-current', 'true');
  await expect(exactJob).toContainText('attempt 1/3');
  await expect(exactJob).toContainText('candidate_validation_failed');
  await expect(exactJob.getByRole('button', { name: 'Retry', exact: true })).toBeVisible();
  expect(exactJobRequests).toBeGreaterThanOrEqual(1);

  const filters = page.getByRole('group', { name: 'Job filters', exact: true });
  await filters.getByLabel('Job status', { exact: true }).selectOption('active');
  await expect(exactJob).toHaveCount(0);
  await expect(page.getByText('Showing exact durable job #96', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Exact durable job #96 is hidden by current filters', { exact: true })).toBeVisible();
  const resetFilters = page.getByRole('button', { name: 'Reset filters', exact: true });
  await expect(resetFilters).toBeVisible();
  await resetFilters.click();
  await expect(filters.getByLabel('Job status', { exact: true })).toHaveValue('all');
  await expect(page.getByText('Showing exact durable job #96', { exact: true })).toBeVisible();
  await expect(exactJob).toBeVisible();
  await expect(exactJob).toBeFocused();
  await expect(exactJob).toHaveAttribute('aria-current', 'true');

  failExactJobRefresh = true;
  await page.getByTitle('Refresh', { exact: true }).click();
  await expect(page.getByText('Showing last loaded revision for durable job #96', { exact: true })).toBeVisible();
  await expect(page.getByText('Preparing exact durable job #96', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Preparing last loaded revision for durable job #96', { exact: true })).toHaveCount(0);
  await expect(page.getByText(
    'The last exact revision remains loaded, but CodeSecurity could not refresh it: CodeSecurity returned job #97 while job #96 was requested.',
    { exact: true },
  )).toBeVisible();
  await expect(exactJob).toBeVisible();
  await expect(exactJob).toHaveAttribute('aria-current', 'true');
  failExactJobRefresh = false;

  await exactJob.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(exactJob.locator('.pill')).toHaveText('Waiting');
  expect(await request.get('/v1/jobs/96').then((response) => response.json())).toMatchObject({
    status: 'queued',
    revision: 5,
    can_cancel: true,
    can_retry: false,
  });
  guards.assertClean();
});

referenceTest('Tools queues an explicit previous-good rollback with confirmation and durable identity', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openTools(page);
  const cache = surface.getByLabel('Offline cache lifecycle');
  await expect(cache).toContainText('0'.repeat(64));

  await surface.getByRole('button', { name: 'Roll back cache', exact: true }).click();
  const rollback = page.locator('dialog.confirmation-dialog');
  await expect(rollback).toBeVisible();
  expect(await rollback.locator('p').innerText()).toContain('previous verified scanner cache generation');
  await rollback.getByRole('button', { name: 'Roll back cache', exact: true }).click();
  await expect(page.getByText('Queuing verified cache rollback', { exact: true })).toBeVisible();
  await expect(cache.locator('.pill')).toHaveText('queued');
  await expect(cache.getByRole('button', { name: /View job #/ })).toBeVisible();

  const commands = await (await request.get('/__test/commands')).json() as Array<{
    route: string;
    idempotency_key: string;
    input: Record<string, unknown>;
  }>;
  expect(commands).toHaveLength(1);
  expect(commands[0].route).toBe('scanner-cache-rollback');
  expect(commands[0].input).toEqual({});
  expect(commands[0].idempotency_key).toMatch(/^web-[0-9a-f-]{36}$/);
  guards.assertClean();
});

referenceTest('Tools disables an incompatible previous cache before job admission and explains why', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'scanner-rollback-incompatible', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openTools(page);
  const rollback = surface.getByRole('button', { name: 'Roll back cache', exact: true });

  await expect(rollback).toBeDisabled();
  await expect(surface.getByText(/Rollback unavailable: The previous cache generation was built from different reviewed scanner locks\./u)).toBeVisible();
  await expect(rollback).toHaveAttribute('title', /Prepare a verified cache for the current scanner catalog instead\./u);
  expect(await (await request.get('/__test/commands')).json()).toEqual([]);
  guards.assertClean();
});

referenceTest('Tools replaces stale rollback eligibility after an integrity refusal while preserving active readiness', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const initial = await request.get('/v1/scanner/preflight').then(response => response.json());
  const message = 'The previous scanner cache generation failed integrity validation and cannot be restored.';
  let rejected = false, commands = 0, releaseRead: () => void = () => {};
  const delayedRead = new Promise<void>(resolve => { releaseRead = resolve; });
  await page.route('**/v1/scanner/preflight', async route => {
    if (!rejected) return route.fallback();
    await delayedRead;
    await route.fulfill({ json: { ...initial, cache_rollback: {
      eligible: false, reason_code: 'previous_generation_invalid', reason: message,
      target_generation: initial.cache_rollback.target_generation,
    } } });
  });
  await page.route('**/v1/scanner/cache/rollback', async route => {
    commands++;
    rejected = true;
    await route.fulfill({ status: 409, json: { detail: {
      code: 'scanner_cache_rollback_unavailable', message, action: 'prepare_scanners',
      context: { reason_code: 'previous_generation_invalid', target_generation: initial.cache_rollback.target_generation },
    } } });
  });
  try {
    const surface = await openTools(page);
    const button = surface.getByRole('button', { name: 'Roll back cache', exact: true });
    await button.click();
    await page.locator('dialog.confirmation-dialog').getByRole('button', { name: 'Roll back cache', exact: true }).click();
    await expect(surface.getByText(`Rollback unavailable: ${message}`, { exact: true })).toBeVisible();
    await expect(button).toBeDisabled();
    await expect(surface.getByText('Ready to Scan', { exact: true })).toBeVisible();
    await expect(surface.getByText('The previous verified cache generation is compatible and can be restored atomically.', { exact: true })).toHaveCount(0);
    releaseRead();
    await expect(page.getByRole('alert').filter({ hasText: message }).first()).toBeVisible();
    await expect(button).toBeDisabled();
    expect(commands).toBe(1);
    expect(await request.get('/__test/commands').then(response => response.json())).toEqual([]);
    expect(guards.failures.http).toEqual([`409 ${new URL(baseURL).origin}/v1/scanner/cache/rollback`]);
    expect(guards.failures.console).toHaveLength(1);
    expect(guards.failures.console[0]).toContain('409 (Conflict)');
    guards.failures.http.length = 0;
    guards.failures.console.length = 0;
    guards.assertClean();
  } finally {
    releaseRead();
  }
});
