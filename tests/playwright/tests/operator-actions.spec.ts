import { referenceTest } from './support/reference-viewport.js';
import { waitForRouteReady } from './support/route-ready.js';
import { APIRequestContext, expect, Locator, Page, Request, Response, Route, test } from '@playwright/test';

import { installRuntimeGuards } from './support/quality.js';
import { BULK_LIFECYCLE_ACTIONS, prepareBulkFindingSelection, performBulkFindingAction,
  verifyBulkFindingRequest, waitForBulkSelection } from '../../../extensions/vscode/test/ui/bulk-finding-actions.mjs';
import { armBulkFindingRace } from '../../../extensions/vscode/test/ui/bulk-finding-race.mjs';

type FindingDisclosure = '.finding-filter-details' | '.bulk-action-disclosure' | '.finding-scan-details';

async function expandFindingDisclosure(owner: Page | Locator, selector: FindingDisclosure) {
  const disclosure = owner.locator(selector);
  await expect(disclosure).toHaveCount(1);
  if (!await disclosure.evaluate((element: HTMLDetailsElement) => element.open)) {
    await disclosure.locator(':scope > summary').click();
  }
  await expect(disclosure).toHaveAttribute('open', '');
  return disclosure;
}

type AdvisorDisclosurePreviewFixture = {
  confirmation: {
    schema: 'lomo-advisor-run-confirmation/v1';
    authorization_id: string;
    provider_id: string;
    provider_config_revision: number;
    provider_config_digest: string;
    transport: 'direct' | 'ssh';
    destination: string;
    disclosure_mode: 'finding_evidence';
    payload_categories: string[];
    model: string;
    model_digest: string;
    consent_approved_at: string;
    finding_id: number;
    finding_revision: number;
    prompt_sha256: string;
    confirmation_digest: string;
  };
  packet: unknown;
  packet_utf8_bytes: number;
};

type AdvisorTriageProviderPinFixture = {
  provider_collection_revision: number;
  provider_id: string;
  transport: 'local' | 'direct' | 'ssh';
  provider_config_revision: number;
  provider_config_digest: string;
  model: string;
  model_digest: string;
};

const advisorDisclosureCategories = [
  'finding_identity',
  'source_location',
  'repository_context',
  'bounded_code_snippet',
  'bounded_scanner_metadata',
] as const;

const SETTINGS_IDE_SLOT = `ks1_${'S'.repeat(43)}`;
const SOURCE_OPEN_IDE_SLOT = `ks1_${'O'.repeat(43)}`;
const INVALID_IDE_SLOT = `ks1_${'I'.repeat(43)}`;
const PENDING_RACE_IDE_SLOT = `ks1_${'P'.repeat(43)}`;
const RESET_RACE_IDE_SLOT = `ks1_${'R'.repeat(43)}`;
const INVALID_IDE_RECOVERY_TOKEN_A = `kir1_${'a'.repeat(64)}`;
const INVALID_IDE_RECOVERY_TOKEN_B = `kir1_${'b'.repeat(64)}`;
const INVALID_IDE_RECOVERY_TOKEN_C = `kir1_${'c'.repeat(64)}`;
const INVALID_IDE_RECOVERY_TOKEN_D = `kir1_${'d'.repeat(64)}`;

type RuntimeGuards = Awaited<ReturnType<typeof installRuntimeGuards>>;

async function openAdvancedScannerMaintenance(surface: Locator) {
  const maintenance = surface.locator('details.scanner-maintenance');
  if (await maintenance.getAttribute('open') === null) {
    await maintenance.getByText('Advanced scanner maintenance', { exact: true }).click();
  }
  await expect(maintenance).toHaveAttribute('open', '');
  return maintenance;
}

function advisorProviderWriteInput(provider: Record<string, unknown>) {
  return {
    id: provider.id,
    name: provider.name,
    transport: provider.transport,
    priority: provider.priority,
    enabled: provider.enabled,
    base_url: provider.base_url,
    model: provider.model,
    model_digest: provider.model_digest,
    ssh_host: provider.ssh_host,
    ssh_port: provider.ssh_port,
    ssh_user: provider.ssh_user,
  };
}

function assertOnlyExpectedConflictResponses(
  guards: RuntimeGuards,
  expectedOrigin: string,
  exactPaths: readonly string[],
) {
  expect(guards.failures.http).toEqual(exactPaths.map((path) => `409 ${expectedOrigin}${path}`));
  expect(guards.failures.console).toEqual(exactPaths.map(
    () => 'Failed to load resource: the server responded with a status of 409 (Conflict)',
  ));
  guards.failures.http.length = 0;
  guards.failures.console.length = 0;
  guards.assertClean();
}

async function openRoute(page: Page, name: string) {
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await page.goto('/?view=overview');
  await waitForRouteReady(page, 'Overview');
  if (name !== 'Overview') {
    await page.getByRole('navigation').getByRole('button', { name, exact: true }).click();
  }
  return waitForRouteReady(page, name);
}

async function installSettingsLoadFaults(
  page: Page,
  origin: string,
  failures: Record<string, { code: string; message: string }>,
) {
  let phase: 'pass' | 'entry-failure' | 'recovery-held' = 'pass';
  let release!: () => void;
  const recoveryGate = new Promise<void>((resolve) => { release = resolve; });
  const failedReads: Request[] = [];
  const recoveryReads: Request[] = [];
  for (const path of ['/v1/config', '/v1/advisor/providers']) {
    await page.route(new URL(path, origin).href, async (route) => {
      const candidate = route.request();
      if (candidate.method() !== 'GET') return route.fallback();
      if (phase === 'entry-failure' && failures[path]) {
        failedReads.push(candidate);
        await route.fulfill({ status: 503, json: { detail: failures[path] } });
        return;
      }
      if (phase === 'recovery-held') {
        recoveryReads.push(candidate);
        await recoveryGate;
      }
      await route.fallback();
    });
  }
  return {
    armEntryFailure() { phase = 'entry-failure'; },
    holdRecovery() { phase = 'recovery-held'; },
    releaseRecovery() { phase = 'pass'; release(); },
    async expectRecoveryReads() {
      await expect.poll(() => recoveryReads.map((read) => new URL(read.url()).pathname).sort())
        .toEqual(['/v1/advisor/providers', '/v1/config']);
    },
    async assertIntentionalFailures(guards: RuntimeGuards) {
      expect([...new Set(failedReads.map((read) => new URL(read.url()).pathname))].sort())
        .toEqual(Object.keys(failures).sort());
      for (const read of failedReads) {
        const response = await read.response();
        expect(response).not.toBeNull();
        expect(response!.status()).toBe(503);
        expect(await response!.json()).toEqual({ detail: failures[new URL(read.url()).pathname] });
        expect(await response!.finished()).toBeNull();
      }
      // Only exact intercepted failures are expected; every other guard remains strict.
      expect([...guards.failures.http].sort()).toEqual(failedReads.map((read) => `503 ${read.url()}`).sort());
      expect(guards.failures.console).toEqual(failedReads.map(
        () => 'Failed to load resource: the server responded with a status of 503 (Service Unavailable)',
      ));
      guards.failures.http.length = 0;
      guards.failures.console.length = 0;
      guards.assertClean();
    },
  };
}

async function findingLifecycle(request: APIRequestContext, findingIds: number[]) {
  const response = await request.get('/v1/scans/41/findings?limit=200');
  expect(response.ok()).toBe(true);
  const payload = await response.json() as {
    items: Array<{ id: number; lifecycle_status: string }>;
  };
  return findingIds.map((findingId) => payload.items.find((finding) => finding.id === findingId)?.lifecycle_status ?? null);
}

async function findingState(request: APIRequestContext, findingIds: number[]) {
  const response = await request.get('/v1/scans/41/findings?limit=200');
  expect(response.ok()).toBe(true);
  const payload = await response.json() as {
    items: Array<{
      gate_effect: string;
      gate_exempt: boolean;
      id: number;
      lifecycle_status: string;
      revision: number;
      suppressed: boolean;
    }>;
  };
  return findingIds.map((findingId) => {
    const finding = payload.items.find((candidate) => candidate.id === findingId);
    return finding ? {
      gate_effect: finding.gate_effect,
      gate_exempt: finding.gate_exempt,
      id: finding.id,
      lifecycle_status: finding.lifecycle_status,
      revision: finding.revision,
      suppressed: finding.suppressed,
    } : null;
  });
}

async function findingLifecycleReasons(request: APIRequestContext, findingIds: number[]) {
  const response = await request.get('/v1/scans/41/findings?limit=200');
  expect(response.status()).toBe(200);
  const payload = await response.json() as {
    revision: number;
    items: Array<{ id: number; scan_finding_number: number; revision: number }>;
  };
  return Promise.all(findingIds.map(async (findingId) => {
    const finding = payload.items.find((candidate) => candidate.id === findingId);
    if (!finding) throw new Error(`Expected lifecycle finding ${findingId} in the current collection.`);
    // List summaries deliberately omit reasons; read the exact revision-bound detail.
    const detailResponse = await request.get(`/v1/scans/41/findings/${finding.scan_finding_number}`, {
      params: { expected_revision: finding.revision, expected_findings_revision: payload.revision },
    });
    expect(detailResponse.status()).toBe(200);
    const detail = await detailResponse.json() as {
      id: number; scan_id: number; scan_finding_number: number; revision: number;
      findings_revision: number; lifecycle_reason: string | null;
    };
    expect(detail).toMatchObject({
      id: findingId, scan_id: 41, scan_finding_number: finding.scan_finding_number,
      revision: finding.revision, findings_revision: payload.revision,
    });
    return detail.lifecycle_reason;
  }));
}

type AdvisorProviderCollectionFixture = {
  revision: number;
  providers: Array<{
    id: string;
    transport: 'local' | 'direct' | 'ssh';
    config_revision: number;
    config_digest: string;
    model: string;
    model_digest: string;
    eligible: boolean;
  }>;
  active_provider_id: string | null;
  resolution: { provider_id: string | null; transport: 'local' | 'direct' | 'ssh' | 'unavailable' };
};

function localAdvisorPin(collection: AdvisorProviderCollectionFixture): AdvisorTriageProviderPinFixture {
  const provider = collection.providers.find((candidate) => candidate.id === collection.resolution.provider_id);
  expect(collection.resolution.transport).toBe('local');
  expect(provider?.eligible).toBe(true);
  if (!provider) throw new Error('The local Advisor fixture did not resolve a provider.');
  return {
    provider_collection_revision: collection.revision,
    provider_id: provider.id,
    transport: provider.transport,
    provider_config_revision: provider.config_revision,
    provider_config_digest: provider.config_digest,
    model: provider.model,
    model_digest: provider.model_digest,
  };
}

async function currentLocalAdvisorPin(request: APIRequestContext): Promise<AdvisorTriageProviderPinFixture> {
  return localAdvisorPin(await request.get('/v1/advisor/providers').then((response) => response.json()));
}

async function observeAdvisorProviderReadBeforePost(
  page: Page,
  expectedOrigin: string,
  postPath: string,
  action: () => Promise<void>,
): Promise<AdvisorProviderCollectionFixture> {
  const providerUrl = new URL('/v1/advisor/providers', expectedOrigin).href;
  const postUrl = new URL(postPath, expectedOrigin).href;
  const reads: Request[] = [];
  const responses: Response[] = [];
  const finished: Request[] = [];
  type Boundary = { reads: Request[]; responses: Response[]; finished: Request[] };
  let boundary: Boundary | null = null;
  const onRequest = (candidate: Request) => {
    if (boundary) return;
    if (candidate.method() === 'GET' && candidate.url() === providerUrl) reads.push(candidate);
    if (candidate.method() === 'POST' && candidate.url() === postUrl) {
      // Freeze at command dispatch; later Jobs/mutation refreshes are separate reads.
      boundary = { reads: [...reads], responses: [...responses], finished: [...finished] };
    }
  };
  const onResponse = (response: Response) => {
    if (!boundary && reads.includes(response.request())) responses.push(response);
  };
  const onFinished = (candidate: Request) => {
    if (!boundary && reads.includes(candidate)) finished.push(candidate);
  };
  page.on('request', onRequest);
  page.on('response', onResponse);
  page.on('requestfinished', onFinished);
  try {
    await action();
  } finally {
    page.off('request', onRequest);
    page.off('response', onResponse);
    page.off('requestfinished', onFinished);
  }
  const observed = boundary as Boundary | null;
  if (!observed) throw new Error(`The Advisor action did not dispatch POST ${postPath}.`);
  expect(observed.reads).toHaveLength(1);
  expect(observed.responses).toHaveLength(1);
  expect(observed.responses[0].request()).toBe(observed.reads[0]);
  expect(observed.finished).toEqual(observed.reads);
  expect(observed.responses[0].status()).toBe(200);
  return observed.responses[0].json();
}

function mutationRequestLog(page: Page) {
  const mutations: string[] = [];
  page.on('request', (candidate) => {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(candidate.method())) {
      const url = new URL(candidate.url());
      mutations.push(`${candidate.method()} ${url.pathname}`);
    }
  });
  return mutations;
}

async function openLifecycleReason(page: Page, scope: string, label: string, trigger: () => Promise<void>) {
  await trigger();
  const dialog = page.getByRole('dialog', { name: `Reason required: ${label}`, exact: true });
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('p')).toHaveText(
    `Explain why ${scope} should be marked ${label}. This audit reason is stored only in the local CodeSecurity database.`,
  );
  const field = dialog.getByLabel('Local audit reason', { exact: true });
  await expect(field).toBeFocused();
  return { dialog, field };
}

async function openConfirmation(page: Page, trigger: () => Promise<void>) {
  await trigger();
  const dialog = page.locator('dialog.confirmation-dialog');
  await expect(dialog).toBeVisible();
  return {
    dialog,
    message: (await dialog.locator('p').innerText()).trim(),
    title: (await dialog.getByRole('heading', { level: 2 }).innerText()).trim(),
  };
}

async function dismissNextConfirmation(page: Page, trigger: () => Promise<void>) {
  const confirmation = await openConfirmation(page, trigger);
  await confirmation.dialog.locator('.confirmation-dialog-actions').getByRole('button').first().click();
  await expect(confirmation.dialog).toHaveCount(0);
  return { type: 'confirm', message: confirmation.message, title: confirmation.title };
}

async function acceptNextConfirmation(page: Page, trigger: () => Promise<void>) {
  const confirmation = await openConfirmation(page, trigger);
  await confirmation.dialog.locator('.confirmation-dialog-actions').getByRole('button').last().click();
  await expect(confirmation.dialog).toHaveCount(0);
  return { type: 'confirm', message: confirmation.message, title: confirmation.title };
}

type RuntimeSettingsSnapshot = {
  ai_mode: 'auto' | 'on' | 'off';
  ollama_base_url: string;
  ollama_model: string;
  ollama_thinking: boolean;
  auto_triage_limit: number;
  component_monitoring_enabled: boolean;
  component_git_proxy_enabled: boolean;
  component_db_admin_enabled: boolean;
  gate_preset: 'observe' | 'baseline' | 'strict' | 'custom';
  gate_active: boolean;
  gate_max_critical: number;
  gate_max_high: number;
  gate_block_secrets: boolean;
};

type RuntimeSettingsUpdate = RuntimeSettingsSnapshot & { gate_apply_to_existing: boolean };

function runtimeSettingsUpdate(
  current: RuntimeSettingsSnapshot,
  overrides: Partial<RuntimeSettingsUpdate> = {},
): RuntimeSettingsUpdate {
  return {
    ai_mode: current.ai_mode,
    ollama_base_url: current.ollama_base_url,
    ollama_model: current.ollama_model,
    ollama_thinking: current.ollama_thinking,
    auto_triage_limit: current.auto_triage_limit,
    component_monitoring_enabled: current.component_monitoring_enabled,
    component_git_proxy_enabled: current.component_git_proxy_enabled,
    component_db_admin_enabled: current.component_db_admin_enabled,
    gate_preset: current.gate_preset,
    gate_active: current.gate_active,
    gate_max_critical: current.gate_max_critical,
    gate_max_high: current.gate_max_high,
    gate_block_secrets: current.gate_block_secrets,
    gate_apply_to_existing: false,
    ...overrides,
  };
}

test.describe('deep operator action journeys', () => {
  test.beforeEach(({}, testInfo) => {
    const responsiveRouteScrollRegression = testInfo.title.startsWith('[WEB-ACT-002]');
    test.skip(
      responsiveRouteScrollRegression
        ? !['desktop-1440', 'mobile-390'].includes(testInfo.project.name)
        : testInfo.project.name !== 'desktop-1440',
      'Deep mutation journeys run once; the route-scroll control covers one desktop main scroller and one narrow window scroller.',
    );
  });

test('AuthGate focuses manual pairing, submits with Enter once, and restores focus for retry', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'auth-required', generation: 1 } });
  const bootstrapRequests: Array<{ method: string; pathname: string; search: string; token: string }> = [];
  let releaseValidRequest = () => {};
  const validRequestReleased = new Promise<void>((resolve) => { releaseValidRequest = resolve; });
  await page.route('**/v1/auth/bootstrap', async (route) => {
    const candidate = route.request();
    const url = new URL(candidate.url());
    const input = candidate.postDataJSON() as { bootstrap_token?: string };
    const token = input.bootstrap_token || '';
    bootstrapRequests.push({ method: candidate.method(), pathname: url.pathname, search: url.search, token });
    if (token === 'valid-bootstrap') await validRequestReleased;
    await route.continue();
  });

  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Pair this browser', exact: true })).toBeVisible();
  const tokenInput = page.getByLabel('One-time browser pairing key', { exact: true });
  const createSession = page.getByRole('button', { name: 'Add this browser', exact: true });
  await expect(tokenInput).toBeFocused();
  await expect(page.locator('.auth-panel')).toContainText('Generate a one-time browser pairing key from CodeSecurity Settings');
  const ownerRecovery = page.locator('.auth-help');
  await expect(ownerRecovery.getByText('Installation-owner recovery', { exact: true })).toBeVisible();
  await expect(ownerRecovery.getByText('If no paired browser remains', { exact: false })).toBeHidden();
  await ownerRecovery.getByText('Installation-owner recovery', { exact: true }).click();
  await expect(ownerRecovery).toContainText('If no paired browser remains, recover access from the CodeSecurity checkout with make auth-info.');
  await expect(tokenInput).toHaveAttribute('type', 'password');
  await tokenInput.fill('   ');
  await expect(createSession).toBeDisabled();
  expect(bootstrapRequests).toEqual([]);

  await tokenInput.fill('expired-bootstrap');
  await tokenInput.press('Enter');
  await expect(page.getByRole('alert')).toContainText('one-time browser pairing key expired');
  await expect(tokenInput).toBeFocused();
  await expect(tokenInput).toHaveValue('');

  await tokenInput.fill('valid-bootstrap');
  await page.locator('.auth-form').evaluate((element) => {
    const form = element as HTMLFormElement;
    form.requestSubmit();
    form.requestSubmit();
    form.requestSubmit();
  });
  await expect(page.locator('.auth-panel')).toHaveAttribute('aria-busy', 'true');
  await expect(createSession).toHaveCount(0);
  await expect.poll(
    () => bootstrapRequests.filter(({ token }) => token === 'valid-bootstrap'),
    { message: 'Concurrent submits must coalesce into one bootstrap request.' },
  ).toHaveLength(1);
  releaseValidRequest();
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  // The heading can paint before its exact scan-detail reads finish.
  await page.waitForLoadState('networkidle');

  await request.post('/__test/auth-revoke');
  // Observe revocation through a user action, not an incidental startup read or the eight-second poll.
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Pair this browser', exact: true })).toBeVisible();
  await expect(page.getByRole('status')).toHaveText('This browser member is missing or revoked, or its local cookie was removed. Pair this browser again.');
  await expect(page.locator('.auth-help')).toContainText('make auth-reset, then make up and make auth-info');
  await expect(tokenInput).toBeFocused();
  await tokenInput.fill('repair-bootstrap');
  await tokenInput.press('Enter');
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();

  expect(bootstrapRequests).toEqual([
    { method: 'POST', pathname: '/v1/auth/bootstrap', search: '', token: 'expired-bootstrap' },
    { method: 'POST', pathname: '/v1/auth/bootstrap', search: '', token: 'valid-bootstrap' },
    { method: 'POST', pathname: '/v1/auth/bootstrap', search: '', token: 'repair-bootstrap' },
  ]);
  const authState = await request.get('/__test/auth-state').then((response) => response.json()) as {
    authenticated: boolean;
    bootstrap_attempts: string[];
  };
  expect(authState).toEqual({
    authenticated: true,
    bootstrap_attempts: ['expired-bootstrap', 'valid-bootstrap', 'repair-bootstrap'],
  });
  const browserStorage = await page.evaluate(() => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
  }));
  expect(JSON.stringify(browserStorage)).not.toMatch(/expired-bootstrap|valid-bootstrap|repair-bootstrap/);
  await expect(page.locator('body')).not.toContainText('valid-bootstrap');
  await expect(page.locator('body')).not.toContainText('repair-bootstrap');
});

test('AuthGate scrubs a successful fragment bootstrap before its single POST and never persists or logs it', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'auth-required', generation: 1 } });
  const fragmentToken = 'valid-bootstrap';
  const consoleMessages: string[] = [];
  const bootstrapUrls: string[] = [];
  let releaseBootstrap = () => {};
  let markBootstrapSeen = () => {};
  const bootstrapReleased = new Promise<void>((resolve) => { releaseBootstrap = resolve; });
  const bootstrapSeen = new Promise<void>((resolve) => { markBootstrapSeen = resolve; });
  page.on('console', (message) => consoleMessages.push(message.text()));
  await page.route('**/v1/auth/bootstrap', async (route) => {
    bootstrapUrls.push(route.request().url());
    markBootstrapSeen();
    await bootstrapReleased;
    await route.continue();
  });

  try {
    await page.goto(`/#bootstrap=${fragmentToken}`);
    await bootstrapSeen;
    await expect(page).toHaveURL(new RegExp(`${new URL(baseURL).origin}/?$`));
    await expect(page.locator('.auth-panel')).toHaveAttribute('aria-busy', 'true');
    await expect(page.getByRole('heading', { level: 1, name: 'Connecting this browser', exact: true })).toBeVisible();
    await expect(page.locator('.auth-panel')).not.toContainText('Generate a one-time browser pairing key');
    await expect(page.locator('.auth-panel')).not.toContainText('make auth-info');
    await expect(page.getByLabel('One-time browser pairing key', { exact: true })).toHaveCount(0);
    expect(bootstrapUrls).toHaveLength(1);
    expect(bootstrapUrls[0]).toBe(`${new URL(baseURL).origin}/v1/auth/bootstrap`);
  } finally {
    releaseBootstrap();
  }

  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  const browserStorage = await page.evaluate(() => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
  }));
  expect(JSON.stringify(browserStorage)).not.toContain(fragmentToken);
  expect(consoleMessages.join('\n')).not.toContain(fragmentToken);
  await expect(page.locator('body')).not.toContainText(fragmentToken);
  const authState = await request.get('/__test/auth-state').then((response) => response.json()) as {
    authenticated: boolean;
    bootstrap_attempts: string[];
  };
  expect(authState).toEqual({ authenticated: true, bootstrap_attempts: [fragmentToken] });
});

test('AuthGate consumes a fresh IDE invitation while retaining an authorized integrated browser', async ({ page, request }) => {
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await page.goto('/#bootstrap=valid-bootstrap');

  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  await expect(page).toHaveURL(/\?view=findings&scan=41$/u);
  expect(new URL(page.url()).hash).toBe('');
  await expect(page.locator('.auth-invite-warning')).toHaveCount(0);
  const authState = await request.get('/__test/auth-state').then((response) => response.json()) as {
    authenticated: boolean;
    bootstrap_attempts: string[];
  };
  expect(authState).toEqual({ authenticated: true, bootstrap_attempts: ['valid-bootstrap'] });
});

test('AuthGate keeps an existing browser member ready when a replayed invitation fails', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await page.goto('/#bootstrap=replayed-integrated-invitation');
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  await expect(page).toHaveURL(/\?view=findings&scan=41$/u);
  expect(new URL(page.url()).hash).toBe('');
  await expect(page.locator('.auth-invite-warning')).toContainText(
    'This browser kept its existing authorized member',
  );
  await page.getByRole('button', { name: 'Dismiss browser invitation warning', exact: true }).click();
  await expect(page.locator('.auth-invite-warning')).toHaveCount(0);
  const authState = await request.get('/__test/auth-state').then((response) => response.json()) as {
    authenticated: boolean;
    bootstrap_attempts: string[];
  };
  expect(authState).toEqual({
    authenticated: true,
    bootstrap_attempts: ['replayed-integrated-invitation'],
  });
});

test('navigation defers off-route scanner and job history but refreshes them on Tools entry', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await openRoute(page, 'Overview');
  const scannerPaths = new Set(['/v1/scanner/tools', '/v1/scanner/lifecycle', '/v1/scanner/preflight', '/v1/jobs']);
  const reads: string[] = [];
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route((url) => scannerPaths.has(url.pathname) && url.searchParams.get('status') !== 'active', async (route) => {
    reads.push(new URL(route.request().url()).pathname);
    await held;
    await route.fallback();
  });
  try {
    await page.locator('nav button[data-view-target="findings"]').click();
    await expect(page.locator('[data-route-surface="findings"]')).not.toHaveAttribute('aria-busy', 'true');
    await expect(page.locator('[data-route-surface="findings"]')).toBeVisible();
    expect(reads).toEqual([]);
    await page.locator('nav button[data-view-target="tools"]').click();
    await expect.poll(() => [...new Set(reads)].sort()).toEqual([...scannerPaths].sort());
  } finally {
    release();
  }
  await expect(page.locator('[data-route-surface="tools"]')).not.toHaveAttribute('aria-busy', 'true');
});

test('off-route navigation preserves fresh active jobs through a failed transition read', async ({ page, request }) => {
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const historical = await request.get('/v1/jobs').then(response => response.json()) as Array<Record<string, unknown>>;
  expect(historical.length).toBeGreaterThan(0);
  const old = { ...historical[0], id: Number(historical[0].id), status: 'failed', revision: 1, can_retry: true, can_cancel: false };
  const active = { ...old, status: 'running', revision: 2, can_retry: false, can_cancel: true };
  const completed = { ...active, status: 'completed', revision: 3, can_cancel: false };
  let phase: 'idle' | 'active' | 'unresolved' | 'completed' = 'idle';
  let historyReads = 0;
  let exactReads = 0;
  await page.route((url) => url.pathname === '/v1/jobs', async route => {
    if (new URL(route.request().url()).searchParams.get('status') === 'active') {
      return route.fulfill({ json: phase === 'active' ? [active] : [] });
    }
    historyReads += 1;
    return route.fulfill({ json: [phase === 'completed' ? completed : old] });
  });
  await page.route((url) => url.pathname === `/v1/jobs/${old.id}`, async route => {
    exactReads += 1;
    return phase === 'completed'
      ? route.fulfill({ json: completed })
      : route.fulfill({ status: 503, json: { detail: 'Owned transition observation unavailable' } });
  });
  await openRoute(page, 'Overview');
  const running = page.locator('header.top .pill').filter({ hasText: /^running$/ });
  // Use the actual global status surface, independent of Jobs history rendering.
  const status = page.locator('header.top');
  await expect(status).toBeVisible();
  const initialReads = historyReads;
  phase = 'active';
  await page.locator('nav button[data-view-target="findings"]').click();
  await expect(page.locator('[data-route-surface="findings"]')).not.toHaveAttribute('aria-busy', 'true');
  await expect(running).toBeVisible();
  phase = 'unresolved';
  for (const view of ['scans', 'overview']) {
    await page.locator(`nav button[data-view-target="${view}"]`).click();
    await expect(page.locator(`[data-route-surface="${view}"]`)).not.toHaveAttribute('aria-busy', 'true');
    await expect(running).toBeVisible();
  }
  expect(exactReads).toBeGreaterThanOrEqual(2);
  expect(historyReads).toBe(initialReads);
  phase = 'completed';
  await page.locator('nav button[data-view-target="projects"]').click();
  await expect(page.locator('[data-route-surface="projects"]')).not.toHaveAttribute('aria-busy', 'true');
  await expect(running).toHaveCount(0);
  await page.locator('nav button[data-view-target="jobs"]').click();
  await expect(page.locator('[data-route-surface="jobs"]')).not.toHaveAttribute('aria-busy', 'true');
  expect(historyReads).toBeGreaterThan(initialReads);
});

test('Settings entry defers unrelated history and the next Findings entry refreshes it', async ({ page, request }) => {
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await openRoute(page, 'Overview');
  const historyPaths = new Set(['/v1/projects', '/v1/scans']);
  const reads: string[] = [];
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route((url) => historyPaths.has(url.pathname), async (route) => {
    reads.push(new URL(route.request().url()).pathname);
    await held;
    await route.fallback();
  });
  try {
    await page.locator('nav button[data-view-target="settings"]').click();
    await expect(page.locator('[data-route-surface="settings"]')).not.toHaveAttribute('aria-busy', 'true');
    await expect(page.locator('[data-route-surface="settings"]')).toBeVisible();
    expect(reads).toEqual([]);
    await page.locator('nav button[data-view-target="findings"]').click();
    await expect.poll(() => [...new Set(reads)].sort()).toEqual([...historyPaths].sort());
    await expect(page.locator('[data-route-surface="findings"]')).toHaveAttribute('aria-busy', 'true');
  } finally {
    release();
  }
  await expect(page.locator('[data-route-surface="findings"]')).not.toHaveAttribute('aria-busy', 'true');
});

for (const mismatchedRevision of [false, true]) {
  test(`Findings overlaps exact summary with history and ${mismatchedRevision ? 'refetches a mismatched revision' : 'reuses only the matching revision'}`, async ({ page, request }) => {
    await request.post('/__test/reset', { data: { profile: 'focus', generation: 1 } });
    await openRoute(page, 'Overview');
    await page.waitForLoadState('networkidle');
    let summaryReads = 0;
    let release!: () => void;
    const summaryReturned = new Promise<void>((resolve) => { release = resolve; });
    await page.route('**/v1/scans?view=history', async (route) => {
      await summaryReturned;
      await route.fallback();
    });
    await page.route('**/v1/scans/41/summary', async (route) => {
      summaryReads += 1;
      const response = await route.fetch();
      const value = await response.json();
      if (summaryReads === 1 && mismatchedRevision) value.revision += 1;
      await route.fulfill({ response, json: value });
      release();
    });
    try {
      await page.locator('nav button[data-view-target="findings"]').click();
      await expect(page.locator('[data-route-surface="findings"]')).not.toHaveAttribute('aria-busy', 'true');
      await expect(page.locator('.finding-list-item')).toHaveCount(14);
      expect(summaryReads).toBe(mismatchedRevision ? 2 : 1);
    } finally {
      release();
    }
  });
}

test('Settings reload recovers runtime configuration and Advisor providers together', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const faults = await installSettingsLoadFaults(page, new URL(baseURL).origin, {
    '/v1/config': { code: 'runtime_config_unavailable', message: 'Generated runtime configuration is temporarily unavailable.' },
    '/v1/advisor/providers': { code: 'advisor_providers_unavailable', message: 'Generated Advisor providers are temporarily unavailable.' },
  });
  const pageMutations: string[] = [];
  page.on('request', (candidate) => {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(candidate.method())) {
      pageMutations.push(`${candidate.method()} ${new URL(candidate.url()).pathname}`);
    }
  });

  await openRoute(page, 'Overview');
  const initialReadUrls = new Set(['/v1/config', '/v1/advisor/providers']
    .map((path) => new URL(path, baseURL).href));
  const heldInitialPaths = new Set<string>();
  let initialReadsHeld = true;
  let releaseInitialReads!: () => void;
  const initialReadGate = new Promise<void>((resolve) => { releaseInitialReads = resolve; });
  await page.route((url) => initialReadUrls.has(url.href), async (route) => {
    if (route.request().method() === 'GET' && initialReadsHeld) {
      heldInitialPaths.add(new URL(route.request().url()).pathname);
      await initialReadGate;
    }
    await route.fallback();
  });
  faults.armEntryFailure();
  const settingsButton = page.getByRole('navigation').getByRole('button', { name: 'Settings', exact: true });
  const surface = page.locator('section[data-route-surface="settings"]');
  try {
    await settingsButton.click();
    await expect.poll(() => [...heldInitialPaths].sort()).toEqual(['/v1/advisor/providers', '/v1/config']);
    await expect(surface).toHaveAttribute('data-settings-config-state', 'loading');
    await expect(surface).toHaveAttribute('data-settings-provider-state', 'loading');
    await expect(surface).toHaveAttribute('aria-busy', 'true');
    await expect(surface).toHaveAttribute('inert', '');
    await expect(surface).toHaveAttribute('aria-hidden', 'true');
    await expect(settingsButton).toBeFocused();
    expect(pageMutations).toEqual([]);
  } finally {
    initialReadsHeld = false;
    releaseInitialReads();
  }
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await expect(surface).not.toHaveAttribute('inert', '');
  await expect(surface).not.toHaveAttribute('aria-hidden', 'true');
  await expect(settingsButton).toBeFocused();
  await expect(surface).toHaveAttribute('data-settings-config-state', 'error');
  await expect(surface).toHaveAttribute('data-settings-provider-state', 'error');
  const runtime = surface.getByRole('heading', { name: 'Runtime', exact: true }).locator('..').locator('..');
  await expect(runtime.getByRole('alert')).toContainText('Runtime configuration failed: Generated runtime configuration is temporarily unavailable.');
  await expect(runtime.getByRole('alert')).toContainText('Advisor providers failed: Generated Advisor providers are temporarily unavailable.');
  await expect(surface.locator('#advisor-providers')).not.toContainText('No Advisor providers configured.');
  await expect(surface.getByRole('button', { name: 'Save Advisor Policy', exact: true })).toBeDisabled();

  const persisted = await request.get('/v1/config').then((response) => response.json()) as {
    ai_mode: 'auto' | 'on' | 'off';
    ollama_base_url: string;
    ollama_model: string;
    ollama_thinking: boolean;
    auto_triage_limit: number;
  };
  const changedLimit = persisted.auto_triage_limit + 3;
  const changed = await request.patch('/v1/config/advisor', { data: {
    ai_mode: persisted.ai_mode,
    ollama_base_url: persisted.ollama_base_url,
    ollama_model: persisted.ollama_model,
    ollama_thinking: persisted.ollama_thinking,
    auto_triage_limit: changedLimit,
  } });
  expect(changed.ok()).toBe(true);

  const reload = runtime.getByRole('button', { name: 'Reload Settings', exact: true });
  const signOut = runtime.getByRole('button', { name: 'Sign out this browser', exact: true });
  faults.holdRecovery();
  try {
    await reload.click();
    await expect(runtime.getByRole('button', { name: 'Reloading Settings…', exact: true })).toBeDisabled();
    await faults.expectRecoveryReads();
    await expect(surface).toHaveAttribute('aria-busy', 'true');
    await expect(surface).not.toHaveAttribute('inert', '');
    await expect(surface).not.toHaveAttribute('aria-hidden', 'true');
    await expect(surface.getByRole('button', { name: 'Save Advisor Policy', exact: true })).toBeDisabled();
    // Session recovery stays reachable during a reload; focusing is not activation.
    await expect(signOut).toBeEnabled();
    await signOut.focus();
    await expect(signOut).toBeFocused();
    expect(pageMutations).toEqual([]);
  } finally {
    faults.releaseRecovery();
  }

  await expect(surface).toHaveAttribute('data-settings-config-state', 'success');
  await expect(surface).toHaveAttribute('data-settings-provider-state', 'success');
  await expect(runtime.getByText('Settings reloaded from durable runtime configuration and Advisor provider state.', { exact: true })).toBeVisible();
  await expect(surface.getByLabel('Auto Triage Limit', { exact: true })).toHaveValue(String(changedLimit));
  await expect(surface.locator('#advisor-providers').locator('.advisor-provider-card', { hasText: 'Local Ollama' })).toHaveCount(1);
  await expect(runtime.getByRole('alert')).toHaveCount(0);
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await expect(signOut).toBeFocused();
  expect(pageMutations).toEqual([]);
  await faults.assertIntentionalFailures(guards);
});

for (const phase of ['entry', 'reload'] as const) {
  for (const failure of ['shape', 'json', 'identity'] as const) {
    referenceTest(`Settings invalid runtime read recovers without writes: ${phase} ${failure}`, async ({ page, request, baseURL }) => {
      if (!baseURL) throw new Error('Playwright baseURL is required.');
      await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
      const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
      const before = await (await request.get('/v1/config')).json();
      const mutations = mutationRequestLog(page);
      const surface = phase === 'reload' ? await openRoute(page, 'Settings')
        : page.locator('section[data-route-surface="settings"]');
      if (phase === 'entry') {
        await openRoute(page, 'Overview');
        await page.waitForLoadState('networkidle');
      }
      const field = surface.getByLabel('Auto Triage Limit', { exact: true });
      const draft = String(before.auto_triage_limit + 1);
      if (phase === 'reload') await field.fill(draft);
      let intercepted = 0;
      await page.route(new URL('/v1/config', baseURL).href, async route => {
        intercepted += 1;
        expect(route.request().method()).toBe('GET');
        await route.fulfill({ contentType: 'application/json', body: failure === 'json' ? '{'
          : JSON.stringify(failure === 'shape' ? {} : { ...before,
            installation_id: phase === 'entry' ? 'invalid' : 'ffffffffffff' }) });
      }, { times: 1 });
      if (phase === 'entry') await page.getByRole('navigation').getByRole('button', { name: 'Settings', exact: true }).click();
      else await surface.getByRole('button', { name: 'Reload Settings', exact: true }).click();
      await expect(surface).toHaveAttribute('data-settings-config-state', 'error');
      await expect(surface).not.toHaveAttribute('aria-busy', 'true');
      if (phase === 'reload') await expect(field).toHaveValue(draft);
      for (const name of ['Save Advisor Policy', 'Save Gate', 'Save Desired Components']) {
        await expect(surface.getByRole('button', { name, exact: true })).toBeDisabled();
      }
      const runtime = surface.getByRole('heading', { name: 'Runtime', exact: true }).locator('..').locator('..');
      await expect(runtime.getByRole('alert')).toContainText('Runtime configuration could not be verified. Use Reload Settings to try again.');
      await surface.getByRole('button', { name: 'Reload Settings', exact: true }).click();
      await expect(surface).toHaveAttribute('data-settings-config-state', 'success');
      await expect(runtime.getByRole('alert')).toHaveCount(0);
      await expect(field).toHaveValue(phase === 'reload' ? draft : String(before.auto_triage_limit));
      await expect(surface.getByRole('button', { name: 'Save Advisor Policy', exact: true })).toBeEnabled();
      expect(intercepted).toBe(1);
      expect(mutations).toEqual([]);
      expect(await (await request.get('/v1/config')).json()).toEqual(before);
      guards.assertClean();
    });
  }
}

referenceTest('Settings ignores a late invalid read after leaving and reopening the page', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const before = await (await request.get('/v1/config')).json();
  const mutations = mutationRequestLog(page);
  const surface = await openRoute(page, 'Settings');
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  let intercepted = false;
  const url = new URL('/v1/config', baseURL).href;
  await page.route(url, async route => {
    intercepted = true;
    await held;
    await route.fulfill({ json: {} });
  }, { times: 1 });
  try {
    await surface.getByRole('button', { name: 'Reload Settings', exact: true }).click();
    await expect.poll(() => intercepted).toBe(true);
    await expect(surface).toHaveAttribute('data-settings-config-state', 'loading');
    await page.getByRole('navigation').getByRole('button', { name: 'Overview', exact: true }).click();
    await expect(surface).toHaveCount(0);
    await page.getByRole('navigation').getByRole('button', { name: 'Settings', exact: true }).click();
    await expect(surface).toHaveAttribute('data-settings-config-state', 'success');
    const late = page.waitForResponse(response => response.url() === url && response.request().method() === 'GET');
    release();
    expect((await late).status()).toBe(200);
    await page.waitForLoadState('networkidle');
    await expect(surface).toHaveAttribute('data-settings-config-state', 'success');
    await expect(surface.getByLabel('Auto Triage Limit', { exact: true })).toHaveValue(String(before.auto_triage_limit));
    await expect(surface.getByRole('button', { name: 'Save Advisor Policy', exact: true })).toBeEnabled();
    expect(mutations).toEqual([]);
    expect(await (await request.get('/v1/config')).json()).toEqual(before);
    guards.assertClean();
  } finally {
    release();
  }
});

for (const phase of ['entry', 'reload'] as const) {
  for (const failure of ['resolution', 'provider', 'activity', 'json'] as const) {
    referenceTest(`Settings invalid provider read recovers without writes: ${phase} ${failure}`, async ({ page, request, baseURL }) => {
      if (!baseURL) throw new Error('Playwright baseURL is required.');
      await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
      const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
      const before = await (await request.get('/v1/advisor/providers')).json();
      const configBefore = await (await request.get('/v1/config')).json();
      const mutations = mutationRequestLog(page);
      const surface = phase === 'reload' ? await openRoute(page, 'Settings')
        : page.locator('section[data-route-surface="settings"]');
      const providers = surface.locator('#advisor-providers');
      if (phase === 'entry') {
        await openRoute(page, 'Overview');
        await page.waitForLoadState('networkidle');
      } else {
        await providers.locator('.advisor-provider-card', { hasText: 'Local Ollama' }).getByRole('button', { name: 'Edit', exact: true }).click();
        await providers.getByLabel('Name', { exact: true }).fill('Retained provider draft');
      }
      let intercepted = 0;
      let faultActive = true;
      await page.route(new URL('/v1/advisor/providers', baseURL).href, async route => {
        if (!faultActive) return route.fallback();
        intercepted += 1;
        expect(route.request().method()).toBe('GET');
        await route.fulfill({ contentType: 'application/json', body: failure === 'json' ? '{'
          : JSON.stringify(failure === 'resolution' ? { ...before, resolution: null }
            : { ...before, providers: [{ ...before.providers[0], ...(failure === 'activity'
              ? { last_activity_at: 'not-a-date' } : { authorization: null }) }] }) });
      });
      if (phase === 'entry') await page.getByRole('navigation').getByRole('button', { name: 'Settings', exact: true }).click();
      else await surface.getByRole('button', { name: 'Reload Settings', exact: true }).click();
      await expect(surface).toHaveAttribute('data-settings-provider-state', 'error');
      await expect(surface).not.toHaveAttribute('aria-busy', 'true');
      await expect(providers.getByRole('alert')).toContainText('Advisor provider state could not be verified. Use Reload Settings to try again.');
      for (const name of ['Save Advisor Policy', 'Save Gate', 'Save Desired Components']) {
        await expect(surface.getByRole('button', { name, exact: true })).toBeDisabled();
      }
      if (phase === 'reload') {
        await expect(providers.getByLabel('Name', { exact: true })).toHaveValue('Retained provider draft');
        await expect(providers.getByRole('button', { name: 'Save provider', exact: true })).toBeDisabled();
      }
      faultActive = false;
      await surface.getByRole('button', { name: 'Reload Settings', exact: true }).click();
      await expect(surface).toHaveAttribute('data-settings-provider-state', 'success');
      await expect(providers.getByRole('alert')).toHaveCount(0);
      if (phase === 'reload') {
        await expect(providers.getByLabel('Name', { exact: true })).toHaveValue('Retained provider draft');
        await expect(providers.getByRole('button', { name: 'Save provider', exact: true })).toBeEnabled();
      }
      await expect(surface.getByRole('button', { name: 'Save Advisor Policy', exact: true })).toBeEnabled();
      expect(intercepted).toBeGreaterThanOrEqual(1);
      expect(mutations).toEqual([]);
      expect(await (await request.get('/v1/advisor/providers')).json()).toEqual(before);
      expect(await (await request.get('/v1/config')).json()).toEqual(configBefore);
      guards.assertClean();
    });
  }
}

for (const action of ['edit', 'toggle', 'remove'] as const) {
  referenceTest(`Settings unconfirmed provider ${action} reloads the saved effect without repeating it`, async ({ page, request, baseURL }) => {
    if (!baseURL) throw new Error('Playwright baseURL is required.');
    await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
    const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
    const configBefore = await (await request.get('/v1/config')).json();
    const surface = await openRoute(page, 'Settings');
    const panel = surface.locator('#advisor-providers');
    const local = panel.locator('.advisor-provider-card', { hasText: 'Local Ollama' });
    if (action === 'toggle') {
      await expect(local.getByRole('button', { name: 'Disable', exact: true })).toBeDisabled();
      await local.getByRole('button', { name: 'Disconnect', exact: true }).click();
      await expect(local.getByRole('button', { name: 'Disable', exact: true })).toBeEnabled();
    }
    const before = await (await request.get('/v1/advisor/providers')).json();
    if (action === 'toggle') expect(before.active_provider_id).toBeNull();
    const mutations = mutationRequestLog(page);
    const method = action === 'remove' ? 'DELETE' : 'PUT';
    let committed: unknown;
    await page.route(new URL('/v1/advisor/providers/local-default', baseURL).href, async route => {
      expect(route.request().method()).toBe(method);
      expect(route.request().postDataJSON().expected_revision).toBe(before.revision);
      const saved = await route.fetch();
      expect(saved.status()).toBe(200);
      committed = await saved.json();
      await route.fulfill({ response: saved, json: {} });
    }, { times: 1 });
    if (action === 'edit') {
      await local.getByRole('button', { name: 'Edit', exact: true }).click();
      const form = panel.locator('.advisor-provider-form');
      await form.getByLabel('Name', { exact: true }).fill('Confirmed after reload');
      await form.getByRole('button', { name: 'Save provider', exact: true }).click();
    } else if (action === 'toggle') {
      await local.getByRole('button', { name: 'Disable', exact: true }).click();
    } else {
      await acceptNextConfirmation(page, () => local.getByRole('button', { name: 'Remove Local Ollama', exact: true }).click());
    }
    await expect(panel.getByRole('alert')).toContainText('The provider change could not be confirmed. Use Reload Settings to check its current state before trying again.');
    await expect(panel.locator(':scope > .status-note[role="status"]')).toHaveCount(0);
    const actual = await (await request.get('/v1/advisor/providers')).json();
    expect(actual).toEqual(committed);
    expect(actual.revision).toBe(before.revision + 1);
    if (action === 'edit') expect(actual.providers[0].name).toBe('Confirmed after reload');
    else if (action === 'toggle') expect(actual.providers[0].enabled).toBe(false);
    else expect(actual.providers).toEqual([]);
    expect(mutations).toEqual([`${method} /v1/advisor/providers/local-default`]);
    await surface.getByRole('button', { name: 'Reload Settings', exact: true }).click();
    await expect(panel.getByRole('alert')).toHaveCount(0);
    await expect(surface).toHaveAttribute('data-settings-provider-state', 'success');
    if (action === 'edit') await expect(panel.getByRole('heading', { name: 'Confirmed after reload', exact: true })).toBeVisible();
    else if (action === 'toggle') await expect(local.getByRole('button', { name: 'Enable', exact: true })).toBeEnabled();
    else await expect(panel.locator('.advisor-provider-card')).toHaveCount(0);
    expect(mutations).toEqual([`${method} /v1/advisor/providers/local-default`]);
    expect(await (await request.get('/v1/advisor/providers')).json()).toEqual(actual);
    expect(await (await request.get('/v1/config')).json()).toEqual(configBefore);
    guards.assertClean();
  });
}

test('Settings reload preserves open Advisor provider Add and Edit drafts without saving them', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const faults = await installSettingsLoadFaults(page, new URL(baseURL).origin, {});
  const initial = await (await request.get('/v1/advisor/providers')).json();
  const pageMutations: string[] = [];
  page.on('request', (candidate) => {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(candidate.method())) {
      pageMutations.push(`${candidate.method()} ${new URL(candidate.url()).pathname}`);
    }
  });

  const surface = await openRoute(page, 'Settings');
  const runtime = surface.getByRole('heading', { name: 'Runtime', exact: true }).locator('..').locator('..');
  const providers = surface.locator('#advisor-providers');
  const local = providers.locator('.advisor-provider-card', { hasText: 'Local Ollama' });

  await local.getByRole('button', { name: 'Edit', exact: true }).click();
  let form = providers.locator('.advisor-provider-form');
  await form.getByLabel('Name', { exact: true }).fill('Retained local draft');
  faults.holdRecovery();
  try {
    await runtime.getByRole('button', { name: 'Reload Settings', exact: true }).click();
    await faults.expectRecoveryReads();
    await expect(form.getByLabel('Name', { exact: true })).toHaveValue('Retained local draft');
    await expect(form.getByRole('button', { name: 'Save provider', exact: true })).toBeDisabled();
    await expect(form).toContainText('Your provider draft is retained.');
  } finally {
    faults.releaseRecovery();
  }
  await expect(runtime.getByText('Settings reloaded from durable runtime configuration and Advisor provider state.', { exact: true })).toBeVisible();
  await expect(form.getByLabel('Name', { exact: true })).toHaveValue('Retained local draft');
  await expect(form.getByRole('button', { name: 'Save provider', exact: true })).toBeEnabled();
  expect(await (await request.get('/v1/advisor/providers')).json()).toEqual(initial);
  await form.getByRole('button', { name: 'Cancel edit', exact: true }).click();

  await local.getByRole('button', { name: 'Edit', exact: true }).click();
  form = providers.locator('.advisor-provider-form');
  await expect(form.getByLabel('Name', { exact: true })).toHaveValue('Local Ollama');
  await form.getByRole('button', { name: 'Cancel edit', exact: true }).click();

  await providers.getByRole('button', { name: 'Add provider', exact: true }).click();
  form = providers.locator('.advisor-provider-form');
  await form.getByLabel('Name', { exact: true }).fill('Retained new provider');
  await runtime.getByRole('button', { name: 'Reload Settings', exact: true }).click();
  await expect(runtime.getByText('Settings reloaded from durable runtime configuration and Advisor provider state.', { exact: true })).toBeVisible();
  await expect(form.getByLabel('Name', { exact: true })).toHaveValue('Retained new provider');
  await expect(form.getByRole('button', { name: 'Add provider', exact: true })).toBeEnabled();
  expect(pageMutations).toEqual([]);
  expect(await (await request.get('/v1/advisor/providers')).json()).toEqual(initial);
  guards.assertClean();
});

test('Settings retains a provider draft through failed reload and saves only its original revision after recovery', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const faults = await installSettingsLoadFaults(page, new URL(baseURL).origin, {
    '/v1/advisor/providers': { code: 'advisor_providers_unavailable', message: 'Generated provider read failure.' },
  });
  const initial = await (await request.get('/v1/advisor/providers')).json();
  const mutations = mutationRequestLog(page);
  const surface = await openRoute(page, 'Settings');
  const providers = surface.locator('#advisor-providers');
  await providers.locator('.advisor-provider-card', { hasText: 'Local Ollama' }).getByRole('button', { name: 'Edit', exact: true }).click();
  const form = providers.locator('.advisor-provider-form');
  await form.getByLabel('Name', { exact: true }).fill('My local model');
  faults.armEntryFailure();
  await surface.getByRole('button', { name: 'Reload Settings', exact: true }).click();
  await expect(surface).toHaveAttribute('data-settings-provider-state', 'error');
  await expect(form.getByLabel('Name', { exact: true })).toHaveValue('My local model');
  await expect(form.getByRole('button', { name: 'Save provider', exact: true })).toBeDisabled();
  await expect(form.getByRole('button', { name: 'Cancel edit', exact: true })).toBeEnabled();
  expect(mutations).toEqual([]);
  faults.releaseRecovery();
  await surface.getByRole('button', { name: 'Reload Settings', exact: true }).click();
  await expect(form.getByRole('button', { name: 'Save provider', exact: true })).toBeEnabled();
  await expect(form.getByLabel('Name', { exact: true })).toHaveValue('My local model');
  const savedResponse = page.waitForResponse(response => response.request().method() === 'PUT'
    && new URL(response.url()).pathname === '/v1/advisor/providers/local-default');
  await form.getByRole('button', { name: 'Save provider', exact: true }).click();
  const saved = await savedResponse;
  expect(saved.status()).toBe(200);
  expect(saved.request().postDataJSON()).toMatchObject({ expected_revision: initial.revision });
  await expect(form).toHaveCount(0);
  const current = await (await request.get('/v1/advisor/providers')).json();
  expect(current.revision).toBe(initial.revision + 1);
  expect(current.providers.find((provider: { id: string }) => provider.id === 'local-default').name).toBe('My local model');
  expect(mutations).toHaveLength(1);
  await faults.assertIntentionalFailures(guards);
});

test('Settings retains but blocks a provider draft when another client changes the collection', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const initial = await (await request.get('/v1/advisor/providers')).json();
  const mutations = mutationRequestLog(page);
  const surface = await openRoute(page, 'Settings');
  const providers = surface.locator('#advisor-providers');
  await providers.locator('.advisor-provider-card', { hasText: 'Local Ollama' }).getByRole('button', { name: 'Edit', exact: true }).click();
  const form = providers.locator('.advisor-provider-form');
  await form.getByLabel('Name', { exact: true }).fill('My unsaved name');
  const original = initial.providers.find((provider: { id: string }) => provider.id === 'local-default');
  const external = await request.put('/v1/advisor/providers/local-default', { data: {
    expected_revision: initial.revision,
    provider: { ...advisorProviderWriteInput(original), name: 'Changed by another client' },
  } });
  expect(external.status()).toBe(200);
  await surface.getByRole('button', { name: 'Reload Settings', exact: true }).click();
  await expect(surface).toHaveAttribute('data-settings-provider-state', 'success');
  await expect(form.getByLabel('Name', { exact: true })).toHaveValue('My unsaved name');
  await expect(form).toContainText('Provider configuration changed while you were editing.');
  await expect(form.getByRole('button', { name: 'Save provider', exact: true })).toBeDisabled();
  await form.getByLabel('Name', { exact: true }).press('Enter');
  expect(mutations).toEqual([]);
  expect(await (await request.get('/v1/advisor/providers')).json()).toEqual(await external.json());
  await form.getByRole('button', { name: 'Cancel edit', exact: true }).click();
  await providers.locator('.advisor-provider-card', { hasText: 'Changed by another client' }).getByRole('button', { name: 'Edit', exact: true }).click();
  await expect(form.getByLabel('Name', { exact: true })).toHaveValue('Changed by another client');
  await expect(form.getByRole('button', { name: 'Save provider', exact: true })).toBeEnabled();
  guards.assertClean();
});

for (const failure of [
  {
    label: 'runtime configuration',
    path: '/v1/config',
    detail: { code: 'runtime_config_unavailable', message: 'Generated runtime configuration is temporarily unavailable.' },
    configState: 'error',
    providerState: 'success',
  },
  {
    label: 'Advisor providers',
    path: '/v1/advisor/providers',
    detail: { code: 'advisor_providers_unavailable', message: 'Generated Advisor providers are temporarily unavailable.' },
    configState: 'success',
    providerState: 'error',
  },
] as const) {
  test(`Settings disables every mutation when only ${failure.label} fails to load`, async ({ page, request, baseURL }) => {
    if (!baseURL) throw new Error('Playwright baseURL is required.');
    await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
    const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
    const faults = await installSettingsLoadFaults(page, new URL(baseURL).origin, { [failure.path]: failure.detail });
    const pageMutations: string[] = [];
    page.on('request', (candidate) => {
      if (!['GET', 'HEAD', 'OPTIONS'].includes(candidate.method())) {
        pageMutations.push(`${candidate.method()} ${new URL(candidate.url()).pathname}`);
      }
    });

    await openRoute(page, 'Overview');
    faults.armEntryFailure();
    await page.getByRole('navigation').getByRole('button', { name: 'Settings', exact: true }).click();
    const surface = page.locator('section[data-route-surface="settings"]');
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await expect(surface).not.toHaveAttribute('inert', '');
    await expect(surface).toHaveAttribute('data-settings-config-state', failure.configState);
    await expect(surface).toHaveAttribute('data-settings-provider-state', failure.providerState);
    const runtime = surface.getByRole('heading', { name: 'Runtime', exact: true }).locator('..').locator('..');
    await expect(runtime.getByRole('alert')).toContainText(failure.detail.message);
    for (const buttonName of ['Add provider', 'Save Advisor Policy', 'Save Gate', 'Save Desired Components']) {
      await expect(surface.getByRole('button', { name: buttonName, exact: true })).toBeDisabled();
    }
    for (const button of await surface.locator('#advisor-providers .advisor-provider-actions button').all()) {
      await expect(button).toBeDisabled();
    }
    expect(pageMutations).toEqual([]);

    faults.holdRecovery();
    try {
      await runtime.getByRole('button', { name: 'Reload Settings', exact: true }).click();
      await expect(runtime.getByRole('button', { name: 'Reloading Settings…', exact: true })).toBeDisabled();
      await faults.expectRecoveryReads();
    } finally {
      faults.releaseRecovery();
    }
    await expect(surface).toHaveAttribute('data-settings-config-state', 'success');
    await expect(surface).toHaveAttribute('data-settings-provider-state', 'success');
    await expect(surface.getByRole('button', { name: 'Add provider', exact: true })).toBeEnabled();
    await expect(surface.getByRole('button', { name: 'Save Advisor Policy', exact: true })).toBeEnabled();
    expect(pageMutations).toEqual([]);
    await faults.assertIntentionalFailures(guards);
  });
}

test('Settings saves Advisor, gate, and component choices and reports command-copy outcomes locally', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await page.addInitScript(() => {
    const state = window as Window & { __applyCommandCopied?: string; __applyCommandCopyFails?: boolean };
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value: string) => {
          if (state.__applyCommandCopyFails) throw new Error('Generated clipboard failure.');
          state.__applyCommandCopied = value;
        },
      },
    });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const pushPoliciesResponse = page.waitForResponse((response) => response.request().method() === 'GET'
    && response.url() === new URL('/v1/git/push-protection', baseURL).href);
  const surface = await openRoute(page, 'Settings');

  const pushPolicies = await pushPoliciesResponse;
  expect(pushPolicies.status()).toBe(200);
  expect(pushPolicies.headers()['content-type']).toContain('application/json');
  expect(await pushPolicies.json()).toEqual({ repositories: [] });
  const pushProtection = surface.locator('#git-push-protection');
  await expect(pushProtection.getByText('No repositories are set up yet. Open this exact repository in VS Code and choose Protect Pushes to review host setup.', { exact: true })).toBeVisible();
  await expect(pushProtection.getByRole('alert')).toHaveCount(0);

  const gate = surface.locator('.gate-policy-panel');
  const components = surface.locator('.band').filter({ has: page.locator('form[data-settings-form="components"]') });
  await expect(components.getByRole('heading', { name: 'Components More information', exact: true })).toBeVisible();
  // This fixture deliberately leaves secret blocking disabled; name it truthfully.
  await expect(gate.getByRole('button', { name: /^Custom/u })).toHaveClass(/active/u);
  await expect(gate.getByLabel('Block secret findings', { exact: true })).not.toBeChecked();
  await gate.getByRole('button', { name: /^Strict/u }).click();
  await components.getByLabel('Monitoring: Grafana and Prometheus', { exact: true }).check();

  const advisor = surface.locator('.band').filter({ has: page.locator('form[data-settings-form="advisor"]') });
  await expect(advisor.getByRole('heading', { name: 'Advisor Policy More information', exact: true })).toBeVisible();
  await advisor.getByRole('combobox', { name: 'Mode', exact: true }).selectOption('off');
  await advisor.getByLabel('Auto Triage Limit', { exact: true }).fill('7');
  await advisor.getByLabel('Thinking mode', { exact: true }).check();
  const advisorRequestPromise = page.waitForRequest((candidate) => candidate.method() === 'PATCH' && new URL(candidate.url()).pathname === '/v1/config/advisor');
  await advisor.getByRole('button', { name: 'Save Advisor Policy', exact: true }).click();
  const advisorRequest = await advisorRequestPromise;
  expect(advisorRequest.postDataJSON()).toEqual({
    ai_mode: 'off',
    ollama_base_url: 'http://127.0.0.1:11434',
    ollama_model: 'generated-local-model',
    ollama_thinking: true,
    auto_triage_limit: 7,
  });
  await expect(advisor.getByRole('status')).toContainText('Advisor policy saved');
  await expect(gate.getByRole('button', { name: /^Strict/u })).toHaveClass(/active/u);
  await expect(components.getByLabel('Monitoring: Grafana and Prometheus', { exact: true })).toBeChecked();
  expect(await request.get('/v1/config').then((response) => response.json())).toMatchObject({
    ai_mode: 'off',
    gate_preset: 'custom',
    component_monitoring_enabled: false,
  });
  expect(await request.get('/healthz').then((response) => response.json())).toMatchObject({
    ai: {
      mode: 'off',
      base_url: 'http://127.0.0.1:11434',
      model: 'generated-local-model',
      thinking: true,
    },
  });
  const advisorStatus = surface.locator('.band').filter({ has: page.getByRole('heading', { name: 'Advisor Route', exact: true }) });
  await expect(advisorStatus.getByText('Generated local advisor is disabled by the saved runtime setting.', { exact: true })).toBeVisible();

  await expect(gate.getByLabel('Max critical', { exact: true })).toHaveValue('0');
  await expect(gate.getByLabel('Max high', { exact: true })).toHaveValue('0');
  await expect(gate.getByLabel('Block secret findings', { exact: true })).toBeChecked();
  await gate.getByLabel('Max critical', { exact: true }).fill('2');
  await gate.getByLabel('Max high', { exact: true }).fill('4');
  await gate.getByLabel('Block secret findings', { exact: true }).uncheck();
  await gate.getByLabel('Apply to existing projects on save', { exact: true }).check();
  await advisor.getByLabel('Auto Triage Limit', { exact: true }).fill('9');
  await components.getByLabel('Git proxy: Gitea', { exact: true }).check();
  await expect(gate.getByRole('button', { name: /^Custom/u })).toHaveClass(/active/u);
  const gateRequestPromise = page.waitForRequest((candidate) => candidate.method() === 'PATCH' && new URL(candidate.url()).pathname === '/v1/config/gate');
  await gate.getByRole('button', { name: 'Save Gate', exact: true }).click();
  const gateRequest = await gateRequestPromise;
  expect(gateRequest.postDataJSON()).toEqual({
    gate_preset: 'custom',
    gate_active: true,
    gate_max_critical: 2,
    gate_max_high: 4,
    gate_block_secrets: false,
    gate_apply_to_existing: true,
  });
  await expect(gate.getByRole('status')).toHaveText('Gate defaults saved as custom and applied to existing projects.');
  await expect(advisor.getByLabel('Auto Triage Limit', { exact: true })).toHaveValue('9');
  await expect(components.getByLabel('Monitoring: Grafana and Prometheus', { exact: true })).toBeChecked();
  await expect(components.getByLabel('Git proxy: Gitea', { exact: true })).toBeChecked();
  expect(await request.get('/v1/config').then((response) => response.json())).toMatchObject({
    ollama_model: 'generated-local-model',
    component_monitoring_enabled: false,
    component_git_proxy_enabled: false,
    gate_preset: 'custom',
    gate_max_critical: 2,
    gate_max_high: 4,
  });
  expect(await request.get('/v1/scans/41').then((response) => response.json())).toMatchObject({
    id: 41,
    revision: 2,
    findings_revision: 1,
    gate_decision: 'pass',
    gate_reasons: [],
  });

  await components.getByLabel('Database UI: Adminer', { exact: true }).check();
  const componentsRequestPromise = page.waitForRequest((candidate) => candidate.method() === 'PATCH' && new URL(candidate.url()).pathname === '/v1/config/components');
  await components.getByRole('button', { name: 'Save Desired Components', exact: true }).click();
  const componentsRequest = await componentsRequestPromise;
  expect(componentsRequest.postDataJSON()).toEqual({
    component_monitoring_enabled: true,
    component_git_proxy_enabled: true,
    component_db_admin_enabled: true,
  });
  await expect(components.getByRole('status')).toContainText('make apply-components COMPONENTS=all');
  await expect(components.locator('.command-box code')).toHaveText('make apply-components COMPONENTS=all');
  await expect(components.locator('.component-card', { hasText: 'grafana' })).toContainText('desired on');

  await components.getByRole('button', { name: 'Copy', exact: true }).click();
  await expect(components.getByRole('status').filter({ hasText: 'Apply command copied.' })).toBeVisible();
  expect(await page.evaluate(() => (window as Window & { __applyCommandCopied?: string }).__applyCommandCopied)).toBe('make apply-components COMPONENTS=all');
  await page.evaluate(() => {
    (window as Window & { __applyCommandCopyFails?: boolean }).__applyCommandCopyFails = true;
  });
  await components.getByRole('button', { name: 'Copy', exact: true }).click();
  await expect(components.getByRole('status').filter({ hasText: 'Apply command could not be copied.' })).toHaveText('Apply command could not be copied. Select the command and copy it manually.');

  const persisted = await request.get('/v1/config').then((response) => response.json()) as Record<string, unknown>;
  expect(persisted).toMatchObject({
    ai_mode: 'off',
    ollama_model: 'generated-local-model',
    gate_preset: 'custom',
    gate_max_critical: 2,
    gate_max_high: 4,
    component_apply_command: 'make apply-components COMPONENTS=all',
  });
  guards.assertClean();
});

for (const target of [
  { scope: 'advisor', field: 'auto_triage_limit', label: 'Auto Triage Limit', button: 'Save Advisor Policy', saved: 'Advisor policy saved' },
  { scope: 'gate', field: 'gate_max_high', label: 'Max high', button: 'Save Gate', saved: 'Gate defaults saved' },
  { scope: 'components', field: 'component_monitoring_enabled', label: 'Monitoring: Grafana and Prometheus', button: 'Save Desired Components', saved: 'Desired components saved' },
] as const) {
  const failures = target.scope === 'advisor'
    ? ['not-delivered', 'lost-response', 'malformed-json', 'malformed-shape', 'wrong-value', 'server-error', 'rejected'] as const
    : ['not-delivered', 'lost-response'] as const;
  for (const failure of failures) {
    const reachedBackend = failure !== 'not-delivered' && failure !== 'rejected';
    referenceTest(`Settings unconfirmed ${target.scope} save preserves edits: ${failure}`, async ({ page, request, baseURL }, testInfo) => {
      if (!baseURL) throw new Error('Playwright baseURL is required.');
      await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
      const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
      const before = await (await request.get('/v1/config')).json();
      const surface = await openRoute(page, 'Settings');
      const panel = surface.locator('.band').filter({ has: page.locator(`form[data-settings-form="${target.scope}"]`) });
      const field = panel.getByLabel(target.label, { exact: true });
      const changed = typeof before[target.field] === 'boolean' ? !before[target.field] : before[target.field] + 1;
      if (typeof changed === 'boolean') await field.setChecked(changed);
      else await field.fill(String(changed));
      const url = new URL(`/v1/config/${target.scope}`, baseURL).href;
      const commands: string[] = [];
      page.on('request', candidate => { if (candidate.method() === 'PATCH') commands.push(candidate.url()); });
      await page.route(url, async route => {
        let saved: Record<string, unknown> | undefined;
        if (reachedBackend) {
          const committed = await route.fetch();
          expect(committed.status()).toBe(200);
          saved = await committed.json();
          expect(saved?.[target.field]).toBe(changed);
        }
        if (failure === 'rejected' || failure === 'server-error') {
          await route.fulfill({ status: failure === 'rejected' ? 422 : 503, contentType: 'application/json',
            body: JSON.stringify({ detail: { code: 'generated_rejection', message: 'Generated save rejection.' } }) });
        } else if (failure === 'malformed-json' || failure === 'malformed-shape' || failure === 'wrong-value') {
          await route.fulfill({ status: 200, contentType: 'application/json', body: failure === 'malformed-json' ? '{'
            : JSON.stringify(failure === 'malformed-shape' ? {} : { ...saved, [target.field]: before[target.field] }) });
        } else {
          await route.abort('failed');
        }
      }, { times: 1 });
      await panel.getByRole('button', { name: target.button, exact: true }).click();
      await expect(panel.getByRole('alert')).toHaveText(failure === 'rejected' ? 'Generated save rejection.'
        : 'Save could not be confirmed. Your edits are still here. Check that the backend is running, then use Reload Settings before saving again.');
      if (failure === 'malformed-shape') {
        const viewport = page.viewportSize()!;
        for (const width of [1440, 768, 390]) {
          await page.setViewportSize({ width, height: viewport.height });
          await expect(panel.getByRole('alert')).toBeVisible();
          const geometry = await panel.getByRole('alert').evaluate(element => ({
            textFits: element.scrollWidth <= element.clientWidth + 1,
            pageFits: document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1,
          }));
          expect(geometry).toEqual({ textFits: true, pageFits: true });
          await testInfo.attach(`unconfirmed-save-${width}.png`, { body: await panel.screenshot(), contentType: 'image/png' });
        }
        await page.setViewportSize(viewport);
      }
      await expect(panel.getByRole('button', { name: target.button, exact: true })).toBeEnabled();
      await expect(panel.getByRole('status').filter({ hasText: target.saved })).toHaveCount(0);
      if (typeof changed === 'boolean') await expect(field).toBeChecked({ checked: changed });
      else await expect(field).toHaveValue(String(changed));
      expect((await (await request.get('/v1/config')).json())[target.field]).toBe(reachedBackend ? changed : before[target.field]);
      await surface.getByRole('button', { name: 'Reload Settings', exact: true }).click();
      await expect(surface).toHaveAttribute('data-settings-config-state', 'success');
      await expect(panel.getByRole('alert')).toHaveCount(0);
      if (typeof changed === 'boolean') await expect(field).toBeChecked({ checked: changed });
      else await expect(field).toHaveValue(String(changed));
      await page.waitForLoadState('networkidle');
      expect(commands, 'reload and recovery never repeat the write automatically').toEqual([url]);
      if (!reachedBackend) {
        await panel.getByRole('button', { name: target.button, exact: true }).click();
        await expect(panel.getByRole('status').filter({ hasText: target.saved })).toBeVisible();
        expect(commands).toEqual([url, url]);
      }
      expect((await (await request.get('/v1/config')).json())[target.field]).toBe(changed);
      const aborted = failure === 'not-delivered' || failure === 'lost-response';
      const status = failure === 'server-error' ? 503 : failure === 'rejected' ? 422 : null;
      expect(guards.failures.request).toEqual(aborted ? [`PATCH ${url}: net::ERR_FAILED`] : []);
      if (status) {
        expect(guards.failures.console).toHaveLength(1);
        expect(guards.failures.console[0]).toContain(`the server responded with a status of ${status}`);
      } else expect(guards.failures.console).toEqual(aborted ? ['Failed to load resource: net::ERR_FAILED'] : []);
      expect(guards.failures.page).toEqual([]);
      expect(guards.failures.http).toEqual(status ? [`${status} ${url}`] : []);
      expect(guards.failures.egress).toEqual([]);
      expect(guards.failures.credentialUrl).toEqual([]);
    });
  }
}

test('[WEB-ACT-005] Components saves a full profile and then returns to the lean core profile', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const components = surface.locator('.band').filter({ has: page.locator('form[data-settings-form="components"]') });
  await expect(components.getByRole('heading', { name: 'Components More information', exact: true })).toBeVisible();
  const monitoring = components.getByLabel('Monitoring: Grafana and Prometheus', { exact: true });
  const gitProxy = components.getByLabel('Git proxy: Gitea', { exact: true });
  const databaseUi = components.getByLabel('Database UI: Adminer', { exact: true });

  await monitoring.check();
  await gitProxy.check();
  await databaseUi.check();
  await components.getByRole('button', { name: 'Save Desired Components', exact: true }).click();
  await expect(components.locator('.command-box code')).toHaveText('make apply-components COMPONENTS=all');
  expect(await request.get('/v1/config').then((response) => response.json())).toMatchObject({
    component_monitoring_enabled: true,
    component_git_proxy_enabled: true,
    component_db_admin_enabled: true,
    component_apply_command: 'make apply-components COMPONENTS=all',
  });

  await monitoring.uncheck();
  await gitProxy.uncheck();
  await databaseUi.uncheck();
  await components.getByRole('button', { name: 'Save Desired Components', exact: true }).click();
  await expect(components.locator('.command-box code')).toHaveText('make apply-components COMPONENTS=core');
  await expect(components.getByRole('status')).toContainText('make apply-components COMPONENTS=core');
  expect(await request.get('/v1/config').then((response) => response.json())).toMatchObject({
    component_monitoring_enabled: false,
    component_git_proxy_enabled: false,
    component_db_admin_enabled: false,
    component_apply_command: 'make apply-components COMPONENTS=core',
  });
  guards.assertClean();
});

test('Settings browser members use unique labels and targeted revoke preserves every other member', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const browsers = surface.locator('.browser-member-management');
  await expect(browsers).toContainText('Last successful authorization');
  const revoke = browsers.getByRole('button', {
    name: 'Revoke browser member Local browser · bbbbbbbb',
    exact: true,
  });
  await revoke.click();
  await page.getByRole('button', { name: 'Keep browser authorized', exact: true }).click();
  expect(await request.get('/v1/auth/browser/sessions').then((response) => response.json())).toHaveLength(2);

  await revoke.click();
  await page.getByRole('button', { name: 'Revoke browser', exact: true }).click();
  await expect(revoke).toHaveCount(0);
  await expect(
    browsers.getByRole('button', {
      name: 'Sign out current browser member Installation owner browser · aaaaaaaa',
      exact: true,
    }),
  ).toHaveCount(1);
  const remaining = await request.get('/v1/auth/browser/sessions').then((response) => response.json());
  expect(remaining).toHaveLength(1);
  expect(remaining[0]).toMatchObject({ member_name: 'Installation owner browser · aaaaaaaa', current: true });
  guards.assertClean();
});

test('IDE authority: Settings reviews a no-paste IDE request while browser pairing remains separate', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const browserPairingKey = `kb1.${'b'.repeat(43)}`;
  const issuedAt = new Date(Date.now() - 1_000).toISOString();
  const browserKeyExpiresAt = new Date(Date.now() + 1_500).toISOString();
  const keyExpiresAt = new Date(Date.now() + 600_000).toISOString();
  const clientCreatedAt = new Date(Date.now() - 86_400_000).toISOString();
  const enrollmentRequestId = `ker1_${'r'.repeat(24)}`;
  const verificationCode = '7KDM-P9QH';
  const enrollmentClientName = `Ubuntu QA profile · ${'x'.repeat(100)}`.slice(0, 120);
  let enrollmentPending = false;
  let decisionRequests = 0;
  let browserIssueRequests = 0;
  await page.addInitScript(() => {
    const state = window as Window & { __pairingKeyCopied?: string };
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value: string) => { state.__pairingKeyCopied = value; },
      },
    });
  });
  await page.route('**/v1/auth/ide/enrollments', async (route) => {
    expect(route.request().method()).toBe('GET');
    await route.fulfill({ json: enrollmentPending ? [{
      request_id: enrollmentRequestId,
      state: 'awaiting_approval',
      revision: 1,
      verification_code: verificationCode,
      scopes: ['event:read', 'scan:create'],
      client_slot: SETTINGS_IDE_SLOT,
      client_name: enrollmentClientName,
      generation: 2,
      requested_at: issuedAt,
      activation_expires_at: keyExpiresAt,
    }] : [] });
  });
  await page.route(`**/v1/auth/ide/enrollments/${enrollmentRequestId}/decision`, async (route) => {
    decisionRequests += 1;
    expect(route.request().method()).toBe('POST');
    expect(route.request().headers()['x-csrf-token']).toBeTruthy();
    expect(route.request().postDataJSON()).toEqual({
      decision: 'approved',
      expected_revision: 1,
      expected_generation: 2,
    });
    enrollmentPending = false;
    await route.fulfill({ json: {
      request_id: enrollmentRequestId,
      state: 'approved',
      revision: 2,
      decision_at: new Date().toISOString(),
      activation_expires_at: keyExpiresAt,
    } });
  });
  await page.route('**/v1/auth/browser/pairing-token', async (route) => {
    browserIssueRequests += 1;
    expect(route.request().method()).toBe('POST');
    expect(route.request().headers()['x-csrf-token']).toBeTruthy();
    await route.fulfill({
      json: {
        bootstrap_token: browserPairingKey,
        issued_at: issuedAt,
        expires_at: browserKeyExpiresAt,
        expires_in: 600,
      },
    });
  });
  await page.route('**/v1/auth/ide/capabilities', async (route) => {
    await route.fulfill({
      json: [{
        state: 'valid',
        id: SETTINGS_IDE_SLOT,
        client_name: 'Ubuntu QA profile',
        scopes: ['event:read', 'source:open-ack'],
        created_at: clientCreatedAt,
        revoked: false,
        active: true,
        connected: true,
        active_generation: 1,
        latest_generation: 1,
        pending_activation: false,
        pending_generation: null,
        pending_client_name: null,
        pending_activation_expires_at: null,
        source_open_available: true,
        source_open_disabled_reason: null,
        invalid_recovery_token: null,
      }],
    });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let surface = await openRoute(page, 'Settings');
  let browserPairing = surface.locator('.browser-pairing-panel');
  await expect(browserPairing).toContainText('authorize one additional local browser profile');
  await expect(browserPairing).toContainText("VS Code's integrated browser is paired by the extension");
  await expect(browserPairing).toContainText('Open Dashboard');
  await expect(browserPairing).toContainText('Pair integrated browser again');
  await expect(browserPairing).not.toContainText("including VS Code's integrated browser");
  await browserPairing.getByRole('button', { name: 'Generate new browser pairing key', exact: true }).click();
  await expect(browserPairing.getByLabel('One-time browser pairing key')).toHaveValue(browserPairingKey);
  await expect(browserPairing.getByText('shown only in the current page state', { exact: false })).toBeVisible();
  await expect(browserPairing).toContainText('If no paired browser remains, the installation owner can recover access with make auth-info.');
  await browserPairing.getByRole('button', { name: 'Copy browser pairing key', exact: true }).click();
  await expect(browserPairing.getByRole('status').filter({ hasText: 'Hidden after copying.' })).toBeVisible();
  await expect(browserPairing).toContainText('Copying does not prove that the target browser consumed it');
  await expect(browserPairing.getByLabel('One-time browser pairing key')).toHaveCount(0);
  expect(await page.evaluate(() => (window as Window & { __pairingKeyCopied?: string }).__pairingKeyCopied)).toBe(browserPairingKey);
  expect(browserIssueRequests).toBe(1);
  await expect(browserPairing.getByRole('status').filter({ hasText: 'The one-time browser pairing key expired.' })).toBeVisible({ timeout: 3_000 });
  await expect(browserPairing).not.toContainText('Hidden after copying.');
  await expect(browserPairing.getByRole('button', { name: 'Generate new browser pairing key', exact: true })).toBeEnabled();

  await page.getByRole('navigation').getByRole('button', { name: 'Overview', exact: true }).click();
  await expect(page.locator('body')).not.toContainText(browserPairingKey);
  surface = await openRoute(page, 'Settings');
  browserPairing = surface.locator('.browser-pairing-panel');
  await expect(browserPairing.getByLabel('One-time browser pairing key')).toHaveCount(0);
  expect(browserIssueRequests).toBe(1);

  const pairing = surface.locator('.ide-pairing-panel');
  await expect(pairing).toContainText('No secret is copied or pasted.');
  await expect(pairing).toContainText("profile's OS-account-private application storage");
  await expect(pairing).toContainText('No IDE access requests are waiting.');
  enrollmentPending = true;
  await page.evaluate(() => { window.location.hash = '#ide-access'; });
  const pendingRequests = pairing.getByRole('list', { name: 'Pending IDE access requests', exact: true });
  await expect(pendingRequests).toContainText(verificationCode);
  await expect(pairing).toBeFocused();
  await expect(pairing).toContainText('Requested scopes: event:read, scan:create');
  await expect(pairing.getByText('(in 10 minutes)', { exact: true })).toBeVisible();
  const visibleVerificationCode = pendingRequests.locator('.ide-enrollment-code');
  await expect(visibleVerificationCode).toHaveText(verificationCode);
  const verificationCodeGeometry = await visibleVerificationCode.evaluate((element) => {
    const row = element.closest('.ide-enrollment-row');
    if (!(row instanceof HTMLElement)) throw new Error('Pending IDE enrollment row is missing.');
    const bounds = element.getBoundingClientRect();
    const rowBounds = row.getBoundingClientRect();
    const style = getComputedStyle(element);
    return {
      clientWidth: element.clientWidth,
      fontSize: Number.parseFloat(style.fontSize),
      left: bounds.left,
      overflow: style.overflow,
      right: bounds.right,
      rowLeft: rowBounds.left,
      rowRight: rowBounds.right,
      scrollWidth: element.scrollWidth,
      textOverflow: style.textOverflow,
    };
  });
  expect(verificationCodeGeometry.left).toBeGreaterThanOrEqual(verificationCodeGeometry.rowLeft - 0.5);
  expect(verificationCodeGeometry.right).toBeLessThanOrEqual(verificationCodeGeometry.rowRight + 0.5);
  expect(verificationCodeGeometry.fontSize).toBeGreaterThanOrEqual(16);
  expect(verificationCodeGeometry.scrollWidth).toBeLessThanOrEqual(verificationCodeGeometry.clientWidth + 1);
  expect(verificationCodeGeometry.overflow).not.toBe('hidden');
  expect(verificationCodeGeometry.textOverflow).not.toBe('ellipsis');
  const clientRow = pairing.getByRole('list', { name: 'Paired IDE clients', exact: true }).getByText('Ubuntu QA profile').locator('..');
  await expect(clientRow).toContainText('active generation 1');
  await expect(clientRow).not.toContainText('authority expires');
  await pairing.getByRole('button', { name: 'Approve', exact: true }).click();
  const approvedMessage = `${enrollmentClientName} was approved. VS Code can now finish activation without a pasted key.`;
  await expect(pairing.getByRole('status').filter({ hasText: approvedMessage })).toContainText(approvedMessage);
  await expect(pairing.getByText('Loading pending IDE requests…', { exact: true })).toHaveCount(0);
  await expect(pairing.getByRole('list', { name: 'Pending IDE access requests', exact: true })).toHaveCount(0);
  expect(decisionRequests).toBe(1);

  await page.reload();
  await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
  surface = page.locator('section[data-route-surface="settings"]');
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await expect(surface.getByLabel('One-time browser pairing key')).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText(browserPairingKey);
  await expect(surface.locator('.ide-pairing-panel')).toContainText('No IDE access requests are waiting.');
  expect(decisionRequests).toBe(1);
  expect(browserIssueRequests).toBe(1);
  const unexpectedReloadFailures = guards.failures.request.filter((failure) => (
    !/^GET .*\/v1\/auth\/(?:browser\/sessions|ide\/enrollments): net::ERR_ABORTED$/u.test(failure)
  ));
  guards.failures.request.splice(0, guards.failures.request.length, ...unexpectedReloadFailures);
  guards.assertClean();
});

test('IDE authority: a committed approval stays truthful when authoritative refresh fails', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const enrollmentRequestId = `ker1_${'s'.repeat(24)}`;
  const expiry = new Date(Date.now() + 600_000).toISOString();
  const retainedClient = {
    state: 'valid',
    id: `ks1_${'R'.repeat(43)}`,
    client_name: 'Retained QA profile',
    scopes: ['event:read', 'source:open-ack'],
    created_at: '2026-08-26T09:00:00Z',
    revoked: false,
    active: true,
    connected: true,
    active_generation: 3,
    latest_generation: 3,
    pending_activation: false,
    pending_generation: null,
    pending_client_name: null,
    pending_activation_expires_at: null,
    source_open_available: true,
    source_open_disabled_reason: null,
    invalid_recovery_token: null,
  };
  const mutations = mutationRequestLog(page);
  let committed = false;
  let decisionAttempts = 0;
  let postCommitEnrollmentReads = 0;
  let postCommitCapabilityReads = 0;
  let enrollmentReadHeld = false;
  let releaseEnrollments!: () => void;
  const enrollmentGate = new Promise<void>((resolve) => { releaseEnrollments = resolve; });
  await page.route('**/v1/auth/ide/enrollments', async (route) => {
    expect(route.request().method()).toBe('GET');
    if (committed) {
      postCommitEnrollmentReads += 1;
      enrollmentReadHeld = true;
      await enrollmentGate;
    }
    await route.fulfill({ json: committed ? [] : [{
      request_id: enrollmentRequestId,
      state: 'awaiting_approval',
      revision: 1,
      verification_code: '8QTR-7NWP',
      scopes: ['event:read'],
      client_slot: SETTINGS_IDE_SLOT,
      client_name: 'Mac QA profile',
      generation: 1,
      requested_at: new Date().toISOString(),
      activation_expires_at: expiry,
    }] });
  });
  await page.route(`**/v1/auth/ide/enrollments/${enrollmentRequestId}/decision`, async (route) => {
    decisionAttempts += 1;
    expect(route.request().method()).toBe('POST');
    expect(new URL(route.request().url()).origin).toBe(new URL(baseURL).origin);
    expect(route.request().headers()['x-csrf-token']).toBeTruthy();
    expect(route.request().postDataJSON()).toEqual({
      decision: 'approved', expected_revision: 1, expected_generation: 1,
    });
    if (decisionAttempts === 1) {
      await route.fulfill({ status: 409, json: {
        detail: {
          code: 'ide_enrollment_revision_conflict',
          message: 'The IDE enrollment changed before this decision was applied.',
          action: 'refresh_pending_enrollments',
        },
      } });
      return;
    }
    committed = true;
    await route.fulfill({ json: {
      request_id: enrollmentRequestId,
      state: 'approved',
      revision: 2,
      decision_at: new Date().toISOString(),
      activation_expires_at: expiry,
    } });
  });
  await page.route('**/v1/auth/ide/capabilities', async (route) => {
    if (!committed) {
      await route.fulfill({ json: [retainedClient] });
      return;
    }
    postCommitCapabilityReads += 1;
    await route.fulfill({ status: 200, contentType: 'application/json', body: '{' });
  });
  const surface = await openRoute(page, 'Settings');
  const pairing = surface.locator('#ide-access');
  const retainedClients = pairing.getByRole('list', { name: 'Paired IDE clients', exact: true });
  await expect(retainedClients.getByRole('listitem')).toHaveCount(1);
  await expect(retainedClients).toContainText(retainedClient.id);
  await expect(retainedClients).toContainText('Latest generation 3 · active generation 3');
  const retainedClientText = await retainedClients.innerText();
  await pairing.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(pairing.getByRole('alert')).toContainText('The IDE enrollment changed before this decision was applied.');
  await expect(pairing.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const exactResponse = (path: string) => page.waitForResponse((response) => (
    response.request().method() === 'GET'
    && committed
    && response.url() === new URL(path, baseURL).href
  ));
  const capabilityResponsePromise = exactResponse('/v1/auth/ide/capabilities');
  const enrollmentResponsePromise = exactResponse('/v1/auth/ide/enrollments');
  const committedDecisionResponse = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && response.url() === new URL(`/v1/auth/ide/enrollments/${enrollmentRequestId}/decision`, baseURL).href
  ));
  const refreshWarning = pairing.getByRole('alert').filter({ hasText: 'Mac QA profile was approved, but current IDE access could not be refreshed' });
  let warningBeforeEnrollmentRelease = false;
  let approvalAcknowledgedBeforeRelease = false;
  let busyBeforeEnrollmentRelease = false;
  try {
    await pairing.getByRole('button', { name: 'Approve', exact: true }).click();
    const decisionResponse = await committedDecisionResponse;
    expect(decisionResponse.status()).toBe(200);
    expect(await decisionResponse.json()).toMatchObject({ request_id: enrollmentRequestId, state: 'approved', revision: 2 });
    await expect.poll(() => enrollmentReadHeld).toBe(true);
    const capabilityResponse = await capabilityResponsePromise;
    expect(capabilityResponse.status()).toBe(200);
    expect(await capabilityResponse.finished()).toBeNull();
    expect(await capabilityResponse.text()).toBe('{');
    // Give the failed body parse its normal task/paint opportunities while the
    // successful enrollment read is held. This adds no sleep or retry budget.
    await page.evaluate(() => new Promise<void>((resolve) => {
      requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
    }));
    approvalAcknowledgedBeforeRelease = await pairing.getByRole('status').filter({ hasText: 'Mac QA profile was approved.' }).isVisible();
    busyBeforeEnrollmentRelease = await pairing.getAttribute('aria-busy') === 'true';
    warningBeforeEnrollmentRelease = await refreshWarning.isVisible();
  } finally {
    releaseEnrollments();
  }
  const enrollmentResponse = await enrollmentResponsePromise;
  expect(enrollmentResponse.status()).toBe(200);
  expect(await enrollmentResponse.finished()).toBeNull();
  expect(await enrollmentResponse.json()).toEqual([]);
  await expect(pairing).toHaveAttribute('aria-busy', 'false');
  await page.evaluate(() => new Promise<void>((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  }));
  await testInfo.attach('ide-approval-refresh-order.json', {
    body: Buffer.from(JSON.stringify({
      warningBeforeEnrollmentRelease,
      approvalAcknowledgedBeforeRelease,
      busyBeforeEnrollmentRelease,
      warningAfterSettlement: await refreshWarning.isVisible(),
      decisionAttempts,
      postCommitEnrollmentReads,
      postCommitCapabilityReads,
    })),
    contentType: 'application/json',
  });
  expect(decisionAttempts).toBe(2);
  expect(postCommitEnrollmentReads).toBe(1);
  expect(postCommitCapabilityReads).toBe(1);
  expect(mutations).toEqual([
    `POST /v1/auth/ide/enrollments/${enrollmentRequestId}/decision`,
    `POST /v1/auth/ide/enrollments/${enrollmentRequestId}/decision`,
  ]);
  await expect(pairing.getByRole('list', { name: 'Pending IDE access requests', exact: true })).toHaveCount(0);
  await expect(retainedClients.getByRole('listitem')).toHaveCount(1);
  await expect(retainedClients).toHaveText(retainedClientText, { useInnerText: true });
  await expect(retainedClients.getByRole('button', { name: `Revoke and allow re-pair for ${retainedClient.client_name} in profile slot ${retainedClient.id}`, exact: true })).toBeEnabled();
  await expect(pairing.getByRole('status')).toContainText('Mac QA profile was approved.');
  await expect(pairing.getByRole('alert')).toContainText('Mac QA profile was approved, but current IDE access could not be refreshed');
  await expect(pairing.getByRole('alert')).not.toContainText('approval failed');
  guards.assertClean();
});

test('IDE authority: Settings distinguishes, generation-cancels, and revokes one exact paired IDE client', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const capability = {
    state: 'valid' as const,
    id: SETTINGS_IDE_SLOT,
    client_name: 'VS Code QA local',
    scopes: ['event:read', 'source:open-ack'],
    created_at: '2026-08-26T09:00:00Z',
    expires_at: '2027-02-22T09:00:00Z',
    revoked: false,
    active: true,
    connected: true,
    active_generation: 1,
    latest_generation: 2,
    pending_activation: true,
    pending_generation: 2 as number | null,
    pending_client_name: 'VS Code QA replacement' as string | null,
    pending_activation_expires_at: '2026-08-26T09:10:00Z' as string | null,
    source_open_available: true,
    source_open_disabled_reason: null,
    invalid_recovery_token: null,
  };
  let capabilities = [capability];
  let capabilityGets = 0;
  const mutations: Array<{ id: string; csrf: string | undefined; method: string; body: unknown }> = [];
  await page.route('**/v1/auth/ide/capabilities', async (route) => {
    capabilityGets += 1;
    await route.fulfill({ json: capabilities });
  });
  await page.route('**/v1/auth/ide/capabilities/**', async (route) => {
    const candidate = route.request();
    const segments = new URL(candidate.url()).pathname.split('/');
    const pendingCancellation = segments.at(-1) === 'pending';
    const id = decodeURIComponent(segments.at(pendingCancellation ? -2 : -1) || '');
    const body = candidate.postDataJSON();
    mutations.push({ id, csrf: candidate.headers()['x-csrf-token'], method: candidate.method(), body });
    if (pendingCancellation) {
      expect(body).toEqual({ expected_pending_generation: 2 });
      capabilities = capabilities.map((client) => client.id === id
        ? {
          ...client,
          pending_activation: false,
          pending_generation: null,
          pending_client_name: null,
          pending_activation_expires_at: null,
        }
        : client);
      await route.fulfill({ json: { cancelled: true } });
      return;
    }
    capabilities = capabilities.map((client) => client.id === id
      ? { ...client, revoked: true, active: false, connected: false, source_open_available: false }
      : client);
    await route.fulfill({ json: { revoked: true } });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const pairing = surface.locator('.ide-pairing-panel');
  const clientList = pairing.getByRole('list', { name: 'Paired IDE clients', exact: true });
  await expect(clientList).toContainText('VS Code QA local');
  await expect(clientList).toContainText('Active · connected');
  await expect(clientList).toContainText('Latest generation 2 · active generation 1');
  await expect(clientList).toContainText('Generation 2 is waiting for durable activation for VS Code QA replacement');

  await pairing.getByRole('button', { name: 'Refresh IDE access', exact: true }).click();
  await expect(pairing.getByRole('status')).toContainText('IDE access refreshed. 0 pending approval. 1 active.');
  const pendingConfirmation = await acceptNextConfirmation(page, () => clientList.getByRole('button', { name: `Cancel pending setup for VS Code QA local in profile slot ${SETTINGS_IDE_SLOT}`, exact: true }).click());
  await expect(pairing.getByRole('status')).toContainText('Unfinished setup for VS Code QA replacement was cancelled. Any previously active generation remains authorized.');
  expect(pendingConfirmation.message).toBe(`Cancel unfinished generation 2 setup for "VS Code QA replacement" in profile slot "${SETTINGS_IDE_SLOT}"? This consumes only that exact pending setup and interrupts activation if VS Code is still completing it. Active generation 1 remains authorized.`);
  expect(mutations[0]).toEqual({
    id: capability.id,
    csrf: 'fixture-csrf-token',
    method: 'DELETE',
    body: { expected_pending_generation: 2 },
  });
  await expect(clientList).not.toContainText('waiting for durable activation');
  await expect(clientList).toContainText('Active · connected');

  const getsBeforeRevoke = capabilityGets;
  const confirmation = await acceptNextConfirmation(page, () => clientList.getByRole('button', { name: `Revoke and allow re-pair for VS Code QA local in profile slot ${SETTINGS_IDE_SLOT}`, exact: true }).click());
  await expect(pairing.getByRole('status')).toContainText('VS Code QA local was revoked and may now be paired again. The authoritative IDE client list was refreshed.');
  await expect(clientList).toContainText('Revoked · ready to re-pair');
  await expect(clientList.getByRole('button', { name: `Revoke and allow re-pair for VS Code QA local in profile slot ${SETTINGS_IDE_SLOT}`, exact: true })).toBeDisabled();
  expect(confirmation.message).toBe(`Revoke and allow re-pair for "VS Code QA local" in profile slot "${SETTINGS_IDE_SLOT}"? This revokes the retained capability, disconnects CodeSecurity in connected VS Code windows if any, cancels unfinished setup, and permits only this exact profile slot to establish a new generation. Current state: latest 2, retained active 1, pending none. Stored scans and findings remain.`);
  expect(mutations[1]).toEqual({
    id: capability.id,
    csrf: 'fixture-csrf-token',
    method: 'DELETE',
    body: {
      expected_latest_generation: 2,
      expected_active_generation: 1,
      expected_pending_generation: null,
    },
  });
  expect(capabilityGets).toBeGreaterThan(getsBeforeRevoke);
  guards.assertClean();
});

test('IDE authority: Settings reconciles exact pending-cancel and full-revoke generation conflicts without claiming stale success', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const baseCapability = {
    state: 'valid' as const,
    id: SETTINGS_IDE_SLOT,
    client_name: 'VS Code concurrent QA',
    scopes: ['event:read', 'source:open-ack'],
    created_at: '2026-08-29T09:00:00Z',
    expires_at: '2027-02-25T09:00:00Z',
    revoked: false,
    active: true,
    connected: true,
    active_generation: 1,
    latest_generation: 2,
    pending_activation: true,
    pending_generation: 2 as number | null,
    pending_client_name: 'VS Code pending generation 2' as string | null,
    pending_activation_expires_at: '2026-08-29T09:10:00Z' as string | null,
    source_open_available: true,
    source_open_disabled_reason: null,
    invalid_recovery_token: null,
  };
  let capabilities = [baseCapability];
  const mutations: Array<{ kind: 'pending' | 'full'; body: unknown }> = [];
  await page.route('**/v1/auth/ide/capabilities', async (route) => {
    await route.fulfill({ json: capabilities });
  });
  await page.route('**/v1/auth/ide/capabilities/**', async (route) => {
    const candidate = route.request();
    const pathname = new URL(candidate.url()).pathname;
    const segments = pathname.split('/');
    const pending = segments.at(-1) === 'pending';
    expect(candidate.method()).toBe('DELETE');
    expect(pathname).toBe(pending
      ? `/v1/auth/ide/capabilities/${SETTINGS_IDE_SLOT}/pending`
      : `/v1/auth/ide/capabilities/${SETTINGS_IDE_SLOT}`);
    mutations.push({ kind: pending ? 'pending' : 'full', body: candidate.postDataJSON() });
    if (pending) {
      capabilities = [{
        ...baseCapability,
        latest_generation: 3,
        pending_generation: 3,
        pending_client_name: 'VS Code concurrent generation 3',
      }];
      await route.fulfill({
        status: 409,
        json: {
          detail: {
            code: 'ide_pairing_pending_generation_conflict',
            message: 'The pending IDE authority changed before this cancellation request was applied.',
            action: 'refresh_paired_ide_clients',
          },
        },
      });
      return;
    }
    capabilities = [{
      ...baseCapability,
      client_name: 'VS Code concurrent generation 4',
      active_generation: 4,
      latest_generation: 4,
      pending_activation: false,
      pending_generation: null,
      pending_client_name: null,
      pending_activation_expires_at: null,
    }];
    await route.fulfill({
      status: 409,
      json: {
        detail: {
          code: 'ide_pairing_reset_generation_conflict',
          message: 'The IDE authority changed before this revocation request was applied.',
          action: 'refresh_paired_ide_clients',
        },
      },
    });
  });

  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const pairing = surface.locator('.ide-pairing-panel');
  const clientList = pairing.getByRole('list', { name: 'Paired IDE clients', exact: true });

  await acceptNextConfirmation(page, () => clientList.getByRole('button', { name: `Cancel pending setup for VS Code concurrent QA in profile slot ${SETTINGS_IDE_SLOT}`, exact: true }).click());
  await expect(pairing.getByRole('alert')).toContainText('The pending IDE authority changed before this cancellation request was applied. The authoritative IDE client list was refreshed; review the exact profile slot state before acting again.');
  await expect(clientList).toContainText('Latest generation 3 · active generation 1');
  await expect(clientList).toContainText('VS Code concurrent generation 3');
  await expect(pairing).not.toContainText('was cancelled');

  await acceptNextConfirmation(page, () => clientList.getByRole('button', { name: `Revoke and allow re-pair for VS Code concurrent QA in profile slot ${SETTINGS_IDE_SLOT}`, exact: true }).click());
  await expect(pairing.getByRole('alert')).toContainText('The IDE authority changed before this revocation request was applied. The authoritative IDE client list was refreshed; review the exact profile slot state before acting again.');
  await expect(clientList).toContainText('VS Code concurrent generation 4');
  await expect(clientList).toContainText('Latest generation 4 · active generation 4');
  await expect(pairing).not.toContainText('was revoked and may now be paired again');

  expect(mutations).toEqual([
    { kind: 'pending', body: { expected_pending_generation: 2 } },
    {
      kind: 'full',
      body: {
        expected_latest_generation: 3,
        expected_active_generation: 1,
        expected_pending_generation: 3,
      },
    },
  ]);
  assertOnlyExpectedConflictResponses(guards, new URL(baseURL).origin, [
    `/v1/auth/ide/capabilities/${SETTINGS_IDE_SLOT}/pending`,
    `/v1/auth/ide/capabilities/${SETTINGS_IDE_SLOT}`,
  ]);
});

test('IDE authority: Settings refreshes both valid-record actions into authoritative invalid rows without stale success', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const pendingClient = {
    state: 'valid',
    id: PENDING_RACE_IDE_SLOT,
    client_name: 'Ubuntu pending-race active',
    scopes: ['event:read'],
    created_at: '2026-08-29T13:00:00Z',
    expires_at: '2027-02-25T13:00:00Z',
    revoked: false,
    active: true,
    connected: false,
    active_generation: 1,
    latest_generation: 2,
    pending_activation: true,
    pending_generation: 2,
    pending_client_name: 'Ubuntu pending-race replacement',
    pending_activation_expires_at: '2026-08-29T13:10:00Z',
    source_open_available: false,
    source_open_disabled_reason: 'This IDE client is not currently connected to the CodeSecurity event stream.',
    invalid_recovery_token: null,
  };
  const resetClient = {
    state: 'valid',
    id: RESET_RACE_IDE_SLOT,
    client_name: 'Fedora reset-race profile',
    scopes: ['event:read'],
    created_at: '2026-08-29T13:01:00Z',
    expires_at: '2027-02-25T13:01:00Z',
    revoked: false,
    active: true,
    connected: false,
    active_generation: 4,
    latest_generation: 4,
    pending_activation: false,
    pending_generation: null,
    pending_client_name: null,
    pending_activation_expires_at: null,
    source_open_available: false,
    source_open_disabled_reason: 'This IDE client is not currently connected to the CodeSecurity event stream.',
    invalid_recovery_token: null,
  };
  const invalidClient = (id: string, recoveryToken: string) => ({
    state: 'invalid',
    id,
    client_name: 'Invalid IDE client record',
    scopes: [],
    created_at: null,
    revoked: false,
    active: false,
    connected: false,
    active_generation: null,
    latest_generation: null,
    pending_activation: false,
    pending_generation: null,
    pending_client_name: null,
    pending_activation_expires_at: null,
    source_open_available: false,
    source_open_disabled_reason: 'This IDE client record is invalid or not active.',
    invalid_recovery_token: recoveryToken,
  });
  const invalidPendingClient = invalidClient(PENDING_RACE_IDE_SLOT, INVALID_IDE_RECOVERY_TOKEN_C);
  const invalidResetClient = invalidClient(RESET_RACE_IDE_SLOT, INVALID_IDE_RECOVERY_TOKEN_D);
  let listing: 'valid' | 'pending-invalid' | 'both-invalid' = 'valid';
  const mutations: Array<{ id: string; kind: 'pending' | 'full'; body: unknown }> = [];
  await page.route('**/v1/auth/ide/capabilities', async (route) => {
    await route.fulfill({
      json: listing === 'valid'
        ? [pendingClient, resetClient]
        : listing === 'pending-invalid'
          ? [invalidPendingClient, resetClient]
          : [invalidPendingClient, invalidResetClient],
    });
  });
  await page.route('**/v1/auth/ide/capabilities/**', async (route) => {
    const candidate = route.request();
    const pathname = new URL(candidate.url()).pathname;
    const segments = pathname.split('/');
    const pending = segments.at(-1) === 'pending';
    const id = decodeURIComponent(segments.at(pending ? -2 : -1) || '');
    expect(candidate.method()).toBe('DELETE');
    expect(pathname).toBe(pending
      ? `/v1/auth/ide/capabilities/${PENDING_RACE_IDE_SLOT}/pending`
      : `/v1/auth/ide/capabilities/${RESET_RACE_IDE_SLOT}`);
    mutations.push({ id, kind: pending ? 'pending' : 'full', body: candidate.postDataJSON() });
    if (pending) {
      expect(id).toBe(PENDING_RACE_IDE_SLOT);
      listing = 'pending-invalid';
    } else {
      expect(id).toBe(RESET_RACE_IDE_SLOT);
      listing = 'both-invalid';
    }
    await route.fulfill({
      status: 409,
      json: {
        detail: {
          code: 'ide_pairing_slot_state_invalid',
          message: `The stored IDE client slot ${id} is invalid and cannot be changed safely.`,
          action: 'review_paired_ide_clients',
        },
      },
    });
  });

  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const pairing = surface.locator('.ide-pairing-panel');
  const clientList = pairing.getByRole('list', { name: 'Paired IDE clients', exact: true });

  await acceptNextConfirmation(page, () => clientList.getByRole('button', {
    name: `Cancel pending setup for Ubuntu pending-race active in profile slot ${PENDING_RACE_IDE_SLOT}`,
    exact: true,
  }).click());
  await expect(pairing.getByRole('alert')).toContainText(`The stored IDE client slot ${PENDING_RACE_IDE_SLOT} is invalid and cannot be changed safely. The authoritative IDE client list was refreshed; review the exact profile slot state before acting again.`);
  await expect(clientList.locator('.ide-client-invalid-row', { hasText: PENDING_RACE_IDE_SLOT })).toBeVisible();
  await expect(pairing).not.toContainText('Ubuntu pending-race replacement was cancelled');

  await acceptNextConfirmation(page, () => clientList.getByRole('button', {
    name: `Revoke and allow re-pair for Fedora reset-race profile in profile slot ${RESET_RACE_IDE_SLOT}`,
    exact: true,
  }).click());
  await expect(pairing.getByRole('alert')).toContainText(`The stored IDE client slot ${RESET_RACE_IDE_SLOT} is invalid and cannot be changed safely. The authoritative IDE client list was refreshed; review the exact profile slot state before acting again.`);
  await expect(clientList.locator('.ide-client-invalid-row', { hasText: PENDING_RACE_IDE_SLOT })).toBeVisible();
  await expect(clientList.locator('.ide-client-invalid-row', { hasText: RESET_RACE_IDE_SLOT })).toBeVisible();
  await expect(pairing).not.toContainText('Fedora reset-race profile was revoked');
  expect(mutations).toEqual([
    {
      id: PENDING_RACE_IDE_SLOT,
      kind: 'pending',
      body: { expected_pending_generation: 2 },
    },
    {
      id: RESET_RACE_IDE_SLOT,
      kind: 'full',
      body: {
        expected_latest_generation: 4,
        expected_active_generation: 4,
        expected_pending_generation: null,
      },
    },
  ]);
  assertOnlyExpectedConflictResponses(guards, new URL(baseURL).origin, [
    `/v1/auth/ide/capabilities/${PENDING_RACE_IDE_SLOT}/pending`,
    `/v1/auth/ide/capabilities/${RESET_RACE_IDE_SLOT}`,
  ]);
});

test('IDE authority: Settings removes one exact invalid IDE record and enables safe re-pairing', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const invalidCapability = {
    state: 'invalid',
    id: INVALID_IDE_SLOT,
    client_name: 'Invalid IDE client record',
    scopes: [],
    created_at: null,
    revoked: false,
    active: false,
    connected: false,
    active_generation: null,
    latest_generation: null,
    pending_activation: false,
    pending_generation: null,
    pending_client_name: null,
    pending_activation_expires_at: null,
    source_open_available: false,
    source_open_disabled_reason: 'This IDE client record is invalid or not active.',
    invalid_recovery_token: INVALID_IDE_RECOVERY_TOKEN_A,
  };
  const validCapability = {
    state: 'valid',
    id: SETTINGS_IDE_SLOT,
    client_name: 'Fedora retained profile',
    scopes: ['event:read'],
    created_at: '2026-08-29T11:00:00Z',
    expires_at: '2027-02-25T11:00:00Z',
    revoked: false,
    active: true,
    connected: false,
    active_generation: 1,
    latest_generation: 1,
    pending_activation: false,
    pending_generation: null,
    pending_client_name: null,
    pending_activation_expires_at: null,
    source_open_available: false,
    source_open_disabled_reason: 'This IDE client is not currently connected to the CodeSecurity event stream.',
    invalid_recovery_token: null,
  };
  let capabilities = [validCapability, invalidCapability];
  const recoveries: Array<{ method: string; csrf: string | undefined; body: unknown }> = [];
  await page.route('**/v1/auth/ide/capabilities', async (route) => {
    await route.fulfill({ json: capabilities });
  });
  await page.route(`**/v1/auth/ide/capabilities/${INVALID_IDE_SLOT}/invalid`, async (route) => {
    recoveries.push({
      method: route.request().method(),
      csrf: route.request().headers()['x-csrf-token'],
      body: route.request().postDataJSON(),
    });
    capabilities = [validCapability];
    await route.fulfill({ json: { recovered: true } });
  });

  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const pairing = surface.locator('.ide-pairing-panel');
  const clientList = pairing.getByRole('list', { name: 'Paired IDE clients', exact: true });
  const invalidRow = clientList.locator('.ide-client-invalid-row');
  await expect(invalidRow).toBeVisible();
  await expect(clientList.locator('.ide-client-row').first()).toHaveClass(/ide-client-invalid-row/u);
  await expect(invalidRow).toContainText('CodeSecurity cannot trust or use this record.');
  await expect(invalidRow).toContainText(INVALID_IDE_SLOT);
  await expect(pairing).not.toContainText(INVALID_IDE_RECOVERY_TOKEN_A);

  const confirmation = await acceptNextConfirmation(page, () => invalidRow.getByRole('button', {
    name: `Remove invalid IDE client record for profile slot ${INVALID_IDE_SLOT} and allow re-pair`,
    exact: true,
  }).click());
  await expect(pairing.getByRole('status')).toContainText(`Invalid IDE client record for profile slot ${INVALID_IDE_SLOT} was removed. That exact slot may now be paired again.`);
  await expect(clientList.locator('.ide-client-invalid-row')).toHaveCount(0);
  await expect(clientList).toContainText('Fedora retained profile');
  expect(confirmation.message).toBe(`Remove invalid IDE client record for profile slot "${INVALID_IDE_SLOT}"? CodeSecurity will delete only the exact invalid server record displayed here if it has not changed. This permits this profile slot to pair from generation 1 again. Stored scans and findings remain.`);
  expect(recoveries).toEqual([{
    method: 'DELETE',
    csrf: 'fixture-csrf-token',
    body: { recovery_token: INVALID_IDE_RECOVERY_TOKEN_A },
  }]);
  guards.assertClean();
});

test('IDE authority: Settings reconciles invalid-record recovery conflict and valid-record race without stale success', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  let listing: 'invalid-a' | 'invalid-b' | 'valid' = 'invalid-a';
  let recoveryAttempts = 0;
  const invalidCapability = (recoveryToken: string) => ({
    state: 'invalid',
    id: INVALID_IDE_SLOT,
    client_name: 'Invalid IDE client record',
    scopes: [],
    created_at: null,
    revoked: false,
    active: false,
    connected: false,
    active_generation: null,
    latest_generation: null,
    pending_activation: false,
    pending_generation: null,
    pending_client_name: null,
    pending_activation_expires_at: null,
    source_open_available: false,
    source_open_disabled_reason: 'This IDE client record is invalid or not active.',
    invalid_recovery_token: recoveryToken,
  });
  const validCapability = {
    state: 'valid',
    id: INVALID_IDE_SLOT,
    client_name: 'VS Code recovered concurrently',
    scopes: ['event:read', 'source:open-ack'],
    created_at: '2026-08-29T12:00:00Z',
    expires_at: '2027-02-25T12:00:00Z',
    revoked: false,
    active: true,
    connected: false,
    active_generation: 1,
    latest_generation: 1,
    pending_activation: false,
    pending_generation: null,
    pending_client_name: null,
    pending_activation_expires_at: null,
    source_open_available: false,
    source_open_disabled_reason: 'This IDE client is not currently connected to the CodeSecurity event stream.',
    invalid_recovery_token: null,
  };
  await page.route('**/v1/auth/ide/capabilities', async (route) => {
    await route.fulfill({
      json: [listing === 'valid'
        ? validCapability
        : invalidCapability(listing === 'invalid-a' ? INVALID_IDE_RECOVERY_TOKEN_A : INVALID_IDE_RECOVERY_TOKEN_B)],
    });
  });
  await page.route(`**/v1/auth/ide/capabilities/${INVALID_IDE_SLOT}/invalid`, async (route) => {
    expect(route.request().method()).toBe('DELETE');
    expect(new URL(route.request().url()).pathname).toBe(`/v1/auth/ide/capabilities/${INVALID_IDE_SLOT}/invalid`);
    recoveryAttempts += 1;
    if (recoveryAttempts === 1) {
      expect(route.request().postDataJSON()).toEqual({ recovery_token: INVALID_IDE_RECOVERY_TOKEN_A });
      listing = 'invalid-b';
      await route.fulfill({
        status: 409,
        json: {
          detail: {
            code: 'ide_pairing_invalid_recovery_conflict',
            message: 'The invalid IDE client slot changed before this recovery request was applied.',
            action: 'refresh_paired_ide_clients',
          },
        },
      });
      return;
    }
    expect(route.request().postDataJSON()).toEqual({ recovery_token: INVALID_IDE_RECOVERY_TOKEN_B });
    listing = 'valid';
    await route.fulfill({
      status: 409,
      json: {
        detail: {
          code: 'ide_pairing_invalid_recovery_not_required',
          message: 'This IDE client slot is valid and cannot be removed by invalid-state recovery.',
          action: 'refresh_paired_ide_clients',
        },
      },
    });
  });

  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const pairing = surface.locator('.ide-pairing-panel');
  const clientList = pairing.getByRole('list', { name: 'Paired IDE clients', exact: true });
  const recoveryButton = () => clientList.getByRole('button', {
    name: `Remove invalid IDE client record for profile slot ${INVALID_IDE_SLOT} and allow re-pair`,
    exact: true,
  });

  await acceptNextConfirmation(page, () => recoveryButton().click());
  await expect(pairing.getByRole('alert')).toContainText('The invalid IDE client slot changed before this recovery request was applied. The authoritative IDE client list was refreshed; review the exact profile slot state before acting again.');
  await expect(recoveryButton()).toBeVisible();
  await expect(pairing).not.toContainText('was removed. That exact slot may now be paired again.');
  await expect(pairing).not.toContainText(INVALID_IDE_RECOVERY_TOKEN_B);

  await acceptNextConfirmation(page, () => recoveryButton().click());
  await expect(pairing.getByRole('alert')).toContainText('This IDE client slot is valid and cannot be removed by invalid-state recovery. The authoritative IDE client list was refreshed; review the exact profile slot state before acting again.');
  await expect(clientList).toContainText('VS Code recovered concurrently');
  await expect(clientList.locator('.ide-client-invalid-row')).toHaveCount(0);
  await expect(pairing).not.toContainText('was removed. That exact slot may now be paired again.');
  expect(recoveryAttempts).toBe(2);
  assertOnlyExpectedConflictResponses(guards, new URL(baseURL).origin, [
    `/v1/auth/ide/capabilities/${INVALID_IDE_SLOT}/invalid`,
    `/v1/auth/ide/capabilities/${INVALID_IDE_SLOT}/invalid`,
  ]);
});

test('Settings signs out only this browser and returns to explicit recovery', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const logoutRequests: Array<{ csrf: string | undefined; method: string }> = [];
  await page.route('**/v1/auth/logout', async (route) => {
    const candidate = route.request();
    logoutRequests.push({ csrf: candidate.headers()['x-csrf-token'], method: candidate.method() });
    await route.fulfill({ json: { authenticated: false } });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const confirmation = await acceptNextConfirmation(page, () => surface.getByRole('button', { name: 'Sign out this browser', exact: true }).click());
  await expect(page.getByRole('heading', { level: 1, name: 'Pair this browser', exact: true })).toBeVisible();
  await expect(page.locator('.auth-help')).toContainText('make auth-reset, then make up and make auth-info');
  expect(confirmation.message).toBe('Sign out this browser? This durably revokes only this browser session. Paired IDE clients remain authorized until you explicitly revoke them.');
  expect(logoutRequests).toEqual([{ csrf: 'fixture-csrf-token', method: 'POST' }]);
  guards.assertClean();
});

test('atomic scoped Settings save preserves newer remote scopes and local unsaved drafts', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const advisor = surface.locator('.band').filter({ has: page.locator('form[data-settings-form="advisor"]') });
  await expect(advisor.getByRole('heading', { name: 'Advisor Policy More information', exact: true })).toBeVisible();
  const gate = surface.locator('.gate-policy-panel');
  const components = surface.locator('.band').filter({ has: page.locator('form[data-settings-form="components"]') });
  await expect(components.getByRole('heading', { name: 'Components More information', exact: true })).toBeVisible();

  // This tab has an unsaved gate draft while another API client advances the
  // persisted component scope after the tab's initial GET. The advisor PATCH
  // must carry no stale gate or component values.
  await gate.getByRole('button', { name: /^Observe/u }).click();
  await advisor.getByRole('combobox', { name: 'Mode', exact: true }).selectOption('off');
  await advisor.getByLabel('Auto Triage Limit', { exact: true }).fill('11');
  const beforeRemoteSave = await request.get('/v1/config').then((response) => response.json()) as RuntimeSettingsSnapshot;
  const remoteResponse = await request.put('/v1/config', {
    data: runtimeSettingsUpdate(beforeRemoteSave, {
      component_git_proxy_enabled: true,
      component_db_admin_enabled: true,
    }),
  });
  expect(remoteResponse.ok()).toBe(true);

  const configRequests: string[] = [];
  page.on('request', (candidate) => {
    const pathname = new URL(candidate.url()).pathname;
    if (pathname.startsWith('/v1/config')) configRequests.push(`${candidate.method()} ${pathname}`);
  });
  const advisorPatch = page.waitForRequest((candidate) => candidate.method() === 'PATCH' && new URL(candidate.url()).pathname === '/v1/config/advisor');
  await advisor.getByRole('button', { name: 'Save Advisor Policy', exact: true }).click();
  const submitted = (await advisorPatch).postDataJSON() as Record<string, unknown>;

  expect(configRequests).toEqual(['PATCH /v1/config/advisor']);
  expect(submitted).toEqual({
    ai_mode: 'off',
    ollama_base_url: beforeRemoteSave.ollama_base_url,
    ollama_model: beforeRemoteSave.ollama_model,
    ollama_thinking: beforeRemoteSave.ollama_thinking,
    auto_triage_limit: 11,
  });
  await expect(advisor.getByRole('status')).toContainText('Advisor policy saved');
  const persisted = await request.get('/v1/config').then((response) => response.json()) as RuntimeSettingsSnapshot;
  expect(persisted).toMatchObject({
    ai_mode: 'off',
    ollama_model: beforeRemoteSave.ollama_model,
    auto_triage_limit: 11,
    component_git_proxy_enabled: true,
    component_db_admin_enabled: true,
    gate_preset: 'custom',
  });
  await expect(gate.getByRole('button', { name: /^Observe/u })).toHaveClass(/active/u);
  await expect(components.getByLabel('Git proxy: Gitea', { exact: true })).toBeChecked();
  await expect(components.getByLabel('Database UI: Adminer', { exact: true })).toBeChecked();
  guards.assertClean();
});

test('source setup accepts only a bounded fragment prefill and performs no authorization', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'auth-required', generation: 1 } });
  const origin = new URL(baseURL).origin;
  const guards = await installRuntimeGuards(page, origin);
  const mutations = mutationRequestLog(page);
  const suggestedPath = '/private/generated/editor suggestion/Žluťoučký';
  const encodedPath = Buffer.from(suggestedPath, 'utf8').toString('base64url');
  const fragmentToken = 'valid-bootstrap';
  const invitationFragment = new URLSearchParams({ bootstrap: fragmentToken, destination: `source=${encodedPath}` });
  const expectedSetupUrl = `${origin}/?view=projects&setup=source#source=${encodedPath}`;
  let releaseBootstrap = () => {};
  let markBootstrapSeen = () => {};
  const bootstrapReleased = new Promise<void>((resolve) => { releaseBootstrap = resolve; });
  const bootstrapSeen = new Promise<void>((resolve) => { markBootstrapSeen = resolve; });
  await page.route(`${origin}/v1/auth/bootstrap`, async (route) => {
    expect(route.request().method()).toBe('POST');
    expect(route.request().postDataJSON()).toEqual({ bootstrap_token: fragmentToken });
    markBootstrapSeen();
    await bootstrapReleased;
    await route.fallback();
  }, { times: 1 });

  // Exercise the real AuthGate before Workbench mounts, using the fixture's
  // successful bootstrap endpoint and the IDE's existing invitation envelope.
  try {
    await page.goto(`/?view=projects&setup=source#${invitationFragment}`);
    await bootstrapSeen;
    await expect(page).toHaveURL(expectedSetupUrl);
    await expect(page.getByRole('heading', { level: 1, name: 'Connecting this browser', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { level: 1, name: 'Projects', exact: true })).toHaveCount(0);
    expect(new URL(page.url()).searchParams.has('source')).toBe(false);
    expect(mutations).toEqual(['POST /v1/auth/bootstrap']);
  } finally {
    releaseBootstrap();
  }
  await expect(page.getByRole('heading', { level: 1, name: 'Projects', exact: true })).toBeVisible();
  await expect(page.locator('.project-registration')).toHaveAttribute('open', '');
  await expect(page.getByLabel('Exact source root')).toBeVisible();
  await expect(page.getByLabel('Exact source root')).toHaveValue(suggestedPath);
  await expect(page.getByRole('status').filter({ hasText: 'Suggested source path received from the editor.' })).toContainText('no source was authorized automatically');
  await expect(page).toHaveURL(expectedSetupUrl);
  await expect(page.locator('section[data-route-surface="projects"]')).not.toHaveAttribute('aria-busy', 'true');
  await page.waitForLoadState('networkidle');
  expect(await request.get('/__test/auth-state').then((response) => response.json())).toEqual({
    authenticated: true, bootstrap_attempts: [fragmentToken],
  });
  expect(await page.evaluate(() => JSON.stringify({ local: Object.entries(localStorage), session: Object.entries(sessionStorage) }))).not.toContain(fragmentToken);
  await expect(page.locator('body')).not.toContainText(fragmentToken);
  expect(mutations).toEqual(['POST /v1/auth/bootstrap']);
  guards.assertClean();

  await page.goto(`/?view=projects&setup=source#source=${encodedPath}`);
  await expect(page.getByRole('heading', { level: 1, name: 'Projects', exact: true })).toBeVisible();
  await expect(page.getByLabel('Exact source root')).toHaveValue(suggestedPath);
  await expect(page.getByRole('status').filter({ hasText: 'Suggested source path received from the editor.' })).toContainText('no source was authorized automatically');
  expect(mutations).toEqual(['POST /v1/auth/bootstrap']);
  guards.assertClean();

  const queryPage = await page.context().newPage();
  const queryGuards = await installRuntimeGuards(queryPage, new URL(baseURL).origin);
  await queryPage.goto(`/?view=projects&setup=source&source=${encodedPath}`);
  await expect(queryPage.getByLabel('Exact source root')).toHaveValue('');
  queryGuards.assertClean();
  await queryPage.close();
  const controlPath = Buffer.from('/private/generated/unsafe\u0000path', 'utf8').toString('base64url');
  const controlPage = await page.context().newPage();
  const controlGuards = await installRuntimeGuards(controlPage, new URL(baseURL).origin);
  await controlPage.goto(`/?view=projects&setup=source#source=${controlPath}`);
  await expect(controlPage.getByLabel('Exact source root')).toHaveValue('');
  controlGuards.assertClean();
  await controlPage.close();
  expect(mutations).toEqual(['POST /v1/auth/bootstrap']);
});

test('local Ollama autodetection lists exact catalog evidence and makes one pinned local provider ready in one action', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'advisor-local-empty', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const panel = surface.locator('#advisor-providers');

  await expect(panel).toContainText('No Advisor providers configured.');
  const useLocal = panel.getByRole('button', { name: 'Use qwen3:8b locally', exact: true });
  const modelDetails = panel.locator('details.advisor-local-catalog');
  await expect(useLocal).toBeVisible();
  await expect(modelDetails).not.toHaveAttribute('open', '');
  await expect(modelDetails.locator('summary')).toHaveText('Detected model details · 1 local · 6 cloud-only');
  const hierarchy = await Promise.all([useLocal, modelDetails].map((locator) => locator.evaluate((element) => element.getBoundingClientRect().top)));
  expect(hierarchy[0], 'the primary local action precedes technical model inventory').toBeLessThan(hierarchy[1]);
  await modelDetails.locator('summary').click();
  const catalog = panel.getByRole('list', { name: 'Detected local Ollama model details' });
  await expect(catalog.getByRole('listitem')).toHaveCount(7);
  await expect(catalog).toContainText('qwen3:8b');
  await expect(catalog).toContainText('local weights');
  await expect(catalog).toContainText('5.2 GB');
  for (const cloudModel of [
    'minimax-m3:cloud',
    'kimi-k3:cloud',
    'glm-5.2:cloud',
    'kimi-k2.7-code:cloud',
    'kimi-k2.6:cloud',
    'glm-5.1:cloud',
  ]) await expect(catalog).toContainText(cloudModel);
  await expect(catalog.getByText('cloud-only', { exact: true })).toHaveCount(6);
  await expect(catalog).toContainText('301 B · 301 bytes metadata only · no local weights');
  await expect(catalog.getByRole('code').filter({ hasText: 'qwen3:8b full SHA-256 digest' }))
    .toHaveText(`qwen3:8b full SHA-256 digest ${'e'.repeat(64)}`);
  await expect(panel.getByLabel('Local model to pin')).toHaveValue('qwen3:8b');
  await expect(panel.getByLabel('Local model to pin').locator('option')).toHaveCount(1);

  const createRequest = page.waitForRequest((candidate) => candidate.method() === 'POST' && new URL(candidate.url()).pathname === '/v1/advisor/providers');
  const activateRequest = page.waitForRequest((candidate) => (
    candidate.method() === 'POST'
    && new URL(candidate.url()).pathname === '/v1/advisor/providers/local-ollama/commands'
  ));
  await useLocal.click();
  expect((await createRequest).postDataJSON()).toMatchObject({
    expected_revision: 1,
    provider: {
      id: 'local-ollama',
      name: 'Local Ollama',
      transport: 'local',
      priority: 0,
      enabled: true,
      base_url: null,
      model: 'qwen3:8b',
      model_digest: 'e'.repeat(64),
      ssh_host: null,
      ssh_port: null,
      ssh_user: null,
    },
  });
  expect((await activateRequest).postDataJSON()).toEqual({
    expected_revision: 2,
    action: 'activate',
    acknowledge_source_disclosure: false,
    source_disclosure_approval: null,
  });
  const local = panel.locator('.advisor-provider-card', { hasText: 'Local Ollama' });
  await expect(local).toContainText('qwen3:8b');
  await expect(local).toContainText('e'.repeat(64));
  await expect(panel.getByRole('button', { name: 'Detect local Ollama', exact: true })).toBeVisible();
  await expect(local.locator('.advisor-provider-operation')).toContainText('Provider activated');
  await expect(panel.getByRole('button', { name: 'qwen3:8b ready locally', exact: true })).toBeDisabled();
  await expect(local.getByRole('button', { name: 'Test connection', exact: true })).toHaveCount(0);
  await expect(local.getByRole('button', { name: 'Activate', exact: true })).toHaveCount(0);
  const providers = await request.get('/v1/advisor/providers').then((response) => response.json()) as {
    active_provider_id: string | null;
    providers: Array<{ id: string; model: string; model_digest: string; status: string }>;
  };
  expect(providers.active_provider_id).toBe('local-ollama');
  expect(providers.providers).toContainEqual(expect.objectContaining({
    id: 'local-ollama',
    model: 'qwen3:8b',
    model_digest: 'e'.repeat(64),
    status: 'active',
  }));
  guards.assertClean();
});

test('local Ollama autodetection reconciles the existing local provider without replacing its identity', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const panel = surface.locator('#advisor-providers');
  const catalog = panel.locator('details.advisor-local-catalog');

  await expect(catalog).not.toHaveAttribute('open', '');
  await expect(panel.getByRole('button', { name: 'Use qwen3:8b locally', exact: true })).toBeVisible();
  const updateRequest = page.waitForRequest((candidate) => (
    candidate.method() === 'PUT'
    && new URL(candidate.url()).pathname === '/v1/advisor/providers/local-default'
  ));
  const activateRequest = page.waitForRequest((candidate) => (
    candidate.method() === 'POST'
    && new URL(candidate.url()).pathname === '/v1/advisor/providers/local-default/commands'
  ));
  await panel.getByRole('button', { name: 'Use qwen3:8b locally', exact: true }).click();
  expect((await updateRequest).postDataJSON()).toMatchObject({
    expected_revision: 1,
    provider: {
      id: 'local-default',
      name: 'Local Ollama',
      transport: 'local',
      priority: 0,
      enabled: true,
      base_url: null,
      model: 'qwen3:8b',
      model_digest: 'e'.repeat(64),
      ssh_host: null,
      ssh_port: null,
      ssh_user: null,
    },
  });
  expect((await activateRequest).postDataJSON()).toEqual({
    expected_revision: 2,
    action: 'activate',
    acknowledge_source_disclosure: false,
    source_disclosure_approval: null,
  });
  const local = panel.locator('.advisor-provider-card', { hasText: 'Local Ollama' });
  await expect(local).toContainText('qwen3:8b');
  await expect(local.locator('.advisor-provider-operation')).toContainText('Provider activated');
  await expect(panel.getByRole('button', { name: 'qwen3:8b ready locally', exact: true })).toBeDisabled();
  await expect(catalog).not.toHaveAttribute('open', '');
  const catalogSummary = catalog.locator('summary');
  await expect(catalogSummary).toHaveText('Detected model details · 1 local · 6 cloud-only');
  await catalogSummary.click();
  await expect(catalog).toHaveAttribute('open', '');
  await expect(catalog.getByRole('listitem')).toHaveCount(7);

  const providers = await request.get('/v1/advisor/providers').then((response) => response.json()) as {
    active_provider_id: string | null;
    providers: Array<{ id: string; model: string; model_digest: string }>;
  };
  expect(providers.active_provider_id).toBe('local-default');
  expect(providers.providers).toContainEqual(expect.objectContaining({
    id: 'local-default',
    model: 'qwen3:8b',
    model_digest: 'e'.repeat(64),
  }));
  guards.assertClean();
});

test('an inactive secondary manual local profile keeps an explicit disclosure-free Use locally action', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const initial = await request.get('/v1/advisor/providers').then((response) => response.json()) as { revision: number };
  const created = await request.post('/v1/advisor/providers', { data: {
    expected_revision: initial.revision,
    provider: {
      id: 'manual-local', name: 'Manual local', transport: 'local', priority: 1, enabled: true,
      base_url: null, model: 'manual:8b', model_digest: '7'.repeat(64),
      ssh_host: null, ssh_port: null, ssh_user: null,
    },
  } });
  expect(created.ok()).toBe(true);
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const panel = surface.locator('#advisor-providers');
  const primary = panel.locator('.advisor-provider-card', { hasText: 'Local Ollama' });
  const secondary = panel.locator('.advisor-provider-card', { hasText: 'Manual local' });
  await expect(primary).toBeVisible();
  await expect(secondary).toBeVisible();
  const commandRequest = page.waitForRequest((candidate) => (
    candidate.method() === 'POST'
    && new URL(candidate.url()).pathname === '/v1/advisor/providers/manual-local/commands'
  ));
  await secondary.getByRole('group', { name: 'Manual local provider actions' })
    .getByRole('button', { name: 'Use locally', exact: true }).click();
  expect((await commandRequest).postDataJSON()).toMatchObject({
    action: 'activate',
    acknowledge_source_disclosure: false,
    source_disclosure_approval: null,
  });
  await expect(secondary.getByText('resolved', { exact: true })).toBeVisible();
  const providers = await request.get('/v1/advisor/providers').then((response) => response.json()) as { active_provider_id: string | null };
  expect(providers.active_provider_id).toBe('manual-local');
  guards.assertClean();
});

test('lost local-provider create response reconciles exact authority and never repeats the mutation', async ({ page, request }) => {
  await request.post('/__test/reset', { data: { profile: 'advisor-local-empty', generation: 1 } });
  let createCount = 0;
  await page.route('**/v1/advisor/providers', async (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    createCount += 1;
    const persisted = await route.fetch();
    expect(persisted.ok()).toBe(true);
    await route.abort('failed');
  });
  const surface = await openRoute(page, 'Settings');
  const panel = surface.locator('#advisor-providers');
  await panel.getByRole('button', { name: 'Use qwen3:8b locally', exact: true }).click();
  await expect(panel.locator('.advisor-provider-operation')).toContainText('Provider activated');
  await expect(panel.getByRole('button', { name: 'qwen3:8b ready locally', exact: true })).toBeDisabled();
  expect(createCount).toBe(1);
});

test('lost local activation response reuses one command identity and reattaches to one durable job', async ({ page, request }) => {
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  let commandAttempts = 0;
  await page.route('**/v1/advisor/providers/local-default/commands', async (route) => {
    commandAttempts += 1;
    if (commandAttempts !== 1) return route.continue();
    const persisted = await route.fetch();
    expect(persisted.ok()).toBe(true);
    await route.abort('failed');
  });
  const surface = await openRoute(page, 'Settings');
  const panel = surface.locator('#advisor-providers');
  await panel.getByRole('button', { name: 'Use qwen3:8b locally', exact: true }).click();
  await expect(panel.locator('.advisor-provider-operation')).toContainText('Provider activated');
  await expect(panel.getByRole('button', { name: 'qwen3:8b ready locally', exact: true })).toBeDisabled();
  expect(commandAttempts).toBe(2);
  const commands = await request.get('/__test/commands').then((response) => response.json()) as Array<{
    route: string;
    idempotency_key: string;
  }>;
  const activationCommands = commands.filter((command) => command.route === 'advisor-provider-activate');
  expect(activationCommands).toHaveLength(2);
  expect(new Set(activationCommands.map((command) => command.idempotency_key)).size).toBe(1);
  const jobs = await request.get('/v1/jobs').then((response) => response.json()) as Array<{
    kind: string;
    provider_id?: string;
  }>;
  expect(jobs.filter((job) => job.kind === 'advisor_provider' && job.provider_id === 'local-default')).toHaveLength(1);
});

test('duplicate exact local-provider update conflict reconciles authority before activation', async ({ page, request }) => {
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  let updateCount = 0;
  await page.route('**/v1/advisor/providers/local-default', async (route) => {
    if (route.request().method() !== 'PUT') return route.continue();
    updateCount += 1;
    const persisted = await route.fetch();
    expect(persisted.ok()).toBe(true);
    await route.fulfill({
      status: 409,
      contentType: 'application/json',
      body: JSON.stringify({ detail: {
        code: 'revision_conflict',
        message: 'Provider revision changed after the exact update was accepted.',
        action: 'refresh_advisor_providers',
        context: {},
      } }),
    });
  });
  const surface = await openRoute(page, 'Settings');
  const panel = surface.locator('#advisor-providers');
  await panel.getByRole('button', { name: 'Use qwen3:8b locally', exact: true }).click();
  await expect(panel.locator('.advisor-provider-operation')).toContainText('Provider activated');
  await expect(panel.getByRole('button', { name: 'qwen3:8b ready locally', exact: true })).toBeDisabled();
  expect(updateCount).toBe(1);
});

test('local one-step setup reports failed retry and stalled cancellation truthfully', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  let collection = await request.get('/v1/advisor/providers').then((response) => response.json()) as {
    revision: number;
    providers: Array<Record<string, unknown>>;
  };
  const local = collection.providers.find((provider) => provider.id === 'local-default');
  if (!local) throw new Error('Local fixture provider is required.');
  expect((await request.put('/v1/advisor/providers/local-default', { data: {
    expected_revision: collection.revision,
    provider: { ...advisorProviderWriteInput(local), name: 'Failing Local' },
  } })).ok()).toBe(true);
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let surface = await openRoute(page, 'Settings');
  let panel = surface.locator('#advisor-providers');
  const activationResponse = page.waitForResponse((response) => response.request().method() === 'POST'
    && response.url() === new URL('/v1/advisor/providers/local-default/commands', baseURL).href);
  await panel.getByRole('button', { name: 'Use qwen3:8b locally', exact: true }).click();
  const activatedResponse = await activationResponse;
  expect(activatedResponse.status()).toBe(202);
  const admittedJob = await activatedResponse.json() as { id: number };
  await expect(panel.locator('.advisor-provider-failure')).toContainText('Connection refused');
  await expect(panel).not.toContainText('fixture-secret');
  const failedJob = await request.get(`/v1/jobs/${admittedJob.id}`).then((response) => response.json()) as {
    id: number; revision: number; provider_id: string; provider_config_revision: number; provider_config_digest: string;
  };
  const retryResponse = page.waitForResponse((response) => response.request().method() === 'POST'
    && response.url() === new URL(`/v1/jobs/${failedJob.id}/retry`, baseURL).href);
  await panel.getByRole('button', { name: 'Retry original snapshot', exact: true }).click();
  const retriedResponse = await retryResponse;
  expect(retriedResponse.status()).toBe(200);
  expect(retriedResponse.request().postDataJSON()).toEqual({ expected_revision: failedJob.revision });
  expect(await retriedResponse.json()).toMatchObject({
    id: failedJob.id, status: 'queued', revision: failedJob.revision + 1,
    provider_id: failedJob.provider_id,
    provider_config_revision: failedJob.provider_config_revision,
    provider_config_digest: failedJob.provider_config_digest,
  });
  await expect(panel.getByRole('button', { name: 'qwen3:8b ready locally', exact: true })).toBeDisabled();
  await expect(panel.locator('.advisor-provider-operation')).toContainText('Provider activated');
  await expect(panel).toContainText('Activation completed.');
  expect(await request.get(`/v1/jobs/${failedJob.id}`).then((response) => response.json())).toMatchObject({
    id: failedJob.id, status: 'completed', revision: failedJob.revision + 2,
    provider_id: failedJob.provider_id,
    provider_config_revision: failedJob.provider_config_revision,
    provider_config_digest: failedJob.provider_config_digest,
  });

  collection = await request.get('/v1/advisor/providers').then((response) => response.json()) as typeof collection;
  const retried = collection.providers.find((provider) => provider.id === 'local-default');
  if (!retried) throw new Error('Retried local fixture provider is required.');
  expect((await request.put('/v1/advisor/providers/local-default', { data: {
    expected_revision: collection.revision,
    provider: { ...advisorProviderWriteInput(retried), name: 'Stalled Local', model: 'old:stalled', model_digest: '8'.repeat(64) },
  } })).ok()).toBe(true);
  const stalledSettingsUrl = page.url();
  expect(new URL(stalledSettingsUrl).searchParams.get('view')).toBe('settings');
  await page.reload();
  await expect(page).toHaveURL(stalledSettingsUrl);
  await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
  surface = page.locator('section[data-route-surface="settings"]');
  panel = surface.locator('#advisor-providers');
  await panel.getByRole('button', { name: 'Use qwen3:8b locally', exact: true }).click();
  await expect(panel.locator('.advisor-provider-stalled')).toContainText('No worker heartbeat for 45 seconds');
  await panel.getByRole('button', { name: 'Cancel operation', exact: true }).click();
  await expect(panel.locator('.advisor-provider-operation')).toContainText('Activation cancelled');
  await expect(panel).toContainText('Cancellation confirmed; connector temporary state was cleaned.');
  await expect(panel.getByRole('button', { name: 'Use qwen3:8b locally', exact: true })).toBeEnabled();
  guards.assertClean();
});

test('hard reload waits for held API reads without aborting their evidence', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Settings');
  await guards.waitForApiIdle();
  guards.assertClean();

  let releaseHeld!: () => void;
  let observeHeld!: () => void;
  const held = new Promise<void>((resolve) => { releaseHeld = resolve; });
  const observed = new Promise<void>((resolve) => { observeHeld = resolve; });
  const order: string[] = [];
  let heldRequest: Request | undefined;
  page.on('requestfinished', (completed) => {
    if (completed === heldRequest) order.push('read-finished');
  });
  await page.route(new URL('/v1/config', baseURL).href, async (route) => {
    heldRequest = route.request();
    observeHeld();
    await held;
    await route.continue();
  }, { times: 1 });
  const read = page.evaluate(async () => {
    const response = await fetch('/v1/config');
    await response.arrayBuffer();
    return response.ok;
  });
  await observed;
  let reloadStarted = false;
  const reload = (async () => {
    await guards.waitForApiIdle();
    guards.assertClean();
    reloadStarted = true;
    order.push('reload-started');
    await page.reload();
  })();
  void reload.catch(() => undefined);
  try {
    // A browser round trip lets an incorrectly immediate fence run while the
    // real API read remains deliberately held; no elapsed-time sleep is needed.
    await page.evaluate(() => true);
    expect(reloadStarted).toBe(false);
    releaseHeld();
    expect(await read).toBe(true);
    await reload;
    expect(order).toEqual(['read-finished', 'reload-started']);
    await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
    await guards.waitForApiIdle();
    guards.assertClean();
  } finally {
    releaseHeld();
    await Promise.allSettled([read, reload]);
  }
});

test('Advisor terminal reconciliation preserves an in-flight post-command refresh', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const collection = await request.get('/v1/advisor/providers').then((response) => response.json()) as { revision: number };
  const added = await request.post('/v1/advisor/providers', { data: {
    expected_revision: collection.revision,
    provider: { id: 'owned-slow-direct', name: 'Owned slow Direct', transport: 'direct', priority: 1, enabled: true,
      base_url: 'http://192.0.2.44:11434', model: 'fixture-advisor-model:latest', model_digest: 'b'.repeat(64),
      ssh_host: null, ssh_port: null, ssh_user: null },
  } });
  expect(added.ok()).toBe(true);
  expect((await request.post('/__test/advisor-provider-authorize', { data: { provider_id: 'owned-slow-direct' } })).ok()).toBe(true);
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await openRoute(page, 'Settings');
  await guards.waitForApiIdle();
  guards.assertClean();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let heldRequest: Request | undefined;
  let heldFailed = false;
  let heldFinished = false;
  let commandPosted = false;
  const healthUrl = new URL('/healthz', baseURL).href;
  const healthReads: Request[] = [];
  const finishedReads = new Set<Request>();
  const order: string[] = [];
  page.on('request', (candidate) => {
    if (candidate.method() === 'POST' && new URL(candidate.url()).pathname === '/v1/advisor/providers/owned-slow-direct/commands') commandPosted = true;
    if (commandPosted && candidate.method() === 'GET' && candidate.url() === healthUrl) {
      healthReads.push(candidate);
      order.push(`read-${healthReads.length}`);
    }
  });
  page.on('requestfailed', (candidate) => { if (candidate === heldRequest) heldFailed = true; });
  page.on('requestfinished', (candidate) => {
    finishedReads.add(candidate);
    if (candidate === heldRequest) { heldFinished = true; order.push('held-finished'); }
  });
  const holdHealth = async (route: Route) => {
    if (!commandPosted || heldRequest) return route.fallback();
    heldRequest = route.request();
    await gate;
    await route.fallback();
  };
  await page.route(healthUrl, holdHealth);
  const card = page.locator('#advisor-providers .advisor-provider-card', { hasText: 'Owned slow Direct' });
  try {
    await card.getByRole('button', { name: 'Test connection', exact: true }).click();
    await expect.poll(() => Boolean(heldRequest), { message: 'post-command refresh reached its held read' }).toBe(true);
    expect(commandPosted).toBe(true);
    // The provider's terminal poll can finish while the first dashboard read
    // is held. Its reconciliation must queue behind that read, not cancel it.
    await expect(card.getByText('available', { exact: true })).toBeVisible();
    expect(heldFailed, 'terminal provider reconciliation must retain the current read owner').toBe(false);
    expect(heldFinished).toBe(false);
    release();
    await guards.waitForApiIdle();
    expect(heldFinished).toBe(true);
    expect(healthReads.length).toBeGreaterThanOrEqual(2);
    expect(finishedReads.has(healthReads[1])).toBe(true);
    expect(order.indexOf('read-2')).toBeGreaterThan(order.indexOf('held-finished'));
    guards.assertClean();
  } finally {
    release();
    await page.unroute(healthUrl, holdHealth);
  }
});

test('Advisor provider cards complete local, direct, and SSH action journeys without exposing credentials', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await page.addInitScript(() => {
    const state = window as Window & { __advisorAuthorizationCommand?: string; __advisorClipboardFails?: boolean };
    state.__advisorAuthorizationCommand = undefined;
    state.__advisorClipboardFails = false;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value: string) => {
          if (state.__advisorClipboardFails) throw new Error('Generated clipboard denial');
          state.__advisorAuthorizationCommand = value;
        },
      },
    });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const panel = surface.locator('#advisor-providers');
  const local = panel.locator('.advisor-provider-card', { hasText: 'Local Ollama' });
  const localActions = local.getByRole('group', { name: 'Local Ollama provider actions' });

  await expect(panel.getByRole('list', { name: 'Ordered Advisor providers' })).toBeVisible();
  await expect(local).toContainText('Local · this device');
  await expect(local).toContainText('This device · auto-detect');
  await expect(local).toContainText('a'.repeat(64));
  await expect(localActions.getByRole('button', { name: 'Disable', exact: true })).toBeDisabled();

  const addProvider = panel.getByRole('button', { name: 'Add provider', exact: true });
  await addProvider.click();
  await expect(panel.locator('.advisor-provider-form')).toBeVisible();
  await panel.getByRole('button', { name: 'Cancel edit', exact: true }).click();
  await expect(panel.locator('.advisor-provider-form')).toHaveCount(0);
  await expect(panel.locator('.advisor-provider-card')).toHaveCount(1);

  await addProvider.click();
  let form = panel.locator('.advisor-provider-form');
  await form.getByLabel('Name', { exact: true }).fill('Invalid Direct');
  await form.locator('select').first().selectOption('direct');
  await form.getByLabel('Exact model', { exact: true }).fill('fixture-advisor-model:latest');
  await form.getByLabel('Exact model SHA-256 digest', { exact: true }).fill('z'.repeat(64));
  await form.getByLabel('Exact Ollama URL', { exact: true }).fill('http://192.0.2.44:11434');
  await form.getByRole('button', { name: 'Add provider', exact: true }).click();
  await expect(form.getByRole('alert')).toContainText('exact 64-character SHA-256 digest');
  await expect(panel.locator('.advisor-provider-card')).toHaveCount(1);
  await form.getByRole('button', { name: 'Cancel', exact: true }).click();

  await addProvider.focus();
  await page.keyboard.press('Enter');
  form = panel.locator('.advisor-provider-form');
  await form.getByLabel('Name', { exact: true }).fill('Failing Direct');
  await form.locator('select').first().selectOption('direct');
  await form.getByLabel('Exact model', { exact: true }).fill('fixture-advisor-model:latest');
  await form.getByLabel('Exact model SHA-256 digest', { exact: true }).fill('b'.repeat(64));
  await form.getByLabel('Exact Ollama URL', { exact: true }).fill('http://192.0.2.44:11434');
  const createRequest = page.waitForRequest((candidate) => candidate.method() === 'POST' && new URL(candidate.url()).pathname === '/v1/advisor/providers');
  await form.getByRole('button', { name: 'Add provider', exact: true }).click();
  const createPayload = (await createRequest).postDataJSON() as { provider: { id: string } };
  expect(createPayload).toMatchObject({
    expected_revision: 1,
    provider: {
      name: 'Failing Direct',
      transport: 'direct',
      priority: 1,
      enabled: true,
      base_url: 'http://192.0.2.44:11434',
      model: 'fixture-advisor-model:latest',
      model_digest: 'b'.repeat(64),
      ssh_host: null,
      ssh_port: null,
      ssh_user: null,
    },
  });
  expect(createPayload.provider.id).toMatch(/^[a-z][a-z0-9-]{0,39}$/u);
  expect(createPayload.provider.id.length).toBeLessThanOrEqual(40);
  let direct = panel.locator('.advisor-provider-card', { hasText: 'Failing Direct' });
  await expect(direct).toContainText('Direct remote');
  await expect(direct).toContainText('not approved');
  const directAuthorization = direct.getByLabel('Failing Direct host authorization command');
  await expect(directAuthorization).not.toContainText('192.0.2.44');
  await direct.getByRole('button', { name: 'Copy authorization command', exact: true }).click();
  const copiedDirectCommand = await page.evaluate(() => (window as Window & { __advisorAuthorizationCommand?: string }).__advisorAuthorizationCommand || '');
  expect(copiedDirectCommand).toMatch(/^KODESEC_ADVISOR_AUTHORIZATION_B64=[A-Za-z0-9_-]+ make authorize-advisor-host && make up$/);
  const directEnvelope = copiedDirectCommand.match(/_B64=([A-Za-z0-9_-]+)/)?.[1];
  const directAuthorizationRecord = JSON.parse(Buffer.from(directEnvelope || '', 'base64url').toString('utf8')) as { provider_id: string };
  expect(directAuthorizationRecord).toEqual({
    schema: 'lomo-advisor-host-authorization/v1',
    provider_id: expect.stringMatching(/^provider-/),
    transport: 'direct',
    host: '192.0.2.44',
  });
  expect(copiedDirectCommand).not.toContain('known_hosts');
  expect(copiedDirectCommand).not.toContain('id_ed25519');
  await request.post('/__test/advisor-provider-authorize', { data: { provider_id: directAuthorizationRecord.provider_id } });

  await direct.getByRole('button', { name: 'Test connection', exact: true }).click();
  await expect(panel.getByRole('button', { name: 'Retry original snapshot', exact: true })).toBeVisible();
  await expect(direct.locator('.advisor-provider-failure')).toContainText('Connection refused');
  await expect(panel).not.toContainText('fixture-secret');
  await expect(panel).not.toContainText('/Users/generated/.ssh/id_ed25519');
  await expect(panel).not.toContainText('/private/generated/known_hosts');
  await panel.getByRole('button', { name: 'Retry original snapshot', exact: true }).click();
  await expect(direct.getByText('available', { exact: true })).toBeVisible();

  await direct.getByRole('button', { name: 'Edit', exact: true }).click();
  form = panel.locator('.advisor-provider-form');
  await expect(form.locator('select').first()).toBeDisabled();
  await form.getByLabel('Name', { exact: true }).fill('Remote GPU');
  await form.locator('select').nth(1).selectOption({ value: '2' });
  await expect(form.locator('select').nth(1)).toHaveValue('2');
  await form.getByRole('button', { name: 'Save provider', exact: true }).click();
  direct = panel.locator('.advisor-provider-card', { hasText: 'Remote GPU' });
  await expect(direct.getByText('Priority 3', { exact: true })).toBeVisible();
  await expect(direct).toContainText('Test and activate this exact provider');
  await expect(direct).toContainText('not approved');
  await direct.getByRole('button', { name: 'Test connection', exact: true }).click();
  await expect(direct.getByText('available', { exact: true })).toBeVisible();

  const directBeforeActivation = (await request.get('/v1/advisor/providers').then((response) => response.json()) as {
    providers: Array<{ id: string; name: string; config_revision: number; config_digest: string; model: string; model_digest: string }>;
  }).providers.find((provider) => provider.name === 'Remote GPU');
  expect(directBeforeActivation).toBeDefined();

  const commandsBeforeDismissedActivation = await request.get('/__test/commands').then((response) => response.json());
  const dismissedActivation = await dismissNextConfirmation(page, () => direct.getByRole('button', { name: 'Activate', exact: true }).click());
  expect(dismissedActivation.message).toContain('finding_identity');
  expect(await request.get('/__test/commands').then((response) => response.json())).toEqual(commandsBeforeDismissedActivation);
  await expect(direct.getByText('active', { exact: true })).toHaveCount(0);

  const disclosure = await acceptNextConfirmation(page, () => direct.getByRole('button', { name: 'Activate', exact: true }).click());
  expect(disclosure.message).toContain('Transport: direct');
  expect(disclosure.message).toContain('http://192.0.2.44:11434');
  expect(disclosure.message).toContain(`Provider configuration revision: ${directBeforeActivation?.config_revision}`);
  expect(disclosure.message).toContain(`Provider configuration digest: ${directBeforeActivation?.config_digest}`);
  expect(disclosure.message).toContain(`Model digest: ${'b'.repeat(64)}`);
  for (const category of ['finding_identity', 'source_location', 'repository_context', 'bounded_code_snippet', 'bounded_scanner_metadata']) {
    expect(disclosure.message).toContain(`- ${category}`);
  }
  expect(disclosure.message).toContain('Connection tests and activation send no finding content and start no Advisor request.');
  expect(disclosure.message).toContain('An active remote profile remains excluded from automatic, scan-wide, and bulk routing.');
  expect(disclosure.message).toContain('Each remote review requires a new exact single-finding disclosure preview and explicit authorization.');
  await expect(direct).toContainText('approved for this exact host');
  await expect(direct.getByText('activated', { exact: true })).toBeVisible();
  await expect(direct).toContainText('active for this exact configuration');
  await expect(direct).toContainText('This remote provider is active for explicitly confirmed one-finding reviews. Automatic, scan-wide, and bulk remote routing remain unavailable.');
  await expect(direct.locator('.advisor-provider-details').getByText('no', { exact: true })).toBeVisible();
  await expect(panel.locator('.advisor-provider-resolution')).toContainText('Resolved provider Local Ollama');
  await expect(direct.getByRole('button', { name: 'Remove Remote GPU', exact: true })).toBeEnabled();
  expect((await request.get(`/v1/advisor/providers/${directAuthorizationRecord.provider_id}/receipt`)).status()).toBe(200);
  const commandsAfterActivation = await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string; input: Record<string, unknown> }>;
  expect(commandsAfterActivation.find((command) => command.route === 'advisor-provider-activate')?.input).toMatchObject({
    action: 'activate',
    acknowledge_source_disclosure: true,
    source_disclosure_approval: {
      schema: 'lomo-advisor-activation-approval/v1',
      provider_id: directBeforeActivation?.id,
      provider_config_revision: directBeforeActivation?.config_revision,
      provider_config_digest: directBeforeActivation?.config_digest,
      transport: 'direct',
      destination: 'http://192.0.2.44:11434',
      disclosure_mode: 'finding_evidence',
      payload_categories: ['finding_identity', 'source_location', 'repository_context', 'bounded_code_snippet', 'bounded_scanner_metadata'],
      model: 'fixture-advisor-model:latest',
      model_digest: 'b'.repeat(64),
    },
  });

  await direct.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await expect(direct).toContainText('Disconnected by the operator.');
  expect((await request.get(`/v1/advisor/providers/${directAuthorizationRecord.provider_id}/receipt`)).status()).toBe(404);
  await direct.getByRole('button', { name: 'Disable', exact: true }).click();
  await expect(direct.getByRole('button', { name: 'Enable', exact: true })).toBeVisible();
  await direct.getByRole('button', { name: 'Enable', exact: true }).click();

  await panel.getByRole('button', { name: 'Add provider', exact: true }).click();
  form = panel.locator('.advisor-provider-form');
  await form.getByLabel('Name', { exact: true }).fill('Stalled SSH');
  await form.locator('select').first().selectOption('ssh');
  await form.getByLabel('Exact model', { exact: true }).fill('fixture-advisor-model:latest');
  await form.getByLabel('Exact model SHA-256 digest', { exact: true }).fill('c'.repeat(64));
  await form.getByLabel('Exact SSH host', { exact: true }).fill('192.0.2.45');
  await expect(form.getByLabel(/^SSH port/u)).toHaveValue('22');
  await expect(form.getByLabel(/^SSH port/u)).toBeDisabled();
  await form.getByLabel('SSH user', { exact: true }).fill('ollama-forward');
  await form.getByRole('button', { name: 'Add provider', exact: true }).click();
  const ssh = panel.locator('.advisor-provider-card', { hasText: 'Stalled SSH' });
  await expect(ssh.getByText('Priority 2', { exact: true })).toBeVisible();
  await expect(ssh).toContainText('SSH remote · outbound local forward');
  await expect(ssh).toContainText('authorization is required', { ignoreCase: true });
  await ssh.getByRole('button', { name: 'Copy authorization command', exact: true }).click();
  const copiedSshCommand = await page.evaluate(() => (window as Window & { __advisorAuthorizationCommand?: string }).__advisorAuthorizationCommand || '');
  const sshEnvelope = copiedSshCommand.match(/_B64=([A-Za-z0-9_-]+)/)?.[1];
  const stalledSshAuthorizationRecord = JSON.parse(Buffer.from(sshEnvelope || '', 'base64url').toString('utf8')) as { provider_id: string };
  expect(stalledSshAuthorizationRecord).toEqual({
    schema: 'lomo-advisor-host-authorization/v1',
    provider_id: expect.stringMatching(/^provider-/),
    transport: 'ssh',
    host: '192.0.2.45',
    port: 22,
    user: 'ollama-forward',
  });
  expect(copiedSshCommand).not.toContain('known_hosts');
  expect(copiedSshCommand).not.toContain('id_ed25519');
  await request.post('/__test/advisor-provider-authorize', { data: { provider_id: stalledSshAuthorizationRecord.provider_id } });
  await page.evaluate(() => {
    (window as Window & { __advisorClipboardFails?: boolean }).__advisorClipboardFails = true;
  });
  await ssh.getByRole('button', { name: 'Copy authorization command', exact: true }).click();
  await expect(ssh.getByRole('status')).toContainText('Automatic copy is unavailable');
  await page.evaluate(() => {
    (window as Window & { __advisorClipboardFails?: boolean }).__advisorClipboardFails = false;
  });
  await direct.getByRole('button', { name: 'Edit', exact: true }).click();
  form = panel.locator('.advisor-provider-form');
  await form.locator('select').nth(1).selectOption({ value: '1' });
  await form.getByRole('button', { name: 'Save provider', exact: true }).click();
  await expect(direct.getByText('Priority 2', { exact: true })).toBeVisible();
  await expect(ssh.getByText('Priority 3', { exact: true })).toBeVisible();
  await ssh.getByRole('button', { name: 'Test connection', exact: true }).click();
  await expect(ssh.locator('.advisor-provider-operation')).toContainText('verify-model-digest');
  await expect(ssh.locator('.advisor-provider-stalled')).toContainText('No worker heartbeat for 45 seconds');
  await panel.getByRole('button', { name: 'Cancel operation', exact: true }).click();
  await expect(panel).toContainText('Connection test ended as cancelled.');
  await expect(ssh).not.toContainText('Disconnected by the operator.');
  await acceptNextConfirmation(page, () => ssh.getByRole('button', { name: 'Remove Stalled SSH', exact: true }).click());
  await expect(ssh).toHaveCount(0);

  await panel.getByRole('button', { name: 'Add provider', exact: true }).click();
  form = panel.locator('.advisor-provider-form');
  await form.getByLabel('Name', { exact: true }).fill('Remote SSH');
  await form.locator('select').first().selectOption('ssh');
  await form.getByLabel('Exact model', { exact: true }).fill('fixture-advisor-model:latest');
  await form.getByLabel('Exact model SHA-256 digest', { exact: true }).fill('d'.repeat(64));
  await form.getByLabel('Exact SSH host', { exact: true }).fill('192.0.2.46');
  await form.getByLabel('SSH user', { exact: true }).fill('ollama-forward');
  await form.getByRole('button', { name: 'Add provider', exact: true }).click();
  const readySsh = panel.locator('.advisor-provider-card', { hasText: 'Remote SSH' });
  const readySshId = JSON.parse(Buffer.from(
    (await readySsh.getByLabel('Remote SSH host authorization command').inputValue()).match(/_B64=([A-Za-z0-9_-]+)/)?.[1] || '',
    'base64url',
  ).toString('utf8')).provider_id as string;
  await request.post('/__test/advisor-provider-authorize', { data: { provider_id: readySshId } });
  const authorizedSettingsUrl = page.url();
  expect(new URL(authorizedSettingsUrl).searchParams.get('view')).toBe('settings');
  guards.assertClean();
  await guards.waitForApiIdle();
  guards.assertClean();
  await page.reload();
  await expect(page).toHaveURL(authorizedSettingsUrl);
  await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
  const refreshedPanel = page.locator('#advisor-providers');
  const authorizedSsh = refreshedPanel.locator('.advisor-provider-card', { hasText: 'Remote SSH' });
  await expect(authorizedSsh).toContainText('authorized');
  await authorizedSsh.getByRole('button', { name: 'Test connection', exact: true }).click();
  await expect(authorizedSsh.getByText('available', { exact: true })).toBeVisible();
  const sshActivationDismissed = await dismissNextConfirmation(page, () => authorizedSsh.getByRole('button', { name: 'Activate', exact: true }).click());
  expect(sshActivationDismissed.message).toContain('ollama-forward@192.0.2.46:22');
  await expect(authorizedSsh.getByText('active', { exact: true })).toHaveCount(0);
  const sshDisclosure = await acceptNextConfirmation(page, () => authorizedSsh.getByRole('button', { name: 'Activate', exact: true }).click());
  expect(sshDisclosure.message).toContain('Transport: ssh');
  expect(sshDisclosure.message).toContain('ssh://ollama-forward@192.0.2.46:22/ollama/127.0.0.1:11434');
  expect(sshDisclosure.message).toContain('bounded_scanner_metadata');
  await expect(authorizedSsh.getByText('activated', { exact: true })).toBeVisible();
  await authorizedSsh.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await expect(authorizedSsh).toContainText('Disconnected by the operator.');
  const dismissedSshRemoval = await dismissNextConfirmation(page, () => authorizedSsh.getByRole('button', { name: 'Remove Remote SSH', exact: true }).click());
  expect(dismissedSshRemoval.message).toContain('Remove Advisor provider Remote SSH?');
  await expect(authorizedSsh).toHaveCount(1);
  await acceptNextConfirmation(page, () => authorizedSsh.getByRole('button', { name: 'Remove Remote SSH', exact: true }).click());
  await expect(authorizedSsh).toHaveCount(0);

  await refreshedPanel.getByRole('button', { name: 'Use qwen3:8b locally', exact: true }).click();
  await expect(local.getByText('resolved', { exact: true })).toBeVisible();
  await expect(local).toContainText('active for this exact configuration');
  await expect(localActions.getByRole('button', { name: 'Test connection', exact: true })).toHaveCount(0);
  await expect(localActions.getByRole('button', { name: 'Activate', exact: true })).toHaveCount(0);
  const commands = await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string; input: Record<string, unknown> }>;
  expect([...commands].reverse().find((command) => command.route === 'advisor-provider-activate')?.input).toMatchObject({
    action: 'activate',
    acknowledge_source_disclosure: false,
    source_disclosure_approval: null,
  });

  await acceptNextConfirmation(page, () => direct.getByRole('button', { name: 'Remove Remote GPU', exact: true }).click());
  await expect(direct).toHaveCount(0);
  await expect(panel.locator('.advisor-provider-card')).toHaveCount(1);

  let boundedCollection = await request.get('/v1/advisor/providers').then((response) => response.json()) as { revision: number };
  for (let index = 1; index <= 7; index += 1) {
    const response = await request.post('/v1/advisor/providers', { data: {
      expected_revision: boundedCollection.revision,
      provider: {
        id: `bounded-local-${index}`,
        name: `Bounded local ${index}`,
        transport: 'local',
        priority: index,
        enabled: true,
        base_url: null,
        model: `fixture-model-${index}`,
        model_digest: 'e'.repeat(64),
        ssh_host: null,
        ssh_port: null,
        ssh_user: null,
      },
    } });
    expect(response.ok()).toBe(true);
    boundedCollection = await response.json() as { revision: number };
  }
  const boundedSettingsUrl = page.url();
  expect(new URL(boundedSettingsUrl).searchParams.get('view')).toBe('settings');
  guards.assertClean();
  await guards.waitForApiIdle();
  guards.assertClean();
  await page.reload();
  await expect(page).toHaveURL(boundedSettingsUrl);
  await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
  const boundedPanel = page.locator('#advisor-providers');
  await expect(boundedPanel.locator('.advisor-provider-card')).toHaveCount(8);
  await expect(boundedPanel.getByRole('button', { name: 'Add provider', exact: true })).toBeDisabled();
  guards.assertClean();
});

test('Advisor provider form rejects DNS and unsafe special-purpose destinations without a mutation request', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const mutations = mutationRequestLog(page);
  const surface = await openRoute(page, 'Settings');
  const panel = surface.locator('#advisor-providers');

  await panel.getByRole('button', { name: 'Add provider', exact: true }).click();
  const form = panel.locator('.advisor-provider-form');
  await form.getByLabel('Name', { exact: true }).fill('Rejected Destination');
  await form.locator('select').first().selectOption('direct');
  await form.getByLabel('Exact model', { exact: true }).fill('fixture-advisor-model:latest');
  await form.getByLabel('Exact model SHA-256 digest', { exact: true }).fill('b'.repeat(64));

  for (const destination of ['http://model-host.example:11434', 'http://127.0.0.1:11434', 'http://169.254.1.9:11434', 'http://224.0.0.1:11434']) {
    await form.getByLabel('Exact Ollama URL', { exact: true }).fill(destination);
    await form.getByRole('button', { name: 'Add provider', exact: true }).click();
    await expect(form.getByRole('alert')).toContainText('safe literal IPv4 address');
  }

  await form.locator('select').first().selectOption('ssh');
  await form.getByLabel('SSH user', { exact: true }).fill('ollama-forward');
  for (const destination of ['ssh-model.example', '127.0.0.1', '240.0.0.1']) {
    await form.getByLabel('Exact SSH host', { exact: true }).fill(destination);
    await form.getByRole('button', { name: 'Add provider', exact: true }).click();
    await expect(form.getByRole('alert')).toContainText('safe literal IPv4 address');
  }

  await expect(panel.locator('.advisor-provider-card')).toHaveCount(1);
  expect(mutations).toEqual([]);
  guards.assertClean();
});

test('Advisor provider revision conflict discards the stale draft before retry', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const panel = surface.locator('#advisor-providers');
  const local = panel.locator('.advisor-provider-card', { hasText: 'Local Ollama' });

  await local.getByRole('button', { name: 'Edit', exact: true }).click();
  let form = panel.locator('.advisor-provider-form');
  await form.getByLabel('Name', { exact: true }).fill('Stale operator draft');

  const collection = await request.get('/v1/advisor/providers').then((response) => response.json()) as { revision: number };
  const concurrent = await request.put('/v1/advisor/providers/local-default', { data: {
    expected_revision: collection.revision,
    provider: {
      id: 'local-default',
      name: 'Concurrent reviewed value',
      transport: 'local',
      priority: 0,
      enabled: true,
      base_url: null,
      model: 'generated-local-model',
      model_digest: 'a'.repeat(64),
      ssh_host: null,
      ssh_port: null,
      ssh_user: null,
    },
  } });
  expect(concurrent.ok()).toBe(true);

  await form.getByRole('button', { name: 'Save provider', exact: true }).click();
  await expect(panel.getByRole('alert')).toContainText('configuration changed');
  await expect(panel.locator('.advisor-provider-form')).toHaveCount(0);
  const reconciled = panel.locator('.advisor-provider-card', { hasText: 'Concurrent reviewed value' });
  await expect(reconciled).toBeVisible();
  await expect(panel).not.toContainText('Stale operator draft');

  await reconciled.getByRole('button', { name: 'Edit', exact: true }).click();
  form = panel.locator('.advisor-provider-form');
  await expect(form.getByLabel('Name', { exact: true })).toHaveValue('Concurrent reviewed value');
  expect(guards.failures.console).toHaveLength(1);
  expect(guards.failures.console[0]).toContain('409 (Conflict)');
  expect(guards.failures.http).toEqual([`409 ${new URL(baseURL).origin}/v1/advisor/providers/local-default`]);
  guards.failures.console.length = 0;
  guards.failures.http.length = 0;
  guards.assertClean();
});

test('Tools toggles scanner admission and one-click preparation queues catalog before deferred cache work', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let surface = await openRoute(page, 'Tools');

  let openGrep = surface.locator('.tool-card', { hasText: 'OpenGrep' });
  await openGrep.getByRole('button', { name: 'Disable', exact: true }).click();
  await expect(openGrep.getByRole('button', { name: 'Enable', exact: true })).toBeVisible();
  await expect(openGrep.locator('.pill')).toHaveText('disabled');
  await expect.poll(async () => {
    const tools = await request.get('/v1/scanner/tools').then((response) => response.json()) as Array<{ id: string; enabled: boolean }>;
    return tools.find((tool) => tool.id === 'opengrep')?.enabled;
  }).toBe(false);

  await openGrep.getByRole('button', { name: 'Enable', exact: true }).click();
  openGrep = surface.locator('.tool-card', { hasText: 'OpenGrep' });
  await expect(openGrep.getByRole('button', { name: 'Disable', exact: true })).toBeVisible();
  await expect(openGrep.locator('.pill')).toHaveText('enabled');
  await expect.poll(async () => {
    const tools = await request.get('/v1/scanner/tools').then((response) => response.json()) as Array<{ id: string; enabled: boolean }>;
    return tools.find((tool) => tool.id === 'opengrep')?.enabled;
  }).toBe(true);

  let checkov = surface.locator('.tool-card', { hasText: 'Checkov' });
  await checkov.getByRole('button', { name: 'Disable', exact: true }).click();
  await checkov.getByRole('button', { name: 'Enable', exact: true }).click();
  checkov = surface.locator('.tool-card', { hasText: 'Checkov' });
  await expect(checkov.getByRole('button', { name: 'Disable', exact: true })).toBeVisible();
  await expect.poll(async () => {
    const tools = await request.get('/v1/scanner/tools').then((response) => response.json()) as Array<{
      id: string;
      enabled: boolean;
      status: string;
      update_available: boolean;
    }>;
    return tools.find((tool) => tool.id === 'checkov');
  }).toMatchObject({ enabled: true, status: 'ready', update_available: true });

  await request.post('/__test/reset', { data: { profile: 'scanner-preparation', generation: 2 } });
  surface = await openRoute(page, 'Tools');
  await surface.getByRole('button', { name: 'Prepare all scanners', exact: true }).click();
  await expect(page.getByText('Preparing every required scanner', { exact: true })).toBeVisible();
  await expect(page.getByText(/Scanner catalog job #\d+ queued/u)).toBeVisible();
  await expect(page.getByText('CodeSecurity is checking the reviewed scanner locks. Verified cache work will be created only if that catalog check passes.', { exact: true })).toBeVisible();
  await expect(surface.getByLabel('Curated catalog lifecycle').locator('.pill')).toHaveText('queued');
  await expect(surface.getByLabel('Offline cache lifecycle').locator('.pill')).toHaveText('idle');
  const commands = await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string; input: Record<string, unknown> }>;
  expect(commands).toEqual([expect.objectContaining({
    route: 'scanner-prepare',
    input: {},
  })]);
  const jobs = await request.get('/v1/jobs').then((response) => response.json()) as Array<{
    id: number;
    kind: string;
    component_ids?: string[];
    prerequisite_job_id?: number;
  }>;
  const catalogJob = jobs.find((job) => job.kind === 'scanner_catalog_check');
  const cacheJob = jobs.find((job) => job.kind === 'scanner_cache_update');
  expect(catalogJob).toMatchObject({ component_ids: [] });
  expect(cacheJob).toBeUndefined();
  const lifecycle = await request.get('/v1/scanner/lifecycle').then((response) => response.json()) as {
    catalog: { job_id: number | null };
    cache: { job_id: number | null };
  };
  expect(lifecycle).toMatchObject({
    catalog: { job_id: catalogJob?.id },
    cache: { job_id: null },
  });
  guards.assertClean();
});

test('enabling blocked or unreported tools never fabricates runtime readiness', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const cases = [
    { profile: 'scanner-preparation', name: 'OpenGrep', id: 'opengrep', readiness: false, label: 'not ready', action: 'prepare_scanners' },
    { profile: 'scanner-readiness-missing', name: 'Checkov', id: 'checkov', readiness: undefined, label: 'not reported', action: 'repair_scanner_runtime' },
  ] as const;

  for (const [index, item] of cases.entries()) {
    await request.post('/__test/reset', { data: { profile: item.profile, generation: index + 1 } });
    const surface = await openRoute(page, 'Tools');
    let card = surface.locator('.tool-card', { hasText: item.name });
    await card.getByRole('button', { name: 'Disable', exact: true }).click();
    await card.getByRole('button', { name: 'Enable', exact: true }).click();
    // The readiness label intentionally stays unchanged. Wait for the exact
    // toggle's mutation refresh to release busy before resetting this fixture.
    await expect(card.getByRole('button', { name: 'Disable', exact: true })).toBeEnabled();
    card = surface.locator('.tool-card', { hasText: item.name });
    await expect(card.locator('.readiness-head strong')).toHaveText(item.label);
    const tools = await request.get('/v1/scanner/tools').then((response) => response.json()) as Array<{
      enabled: boolean;
      id: string;
      runtime_ready?: boolean;
      status: string;
    }>;
    const enabled = tools.find((tool) => tool.id === item.id);
    expect(enabled).toMatchObject({ enabled: true, id: item.id, status: 'ready' });
    expect(enabled?.runtime_ready).toBe(item.readiness);
    expect(await request.get('/v1/scanner/preflight').then((response) => response.json())).toMatchObject({
      ready: false,
      recommended_action: item.action,
      blocked_tools: expect.arrayContaining([expect.objectContaining({ id: item.id })]),
    });
  }
  guards.assertClean();
});

test('catalog and cache controls persist selection, cancellation, and rollback side effects', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'scanner-readiness-missing', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let surface = await openRoute(page, 'Tools');
  await openAdvancedScannerMaintenance(surface);

  const trivyJava = surface.getByRole('checkbox', { name: /Trivy Java DB/u });
  await expect(trivyJava).toBeDisabled();
  await expect(trivyJava).toHaveAttribute('title', /no newer attested candidate/u);
  await surface.getByRole('checkbox', { name: /Trivy vulnerability DB/u }).check();
  await surface.getByRole('checkbox', { name: /OpenGrep reviewed rules/u }).check();
  await surface.getByRole('button', { name: 'Update selected cache', exact: true }).click();
  const cache = surface.getByLabel('Offline cache lifecycle');
  await expect(cache.locator('.pill')).toHaveText('queued');
  const queuedCache = await request.get('/v1/scanner/lifecycle').then((response) => response.json()) as { cache: { job_id: number } };
  expect(await request.get(`/v1/jobs/${queuedCache.cache.job_id}`).then((response) => response.json())).toMatchObject({
    kind: 'scanner_cache_update',
    status: 'queued',
  });

  await surface.getByRole('button', { name: 'Check curated catalog', exact: true }).click();
  await expect(surface.getByLabel('Curated catalog lifecycle').locator('.pill')).toHaveText('queued');
  const firstCommands = await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string; input: Record<string, unknown> }>;
  expect(firstCommands).toEqual([
    expect.objectContaining({ route: 'scanner-cache-update', input: { component_ids: ['opengrep-reviewed-rules', 'trivy-db'], catalog_digest: null } }),
    expect.objectContaining({ route: 'scanner-catalog-check', input: {} }),
  ]);

  await acceptNextConfirmation(page, () => cache.getByRole('button', { name: 'Cancel', exact: true }).click());
  await expect(cache.locator('.pill')).toHaveText('cancelled');
  expect(await request.get(`/v1/jobs/${queuedCache.cache.job_id}`).then((response) => response.json())).toMatchObject({
    status: 'cancelled',
    can_cancel: false,
  });

  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 2 } });
  surface = await openRoute(page, 'Tools');
  await openAdvancedScannerMaintenance(surface);
  await acceptNextConfirmation(page, () => surface.getByRole('button', { name: 'Roll back cache', exact: true }).click());
  await expect(surface.getByLabel('Offline cache lifecycle').locator('.pill')).toHaveText('queued');
  const rollbackCommands = await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string; input: Record<string, unknown> }>;
  expect(rollbackCommands).toEqual([expect.objectContaining({ route: 'scanner-cache-rollback', input: {} })]);
  guards.assertClean();
});

test('[WEB-ACT-006] Jobs filters stay actionable while cancel and retry persist exact durable state', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'durable', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Jobs');

  const filters = surface.getByRole('group', { name: 'Job filters', exact: true });
  await expect(filters).toBeVisible();
  await filters.getByLabel('Job status', { exact: true }).selectOption('active');
  await expect(surface.locator('.job-row')).toHaveCount(4);
  await filters.getByLabel('Job kind', { exact: true }).selectOption('advisor');
  await expect(surface.locator('.job-row')).toHaveCount(2);
  const search = filters.getByLabel('Search jobs', { exact: true });
  await search.focus();
  await search.pressSequentially('Leased advisor');
  await expect(search).toHaveValue('Leased advisor');
  await expect(search).toBeFocused();
  expect(await search.evaluate((element) => Boolean(element.closest('[inert], [aria-hidden="true"]')))).toBe(false);
  await expect(surface.locator('.job-row')).toHaveCount(1);
  await expect(surface.getByLabel(/^Job #91:/u)).toBeVisible();
  await search.fill('no matching durable work');
  await expect(search).toBeFocused();
  await expect(surface.getByText('No jobs match the current filters.', { exact: true })).toBeVisible();
  await search.fill('');
  await filters.getByLabel('Job status', { exact: true }).selectOption('all');
  await filters.getByLabel('Job kind', { exact: true }).selectOption('all');

  const cancelJobButton = surface.getByLabel(/^Job #92:/u).getByRole('button', { name: 'Cancel', exact: true });
  const keyboardDialog = await openConfirmation(page, () => cancelJobButton.click());
  const safeCancel = keyboardDialog.dialog.getByRole('button', { name: 'Keep job running', exact: true });
  await expect(safeCancel).toBeFocused();
  // Embedded editor browsers can suppress the dialog's native cancel event.
  // Escape must still dismiss through the focused control without changing a job.
  await keyboardDialog.dialog.evaluate((dialog) => {
    dialog.addEventListener('cancel', (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();
    }, { capture: true });
  });
  await safeCancel.press('Escape');
  await expect(keyboardDialog.dialog).toHaveCount(0);
  await expect(cancelJobButton).toBeFocused();
  expect(await request.get('/v1/jobs/92').then((response) => response.json())).toMatchObject({ status: 'running', can_cancel: true, revision: 3 });

  await acceptNextConfirmation(page, () => cancelJobButton.click());
  await expect(surface.getByLabel(/^Job #92:/u).locator('.job-status-cell')).toHaveText('Cancelling');
  expect(await request.get('/v1/jobs/92').then((response) => response.json())).toMatchObject({ status: 'cancelling', can_cancel: false, revision: 4 });

  await surface.getByLabel(/^Job #82:/u).getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(surface.getByLabel(/^Job #82:/u).locator('.job-status-cell')).toHaveText('Waiting');
  expect(await request.get('/v1/jobs/82').then((response) => response.json())).toMatchObject({ status: 'queued', can_cancel: true, can_retry: false, revision: 7 });
  guards.assertClean();
});

test('Jobs and Overview shortcuts navigate to the exact resource revision and focused section', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const mutations = mutationRequestLog(page);
  const findingDetailRequests: URL[] = [];
  page.on('request', (candidate) => {
    const url = new URL(candidate.url());
    if (url.pathname === '/v1/scans/41/findings/1') findingDetailRequests.push(url);
  });
  let surface = await openRoute(page, 'Jobs');
  mutations.length = 0;

  await surface.getByLabel(/^Job #81:/u).getByRole('button', { name: 'Scan #41', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  let findingsSurface = page.locator('section[data-route-surface="findings"]');
  await expect(findingsSurface).not.toHaveAttribute('aria-busy', 'true');
  await expect(findingsSurface.getByLabel('Scan', { exact: true })).toHaveValue('41');
  await expect(findingsSurface.locator('.finding-detail')).toHaveAttribute('data-finding-id', '501');
  await expect(findingsSurface.locator('.finding-detail h2')).toHaveText('S41-F001');
  const findingsNav = page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true });
  await expect(findingsNav).toBeFocused();
  expect(new URL(page.url()).searchParams.toString()).toBe('view=findings&scan=41&finding=1');
  expect(await request.get('/v1/scans/41').then((response) => response.json())).toMatchObject({
    id: 41,
    revision: 1,
    findings_revision: 1,
  });
  expect(await findingState(request, [501])).toEqual([expect.objectContaining({ id: 501, revision: 1 })]);
  expect(findingDetailRequests.some((url) => (
    url.searchParams.get('expected_revision') === '1'
    && url.searchParams.get('expected_findings_revision') === '1'
  ))).toBe(true);
  expect(mutations).toEqual([]);

  const navigation = page.getByRole('navigation');
  await navigation.getByRole('button', { name: 'Overview', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible();
  let overview = page.locator('section[data-route-surface="overview"]');
  const severity = overview.locator('.band').filter({ has: page.getByRole('heading', { level: 2, name: 'Findings by severity', exact: true }) });
  await expect(severity).toHaveCount(1);
  await expect(severity.getByRole('heading', { level: 2, name: 'Findings by severity', exact: true })).toBeVisible();
  await severity.getByRole('button', { name: 'Findings', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  findingsSurface = page.locator('section[data-route-surface="findings"]');
  await expect(findingsSurface.getByLabel('Scan', { exact: true })).toHaveValue('41');
  await expect(findingsSurface.locator('.finding-detail')).toHaveAttribute('data-finding-id', '501');
  await expect(findingsNav).toBeFocused();
  expect(await request.get('/v1/scans/41').then((response) => response.json())).toMatchObject({ id: 41, revision: 1, findings_revision: 1 });
  expect(mutations).toEqual([]);

  await navigation.getByRole('button', { name: 'Overview', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible();
  overview = page.locator('section[data-route-surface="overview"]');
  const recentScans = overview.locator('.band').filter({ has: page.getByRole('heading', { level: 2, name: 'Recent Scans', exact: true }) });
  await expect(recentScans).toHaveCount(1);
  await expect(recentScans.getByRole('heading', { level: 2, name: 'Recent Scans', exact: true })).toBeVisible();
  // Recent rows open their own scan, including a non-default scan with no
  // normalized findings. Pointer and native keyboard activation share the same
  // visible command; neither can leak the preceding scan's selected finding.
  const scan40Before = await request.get('/v1/scans/40').then((response) => response.json());
  const findingsBefore = await findingState(request, [501, 502, 503]);
  expect(scan40Before).toMatchObject({ id: 40, revision: 1, findings_revision: 1, status: 'partial', gate_decision: 'incomplete' });
  for (const activation of ['pointer', 'keyboard'] as const) {
    await expect(overview).not.toHaveAttribute('aria-busy', 'true');
    await page.waitForLoadState('networkidle');
    await expect(recentScans.getByRole('button', { name: /^Delete scan #/u })).toHaveCount(0);
    const recent40 = recentScans.getByRole('row', { name: 'Open findings for scan #40', exact: true });
    const openRecent40 = recent40.getByRole('button', { name: 'Open findings', exact: true });
    await expect(openRecent40).toBeVisible();
    if (activation === 'pointer') {
      await openRecent40.click();
    } else {
      await openRecent40.focus();
      await expect(openRecent40).toBeFocused();
      await page.keyboard.press('Enter');
    }
    await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
    findingsSurface = page.locator('section[data-route-surface="findings"]');
    await expect(findingsSurface.getByLabel('Scan', { exact: true })).toHaveValue('40');
    await expect(findingsSurface).not.toHaveAttribute('aria-busy', 'true');
    await expect(findingsSurface).toHaveAttribute('data-findings-render-stage', 'ready');
    await expect(findingsSurface.locator('.finding-list-item')).toHaveCount(0);
    await expect(findingsSurface.locator('.finding-detail[data-finding-id="501"]')).toHaveCount(0);
    await expect(findingsSurface.locator('.scan-metrics .stat').filter({ hasText: 'Gate' }).locator('strong')).toHaveText('incomplete');
    await expect(findingsNav).toBeFocused();
    expect(new URL(page.url()).searchParams.toString()).toBe('view=findings&scan=40');
    await page.waitForLoadState('networkidle');
    expect(await request.get('/v1/scans/40').then((response) => response.json())).toEqual(scan40Before);
    expect(await findingState(request, [501, 502, 503])).toEqual(findingsBefore);
    expect(mutations).toEqual([]);

    // Restore the default scan so each activation proves a distinct handoff.
    await findingsSurface.getByLabel('Scan', { exact: true }).selectOption('41');
    await expect(findingsSurface.locator('.finding-detail')).toHaveAttribute('data-finding-id', '501');
    await expect(findingsSurface).not.toHaveAttribute('aria-busy', 'true');
    await page.waitForLoadState('networkidle');
    await navigation.getByRole('button', { name: 'Overview', exact: true }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible();
  }
  await expect(overview).not.toHaveAttribute('aria-busy', 'true');
  await page.waitForLoadState('networkidle');
  await recentScans.getByRole('button', { name: 'Open', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Scans', exact: true })).toBeVisible();
  surface = page.locator('section[data-route-surface="scans"]');
  await expect(surface.getByRole('row').filter({ hasText: '#41' })).toHaveCount(1);
  await expect(navigation.getByRole('button', { name: 'Scans', exact: true })).toBeFocused();
  expect(await request.get('/v1/scans/41').then((response) => response.json())).toMatchObject({ id: 41, revision: 1, findings_revision: 1 });
  expect(mutations).toEqual([]);
  guards.assertClean();
});

test('dismissing cache and job confirmations preserves exact durable state without mutation requests', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const mutations = mutationRequestLog(page);

  await request.post('/__test/reset', { data: { profile: 'scanner-readiness-missing', generation: 1 } });
  let surface = await openRoute(page, 'Tools');
  await openAdvancedScannerMaintenance(surface);
  await surface.getByRole('checkbox', { name: /OpenGrep reviewed rules/u }).check();
  await surface.getByRole('button', { name: 'Update selected cache', exact: true }).click();
  const cache = surface.getByLabel('Offline cache lifecycle');
  await expect(cache.locator('.pill')).toHaveText('queued');
  const cacheLifecycleBefore = await request.get('/v1/scanner/lifecycle').then((response) => response.json()) as { cache: { job_id: number } };
  const cacheJobBefore = await request.get(`/v1/jobs/${cacheLifecycleBefore.cache.job_id}`).then((response) => response.json());
  const cacheCommandsBefore = await request.get('/__test/commands').then((response) => response.json());
  mutations.length = 0;
  const cacheCancel = await dismissNextConfirmation(page, () => cache.getByRole('button', { name: 'Cancel', exact: true }).click());
  expect(cacheCancel.type).toBe('confirm');
  expect(cacheCancel.message).toContain(`Cancel job #${cacheLifecycleBefore.cache.job_id}?`);
  expect(await request.get('/v1/scanner/lifecycle').then((response) => response.json())).toEqual(cacheLifecycleBefore);
  expect(await request.get(`/v1/jobs/${cacheLifecycleBefore.cache.job_id}`).then((response) => response.json())).toEqual(cacheJobBefore);
  expect(await request.get('/__test/commands').then((response) => response.json())).toEqual(cacheCommandsBefore);
  expect(mutations).toEqual([]);

  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 2 } });
  surface = await openRoute(page, 'Tools');
  await openAdvancedScannerMaintenance(surface);
  const rollbackLifecycleBefore = await request.get('/v1/scanner/lifecycle').then((response) => response.json());
  const rollbackCommandsBefore = await request.get('/__test/commands').then((response) => response.json());
  mutations.length = 0;
  const rollback = await dismissNextConfirmation(page, () => surface.getByRole('button', { name: 'Roll back cache', exact: true }).click());
  expect(rollback).toEqual({
    type: 'confirm',
    message: 'Roll back to the previous verified scanner cache generation? The current generation will remain available as the new previous-good generation.',
    title: 'Roll back scanner cache?',
  });
  expect(await request.get('/v1/scanner/lifecycle').then((response) => response.json())).toEqual(rollbackLifecycleBefore);
  expect(await request.get('/__test/commands').then((response) => response.json())).toEqual(rollbackCommandsBefore);
  expect(mutations).toEqual([]);

  await request.post('/__test/reset', { data: { profile: 'durable', generation: 3 } });
  surface = await openRoute(page, 'Jobs');
  const jobBefore = await request.get('/v1/jobs/92').then((response) => response.json());
  const scanBefore = await request.get('/v1/scans/39').then((response) => response.json());
  const jobCommandsBefore = await request.get('/__test/commands').then((response) => response.json());
  mutations.length = 0;
  const jobCancel = await dismissNextConfirmation(page, () => surface.getByLabel(/^Job #92:/u).getByRole('button', { name: 'Cancel', exact: true }).click());
  expect(jobCancel.type).toBe('confirm');
  expect(jobCancel.message).toContain('Cancel job #92?');
  expect(await request.get('/v1/jobs/92').then((response) => response.json())).toEqual(jobBefore);
  expect(await request.get('/v1/scans/39').then((response) => response.json())).toEqual(scanBefore);
  expect(await request.get('/__test/commands').then((response) => response.json())).toEqual(jobCommandsBefore);
  expect(mutations).toEqual([]);
  guards.assertClean();
});

test('[WEB-ACT-002] project registration and normal scan buttons persist the exact source and durable command', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Projects');
  await surface.locator('.project-registration > summary').click();
  await surface.getByLabel('Name', { exact: true }).fill('Operator Journey Service');
  await surface.getByLabel('Repository Path', { exact: true }).fill('/workspace/generated/operator-journey');
  await surface.getByLabel('Remote URL', { exact: true }).fill('https://example.invalid/operator-journey.git');
  await surface.getByRole('button', { name: 'Add Project', exact: true }).click();
  await expect(surface.locator('.project-row', { hasText: 'Operator Journey Service' })).toBeVisible();
  await expect(surface.locator('.project-row')).toHaveCount(2);
  const projects = await request.get('/v1/projects').then((response) => response.json()) as Array<{ id: number; name: string; repo_path: string }>;
  expect(projects).toEqual([
    expect.objectContaining({ id: 12, name: 'Operator Journey Service', repo_path: '/workspace/generated/operator-journey' }),
    expect.objectContaining({ id: 11, name: 'Generated Demo Service', repo_path: '/workspace/generated/demo-service' }),
  ]);
  const projectSelect = surface.locator('select[name="project_id"]');
  expect(await projectSelect.locator('option').evaluateAll((options) => options.map((option) => ({
    label: option.textContent,
    value: (option as HTMLOptionElement).value,
  })))).toEqual([
    { label: 'Operator Journey Service', value: '12' },
    { label: 'Generated Demo Service', value: '11' },
  ]);
  const openedProjectRow = surface.locator('.project-row', { hasText: 'Operator Journey Service' });
  await openedProjectRow.getByRole('button', { name: 'Open', exact: true }).click();
  await expect(projectSelect).toHaveValue('12');
  await expect(projectSelect).toBeFocused();
  await expect(openedProjectRow).toHaveAttribute('data-project-selected', 'true');
  await expect(surface.getByRole('status').filter({ hasText: 'Current project: Operator Journey Service.' })).toBeVisible();

  const scanButton = surface.getByRole('button', { name: 'Scan', exact: true });
  await scanButton.scrollIntoViewIfNeeded();
  const projectsScroll = await page.evaluate(() => {
    const main = document.querySelector('main');
    const heading = document.querySelector<HTMLHeadingElement>('h1[data-view-title="projects"]');
    if (!main || !heading) throw new Error('Projects route scroll evidence is unavailable.');
    return {
      headingBottom: heading.getBoundingClientRect().bottom,
      main: main.scrollTop,
      window: window.scrollY,
    };
  });
  expect(projectsScroll.headingBottom, 'Projects heading is above the viewport before the cross-route Scan action').toBeLessThan(0);
  expect(Math.max(projectsScroll.main, projectsScroll.window), 'one responsive route scroll owner is below its top').toBeGreaterThan(0);

  await scanButton.click();
  await expect(page.getByText('Scan #42 queued', { exact: true })).toBeVisible();
  await expect(page.locator('main')).toHaveAttribute('data-rendered-view', 'findings');
  const findingsHeading = page.getByRole('heading', { level: 1, name: 'Findings', exact: true });
  const findingsScanFilter = page.getByLabel('Scan', { exact: true });
  await expect(findingsHeading).toBeInViewport();
  await expect(findingsScanFilter).toBeInViewport();
  expect(await page.evaluate(() => ({
    main: document.querySelector('main')?.scrollTop ?? -1,
    window: window.scrollY,
  })), 'the committed Findings route resets both responsive scroll owners').toEqual({ main: 0, window: 0 });
  expect(await request.get('/v1/scans/42').then((response) => response.json())).toMatchObject({
    id: 42,
    project_id: 12,
    status: 'pending',
    gate_decision: 'pending',
  });
  const scans = await request.get('/v1/scans').then((response) => response.json()) as Array<{ id: number; project_id: number }>;
  expect(scans.map(({ id, project_id: projectId }) => ({ id, project_id: projectId }))).toEqual([
    { id: 42, project_id: 12 },
    { id: 41, project_id: 11 },
    { id: 40, project_id: 11 },
    { id: 39, project_id: 11 },
  ]);
  const registeredProjectIds = new Set(projects.map((project) => project.id));
  expect(scans.every((scan) => registeredProjectIds.has(scan.project_id)), 'every scan remains owned by a registered project').toBe(true);
  const commands = await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string; input: Record<string, unknown> }>;
  expect(commands).toEqual([expect.objectContaining({
    route: 'scan',
    input: expect.objectContaining({ project_id: 12, mode: 'full', coverage: 'complete', acknowledge_limited_coverage: false }),
  })]);
  guards.assertClean();
});

test('project source and scan selectors preserve exact operator intent', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const mutations = mutationRequestLog(page);

  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  let surface = await openRoute(page, 'Projects');
  await surface.locator('.project-registration > summary').click();
  const sourceToggle = surface.getByRole('button', { name: 'Authorize another source root', exact: true });
  await expect(sourceToggle).toHaveAttribute('aria-expanded', 'false');
  await sourceToggle.click();
  await expect(surface.locator('#source-authorization-setup')).toBeVisible();
  await expect(surface.getByRole('button', { name: 'Hide source setup', exact: true })).toHaveAttribute('aria-expanded', 'true');
  await surface.getByLabel('Exact source root', { exact: true }).fill('/workspace/generated/narrow-team');
  await expect(surface.getByLabel('Source authorization host command', { exact: true })).toHaveValue(/make apply-source$/u);
  await surface.getByRole('button', { name: 'Hide source setup', exact: true }).click();
  await expect(surface.locator('#source-authorization-setup')).toHaveCount(0);
  expect(mutations).toEqual([]);

  await surface.locator('select[name="mode"]').selectOption({ value: 'incremental_diff' });
  await surface.locator('input[name="base_ref"]').fill('origin/main');
  await surface.locator('input[name="head_ref"]').fill('feature/provider-ui');
  await surface.locator('input[name="use_ai"]').check();
  await surface.getByRole('button', { name: 'Scan', exact: true }).click();
  await expect(page.getByText('Scan #42 queued', { exact: true })).toBeVisible();
  const scanCommand = (await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string; input: Record<string, unknown> }>).find((command) => command.route === 'scan');
  expect(scanCommand?.input).toMatchObject({
    project_id: 11,
    mode: 'incremental_diff',
    base_ref: 'origin/main',
    head_ref: 'feature/provider-ui',
    use_ai: true,
    coverage: 'complete',
    acknowledge_limited_coverage: false,
  });
  guards.assertClean();
});

test('complete-coverage controls preserve explicit limited-scan acknowledgment', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  // A fresh page keeps the previous scan's polling separate from this fixture
  // reset, which deliberately replaces the server's projects and jobs.
  await request.post('/__test/reset', { data: { profile: 'scanner-preparation', generation: 2 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Projects');
  await acceptNextConfirmation(page, () => surface.getByRole('button', { name: 'Review Advanced Limited Scan', exact: true }).click());
  await expect(surface.getByRole('status').filter({ hasText: 'Advanced limited coverage acknowledged.' })).toBeVisible();
  await surface.getByRole('button', { name: 'Use complete coverage', exact: true }).click();
  await expect(surface.getByRole('button', { name: 'Review Advanced Limited Scan', exact: true })).toBeVisible();
  await expect(surface.getByRole('button', { name: 'Run Advanced Limited Scan', exact: true })).toHaveCount(0);
  expect((await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string }>).filter((command) => command.route === 'scan')).toHaveLength(0);
  guards.assertClean();
});

referenceTest('[WEB-FINDINGS-BULK-001] cross-page selection exposes its atomic limit and clear recovery', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'paginated-findings', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const selectedDetailRevisions: Array<[string | null, string | null]> = [];
  page.on('request', (candidate) => {
    const url = new URL(candidate.url());
    if (url.pathname === '/v1/scans/41/findings/1') {
      selectedDetailRevisions.push([
        url.searchParams.get('expected_revision'), url.searchParams.get('expected_findings_revision'),
      ]);
    }
  });
  await page.goto('/?view=findings&scan=41');
  const surface = page.locator('section[data-route-surface="findings"]');
  await expect(surface).toHaveAttribute('data-findings-render-stage', 'ready');
  await expandFindingDisclosure(surface, '.bulk-action-disclosure');
  const bulk = surface.getByRole('region', { name: 'Bulk finding actions' });
  const mutations = mutationRequestLog(page);
  for (let selectedPage = 1; selectedPage <= 8; selectedPage += 1) {
    await expect(surface.locator('.finding-list .pager span')).toHaveText(`${selectedPage} / 19`);
    await expect(surface.locator('.finding-list-item')).toHaveCount(25);
    await surface.getByRole('button', { name: 'Select visible', exact: true }).click();
    await expect(bulk.locator('strong')).toHaveText(`${selectedPage * 25} selected`);
    await surface.locator('.finding-list').getByTitle('Next page', { exact: true }).click();
  }
  await expect(surface.locator('.finding-list .pager span')).toHaveText('9 / 19');
  const needsReview = bulk.getByRole('button', { name: 'Needs review', exact: true });
  await expect(needsReview).toBeEnabled();
  const extra = surface.locator('.finding-list-item').first().getByRole('checkbox');
  await extra.check();
  await expect(bulk.locator('strong')).toHaveText('201 selected');
  const reason = 'Select at most 200 findings per action. 201 are selected across pages; deselect findings or clear the selection to continue.';
  await expect(bulk.getByRole('status')).toHaveText(reason);
  for (const name of ['Advisor', 'Non-blocking', 'Ignore', 'Accept Risk', 'False positive', 'Fixed', 'Needs review', 'Reopen', 'Delete']) {
    const action = bulk.getByRole('button', { name, exact: true });
    await expect(action).toBeDisabled();
    await expect(action).toHaveAccessibleDescription(reason);
  }
  expect(mutations).toEqual([]);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await testInfo.attach('bulk-201-disabled.png', {
    body: await bulk.screenshot(), contentType: 'image/png',
  });
  await extra.uncheck();
  await expect(needsReview).toBeEnabled();
  const selectedIds = Array.from({ length: 200 }, (_value, index) => 20_001 + index);
  const accepted = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && response.url() === new URL('/v1/findings/bulk', baseURL).href
  ));
  await needsReview.click();
  const response = await accepted;
  expect(response.status()).toBe(200);
  expect(response.request().postDataJSON()).toEqual({
    finding_ids: selectedIds,
    action: 'needs_review',
    expected_revisions: Object.fromEntries(selectedIds.map((id) => [id, 1])),
  });
  expect(await response.json()).toEqual({ updated: 200, deleted: 0, scan_ids: [41] });
  expect(await response.finished()).toBeNull();
  expect(await findingState(request, selectedIds)).toEqual(selectedIds.map((id) => ({
    id, lifecycle_status: 'needs_review', revision: 2,
    gate_effect: 'blocking', gate_exempt: false, suppressed: false,
  })));
  // Lifecycle updates preserve the checked set after reconciliation; only an
  // explicit Clear selection resets it before the next independent selection.
  await expect(needsReview).toBeEnabled();
  await expect(bulk.locator('strong')).toHaveText('200 selected');
  await expect(surface.locator('.finding-detail h2')).toHaveText('S41-F001');
  await expect(surface.locator('.finding-detail .identity-strip span').filter({ hasText: 'Lifecycle' }).locator('strong')).toHaveText('needs review');
  expect(selectedDetailRevisions).toEqual([['1', '1'], ['2', '2']]);
  await testInfo.attach('bulk-200-updated.png', {
    body: await surface.locator('.finding-detail').screenshot(), contentType: 'image/png',
  });
  await expect(surface.locator('.finding-list .pager span')).toHaveText('9 / 19');
  await expect(surface.locator('.finding-list-item input[type="checkbox"]:checked')).toHaveCount(0);
  for (let selectedPage = 8; selectedPage >= 1; selectedPage -= 1) {
    await surface.locator('.finding-list').getByTitle('Previous page', { exact: true }).click();
    await expect(surface.locator('.finding-list .pager span')).toHaveText(`${selectedPage} / 19`);
    await expect.poll(() => surface.locator('.finding-list-item input[type="checkbox"]').evaluateAll((inputs) => (
      inputs.map((input) => ({
        label: input.getAttribute('aria-label'), checked: (input as HTMLInputElement).checked,
      }))
    ))).toEqual(Array.from({ length: 25 }, (_value, index) => ({
      label: `Select S41-F${String((selectedPage - 1) * 25 + index + 1).padStart(3, '0')}`,
      checked: true,
    })));
    await expect(bulk.locator('strong')).toHaveText('200 selected');
  }
  await bulk.getByRole('button', { name: 'Clear selection', exact: true }).click();
  await expect(bulk.locator('.bulk-action-disclosure > summary')).toHaveText('No findings selected · Review actions');
  await expect(surface.locator('.finding-list-item.selected')).toHaveCount(0);
  await surface.getByRole('button', { name: 'Select visible', exact: true }).click();
  await expect(bulk.locator('strong')).toHaveText('25 selected');
  await bulk.getByRole('button', { name: 'Clear selection', exact: true }).click();
  await expect(bulk.locator('.bulk-action-disclosure > summary')).toHaveText('No findings selected · Review actions');
  await expect(surface.locator('.finding-list-item.selected')).toHaveCount(0);
  expect(mutations).toHaveLength(1);
  guards.assertClean();
});

test('scan rows and findings filters expose complete keyboard and clear-state behavior', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 3 } });
  let surface = await openRoute(page, 'Scans');
  const scan41 = surface.getByLabel('Open findings for scan #41', { exact: true });
  await scan41.focus();
  await expect(scan41).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  await expect(page.getByLabel('Scan', { exact: true })).toHaveValue('41');
  await expect(page.locator('section[data-route-surface="findings"]')).toHaveAttribute('data-findings-render-stage', 'ready');
  await page.getByRole('navigation').getByRole('button', { name: 'Scans', exact: true }).click();
  surface = page.locator('section[data-route-surface="scans"]');
  const scan40 = surface.getByLabel('Open findings for scan #40', { exact: true });
  await scan40.focus();
  await page.keyboard.press(' ');
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  await expect(page.getByLabel('Scan', { exact: true })).toHaveValue('40');
  await expect(page.locator('section[data-route-surface="findings"]')).toHaveAttribute('data-findings-render-stage', 'ready');

  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 4 } });
  surface = await openRoute(page, 'Findings');
  const clearFilters = surface.getByRole('button', { name: 'Clear filters', exact: true });
  await expect(clearFilters).toBeDisabled();
  const initiallySelected = surface.locator('.finding-list-item').first();
  await expect(surface.getByRole('list', { name: 'Findings in the current page', exact: true })).toHaveCount(1);
  await initiallySelected.locator('input[type="checkbox"]').check();
  await expect(surface.getByRole('region', { name: 'Bulk finding actions' })).toContainText('1 selected');
  await surface.getByLabel('Search findings', { exact: true }).fill('no finding can match this');
  await expect(surface.locator('.finding-list-item')).toHaveCount(0);
  await expect(surface.getByRole('list', { name: 'Findings in the current page', exact: true })).toHaveCount(0);
  await expect(surface.locator('.finding-detail')).toHaveCount(0);
  await expect(surface.locator('.finding-list')).toContainText('No findings match the current filters. Clear filters to review this scan.');
  await expect(surface.getByRole('region', { name: 'Bulk finding actions' })).toContainText('No findings selected');
  await expandFindingDisclosure(surface, '.bulk-action-disclosure');
  await expect(surface.getByRole('region', { name: 'Bulk finding actions' }).getByRole('button', { name: 'Non-blocking', exact: true })).toBeDisabled();
  await clearFilters.click();
  await expect(surface.locator('.finding-list-item')).toHaveCount(3);
  await expect(surface.getByRole('list', { name: 'Findings in the current page', exact: true })).toHaveCount(1);
  // Finish the restored detail before testing a different filter selection.
  await expect(surface.locator('.finding-detail')).toHaveAttribute('data-finding-id', '501');
  await expect(surface.locator('.finding-detail')).toHaveAttribute('aria-busy', 'false');
  const selectedDetailResponsePromise = page.waitForResponse((response) => (
    response.request().method() === 'GET'
    && new URL(response.url()).origin === new URL(baseURL).origin
    && new URL(response.url()).pathname === '/v1/scans/41/findings/2'
  ));
  await surface.getByLabel('Search findings', { exact: true }).fill('CKV_FIXTURE');
  const filters = surface.locator('.finding-filter-details');
  const filterSummary = filters.locator(':scope > summary');
  await expect(filters).not.toHaveAttribute('open', '');
  await filterSummary.focus();
  await expect(filterSummary).toBeFocused();
  await filterSummary.press('Enter');
  await expect(filters).toHaveAttribute('open', '');
  await filterSummary.press('Tab');
  await expect(surface.getByLabel('Severity', { exact: true })).toBeFocused();
  await surface.getByLabel('Severity', { exact: true }).selectOption('medium');
  await surface.getByLabel('Scanner', { exact: true }).selectOption('checkov');
  await surface.getByLabel('Lifecycle', { exact: true }).selectOption('non_blocking');
  await expect(filterSummary).toContainText('3 active');
  await expect(filterSummary).toContainText('medium · checkov · non blocking');
  await filterSummary.focus();
  await filterSummary.press(' ');
  await expect(filters).not.toHaveAttribute('open', '');
  await expect(filterSummary).toBeFocused();
  await expect(surface.getByLabel('Severity', { exact: true })).toBeHidden();
  await expect(filterSummary).toContainText('medium · checkov · non blocking');
  await expect(clearFilters).toBeEnabled();
  await expect(surface.locator('.finding-list-item')).toHaveCount(1);
  const selectedDetailResponse = await selectedDetailResponsePromise;
  expect(selectedDetailResponse.status()).toBe(200);
  expect(new URL(selectedDetailResponse.url()).searchParams.toString()).toBe('expected_revision=1&expected_findings_revision=1');
  expect(await selectedDetailResponse.json()).toMatchObject({
    id: 502, scan_id: 41, scan_finding_number: 2, revision: 1, findings_revision: 1,
  });
  const selectedDetail = surface.locator('.finding-detail');
  await expect(selectedDetail).toHaveAttribute('data-finding-id', '502');
  await expect(selectedDetail).toHaveAttribute('aria-busy', 'false');
  await clearFilters.click();
  await expect(surface.getByLabel('Search findings', { exact: true })).toHaveValue('');
  await expect(surface.getByLabel('Severity', { exact: true })).toHaveValue('all');
  await expect(surface.getByLabel('Scanner', { exact: true })).toHaveValue('all');
  await expect(surface.getByLabel('Lifecycle', { exact: true })).toHaveValue('all');
  await expect(filters).not.toHaveAttribute('open', '');
  await expect(filterSummary).toHaveText('Filters and scanner counts');
  await expect(clearFilters).toBeDisabled();
  await expect(surface.locator('.finding-list-item')).toHaveCount(3);
  await expect(selectedDetail).toHaveAttribute('data-finding-id', '502');
  await expect(selectedDetail).toHaveAttribute('aria-busy', 'false');
  await expect(selectedDetail.locator('h2')).toHaveText('S41-F002');
  expect(new URL(page.url()).searchParams.toString()).toBe('view=findings&scan=41&finding=2');
  const protectionNavigationMutations = mutationRequestLog(page);
  await surface.getByRole('button', { name: 'Manage push protection', exact: true }).click();
  const settings = page.locator('section[data-route-surface="settings"]');
  await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
  await expect(settings).not.toHaveAttribute('aria-busy', 'true');
  await expect(settings).not.toHaveAttribute('inert', '');
  await expect(settings.locator('#git-push-protection').getByRole('heading', { name: 'Git push protection', exact: true })).toBeInViewport();
  expect(new URL(page.url()).searchParams.get('view')).toBe('settings');
  expect(protectionNavigationMutations, 'opening protection settings must not change repository policy').toEqual([]);
  guards.assertClean();
});

test('Findings filter fallback keeps the exact visible finding URL and selected-scan empty guidance', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.goto('/?view=findings&scan=41&finding=2&lomo_browser=vscode');
  const surface = page.locator('section[data-route-surface="findings"]');
  const detail = surface.locator('.finding-detail');
  await expect(surface).toHaveAttribute('data-findings-render-stage', 'ready');
  await expect(detail).toHaveAttribute('data-finding-id', '502');
  await expect(detail).toHaveAttribute('aria-busy', 'false');
  const historyLength = await page.evaluate(() => history.length);
  const mutations = mutationRequestLog(page);
  const selected = surface.getByLabel('Select S41-F002', { exact: true });
  await selected.check();
  const search = surface.getByLabel('Search findings', { exact: true });
  await search.fill('no finding can match this');
  await expect(surface.locator('.finding-list-item')).toHaveCount(0);
  await expect(detail).toHaveCount(0);
  await expect(surface.locator('.finding-list')).toContainText('No findings match the current filters. Clear filters to review this scan.');
  await expect(surface.getByLabel('Scan', { exact: true })).toHaveValue('41');
  await expect.poll(() => new URL(page.url()).searchParams.get('finding')).toBeNull();
  await expect(surface.getByRole('region', { name: 'Bulk finding actions' })).toContainText('No findings selected');
  await surface.getByRole('button', { name: 'Clear filters', exact: true }).click();
  await expect(surface.locator('.finding-list-item')).toHaveCount(3);
  await expect(detail).toHaveAttribute('data-finding-id', '501');
  await expect.poll(() => new URL(page.url()).searchParams.get('finding')).toBe('1');
  await expect(surface.locator('.finding-list-item input:checked')).toHaveCount(0);
  await search.fill('CKV_FIXTURE_RESOURCE_LIMIT');
  await expect(detail).toHaveAttribute('data-finding-id', '502');
  await expect.poll(() => new URL(page.url()).searchParams.get('finding')).toBe('2');
  await surface.getByRole('button', { name: 'Clear filters', exact: true }).click();
  await expect(detail).toHaveAttribute('data-finding-id', '502');
  expect(new URL(page.url()).searchParams.get('finding')).toBe('2');
  expect(new URL(page.url()).searchParams.get('lomo_browser')).toBe('vscode');
  expect(await page.evaluate(() => history.length)).toBe(historyLength);
  await expect(detail).toHaveAttribute('aria-busy', 'false');
  await page.reload();
  await expect(surface).toHaveAttribute('data-findings-render-stage', 'ready');
  await expect(detail).toHaveAttribute('data-finding-id', '502');
  expect(mutations).toEqual([]);
  guards.assertClean();
});

test('lifecycle validation keeps the focused submit fully visible in a short dialog viewport', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  await page.setViewportSize({ width: 600, height: 432 });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Findings');
  const mutations = mutationRequestLog(page);
  const before = await findingState(request, [501, 502, 503]);
  const menu = surface.locator('.finding-detail .finding-action-menu');
  await menu.locator('summary').click();
  const trigger = menu.getByRole('button', { name: 'Accept risk', exact: true });
  await trigger.click();
  const dialog = page.getByRole('dialog');
  const field = dialog.getByLabel('Local audit reason', { exact: true });
  const submit = dialog.getByRole('button', { name: 'Mark accepted risk', exact: true });
  for (const value of ['', '   ']) {
    await field.fill(value);
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    await expect(submit).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(dialog.getByRole('alert')).toHaveText('Local audit reason is required. No change was made.');
    await expect(submit).toBeFocused();
    await expect.poll(() => submit.evaluate((button) => {
      const owner = button.closest('dialog')!;
      const viewport = owner.getBoundingClientRect();
      const control = button.getBoundingClientRect();
      const style = getComputedStyle(button);
      const outset = Math.max(0, Number.parseFloat(style.outlineWidth) + Number.parseFloat(style.outlineOffset));
      const top = Math.max(0, viewport.top + owner.clientTop);
      const bottom = Math.min(window.innerHeight, viewport.top + owner.clientTop + owner.clientHeight);
      const left = Math.max(0, viewport.left + owner.clientLeft);
      const right = Math.min(window.innerWidth, viewport.left + owner.clientLeft + owner.clientWidth);
      return button.matches(':focus-visible') && style.outlineStyle !== 'none' && outset > 0
        && control.top - outset >= top && control.bottom + outset <= bottom
        && control.left - outset >= left && control.right + outset <= right;
    })).toBe(true);
  }
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(trigger).toBeFocused();
  expect(await findingState(request, [501, 502, 503])).toEqual(before);
  expect(mutations).toEqual([]);
  guards.assertClean();
});

test('Baseline, component destinations, and Settings links expose exact bounded targets', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 5 } });
  const surface = await openRoute(page, 'Settings');
  const gate = surface.locator('.gate-policy-panel');
  await gate.getByRole('button', { name: /^Strict/u }).click();
  await gate.getByRole('button', { name: /^Baseline/u }).click();
  await expect(gate.getByRole('button', { name: /^Baseline/u })).toHaveClass(/active/u);
  await expect(gate.getByLabel('Enable gate evaluation', { exact: true })).toBeChecked();
  await expect(gate.getByLabel('Max critical', { exact: true })).toHaveValue('0');
  await expect(gate.getByLabel('Max high', { exact: true })).toHaveValue('-1');
  await expect(gate.getByLabel('Block secret findings', { exact: true })).toBeChecked();
  await gate.getByRole('button', { name: 'Save Gate', exact: true }).click();
  await expect(gate.getByRole('status')).toContainText('Gate defaults saved as baseline');
  expect(await request.get('/v1/config').then((response) => response.json())).toMatchObject({
    gate_preset: 'baseline', gate_active: true, gate_max_critical: 0, gate_max_high: -1, gate_block_secrets: true,
  });

  await expect(surface.locator('a.component-card', { hasText: /^control/u })).toHaveAttribute('href', `${new URL(baseURL).origin}/`);
  await expect(surface.locator('a.component-card', { hasText: /^scanner/u })).toHaveAttribute('href', `${new URL(baseURL).origin}/fixture/scanner`);
  const openApi = surface.getByRole('link', { name: 'OpenAPI schema', exact: true });
  await expect(openApi).toHaveAttribute('href', new URL('/openapi.json', baseURL).href);
  await expect(openApi).toHaveAttribute('target', '_blank');
  await expect(openApi).toHaveAttribute('rel', 'noreferrer');
  const config = await request.get('/v1/config').then((response) => response.json()) as {
    components: Array<{ id: string; desired_enabled: boolean; desired_state: string;
      observed_state: string; healthy: boolean; reachable: boolean; url: string; message: string }>;
  };
  const links = surface.locator('.band').filter({ has: page.getByRole('heading', { name: 'Links', exact: true }) });
  for (const [id, label] of [['grafana', 'Grafana'], ['gitea', 'Gitea'], ['prometheus', 'Prometheus']] as const) {
    expect(config.components.find((component) => component.id === id)).toMatchObject({
      desired_enabled: false, desired_state: 'disabled', observed_state: 'not_observed',
      healthy: false, reachable: false, url: '',
      message: 'Not observed; optional component is desired off.',
    });
    const disabled = links.getByText(`${label} · disabled`, { exact: true });
    await expect(disabled).toBeVisible();
    await expect(disabled).toHaveAttribute('aria-disabled', 'true');
    await expect(disabled).toHaveAttribute('title', 'Not observed; optional component is desired off.');
    await expect(links.getByRole('link', { name: label, exact: true })).toHaveCount(0);
  }
  guards.assertClean();
});

test('local Advisor commands pin the exact authoritative provider for single, scan-wide, and bulk triage', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const expectedPin = await currentLocalAdvisorPin(request);
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let surface = await openRoute(page, 'Findings');
  let resolvedProviders = await observeAdvisorProviderReadBeforePost(page, new URL(baseURL).origin, '/v1/findings/501/triage', async () => {
    await surface.locator('.finding-detail').getByRole('button', { name: 'Run Advisor', exact: true }).click();
    await expect(page.getByText(/Advisor job #\d+ queued/u)).toBeVisible();
  });
  expect(localAdvisorPin(resolvedProviders)).toEqual(expectedPin);
  let commands = await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string; input: Record<string, unknown> }>;
  expect(commands).toEqual([expect.objectContaining({
    route: 'finding-advisor',
    input: { expected_revision: 1, advisor_provider_pin: expectedPin },
  })]);
  expect(await request.get('/__test/requests').then((response) => response.json())).toMatchObject({
    advisorPreviews: 0,
    advisorSubmissions: 1,
  });
  await page.waitForLoadState('networkidle');

  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 2 } });
  surface = await openRoute(page, 'Findings');
  resolvedProviders = await observeAdvisorProviderReadBeforePost(page, new URL(baseURL).origin, '/v1/scans/41/triage', async () => {
    await surface.getByRole('button', { name: 'Scan Advisor', exact: true }).click();
    await expect(page.getByText(/Advisor job #\d+ queued/u)).toBeVisible();
  });
  expect(localAdvisorPin(resolvedProviders)).toEqual(expectedPin);
  commands = await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string; input: Record<string, unknown> }>;
  expect(commands).toEqual([expect.objectContaining({
    route: 'scan-advisor',
    input: { include_existing: false, advisor_provider_pin: expectedPin },
  })]);
  await page.waitForLoadState('networkidle');

  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 3 } });
  surface = await openRoute(page, 'Findings');
  await surface.locator('.finding-list-item', { hasText: 'S41-F001' }).getByRole('checkbox').check();
  await surface.locator('.finding-list-item', { hasText: 'S41-F002' }).getByRole('checkbox').check();
  await expandFindingDisclosure(surface, '.bulk-action-disclosure');
  resolvedProviders = await observeAdvisorProviderReadBeforePost(page, new URL(baseURL).origin, '/v1/findings/bulk', async () => {
    await surface.getByRole('region', { name: 'Bulk finding actions' }).getByRole('button', { name: 'Advisor', exact: true }).click();
    await expect(page.getByText(/Advisor job #\d+ queued/u)).toBeVisible();
  });
  expect(localAdvisorPin(resolvedProviders)).toEqual(expectedPin);
  commands = await request.get('/__test/commands').then((response) => response.json()) as Array<{ route: string; input: Record<string, unknown> }>;
  expect(commands).toEqual([expect.objectContaining({
    route: 'bulk-advisor',
    input: {
      finding_ids: [501, 502],
      action: 'triage',
      expected_revisions: { 501: 1, 502: 1 },
      advisor_provider_pin: expectedPin,
    },
  })]);
  await page.waitForLoadState('networkidle');
  guards.assertClean();
});

test('active remote Advisor explicitly submits one exact finding while scan-wide and bulk triage send nothing', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'advisor-remote-disabled', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const mutations = mutationRequestLog(page);
  const jobsBefore = await request.get('/v1/jobs?limit=500').then((response) => response.json());
  // Admit the settled initial snapshot before testing Advisor actions. A user
  // navigating during this prefetch intentionally cancels its older owner.
  await openRoute(page, 'Overview');
  expect(await request.get('/__test/requests').then((response) => response.json())).toMatchObject({
    findings: 1,
    findingDetails: 0,
    scanSummaries: 2,
    artifacts: 1,
  });
  await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  let surface = page.locator('section[data-route-surface="findings"]');
  await expect(surface).toHaveCount(1);
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await expect(surface).not.toHaveAttribute('inert', '');
  await page.waitForLoadState('networkidle');
  await surface.locator('.finding-list-item', { hasText: 'S41-F002' }).locator('.finding-list-main').click();
  await expect(surface.locator('.advisor-panel')).toContainText(
    'supports one explicit finding submission after its exact disclosure preview is reviewed and confirmed',
  );
  await expect(surface.locator('.advisor-panel')).toContainText(
    'Automatic remote routing, scan-wide review, and bulk review remain unavailable',
  );
  await surface.locator('.finding-list-item', { hasText: 'S41-F001' }).locator('.finding-list-main').click();

  const previewResponsePromise = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/v1/findings/501/advisor-disclosure-preview'
  ));
  const previewProviders = await observeAdvisorProviderReadBeforePost(page, new URL(baseURL).origin, '/v1/findings/501/advisor-disclosure-preview', async () => {
    await surface.locator('.finding-detail').getByRole('button', { name: 'Run Advisor', exact: true }).click();
    await previewResponsePromise;
  });
  const previewResponse = await previewResponsePromise;
  expect(previewResponse.ok()).toBe(true);
  const preview = await previewResponse.json() as AdvisorDisclosurePreviewFixture;
  const confirmation = preview.confirmation;
  expect(previewProviders).toMatchObject({
    active_provider_id: confirmation.provider_id,
    providers: expect.arrayContaining([expect.objectContaining({
      id: confirmation.provider_id,
      transport: confirmation.transport,
      config_revision: confirmation.provider_config_revision,
      config_digest: confirmation.provider_config_digest,
      model: confirmation.model,
      model_digest: confirmation.model_digest,
    })]),
  });
  const expectedPacket = {
    schema_version: 1,
    finding: {
      id: 501,
      display_id: 'S41-F001',
      scanner: 'opengrep',
      rule_id: 'javascript.lang.audit.dynamic-code',
      severity: 'high',
      message: 'Dynamic code execution can consume untrusted input.',
      fingerprint: 'fixture-fingerprint-001',
    },
    location: {
      file_path: 'src/handler.ts',
      start_line: 12,
      start_column: null,
      end_line: 12,
      end_column: null,
    },
    repo_context: {
      project: 'Generated Demo Service',
      repo_path: '/workspace/generated/demo-service',
      remote_url: null,
      scan_id: 41,
      mode: 'full',
      base_ref: null,
      head_ref: null,
    },
    scanner_evidence: {
      code_snippet: 'export function handle(userInput: string) {\n  const normalized = userInput.trim();\n  return eval(normalized);\n}',
      metadata: { snippet_start_line: 10 },
    },
  };
  const expectedPacketBytes = Buffer.byteLength(JSON.stringify(expectedPacket, null, 2), 'utf8');
  expect(preview.packet).toEqual(expectedPacket);
  expect(preview.packet_utf8_bytes).toBe(expectedPacketBytes);
  const dialog = page.getByRole('dialog', { name: 'Review one Advisor disclosure', exact: true });
  await expect(dialog).toBeVisible();
  for (const value of [
    'Synthetic Direct Review',
    'direct-review',
    'direct',
    'http://192.0.2.202:11434',
    `revision ${confirmation.provider_config_revision}`,
    confirmation.provider_config_digest,
    'S41-F001',
    `revision ${confirmation.finding_revision}`,
    confirmation.model,
    confirmation.model_digest,
    confirmation.prompt_sha256,
    confirmation.confirmation_digest,
    ...advisorDisclosureCategories,
  ]) await expect(dialog).toContainText(value);
  await expect(dialog.getByText(`${expectedPacketBytes} UTF-8 bytes`, { exact: true })).toBeVisible();
  await expect(dialog.getByText(
    `${expectedPacketBytes} UTF-8 bytes in the serialized JSON block`,
    { exact: true },
  )).toBeVisible();
  const displayedPacketFields = [
    ['schema_version', '1'],
    ['finding.id', '501'],
    ['finding.display_id', 'S41-F001'],
    ['finding.scanner', 'opengrep'],
    ['finding.rule_id', 'javascript.lang.audit.dynamic-code'],
    ['finding.severity', 'high'],
    ['finding.message', 'Dynamic code execution can consume untrusted input.'],
    ['finding.fingerprint', 'fixture-fingerprint-001'],
    ['location.file_path', 'src/handler.ts'],
    ['location.start_line', '12'],
    ['location.start_column', 'null'],
    ['location.end_line', '12'],
    ['location.end_column', 'null'],
    ['repo_context.project', 'Generated Demo Service'],
    ['repo_context.repo_path', '/workspace/generated/demo-service'],
    ['repo_context.remote_url', 'null'],
    ['repo_context.scan_id', '41'],
    ['repo_context.mode', 'full'],
    ['repo_context.base_ref', 'null'],
    ['repo_context.head_ref', 'null'],
    ['scanner_evidence.code_snippet', expectedPacket.scanner_evidence.code_snippet],
    ['scanner_evidence.metadata', JSON.stringify(expectedPacket.scanner_evidence.metadata, null, 2)],
  ] as const;
  const packetRows = dialog.locator('.advisor-confirmation-packet > dl > div');
  await expect(packetRows).toHaveCount(displayedPacketFields.length);
  for (const [index, [key, value]] of displayedPacketFields.entries()) {
    await expect(packetRows.nth(index).locator('dt code')).toHaveText(key);
    expect(await packetRows.nth(index).locator('dd pre').textContent()).toBe(value);
  }
  const authorize = dialog.getByRole('button', { name: 'Authorize & send one finding', exact: true });
  await expect(authorize).toBeDisabled();
  await expect(dialog.getByText('I authorize sending this one bounded finding disclosure', { exact: false })).toBeVisible();
  expect(await dialog.innerText()).toContain('return eval(normalized)');
  expect(await dialog.innerText()).not.toContain('?view=');
  expect(await request.get('/__test/commands').then((response) => response.json())).toEqual([]);
  expect(await request.get('/v1/jobs?limit=500').then((response) => response.json())).toEqual(jobsBefore);
  expect(await request.get('/__test/requests').then((response) => response.json())).toMatchObject({
    advisorPreviews: 1,
    advisorSubmissions: 0,
  });
  await dialog.getByRole('button', { name: 'Cancel — send nothing', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('No finding evidence was sent and no Advisor job was created.', { exact: true })).toBeVisible();
  expect(await request.get('/__test/commands').then((response) => response.json())).toEqual([]);
  expect(await request.get('/v1/jobs?limit=500').then((response) => response.json())).toEqual(jobsBefore);
  expect(await request.get('/__test/requests').then((response) => response.json())).toMatchObject({ advisorPreviews: 1, advisorSubmissions: 0 });

  const secondPreviewPromise = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/v1/findings/501/advisor-disclosure-preview'
  ));
  const secondPreviewProviders = await observeAdvisorProviderReadBeforePost(page, new URL(baseURL).origin, '/v1/findings/501/advisor-disclosure-preview', async () => {
    await surface.locator('.finding-detail').getByRole('button', { name: 'Run Advisor', exact: true }).click();
    await secondPreviewPromise;
  });
  expect(secondPreviewProviders).toEqual(previewProviders);
  const secondPreviewResponse = await secondPreviewPromise;
  expect(secondPreviewResponse.ok()).toBe(true);
  const secondPreview = await secondPreviewResponse.json() as AdvisorDisclosurePreviewFixture;
  const secondConfirmation = secondPreview.confirmation;
  expect(secondConfirmation.authorization_id).toMatch(/^[0-9a-f]{32}$/u);
  expect(secondConfirmation.authorization_id).not.toBe(confirmation.authorization_id);
  expect(secondConfirmation.confirmation_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(secondConfirmation.confirmation_digest).not.toBe(confirmation.confirmation_digest);
  expect(secondPreview).toEqual({
    ...preview,
    confirmation: {
      ...confirmation,
      authorization_id: secondConfirmation.authorization_id,
      confirmation_digest: secondConfirmation.confirmation_digest,
    },
  });
  const confirmedDialog = page.getByRole('dialog', { name: 'Review one Advisor disclosure', exact: true });
  await expect(confirmedDialog).toContainText(secondConfirmation.confirmation_digest);
  await expect(confirmedDialog).not.toContainText(confirmation.confirmation_digest);
  await expect(confirmedDialog.getByRole('button', { name: 'Authorize & send one finding', exact: true })).toBeDisabled();
  await confirmedDialog.getByRole('checkbox', { name: 'I authorize sending this one bounded finding disclosure', exact: false }).check();
  const submissionPromise = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/v1/findings/501/triage'
  ));
  await confirmedDialog.getByRole('button', { name: 'Authorize & send one finding', exact: true }).click();
  expect((await submissionPromise).status()).toBe(202);
  await expect(confirmedDialog).toHaveCount(0);
  await expect(page.getByText(/Remote Advisor job #\d+ queued/u)).toBeVisible();
  await expect(page.getByText('Watch Jobs for transport and terminal status.', { exact: false })).toBeVisible();
  const jobsAfterSubmission = await request.get('/v1/jobs?limit=500').then((response) => response.json()) as unknown[];
  expect(jobsAfterSubmission).toHaveLength((jobsBefore as unknown[]).length + 1);
  const commands = await request.get('/__test/commands').then((response) => response.json()) as Array<{
    input: Record<string, unknown>;
    method: string;
    route: string;
  }>;
  expect(commands).toHaveLength(1);
  expect(commands[0]).toMatchObject({ method: 'POST', route: 'finding-advisor-remote' });
  expect(Object.keys(commands[0].input).sort()).toEqual([
    'acknowledge_remote_source_disclosure',
    'expected_revision',
    'remote_advisor_confirmation',
  ]);
  expect(commands[0].input).toEqual({
    expected_revision: 1,
    acknowledge_remote_source_disclosure: true,
    remote_advisor_confirmation: secondConfirmation,
  });

  await expect(page.getByRole('heading', { level: 1, name: 'Jobs', exact: true })).toBeVisible();
  await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  surface = page.locator('section[data-route-surface="findings"]');
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await expect(surface).not.toHaveAttribute('inert', '');
  await expect(surface.locator('.finding-detail')).not.toHaveAttribute('aria-busy', 'true');

  await page.waitForLoadState('networkidle');
  const resolutionsBeforeScan = (
    await request.get('/__test/requests').then((response) => response.json()) as { advisorProviderResolutions: number }
  ).advisorProviderResolutions;
  const scanAdvisor = surface.getByRole('button', { name: 'Scan Advisor', exact: true });
  const scanDisabledReason = 'Scan-wide Advisor review is disabled because Synthetic Direct Review is a remote provider. Remote Advisor use remains limited to one selected finding after its exact disclosure preview is confirmed.';
  await expect(scanAdvisor).toBeDisabled();
  await expect(scanAdvisor).toHaveAttribute('title', scanDisabledReason);
  await expect(scanAdvisor).toHaveAttribute('aria-describedby', 'scan-advisor-disabled-reason');
  const scanGuidance = surface.locator('details.finding-advisor-guidance');
  await expect(scanGuidance).not.toHaveAttribute('open', '');
  const scanGuidanceSummary = scanGuidance.locator('summary');
  await expect(scanGuidanceSummary).toHaveAccessibleName('Why is Scan Advisor unavailable?');
  await scanGuidanceSummary.focus();
  await scanGuidanceSummary.press('Enter');
  await expect(scanGuidance).toHaveAttribute('open', '');
  await expect(surface.locator('#scan-advisor-disabled-reason')).toBeVisible();
  await expect(surface.locator('#scan-advisor-disabled-reason')).toHaveText(scanDisabledReason);
  expect(await request.get('/__test/requests').then((response) => response.json())).toMatchObject({
    advisorProviderResolutions: resolutionsBeforeScan,
    advisorPreviews: 2,
    advisorSubmissions: 1,
  });
  expect(await request.get('/__test/commands').then((response) => response.json())).toEqual(commands);
  expect(await request.get('/v1/jobs?limit=500').then((response) => response.json())).toEqual(jobsAfterSubmission);

  await surface.locator('.finding-list-item', { hasText: 'S41-F001' }).getByRole('checkbox').check();
  await surface.locator('.finding-list-item', { hasText: 'S41-F002' }).getByRole('checkbox').check();
  await expandFindingDisclosure(surface, '.bulk-action-disclosure');
  const bulkActions = surface.getByRole('region', { name: 'Bulk finding actions' });
  await expect(bulkActions.locator('strong')).toHaveText('2 selected');
  const bulkAdvisor = bulkActions.getByRole('button', { name: 'Advisor', exact: true });
  await expect(bulkAdvisor).toBeEnabled();
  const resolutionsBeforeBulk = (
    await request.get('/__test/requests').then((response) => response.json()) as { advisorProviderResolutions: number }
  ).advisorProviderResolutions;
  const bulkProviderResponsePromise = page.waitForResponse((response) => (
    response.request().method() === 'GET'
    && response.url() === new URL('/v1/advisor/providers', baseURL).href
  ));
  await bulkAdvisor.click();
  const bulkProviderResponse = await bulkProviderResponsePromise;
  expect(bulkProviderResponse.status()).toBe(200);
  expect(await bulkProviderResponse.json()).toEqual(secondPreviewProviders);
  await expect(page.locator('.notice')).toHaveText('Remote Advisor review through Synthetic Direct Review requires one selected finding and an exact disclosure confirmation. Select one finding and choose Run Advisor; no bulk request was sent.');
  await expect.poll(async () => (
    await request.get('/__test/requests').then((response) => response.json()) as { advisorProviderResolutions: number }
  ).advisorProviderResolutions).toBe(resolutionsBeforeBulk + 1);
  await expect(page.getByText('Queuing selected advisor reviews', { exact: true })).toHaveCount(0);
  expect(await request.get('/__test/commands').then((response) => response.json())).toEqual(commands);
  expect(await request.get('/v1/jobs?limit=500').then((response) => response.json())).toEqual(jobsAfterSubmission);
  expect(await request.get('/__test/requests').then((response) => response.json())).toMatchObject({
    advisorPreviews: 2,
    advisorSubmissions: 1,
  });
  expect(mutations).toEqual([
    'POST /v1/findings/501/advisor-disclosure-preview',
    'POST /v1/findings/501/advisor-disclosure-preview',
    'POST /v1/findings/501/triage',
  ]);

  await expect(surface.locator('.finding-detail')).not.toHaveAttribute('aria-busy', 'true');
  await page.getByRole('navigation').getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Settings', exact: true })).toBeVisible();
  surface = page.locator('section[data-route-surface="settings"]');
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await expect(surface).not.toHaveAttribute('inert', '');
  const panel = surface.locator('#advisor-providers');
  const direct = panel.locator('.advisor-provider-card', { hasText: 'Synthetic Direct Review' });
  await expect(panel.locator('.advisor-provider-resolution')).toContainText('Resolved provider none');
  await expect(panel.locator('.advisor-provider-resolution')).toContainText('Transport unavailable');
  await expect(panel.locator('.advisor-provider-resolution')).toContainText('Remote Advisor requires confirmation for one exact finding.');
  await expect(direct.getByText('activated', { exact: true })).toBeVisible();
  await expect(direct.locator('.advisor-provider-details').getByText('no', { exact: true })).toBeVisible();
  await expect(direct).toContainText('active for this exact configuration');
  await expect(direct).toContainText('Ready for an explicit one-finding Advisor review');
  guards.assertClean();
});

test('Advisor provider pin interleaving rejects stale single, scan-wide, and bulk submissions before durable enqueue', async ({ request }) => {
  const commands = [
    {
      path: '/v1/findings/501/triage',
      input: (pin: AdvisorTriageProviderPinFixture) => ({ expected_revision: 1, advisor_provider_pin: pin }),
    },
    {
      path: '/v1/scans/41/triage',
      input: (pin: AdvisorTriageProviderPinFixture) => ({ include_existing: false, advisor_provider_pin: pin }),
    },
    {
      path: '/v1/findings/bulk',
      input: (pin: AdvisorTriageProviderPinFixture) => ({
        finding_ids: [501, 502],
        action: 'triage',
        expected_revisions: { 501: 1, 502: 1 },
        advisor_provider_pin: pin,
      }),
    },
  ] as const;

  for (const [index, command] of commands.entries()) {
    await request.post('/__test/reset', { data: { profile: 'fresh', generation: index + 10 } });
    const pin = await currentLocalAdvisorPin(request);
    const jobsBefore = await request.get('/v1/jobs?limit=500').then((response) => response.json());
    const removed = await request.delete('/v1/advisor/providers/local-default', {
      data: { expected_revision: pin.provider_collection_revision },
    });
    expect(removed.ok()).toBe(true);

    const response = await request.post(command.path, {
      headers: { 'Idempotency-Key': `web-00000000-0000-4000-8000-00000000000${index + 1}` },
      data: command.input(pin),
    });
    expect(response.status()).toBe(409);
    expect(await response.json()).toEqual({ detail: {
      code: 'advisor_provider_selection_stale',
      message: 'Advisor provider configuration changed after selection; no Advisor job was queued.',
      action: 'refresh_advisor_providers',
      safe_details: {
        expected_revision: 1,
        current_revision: 2,
      },
    } });
    expect(await request.get('/__test/commands').then((result) => result.json())).toEqual([]);
    expect(await request.get('/v1/jobs?limit=500').then((result) => result.json())).toEqual(jobsBefore);
  }
});

test('single-finding Advisor surfaces a stale provider-pin interleaving and queues no durable job', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 20 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const jobsBefore = await request.get('/v1/jobs?limit=500').then((response) => response.json());
  let submittedPin: AdvisorTriageProviderPinFixture | null = null;
  await page.route('**/v1/findings/501/triage', async (route) => {
    const input = route.request().postDataJSON() as { advisor_provider_pin?: AdvisorTriageProviderPinFixture };
    if (!input.advisor_provider_pin) throw new Error('The UI omitted its exact Advisor provider pin.');
    const pin = input.advisor_provider_pin;
    submittedPin = pin;
    const removed = await request.delete(`/v1/advisor/providers/${pin.provider_id}`, {
      data: { expected_revision: pin.provider_collection_revision },
    });
    if (!removed.ok()) throw new Error(`Could not create the provider interleaving: HTTP ${removed.status()}.`);
    await route.continue();
  });

  const surface = await openRoute(page, 'Findings');
  const responsePromise = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/v1/findings/501/triage'
  ));
  await surface.locator('.finding-detail').getByRole('button', { name: 'Run Advisor', exact: true }).click();
  const response = await responsePromise;
  expect(response.status()).toBe(409);
  expect(await response.json()).toEqual({ detail: {
    code: 'advisor_provider_selection_stale',
    message: 'Advisor provider configuration changed after selection; no Advisor job was queued.',
    action: 'refresh_advisor_providers',
    safe_details: {
      expected_revision: 1,
      current_revision: 2,
    },
  } });
  expect(submittedPin).toMatchObject({
    provider_collection_revision: 1,
    provider_id: 'local-default',
    transport: 'local',
  });
  await expect(page.locator('.notice')).toContainText('Advisor provider configuration changed after selection; no Advisor job was queued.');
  expect(await request.get('/__test/commands').then((result) => result.json())).toEqual([]);
  expect(await request.get('/v1/jobs?limit=500').then((result) => result.json())).toEqual(jobsBefore);
  expect(guards.failures.http).toEqual([`409 ${new URL(baseURL).origin}/v1/findings/501/triage`]);
  expect(guards.failures.console).toHaveLength(1);
  expect(guards.failures.console[0]).toContain('409 (Conflict)');
  expect(guards.failures.page).toEqual([]);
  expect(guards.failures.request).toEqual([]);
  expect(guards.failures.egress).toEqual([]);
  expect(guards.failures.credentialUrl).toEqual([]);
});

test('remote Advisor rejects a stale disclosure preview before confirmation and sends no finding evidence', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'advisor-remote-disabled', generation: 21 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const mutations = mutationRequestLog(page);
  const jobsBefore = await request.get('/v1/jobs?limit=500').then((response) => response.json());
  let interleaved = false;
  await page.route('**/v1/findings/501/advisor-disclosure-preview', async (route) => {
    const changed = await request.patch('/v1/findings/501/lifecycle', { data: {
      action: 'needs_review',
      expected_revision: 1,
    } });
    if (!changed.ok()) throw new Error(`Could not create the finding interleaving: HTTP ${changed.status()}.`);
    interleaved = true;
    await route.continue();
  });

  const surface = await openRoute(page, 'Findings');
  const responsePromise = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/v1/findings/501/advisor-disclosure-preview'
  ));
  await observeAdvisorProviderReadBeforePost(
    page, new URL(baseURL).origin, '/v1/findings/501/advisor-disclosure-preview',
    async () => {
      await surface.locator('.finding-detail').getByRole('button', { name: 'Run Advisor', exact: true }).click();
      await responsePromise;
    },
  );
  const response = await responsePromise;
  expect(interleaved).toBe(true);
  expect(response.status()).toBe(409);
  expect(await response.json()).toEqual({ detail: {
    code: 'revision_conflict',
    message: 'The selected finding changed before disclosure preview.',
    action: 'refresh_findings',
    context: { finding_id: 501, expected_revision: 1, current_revision: 2 },
    safe_details: { expected_revision: 1, current_revision: 2 },
  } });
  await expect(page.locator('.notice')).toHaveText('The selected finding or remote disclosure changed before Advisor could queue a review. No evidence was sent.');
  await expect(page.getByRole('dialog', { name: 'Review one Advisor disclosure', exact: true })).toHaveCount(0);
  expect(await request.get('/__test/commands').then((result) => result.json())).toEqual([]);
  expect(await request.get('/v1/jobs?limit=500').then((result) => result.json())).toEqual(jobsBefore);
  expect(await request.get('/__test/requests').then((result) => result.json())).toMatchObject({
    advisorPreviews: 1,
    advisorSubmissions: 0,
  });
  expect(mutations).toEqual(['POST /v1/findings/501/advisor-disclosure-preview']);
  expect(guards.failures.http).toEqual([`409 ${new URL(baseURL).origin}/v1/findings/501/advisor-disclosure-preview`]);
  expect(guards.failures.console).toHaveLength(1);
  expect(guards.failures.console[0]).toContain('409 (Conflict)');
  expect(guards.failures.page).toEqual([]);
  expect(guards.failures.request).toEqual([]);
  expect(guards.failures.egress).toEqual([]);
  expect(guards.failures.credentialUrl).toEqual([]);
});

test('fake API durably admits one exact remote confirmation', async ({ request }) => {
  await request.post('/__test/reset', { data: { profile: 'advisor-remote-disabled', generation: 1 } });
  const collectionResponse = await request.get('/v1/advisor/providers');
  expect(collectionResponse.ok()).toBe(true);
  expect(await collectionResponse.json()).toMatchObject({
    active_provider_id: 'direct-review',
    resolution: {
      provider_id: null,
      transport: 'unavailable',
      reason: 'remote_single_finding_confirmation_required',
      eligible_provider_ids: [],
    },
  });

  const previewResponse = await request.post('/v1/findings/501/advisor-disclosure-preview', { data: {
    expected_revision: 1,
    provider_id: 'direct-review',
  } });
  expect(previewResponse.ok()).toBe(true);
  const preview = await previewResponse.json() as AdvisorDisclosurePreviewFixture;
  expect(preview.confirmation).toMatchObject({
    schema: 'lomo-advisor-run-confirmation/v1',
    provider_id: 'direct-review',
    transport: 'direct',
    destination: 'http://192.0.2.202:11434',
    payload_categories: [...advisorDisclosureCategories],
    finding_id: 501,
    finding_revision: 1,
  });
  expect(preview.confirmation.authorization_id).toMatch(/^[0-9a-f]{32}$/u);

  const submitResponse = await request.post('/v1/findings/501/triage', {
    headers: { 'Idempotency-Key': 'web-00000000-0000-4000-8000-000000000001' },
    data: {
      expected_revision: 1,
      acknowledge_remote_source_disclosure: true,
      remote_advisor_confirmation: preview.confirmation,
    },
  });
  expect(submitResponse.status()).toBe(202);
  const submittedJob = await submitResponse.json() as { id: number };
  expect(submittedJob).toMatchObject({
    kind: 'advisor',
    status: 'queued',
    scan_id: 41,
    finding_id: 501,
    detail: 'Disclosure-bound direct Advisor job persisted for one finding.',
  });
  const replayResponse = await request.post('/v1/findings/501/triage', {
    headers: { 'Idempotency-Key': 'web-00000000-0000-4000-8000-000000000002' },
    data: {
      expected_revision: 1,
      acknowledge_remote_source_disclosure: true,
      remote_advisor_confirmation: preview.confirmation,
    },
  });
  expect(replayResponse.status()).toBe(202);
  expect(await replayResponse.json()).toMatchObject({ id: submittedJob.id });
  expect(await request.get('/__test/commands').then((response) => response.json())).toMatchObject([{
    method: 'POST',
    route: 'finding-advisor-remote',
    input: {
      expected_revision: 1,
      acknowledge_remote_source_disclosure: true,
      remote_advisor_confirmation: preview.confirmation,
    },
  }]);
  expect(await request.get('/__test/requests').then((response) => response.json())).toMatchObject({
    advisorProviderResolutions: 1,
    advisorPreviews: 1,
    advisorSubmissions: 2,
  });
});

test('Findings search, severity, scanner, lifecycle, and pager controls change the visible evidence', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let surface = await openRoute(page, 'Findings');

  const search = surface.getByLabel('Search findings', { exact: true });
  await search.fill('CKV_FIXTURE_RESOURCE_LIMIT');
  await expect(surface.locator('.list-head strong')).toHaveText('1 finding');
  await expect(surface.locator('.finding-list-item')).toHaveCount(1);
  await expect(surface.locator('.finding-list-item')).toContainText('S41-F002');
  await search.fill('');

  await expandFindingDisclosure(surface, '.finding-filter-details');
  await surface.getByLabel('Severity', { exact: true }).selectOption('high');
  await expect(surface.locator('.finding-list-item')).toHaveCount(1);
  await expect(surface.locator('.finding-list-item')).toContainText('S41-F001');
  await surface.getByLabel('Severity', { exact: true }).selectOption('all');
  await surface.locator('.scanner-tile', { hasText: 'checkov' }).click();
  await expect(surface.locator('.finding-list-item')).toHaveCount(1);
  await expect(surface.locator('.finding-list-item')).toContainText('S41-F002');
  await surface.locator('.scanner-tile', { hasText: 'checkov' }).click();
  await surface.getByLabel('Lifecycle', { exact: true }).selectOption('ignored');
  await expect(surface.locator('.finding-list-item')).toHaveCount(1);
  await expect(surface.locator('.finding-list-item')).toContainText('S41-F003');

  await request.post('/__test/reset', { data: { profile: 'large-findings', generation: 2 } });
  // Overview prefetches the reset dataset too. Settle that owner before
  // switching views so this paging test keeps the ordinary error guards.
  await openRoute(page, 'Overview');
  await page.waitForLoadState('networkidle');
  await page.getByRole('navigation').getByRole('button', { name: 'Findings', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Findings', exact: true })).toBeVisible();
  surface = page.locator('section[data-route-surface="findings"]');
  await expect(surface).toHaveCount(1);
  await expect(surface).not.toHaveAttribute('aria-busy', 'true');
  await expect(surface).not.toHaveAttribute('inert', '');
  await page.waitForLoadState('networkidle');
  await expect(surface.locator('.finding-list .pager span')).toHaveText('1 / 401');
  await surface.locator('.finding-list').getByTitle('Next page').click();
  await expect(surface.locator('.finding-list .pager span')).toHaveText('2 / 401');
  await expect(surface.locator('.finding-list-item', { hasText: 'S41-F026' })).toBeVisible();
  await surface.locator('.finding-list').getByTitle('Previous page').click();
  await expect(surface.locator('.finding-list .pager span')).toHaveText('1 / 401');
  await expect(surface.locator('.finding-list-item', { hasText: 'S41-F001' })).toBeVisible();
  guards.assertClean();
});

test('IDE authority: Web source navigation excludes invalid records, guides only-invalid recovery, and reports command states', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const capability = {
    state: 'valid' as const,
    id: SOURCE_OPEN_IDE_SLOT,
    client_name: 'VS Code QA',
    scopes: ['source:open-ack'],
    created_at: '2026-08-26T00:00:00Z',
    expires_at: '2027-08-26T00:00:00Z',
    revoked: false,
    active: true,
    connected: true,
    active_generation: 1,
    latest_generation: 1,
    pending_activation: false,
    pending_generation: null,
    pending_client_name: null,
    pending_activation_expires_at: null,
    source_open_available: true,
    source_open_disabled_reason: null as string | null,
    invalid_recovery_token: null,
  };
  const invalidCapability = {
    state: 'invalid',
    id: INVALID_IDE_SLOT,
    client_name: 'Invalid IDE client record',
    scopes: [],
    created_at: null,
    revoked: false,
    active: false,
    connected: false,
    active_generation: null,
    latest_generation: null,
    pending_activation: false,
    pending_generation: null,
    pending_client_name: null,
    pending_activation_expires_at: null,
    source_open_available: false,
    source_open_disabled_reason: 'This IDE client record is invalid or not active.',
    invalid_recovery_token: INVALID_IDE_RECOVERY_TOKEN_A,
  };
  let capabilities = [invalidCapability, capability];
  let terminalStatus: 'opened' | 'failed' = 'opened';
  let nextCommand = 1;
  let releaseFirstWait = () => {};
  const firstWaitReleased = new Promise<void>((resolve) => { releaseFirstWait = resolve; });
  let observeFirstWait = () => {};
  const firstWaitObserved = new Promise<void>((resolve) => { observeFirstWait = resolve; });
  const sourceRequests: Array<{ headers: Record<string, string>; payload: Record<string, unknown> }> = [];
  const commands = new Map<string, Record<string, unknown>>();

  await page.route('**/v1/auth/ide/capabilities', async (route) => {
    await route.fulfill({ json: capabilities });
  });
  await page.route('**/v1/ide/source-open-commands', async (route) => {
    const candidate = route.request();
    const id = String(nextCommand).padStart(32, '0');
    nextCommand += 1;
    const payload = candidate.postDataJSON() as Record<string, unknown>;
    sourceRequests.push({ headers: candidate.headers(), payload });
    const command = {
      id,
      finding_id: payload.finding_id,
      project_id: 11,
      scan_id: 41,
      scan_finding_number: 1,
      expected_finding_revision: payload.expected_finding_revision,
      expected_findings_revision: payload.expected_findings_revision,
      target_capability_id: payload.target_capability_id,
      expected_target_generation: payload.expected_target_generation,
      status: 'queued',
      revision: 1,
      error_code: null,
      created_at: '2026-08-26T00:00:00Z',
      expires_at: '2026-08-26T00:05:00Z',
      acknowledged_at: null,
    };
    commands.set(id, command);
    await route.fulfill({ status: 201, json: command });
  });
  await page.route(/\/v1\/ide\/source-open-commands\/[0-9]{32}\/wait$/u, async (route) => {
    const id = new URL(route.request().url()).pathname.split('/').at(-2) || '';
    const command = commands.get(id);
    if (!command) throw new Error(`Unknown source-open command ${id}`);
    if (id === '00000000000000000000000000000001') {
      observeFirstWait();
      await firstWaitReleased;
    }
    await route.fulfill({
      json: {
        ...command,
        status: terminalStatus,
        revision: 2,
        error_code: terminalStatus === 'failed' ? 'workspace_not_open' : null,
        acknowledged_at: '2026-08-26T00:00:01Z',
      },
    });
  });

  const surface = await openRoute(page, 'Findings');
  await expect(surface.locator('.finding-detail h2')).toHaveText('S41-F001');
  const ideConnection = surface.locator('.finding-ide-menu > summary');
  await ideConnection.click();
  const targetSelector = surface.getByLabel('IDE target for source navigation');
  await expect(targetSelector).toHaveValue(SOURCE_OPEN_IDE_SLOT);
  await expect(targetSelector.getByRole('option', { name: /Invalid IDE client record/u })).toHaveCount(0);
  const openSource = surface.getByRole('button', { name: 'Open source in VS Code', exact: true });
  await openSource.click();
  await firstWaitObserved;
  await expect(surface.getByRole('status').filter({ hasText: 'VS Code source request: queued.' })).toBeVisible();
  releaseFirstWait();
  await expect(surface.getByRole('status').filter({ hasText: 'VS Code source request: opened.' })).toBeVisible();

  expect(sourceRequests[0]?.payload).toEqual({
    finding_id: 501,
    expected_finding_revision: 1,
    expected_findings_revision: 1,
    target_capability_id: SOURCE_OPEN_IDE_SLOT,
    expected_target_generation: 1,
  });
  expect(sourceRequests[0]?.headers['idempotency-key']).toMatch(/^web-[0-9a-f-]+$/u);

  terminalStatus = 'failed';
  await surface.getByRole('button', { name: 'Open source in VS Code', exact: true }).click();
  await expect(surface.getByRole('status').filter({ hasText: 'VS Code source request: failed (workspace_not_open).' })).toBeVisible();

  capabilities = [invalidCapability, {
    ...capability,
    source_open_available: false,
    source_open_disabled_reason: 'This IDE capability has multiple connected windows. Close or re-pair until exactly one target window is connected.',
  }];
  await surface.getByTitle('Refresh connected IDE clients').click();
  await expect(surface.getByRole('button', { name: 'Open source in VS Code', exact: true })).toBeDisabled();
  await expect(surface.locator('#finding-source-unavailable-reason')).toHaveText(capabilities[1].source_open_disabled_reason!);
  await expect(surface.locator('#finding-source-unavailable-reason')).toBeVisible();
  await expect(openSource).toHaveAccessibleDescription(capabilities[1].source_open_disabled_reason!);
  await ideConnection.click();
  await expect(surface.locator('#finding-source-unavailable-reason')).toBeVisible();
  await expect(openSource).toHaveAccessibleDescription(capabilities[1].source_open_disabled_reason!);
  await ideConnection.click();
  expect(sourceRequests).toHaveLength(2);

  capabilities = [invalidCapability];
  await surface.getByTitle('Refresh connected IDE clients').click();
  await expect(targetSelector).toHaveValue('');
  await expect(targetSelector.getByRole('option')).toHaveCount(1);
  await expect(targetSelector.getByRole('option', { name: /Invalid IDE client record/u })).toHaveCount(0);
  await expect(surface.getByRole('button', { name: 'Open source in VS Code', exact: true })).toBeDisabled();
  const invalidRecoveryReason = 'Only invalid IDE client records are available. Open Settings → IDE access, remove each exact invalid profile record, then let VS Code request access again before opening source.';
  await expect(surface.locator('#finding-source-unavailable-reason')).toHaveText(invalidRecoveryReason);
  await expect(surface.locator('#finding-source-unavailable-reason')).toBeVisible();
  await expect(openSource).toHaveAccessibleDescription(invalidRecoveryReason);
  expect(sourceRequests).toHaveLength(2);

  capabilities = [capability, { ...capability, id: SETTINGS_IDE_SLOT, client_name: 'VS Code second workspace' }];
  await surface.getByTitle('Refresh connected IDE clients').click();
  await expect(targetSelector).toHaveValue('');
  await expect(openSource).toBeDisabled();
  await expect(surface.locator('#finding-source-unavailable-reason')).toHaveText('Choose one connected editor under IDE.');
  await expect(surface.locator('#finding-source-unavailable-reason')).toBeVisible();
  await expect(openSource).toHaveAccessibleDescription('Choose one connected editor under IDE.');
  await targetSelector.selectOption(SETTINGS_IDE_SLOT);
  await expect(openSource).toBeEnabled();
  expect(sourceRequests).toHaveLength(2);
  await ideConnection.click();
  await expect(targetSelector).not.toBeVisible();
  await openSource.click();
  await expect.poll(() => sourceRequests.length).toBe(3);
  expect(sourceRequests[2]?.payload.target_capability_id).toBe(SETTINGS_IDE_SLOT);
  await expect(surface.getByRole('status').filter({ hasText: 'VS Code source request: failed (workspace_not_open).' })).toBeVisible();
  guards.assertClean();
});

test('every single-finding lifecycle menu action persists its exact state', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Findings');
  const actions = [
    ['Non-blocking for gate', 'gate_exempt', 'non-blocking for gate'],
    ['Accept risk', 'accepted_risk', 'accepted risk'],
    ['Ignore / not counted', 'ignore', 'ignored and not counted'],
    ['False positive', 'false_positive', 'a false positive'],
    ['Mark fixed', 'fixed', 'fixed'],
    ['Needs review', 'needs_review', null],
    ['Reopen as blocking', 'open', null],
  ] as const;

  for (const [buttonName, expectedStatus, reasonLabel] of actions) {
    const menu = surface.locator('.finding-detail .finding-action-menu');
    if (!await menu.evaluate((element: HTMLDetailsElement) => element.open)) {
      await menu.locator('summary').click();
    }
    const trigger = () => menu.getByRole('button', { name: buttonName, exact: true }).click();
    if (reasonLabel) {
      const { dialog, field } = await openLifecycleReason(page, 'S41-F001', reasonLabel, trigger);
      await field.fill('Generated operator lifecycle reason.');
      await dialog.getByRole('button', { name: `Mark ${reasonLabel}`, exact: true }).click();
      await expect(dialog).toHaveCount(0);
    } else {
      await trigger();
    }
    await expect.poll(() => findingLifecycle(request, [501])).toEqual([expectedStatus]);
    if (reasonLabel) expect(await findingLifecycleReasons(request, [501])).toEqual([
      'Generated operator lifecycle reason.',
    ]);
    await expect(surface.locator('.finding-detail h2')).toHaveText('S41-F001');
  }
  guards.assertClean();
});

for (const viewport of [{ name: 'desktop', width: 1440, height: 900 }, { name: 'compact native dashboard', width: 776, height: 460 }]) {
test(`every bulk lifecycle button persists the selected set without losing the selection (${viewport.name})`, async ({ page, request, baseURL }) => {
  await page.setViewportSize({ width: viewport.width, height: viewport.height });
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Findings');
  const untouched = await findingState(request, [503]);
  const selected = [{ id: 501, display_id: 'S41-F001' }, { id: 502, display_id: 'S41-F002' }];
  await prepareBulkFindingSelection({ page, surface, selected, assertCurrent: async () => {} });
  const bulk = surface.getByRole('region', { name: 'Bulk finding actions' });
  await expect(bulk.locator('strong')).toHaveText('2 selected');

  let expectedRevision = 1;
  for (const [buttonName, expectedStatus, reasonLabel] of BULK_LIFECYCLE_ACTIONS) {
    const reason = reasonLabel ? 'Generated bulk lifecycle reason.' : null;
    const mutation = await performBulkFindingAction({ page, surface, endpoint: baseURL,
      action: expectedStatus, reason, assertCurrent: async () => {} });
    verifyBulkFindingRequest(mutation, { selected: selected.map(row => ({ ...row, revision: expectedRevision })),
      action: expectedStatus, reason, scanId: 41 });
    expectedRevision += 1;
    await expect.poll(() => findingLifecycle(request, [501, 502])).toEqual([expectedStatus, expectedStatus]);
    if (reasonLabel) expect(await findingLifecycleReasons(request, [501, 502])).toEqual([
      'Generated bulk lifecycle reason.',
      'Generated bulk lifecycle reason.',
    ]);
    // Backend persistence can precede UI reconciliation. The action remains
    // disabled until that refresh settles; wait for its actual local owner.
    await expect(bulk.getByRole('button', { name: buttonName, exact: true })).toBeEnabled();
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await expect(bulk.locator('strong')).toHaveText('2 selected');
    await expect(surface.getByLabel('Select S41-F001', { exact: true })).toBeChecked();
    await expect(surface.getByLabel('Select S41-F002', { exact: true })).toBeChecked();
    await waitForBulkSelection({ page, selected, status: expectedStatus });
  }
  expect(await findingState(request, [503])).toEqual(untouched);
  guards.assertClean();
});
}

test('dismissing every finding lifecycle prompt and delete confirmation is a zero-mutation operation', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Findings');
  const mutations = mutationRequestLog(page);
  const findingBefore = await findingState(request, [501, 502]);
  const scanBefore = await request.get('/v1/scans/41').then((response) => response.json());
  const commandsBefore = await request.get('/__test/commands').then((response) => response.json());
  const singleActions = [
    ['Non-blocking for gate', 'non-blocking for gate'],
    ['Accept risk', 'accepted risk'],
    ['Ignore / not counted', 'ignored and not counted'],
    ['False positive', 'a false positive'],
    ['Mark fixed', 'fixed'],
  ] as const;
  const lifecycleMenu = surface.locator('.finding-detail .finding-action-menu');

  for (const [buttonName, reasonLabel] of singleActions) {
    if (!await lifecycleMenu.evaluate((element: HTMLDetailsElement) => element.open)) await lifecycleMenu.locator('summary').click();
    const { dialog, field } = await openLifecycleReason(page, 'S41-F001', reasonLabel,
      () => lifecycleMenu.getByRole('button', { name: buttonName, exact: true }).click());
    await field.fill('Unsaved cancellation regression input');
    await dialog.evaluate((element) => {
      element.addEventListener('cancel', (event) => {
        event.preventDefault();
        event.stopImmediatePropagation();
      }, { capture: true });
    });
    await field.press('Escape');
    await expect(dialog).toHaveCount(0);
    await expect(lifecycleMenu.getByRole('button', { name: buttonName, exact: true })).toBeFocused();
    expect(await findingState(request, [501, 502])).toEqual(findingBefore);
    expect(await request.get('/v1/scans/41').then((response) => response.json())).toEqual(scanBefore);
    expect(mutations).toEqual([]);
  }

  const findingDelete = await dismissNextConfirmation(page, () => lifecycleMenu.getByRole('button', { name: 'Delete finding', exact: true }).click());
  expect(findingDelete).toEqual({
    type: 'confirm',
    message: 'Delete S41-F001 (javascript.lang.audit.dynamic-code) from this scan?',
    title: 'Delete S41-F001?',
  });
  expect(await findingState(request, [501, 502])).toEqual(findingBefore);
  expect(await request.get('/v1/scans/41').then((response) => response.json())).toEqual(scanBefore);
  expect(mutations).toEqual([]);

  if (await lifecycleMenu.evaluate((element: HTMLDetailsElement) => element.open)) await lifecycleMenu.locator('summary').click();
  await surface.locator('.finding-list-item', { hasText: 'S41-F001' }).getByRole('checkbox').check();
  await surface.locator('.finding-list-item', { hasText: 'S41-F002' }).getByRole('checkbox').check();
  await expandFindingDisclosure(surface, '.bulk-action-disclosure');
  const bulk = surface.getByRole('region', { name: 'Bulk finding actions' });
  await expect(bulk.locator('strong')).toHaveText('2 selected');
  const bulkActions = [
    ['Non-blocking', 'non-blocking for gate'], ['Accept Risk', 'accepted risk'],
    ['Ignore', 'ignored and not counted'], ['False positive', 'a false positive'], ['Fixed', 'fixed'],
  ] as const;
  for (const [buttonName, reasonLabel] of bulkActions) {
    const action = BULK_LIFECYCLE_ACTIONS.find(row => row[0] === buttonName)![1];
    await performBulkFindingAction({ page, surface, endpoint: baseURL, action,
      reason: 'Cancelled qualification draft.', cancel: true, assertCurrent: async () => {} });
    await expect(bulk.locator('strong')).toHaveText('2 selected');
    expect(await findingState(request, [501, 502])).toEqual(findingBefore);
    expect(await request.get('/v1/scans/41').then((response) => response.json())).toEqual(scanBefore);
    expect(mutations).toEqual([]);
  }

  expect(await performBulkFindingAction({ page, surface, endpoint: baseURL, action: 'delete',
    cancel: true, assertCurrent: async () => {} })).toEqual({ action: 'delete', cancelled: true });
  await expect(bulk.locator('strong')).toHaveText('2 selected');
  expect(await findingState(request, [501, 502])).toEqual(findingBefore);
  expect(await request.get('/v1/scans/41').then((response) => response.json())).toEqual(scanBefore);
  expect(await request.get('/__test/commands').then((response) => response.json())).toEqual(commandsBefore);
  expect(mutations).toEqual([]);
  guards.assertClean();
});

test('dismissing project and scan deletion preserves resources, evidence, and revisions without mutation requests', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const mutations = mutationRequestLog(page);

  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  let surface = await openRoute(page, 'Projects');
  const projectsBefore = await request.get('/v1/projects').then((response) => response.json());
  const projectScansBefore = await request.get('/v1/scans').then((response) => response.json());
  const projectFindingsBefore = await findingState(request, [501, 502, 503]);
  mutations.length = 0;
  const projectDelete = await dismissNextConfirmation(page, () => surface.getByTitle('Delete project and scan data').click());
  expect(projectDelete).toEqual({
    type: 'confirm',
    message: 'Delete project Generated Demo Service and all related scans/findings/artifacts?',
    title: 'Delete project Generated Demo Service?',
  });
  expect(await request.get('/v1/projects').then((response) => response.json())).toEqual(projectsBefore);
  expect(await request.get('/v1/scans').then((response) => response.json())).toEqual(projectScansBefore);
  expect(await findingState(request, [501, 502, 503])).toEqual(projectFindingsBefore);
  expect(mutations).toEqual([]);

  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 2 } });
  surface = await openRoute(page, 'Scans');
  const scansBefore = await request.get('/v1/scans').then((response) => response.json());
  const scanBefore = await request.get('/v1/scans/41').then((response) => response.json());
  const scanFindingsBefore = await findingState(request, [501, 502, 503]);
  mutations.length = 0;
  const scanDelete = await dismissNextConfirmation(page, () => surface.getByRole('row').filter({ hasText: '#41' }).getByTitle('Delete scan, findings, and artifacts').click());
  expect(scanDelete).toEqual({
    type: 'confirm',
    message: 'Delete scan #41, findings, and publishable artifacts?',
    title: 'Delete scan #41?',
  });
  expect(await request.get('/v1/scans').then((response) => response.json())).toEqual(scansBefore);
  expect(await request.get('/v1/scans/41').then((response) => response.json())).toEqual(scanBefore);
  expect(await findingState(request, [501, 502, 503])).toEqual(scanFindingsBefore);
  expect(mutations).toEqual([]);
  guards.assertClean();
});

test('bulk finding deletion confirms scope and removes only the selected findings', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Findings');
  await surface.locator('.finding-list-item', { hasText: 'S41-F001' }).getByRole('checkbox').check();
  await surface.locator('.finding-list-item', { hasText: 'S41-F002' }).getByRole('checkbox').check();
  await expandFindingDisclosure(surface, '.bulk-action-disclosure');
  const deletion = await performBulkFindingAction({ page, surface, endpoint: baseURL,
    action: 'delete', assertCurrent: async () => {} });
  verifyBulkFindingRequest(deletion, { selected: [{ id: 501, revision: 1 }, { id: 502, revision: 1 }], action: 'delete', scanId: 41 });
  await expect(page.getByText('2 findings deleted', { exact: true })).toBeVisible();
  await expect(surface.locator('.list-head strong')).toHaveText('1 finding');
  expect(await findingLifecycle(request, [501, 502])).toEqual([null, null]);
  guards.assertClean();
});

test('shared bulk race rejects stale revisions without retry and refresh preserves the selected findings', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Findings');
  const selected = [{ id: 501, revision: 1, display_id: 'S41-F001' }, { id: 502, revision: 1, display_id: 'S41-F002' }];
  await prepareBulkFindingSelection({ page, surface, selected, assertCurrent: async () => {} });
  const before = await findingState(request, [501, 502, 503]);
  let afterCompeting: Awaited<ReturnType<typeof findingState>> | null = null;
  let afterScan: unknown;
  const mutations = mutationRequestLog(page);
  const race = await armBulkFindingRace({ page, endpoint: baseURL, selected, observeCompeting: async fault => {
    expect(fault).toEqual({ kind: 'controlled-api-race-fault', mutation_requests: 1, finding_id: 501, expected_revision: 1 });
    afterCompeting = await findingState(request, [501, 502, 503]);
    expect(afterCompeting).toEqual([{ ...before[0], lifecycle_status: 'needs_review', revision: 2 }, before[1], before[2]]);
    afterScan = await request.get('/v1/scans/41').then(response => response.json());
    return { status: 'PASS' };
  } });
  try {
    const rejected = await performBulkFindingAction({ page, surface, endpoint: baseURL,
      action: 'needs_review', assertCurrent: async () => {} });
    expect(race.observed().status).toBe('PASS');
    verifyBulkFindingRequest(rejected, { selected, action: 'needs_review', scanId: 41, conflict: { '501': 2 } });
  } finally { await race.close(); }
  await expect(page.getByText('Bulk finding action failed', { exact: true })).toBeVisible();
  expect(await findingState(request, [501, 502, 503])).toEqual(afterCompeting);
  expect(await request.get('/v1/scans/41').then(response => response.json())).toEqual(afterScan);
  expect(mutations).toHaveLength(1);
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  const current = selected.map(row => ({ ...row, revision: row.id === 501 ? 2 : 1,
    status: row.id === 501 ? 'needs_review' as const : 'gate_exempt' as const }));
  await waitForBulkSelection({ page, selected: current });
  const reopened = await performBulkFindingAction({ page, surface, endpoint: baseURL,
    action: 'open', assertCurrent: async () => {} });
  verifyBulkFindingRequest(reopened, { selected: current, action: 'open', scanId: 41 });
  await waitForBulkSelection({ page, selected, status: 'open' });
  expect(await findingState(request, [501, 502, 503])).toEqual([
    { ...before[0], revision: 3 }, { ...before[1], revision: 2, lifecycle_status: 'open',
      gate_exempt: false, gate_effect: 'blocking', suppressed: false }, before[2],
  ]);
  expect(mutations).toHaveLength(2);
  expect(guards.failures.http).toEqual([`409 ${new URL('/v1/findings/bulk', baseURL).href}`]);
  expect(guards.failures.console).toEqual(['Failed to load resource: the server responded with a status of 409 (Conflict)']);
  guards.failures.http.length = 0; guards.failures.console.length = 0;
  guards.assertClean();
});

test('project deletion rejects active durable work and exposes the exact cancellation path', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let surface = await openRoute(page, 'Projects');
  const confirmation = await acceptNextConfirmation(page, () => surface.getByTitle('Delete project and scan data').click());
  expect(confirmation.message).toContain('Delete project Generated Demo Service and all related scans/findings/artifacts?');
  const deletionFailure = page.locator('.toast-stack').getByRole('alert').filter({
    has: page.locator('strong', { hasText: /^Project delete failed$/u }),
  });
  await expect(deletionFailure).toHaveCount(1);
  await expect(deletionFailure.locator('strong')).toHaveText('Project delete failed');
  await expect(deletionFailure.locator('span')).toHaveText('resource has active durable job #83; cancel and wait for terminal cleanup first');
  expect(await request.get('/v1/projects').then((response) => response.json())).toHaveLength(1);

  surface = await openRoute(page, 'Jobs');
  const running = surface.locator('.job-row', { hasText: 'Scan #39' });
  await acceptNextConfirmation(page, () => running.getByRole('button', { name: 'Cancel', exact: true }).click());
  await expect(page.getByText('Job #83 cancelling', { exact: true })).toBeVisible();
  expect(await request.get('/v1/jobs/83').then((response) => response.json())).toMatchObject({
    id: 83,
    status: 'cancelling',
    can_cancel: false,
  });
  expect(guards.failures.http).toHaveLength(1);
  expect(guards.failures.http[0]).toContain('409');
  expect(guards.failures.console).toHaveLength(1);
  expect(guards.failures.console[0]).toContain('409');
  expect(guards.failures.page).toEqual([]);
  expect(guards.failures.request).toEqual([]);
  expect(guards.failures.egress).toEqual([]);
  expect(guards.failures.credentialUrl).toEqual([]);
});

test('quiescent project deletion confirms cascade scope and leaves source registration usable', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'quiescent', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Projects');
  const deleteProjectButton = surface.getByTitle('Delete project and scan data');
  const safeDialog = await openConfirmation(page, () => deleteProjectButton.click());
  const keepProjectButton = safeDialog.dialog.getByRole('button', { name: 'Keep project', exact: true });
  await expect(keepProjectButton).toBeFocused();
  await keepProjectButton.press('Enter');
  await expect(safeDialog.dialog).toHaveCount(0);
  await expect(deleteProjectButton).toBeFocused();
  expect(await request.get('/v1/projects').then((response) => response.json())).toHaveLength(1);

  const confirmation = await acceptNextConfirmation(page, () => deleteProjectButton.click());
  expect(confirmation.message).toContain('Delete project Generated Demo Service and all related scans/findings/artifacts?');
  await expect(page.getByText('Project deleted', { exact: true })).toBeVisible();
  await expect(surface.locator('.project-row')).toHaveCount(0);
  await expect(surface.locator('.project-registration')).toHaveAttribute('open', '');
  await expect(surface.getByLabel('Name', { exact: true })).toBeVisible();
  await expect(surface.getByLabel('Name', { exact: true })).toBeEnabled();
  expect(await request.get('/v1/projects').then((response) => response.json())).toEqual([]);
  expect(await request.get('/v1/scans').then((response) => response.json())).toEqual([]);
  guards.assertClean();
});

test('scan deletion confirms evidence scope while preserving unrelated scans', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Scans');
  const scan = surface.getByRole('row').filter({ hasText: '#41' });
  const confirmation = await acceptNextConfirmation(page, () => scan.getByTitle('Delete scan, findings, and artifacts').click());
  expect(confirmation.message).toContain('Delete scan #41, findings, and publishable artifacts?');
  await expect(page.getByText('Scan #41 deleted', { exact: true })).toBeVisible();
  await expect(surface.getByRole('row').filter({ hasText: '#41' })).toHaveCount(0);
  const remaining = await request.get('/v1/scans').then((response) => response.json()) as Array<{ id: number }>;
  expect(remaining.map((item) => item.id)).toEqual([40, 39]);
  expect((await request.get('/v1/scans/41')).status()).toBe(404);
  guards.assertClean();
});

test('artifact controls open and download the exact same-origin sanitized fixture', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Findings');
  const scope = surface.locator('.finding-scan-details');
  const scopeSummary = scope.locator(':scope > summary');
  await expect(scope).not.toHaveAttribute('open', '');
  await expect(scopeSummary).toContainText('1 artifact');
  await scopeSummary.focus();
  await scopeSummary.press('Enter');
  await expect(scope).toHaveAttribute('open', '');
  await expect(scope.getByRole('heading', { name: /^Scan Scope(?: |$)/u })).toBeVisible();
  await expect(scope.getByRole('heading', { name: /^Derived Artifacts(?: |$)/u })).toBeVisible();
  const artifact = surface.locator('.artifact-card', { hasText: 'syft' });
  const open = artifact.getByRole('link', { name: 'Open', exact: true });
  expect(new URL(await open.getAttribute('href') || '', baseURL).pathname).toBe('/v1/artifacts/301/open');
  await expect(open).toHaveAttribute('target', '_blank');
  const popupPromise = page.waitForEvent('popup');
  await open.click();
  const popup = await popupPromise;
  await popup.waitForLoadState('domcontentloaded');
  expect(new URL(popup.url()).pathname).toBe('/v1/artifacts/301/open');
  const openedBody = JSON.parse((await popup.locator('body').innerText()).trim());
  expect(openedBody).toMatchObject({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: 'urn:uuid:generated-playwright-artifact-301',
    components: [],
  });
  await popup.close();

  const downloadLink = artifact.getByRole('link', { name: 'Download', exact: true });
  expect(new URL(await downloadLink.getAttribute('href') || '', baseURL).pathname).toBe('/v1/artifacts/301/download');
  const downloadPromise = page.waitForEvent('download');
  await downloadLink.click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('scan-41-syft.cyclonedx.json');
  const stream = await download.createReadStream();
  if (!stream) throw new Error('Artifact download stream is unavailable.');
  let body = '';
  for await (const chunk of stream) body += Buffer.from(chunk).toString('utf8');
  expect(JSON.parse(body)).toMatchObject({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: 'urn:uuid:generated-playwright-artifact-301',
    components: [],
  });
  guards.assertClean();
});

});

test('pending IDE verification code stays fully readable beside the longest accepted client name', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const verificationCode = '7KDM-P9QH';
  const enrollmentClientName = `Tablet profile · ${'x'.repeat(120)}`.slice(0, 120);
  await page.route('**/v1/auth/ide/enrollments', async (route) => {
    await route.fulfill({ json: [{
      request_id: `ker1_${'v'.repeat(24)}`,
      state: 'awaiting_approval',
      revision: 1,
      verification_code: verificationCode,
      scopes: ['event:read', 'scan:create'],
      client_slot: SETTINGS_IDE_SLOT,
      client_name: enrollmentClientName,
      generation: 2,
      requested_at: new Date(Date.now() - 1_000).toISOString(),
      activation_expires_at: new Date(Date.now() + 600_000).toISOString(),
    }] });
  });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  const surface = await openRoute(page, 'Settings');
  const pendingRequests = surface.getByRole('list', { name: 'Pending IDE access requests', exact: true });
  await expect(pendingRequests).toContainText(enrollmentClientName);
  const visibleVerificationCode = pendingRequests.locator('.ide-enrollment-code');
  await expect(visibleVerificationCode).toHaveText(verificationCode);
  const geometry = await visibleVerificationCode.evaluate((element) => {
    const row = element.closest('.ide-enrollment-row');
    if (!(row instanceof HTMLElement)) throw new Error('Pending IDE enrollment row is missing.');
    const bounds = element.getBoundingClientRect();
    const rowBounds = row.getBoundingClientRect();
    const style = getComputedStyle(element);
    return {
      clientWidth: element.clientWidth,
      fontSize: Number.parseFloat(style.fontSize),
      left: bounds.left,
      overflow: style.overflow,
      right: bounds.right,
      rowLeft: rowBounds.left,
      rowRight: rowBounds.right,
      scrollWidth: element.scrollWidth,
      textOverflow: style.textOverflow,
    };
  });
  expect(geometry.left).toBeGreaterThanOrEqual(geometry.rowLeft - 0.5);
  expect(geometry.right).toBeLessThanOrEqual(geometry.rowRight + 0.5);
  expect(geometry.fontSize).toBeGreaterThanOrEqual(16);
  expect(geometry.scrollWidth).toBeLessThanOrEqual(geometry.clientWidth + 1);
  expect(geometry.overflow).not.toBe('hidden');
  expect(geometry.textOverflow).not.toBe('ellipsis');
  guards.assertClean();
});

test('primary Jobs, Settings, and Tools actions remain reachable and stateful at every non-reference viewport', async ({ page, request, baseURL }, testInfo) => {
  test.skip(testInfo.project.name === 'desktop-1440', 'The deep reference suite covers this viewport.');
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  expect(['desktop-1920', 'tablet-768', 'mobile-390']).toContain(testInfo.project.name);
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  let surface = await openRoute(page, 'Settings');

  const gate = surface.locator('.gate-policy-panel');
  await gate.getByRole('button', { name: /^Observe/u }).click();
  await gate.getByRole('button', { name: 'Save Gate', exact: true }).click();
  await expect(gate.getByRole('status')).toContainText('Gate defaults saved as observe');
  expect(await request.get('/v1/config').then((response) => response.json())).toMatchObject({
    gate_preset: 'observe',
    gate_active: false,
    component_db_admin_enabled: false,
  });

  const components = surface.locator('.band').filter({ has: page.locator('form[data-settings-form="components"]') });
  await expect(components.getByRole('heading', { name: 'Components More information', exact: true })).toBeVisible();
  await components.getByLabel('Database UI: Adminer', { exact: true }).check();
  await components.getByRole('button', { name: 'Save Desired Components', exact: true }).click();
  await expect(components.locator('.command-box code')).toHaveText('make apply-components COMPONENTS=db-admin');
  expect(await request.get('/v1/config').then((response) => response.json())).toMatchObject({
    gate_preset: 'observe',
    component_db_admin_enabled: true,
    component_apply_command: 'make apply-components COMPONENTS=db-admin',
  });

  surface = await openRoute(page, 'Tools');
  const openGrep = surface.locator('.tool-card', { hasText: 'OpenGrep' });
  await openGrep.getByRole('button', { name: 'Disable', exact: true }).click();
  await expect(openGrep.locator('.pill')).toHaveText('disabled');
  expect(await request.get('/v1/scanner/tools').then((response) => response.json())).toEqual(expect.arrayContaining([
    expect.objectContaining({ id: 'opengrep', enabled: false }),
  ]));

  await request.post('/__test/reset', { data: { profile: 'durable', generation: 2 } });
  surface = await openRoute(page, 'Jobs');
  const filters = surface.getByRole('group', { name: 'Job filters', exact: true });
  const search = filters.getByLabel('Search jobs', { exact: true });
  await filters.getByLabel('Job status', { exact: true }).selectOption('active');
  await filters.getByLabel('Job kind', { exact: true }).selectOption('advisor');
  await search.pressSequentially('Leased advisor');
  await expect(search).toBeFocused();
  await expect(search).toHaveValue('Leased advisor');
  await expect(surface.getByLabel(/^Job #91:/u)).toBeVisible();
  const toolbarBounds = await filters.evaluate((element) => {
    const rect = element.getBoundingClientRect();
    return { left: rect.left, right: rect.right, viewportWidth: window.innerWidth };
  });
  expect(toolbarBounds.left).toBeGreaterThanOrEqual(0);
  expect(toolbarBounds.right).toBeLessThanOrEqual(toolbarBounds.viewportWidth + 1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
  guards.assertClean();
});

referenceTest('project gate preserves drafts and refuses stale writes without changing another project', async ({ page, request }) => {
  await request.post('/__test/reset', { data: { profile: 'fresh', generation: 1 } });
  const other = await request.post('/v1/projects', { data: { name: 'Independent project', repo_path: '/workspace/generated/other' } });
  expect(other.status()).toBe(201);
  const otherId = (await other.json()).id;
  const otherBefore = await (await request.get(`/v1/gate-policies/${otherId}`)).json();
  expect(otherBefore).toEqual({ project_id: otherId, active: true, max_critical: 0, max_high: -1, block_secrets: false });
  const before = await (await request.get('/v1/gate-policies/11')).json();
  const { project_id: _beforeProjectId, ...originalPolicy } = before;
  for (const invalid of [
    { ...originalPolicy, unknown: true, expected_policy: originalPolicy },
    { ...originalPolicy, expected_policy: { ...originalPolicy, unknown: true } },
  ]) {
    expect((await request.put('/v1/gate-policies/11', { data: invalid })).status()).toBe(422);
    expect(await (await request.get('/v1/gate-policies/11')).json()).toEqual(before);
  }
  await page.goto('/?view=projects');
  await page.getByRole('combobox', { name: 'Project', exact: true }).selectOption('11');
  const gate = page.getByRole('region', { name: 'Scan gate for Generated Demo Service', exact: true });
  const maximum = gate.getByLabel('Maximum high findings', { exact: true });
  await expect(maximum).toHaveValue('0');
  await maximum.fill('2');
  await gate.getByRole('button', { name: 'Save project gate', exact: true }).click();
  await expect(gate.getByRole('status')).toContainText('Policy saved for Generated Demo Service.');
  const saved = await (await request.get('/v1/gate-policies/11')).json();
  expect(saved).toEqual({ ...before, max_high: 2 });
  expect(await (await request.get('/v1/gate-policies/' + otherId)).json()).toEqual(otherBefore);
  const scans = await (await request.get('/v1/scans')).json();
  expect(scans.find((scan: { id: number }) => scan.id === 41).gate_decision).toBe('pass');
  expect(scans.find((scan: { id: number }) => scan.id === 40).gate_decision).toBe('incomplete');

  await maximum.fill('3');
  const { project_id: _projectId, ...observed } = saved;
  const competing = await request.put('/v1/gate-policies/11', { data: { ...observed, max_high: 4, expected_policy: observed } });
  expect(competing.status()).toBe(200);
  await gate.getByRole('button', { name: 'Save project gate', exact: true }).click();
  await expect(gate.getByRole('alert')).toContainText("This project's gate policy changed.");
  await expect(maximum).toHaveValue('3');
  await gate.getByRole('button', { name: 'Reload policy', exact: true }).click();
  await expect(gate.getByRole('status')).toContainText('Your unsaved changes are retained');
  await expect(maximum).toHaveValue('3');
  await gate.getByRole('button', { name: 'Reset draft', exact: true }).click();
  await expect(maximum).toHaveValue('4');
  await expect(gate.getByRole('button', { name: 'Save project gate', exact: true })).toBeDisabled();
  expect(await (await request.get(`/v1/gate-policies/${otherId}`)).json()).toEqual(otherBefore);
});
