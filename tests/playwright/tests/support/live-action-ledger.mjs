const MAX_TEXT_LENGTH = 512;
const AUTHORITY_TEXT_PATTERN = /\b(?:kc1\.|kbi1\.|bootstrap[_ -]?token|csrf[_ -]?token|authorization:\s*bearer|cookie:)/iu;
// Browser sessions have no named prefix. Keep this exact token shape separate
// from non-secret member IDs, invalid-record CAS values and content digests.
const BROWSER_SESSION_PATTERN = /(?:^|[^A-Za-z0-9_-])[A-Za-z0-9_-]{32}\.[0-9a-f]{64}(?![A-Za-z0-9_-])/u;
const containsAuthority = value => AUTHORITY_TEXT_PATTERN.test(value) || BROWSER_SESSION_PATTERN.test(value);

export const LIVE_WEB_ACTION_LEDGER_SCHEMA = 'lomo-live-web-action-ledger/v2';

const control = (id, screen, name, precondition, expectedVisible, expectedBackend) => Object.freeze({
  id,
  screen,
  control: name,
  precondition,
  expected_visible: expectedVisible,
  expected_backend: expectedBackend,
});

/**
 * Stable inventory for the real, authenticated Web UI journey. The inventory
 * deliberately describes effects rather than selectors: the journey owns its
 * semantic role/label selector beside the click, while this catalog remains a
 * reusable receipt contract for Compose, Ansible and future CI runners.
 */
export const LIVE_WEB_ACTION_CATALOG = Object.freeze([
  control('WEB-LIVE-001', 'Projects', 'Add Project', 'Disposable directory exists inside the authorized source root.', 'The new project row is visible and selected.', 'GET /v1/projects contains the exact created project.'),
  control('WEB-LIVE-002', 'Projects', 'Open', 'The disposable project exists.', 'The selected project is the scan target.', 'The selected project identity is unchanged.'),
  control('WEB-LIVE-003', 'Projects', 'Delete Project', 'The disposable project has no retained evidence needed by later steps.', 'The exact project row disappears.', 'GET /v1/projects no longer contains the exact project.'),
  control('WEB-LIVE-004', 'Projects', 'Scan', 'The selected project has complete scanner readiness.', 'A scan is admitted and reaches a truthful terminal state.', 'The exact scan resource exists with complete coverage.'),
  control('WEB-LIVE-005', 'Projects', 'Run Advanced Limited Scan', 'At least one enabled scanner is ready and incomplete coverage is acknowledged in the visible dialog.', 'A partial scan is admitted and explicitly labelled limited.', 'The exact scan records limited coverage, omitted scanners and a partial terminal state.'),
  control('WEB-LIVE-006', 'Findings', 'Finding filters', 'A terminal scan has findings.', 'Search, severity, scanner and lifecycle filters change only the visible result set.', 'The selected scan and finding collection revision remain authoritative.'),
  control('WEB-LIVE-007', 'Findings', 'Finding row', 'One filtered finding is visible.', 'Exact detail, multiline evidence and source location render without clipping.', 'The detail identity and revisions match the selected scan-local finding.'),
  control('WEB-LIVE-008', 'Jobs', 'Job row', 'A durable job exists.', 'The exact job detail exposes truthful phase, activity and terminal/action state.', 'GET /v1/jobs/{id} matches the visible job.'),
  control('WEB-LIVE-009', 'Jobs', 'Cancel', 'An exact job advertises can_cancel.', 'The visible job enters cancelling or a truthful terminal state.', 'The exact job records the cancellation request and later a terminal receipt.'),
  control('WEB-LIVE-010', 'Jobs', 'Retry', 'An exact terminal job advertises can_retry.', 'The same job resumes with a higher attempt allowance and reaches a truthful terminal state.', 'The exact job, scan, command and request identities persist; the admitted revision and attempt allowance advance.'),
  control('WEB-LIVE-011', 'Tools', 'Prepare all scanners', 'One or more enabled scanners need reviewed runtime data.', 'Catalog preparation starts once; cache work is shown only after the catalog succeeds.', 'The catalog job exists and any cache child is linked to its prerequisite.'),
  control('WEB-LIVE-012', 'Tools', 'Check curated catalog', 'Advanced scanner maintenance is expanded and no catalog operation is active.', 'The catalog lifecycle shows the exact admitted job.', 'The linked scanner_catalog_check job exists.'),
  control('WEB-LIVE-013', 'Tools', 'Update selected cache', 'At least one reviewed component is selectable and no cache operation is active.', 'The cache lifecycle lists the selected components and real activity.', 'The linked scanner_cache_update job contains the exact sorted component identities.'),
  control('WEB-LIVE-014', 'Tools', 'Roll back cache', 'A distinct previous-good generation is available.', 'Rollback is confirmed and its lifecycle becomes visible.', 'The linked rollback job targets only the previous-good generation.'),
  control('WEB-LIVE-015', 'Findings', 'Open artifact', 'A terminal scan published a sanitized indexed artifact.', 'The artifact opens without exposing a credential-bearing URL.', 'The exact artifact open route returns its indexed media type and bytes.'),
  control('WEB-LIVE-016', 'Findings', 'Download artifact', 'A terminal scan published a sanitized indexed artifact.', 'A browser download with the verified filename begins.', 'The downloaded bytes and digest match the exact artifact resource.'),
  control('WEB-LIVE-017', 'Settings', 'Generate new browser pairing key', 'The current browser is an authenticated owner member.', 'A single-use pairing key and clear expiry are shown only in current page state.', 'A distinct pending browser invitation exists and no member is silently replaced.'),
  control('WEB-LIVE-018', 'Settings', 'Revoke browser', 'A disposable additional browser member exists.', 'Only the selected browser member disappears.', 'The exact browser member is revoked while the owner and IDE members remain active.'),
  control('WEB-LIVE-019', 'Settings', 'Save Desired Components', 'The owner has reviewed the optional component choices.', 'The exact host command reflects the saved desired set; saving alone claims no runtime change.', 'GET /v1/config persists only the desired component flags.'),
  control('WEB-LIVE-020', 'Settings', 'Optional component states', 'Lean core or an explicitly applied optional profile is running.', 'Desired-off services are neutral; desired-on services distinguish observed state from preference.', 'The component projection contains safe desired and observed states without raw DNS errors.'),
  control('WEB-LIVE-021', 'Settings', 'schema-init status', 'The control API completed startup schema verification.', 'The one-shot initializer says Completed successfully; expected to stop and is not startable.', 'The schema identity, DDL fingerprint and initialization receipt match startup verification.'),
  control('WEB-LIVE-022', 'Jobs', 'Check cache outcome', 'An exact failed preparation advertises uncertain cache outcome and read-only reconciliation.', 'A distinct recovery job is linked to the original; the original remains failed.', 'The recovery has its own immutable budget and exact original job/revision; validated outcome is persisted without changing the active pointer or renewing preparation.'),
]);

const catalogById = new Map(LIVE_WEB_ACTION_CATALOG.map((item) => [item.id, item]));

export const REQUIRED_LIVE_WEB_ACTION_IDS = Object.freeze(LIVE_WEB_ACTION_CATALOG.map((item) => item.id));

export class LiveWebActionError extends Error {
  constructor(message, { actionId, ledger } = {}) {
    super(message);
    this.name = 'LiveWebActionError';
    this.actionId = actionId;
    this.ledger = ledger;
  }
}

function safeText(value, field) {
  if (typeof value !== 'string' || value.length < 1 || value.length > MAX_TEXT_LENGTH || /[\0\r\n]/u.test(value)) {
    throw new Error(`${field} must be a bounded single-line string.`);
  }
  if (containsAuthority(value)) {
    throw new Error(`${field} must not contain browser, bootstrap, CSRF, or IDE authority material.`);
  }
  return value;
}

function safeErrorText(cause) {
  const raw = cause instanceof Error ? cause.message : 'Unknown live action failure.';
  const singleLine = raw.replace(/\s+/gu, ' ').trim();
  return safeText(
    containsAuthority(singleLine)
      ? 'Action failed with protected authority material in the underlying error; detail was redacted.'
      : singleLine.slice(0, MAX_TEXT_LENGTH) || 'Unknown live action failure.',
    'action error',
  );
}

function safeEvidence(value, field) {
  if (value === null || typeof value === 'boolean' || Number.isSafeInteger(value)) return value;
  if (typeof value === 'string') return safeText(value, field);
  if (Array.isArray(value)) {
    if (value.length > 32) throw new Error(`${field} exceeds the bounded evidence list.`);
    return value.map((item, index) => safeEvidence(item, `${field}[${index}]`));
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length > 32) throw new Error(`${field} exceeds the bounded evidence object.`);
    return Object.fromEntries(entries.map(([key, item]) => {
      if (!/^[a-z][a-z0-9_]{0,63}$/u.test(key)) throw new Error(`${field} contains an invalid evidence key.`);
      return [key, safeEvidence(item, `${field}.${key}`)];
    }));
  }
  throw new Error(`${field} contains unsupported evidence.`);
}

function normalizeProof(proof, field) {
  if (!proof || typeof proof !== 'object' || proof.ok !== true) {
    throw new Error(`${field} must return { ok: true, summary, evidence }.`);
  }
  return {
    summary: safeText(proof.summary, `${field}.summary`),
    evidence: safeEvidence(proof.evidence ?? {}, `${field}.evidence`),
  };
}

function snapshot(ledger) {
  const passed = ledger.entries.filter((entry) => entry.result === 'pass').map((entry) => entry.id);
  const failed = ledger.entries.filter((entry) => entry.result === 'fail').map((entry) => entry.id);
  const observed = new Set([...passed, ...failed]);
  return Object.freeze({
    ...ledger,
    coverage: Object.freeze({
      complete: passed.length === REQUIRED_LIVE_WEB_ACTION_IDS.length,
      required_ids: REQUIRED_LIVE_WEB_ACTION_IDS,
      passed_ids: Object.freeze(passed),
      failed_ids: Object.freeze(failed),
      unexecuted_ids: Object.freeze(REQUIRED_LIVE_WEB_ACTION_IDS.filter((id) => !observed.has(id))),
    }),
    entries: Object.freeze(ledger.entries.map((entry) => Object.freeze({ ...entry }))),
  });
}

/**
 * Runs an ordered, foreground action list and records both visible and backend
 * proof. A step cannot pass on a click alone. Callers provide the real semantic
 * selectors and API/resource checks so this helper never invents state or
 * duplicates product rules.
 */
export async function runLiveWebActionLedger({
  platform,
  runId,
  steps,
  clock = () => new Date().toISOString(),
}) {
  safeText(platform, 'platform');
  safeText(runId, 'runId');
  if (!Array.isArray(steps) || steps.length < 1 || steps.length > LIVE_WEB_ACTION_CATALOG.length) {
    throw new Error('Live Web action steps must be a bounded non-empty array.');
  }
  const seen = new Set();
  const ledger = {
    schema: LIVE_WEB_ACTION_LEDGER_SCHEMA,
    platform,
    run_id: runId,
    started_at: safeText(clock(), 'startedAt'),
    completed_at: null,
    status: 'running',
    entries: [],
  };

  for (const step of steps) {
    const definition = catalogById.get(step?.id);
    if (!definition) throw new Error(`Unknown live Web action: ${step?.id ?? 'missing'}.`);
    if (seen.has(definition.id)) throw new Error(`Duplicate live Web action: ${definition.id}.`);
    seen.add(definition.id);
    if (typeof step.act !== 'function' || typeof step.verifyVisible !== 'function' || typeof step.verifyBackend !== 'function') {
      throw new Error(`${definition.id} requires act, verifyVisible and verifyBackend functions.`);
    }
    const startedAt = safeText(clock(), `${definition.id}.startedAt`);
    try {
      await step.act();
      const visible = normalizeProof(await step.verifyVisible(), `${definition.id}.visible`);
      const backend = normalizeProof(await step.verifyBackend(), `${definition.id}.backend`);
      ledger.entries.push({
        ...definition,
        action: safeText(step.action, `${definition.id}.action`),
        actual_visible: visible.summary,
        actual_backend: backend.summary,
        evidence: safeEvidence({ visible: visible.evidence, backend: backend.evidence }, `${definition.id}.evidence`),
        evidence_pointer: safeText(step.evidencePointer, `${definition.id}.evidencePointer`),
        started_at: startedAt,
        completed_at: safeText(clock(), `${definition.id}.completedAt`),
        result: 'pass',
      });
    } catch (cause) {
      const message = safeErrorText(cause);
      ledger.entries.push({
        ...definition,
        action: safeText(step.action, `${definition.id}.action`),
        actual_visible: 'Action did not produce complete visible proof.',
        actual_backend: 'Action did not produce complete backend proof.',
        evidence: {},
        evidence_pointer: safeText(step.evidencePointer, `${definition.id}.evidencePointer`),
        started_at: startedAt,
        completed_at: safeText(clock(), `${definition.id}.failedAt`),
        result: 'fail',
        error: message,
      });
      ledger.status = 'failed';
      ledger.completed_at = safeText(clock(), 'failedAt');
      throw new LiveWebActionError(`${definition.id} failed: ${message}`, {
        actionId: definition.id,
        ledger: snapshot(ledger),
      });
    }
  }

  // A successful subset is useful evidence but cannot clear the full catalog.
  ledger.status = ledger.entries.length === REQUIRED_LIVE_WEB_ACTION_IDS.length ? 'passed' : 'partial';
  ledger.completed_at = safeText(clock(), 'completedAt');
  return snapshot(ledger);
}

export async function openLiveWebRoute(page, route, options = {}) {
  const { timeoutMs = 10000 } = options;
  if (!page || typeof page.getByRole !== 'function' || typeof page.locator !== 'function') {
    throw new Error('A Playwright-compatible page is required.');
  }
  if (!['Overview', 'Projects', 'Jobs', 'Scans', 'Findings', 'Tools', 'Settings'].includes(route)) {
    throw new Error(`Unknown Web route: ${route}`);
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 234000) throw new Error('Invalid original-clock route timeout.');
  const bounded = options.timeoutMs !== undefined, deadline = Date.now() + timeoutMs;
  const budget = () => {
    const left = deadline - Date.now();
    if (left <= 0) throw new Error('Original route deadline expired.');
    return left;
  };
  const renderedView = route.toLowerCase();
  await page.getByRole('navigation').getByRole('button', { name: route, exact: true }).click(bounded ? { timeout: budget() } : undefined);
  const heading = page.getByRole('heading', { level: 1, name: route, exact: true });
  await heading.waitFor({ state: 'visible', ...(bounded ? { timeout: budget() } : {}) });
  const surface = page.locator(`main > section[data-route-surface="${renderedView}"]`);
  await surface.waitFor({ state: 'visible', ...(bounded ? { timeout: budget() } : {}) });
  // The heading precedes painted row batches. Functional action readiness must
  // wait for the actual surface; navigation timing has its separate fixed gate.
  const readinessDeadline = bounded ? deadline : Date.now() + timeoutMs;
  while (true) {
    const left = readinessDeadline - Date.now();
    if (left <= 0) throw new Error('Original route deadline expired.');
    await page.locator(`main > section[data-route-surface="${renderedView}"]:not([aria-busy="true"]):not([inert])`)
      .waitFor({ state: 'visible', timeout: left });
    if (bounded) budget();
    const [busy, inert] = await Promise.all([surface.getAttribute('aria-busy'), surface.getAttribute('inert')]);
    if (busy !== 'true' && inert === null) return surface;
    // Polling can start another load between the selector and attribute reads.
    // Reobserve within the same clock, without clicking the route again.
  }
}
