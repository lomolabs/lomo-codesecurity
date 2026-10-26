import { isDeepStrictEqual as equal } from 'node:util';

const require = (value, message) => { if (!value) throw Error(`Bulk findings UI: ${message}`); };

/** The native owner supplies its original remaining clock. Check it after each
 * awaited read and immediately before the next input; clip every wait freshly.
 * Hermetic callers keep the same finite per-operation timeout without a guest
 * clock. An elapsed operation cannot authorize a successor. */
export function bulkActionOwner({ assertCurrent = async () => {}, remaining, timeout = 15000 }) {
  require(typeof assertCurrent === 'function' && (remaining === undefined || typeof remaining === 'function')
    && Number.isFinite(timeout) && timeout > 0 && timeout <= 120000, 'bounded owner required');
  const budget = () => {
    const left = remaining ? remaining() - 30000 : timeout;
    require(Number.isFinite(left) && left > 0, 'original action owner expired');
    return Math.min(timeout, left);
  };
  return { budget, async current() { await assertCurrent(); return budget(); },
    async call(action) { const value = await action(await this.current()); budget(); return value; } };
}

// Shared by the hermetic Web suite and native real-backend platform adapters.
// These functions perform UI actions; an independent inspector proves effects.
export const BULK_LIFECYCLE_ACTIONS = Object.freeze([
  ['Non-blocking', 'gate_exempt', 'non-blocking for gate'],
  ['Accept Risk', 'accepted_risk', 'accepted risk'],
  ['Ignore', 'ignore', 'ignored and not counted'],
  ['False positive', 'false_positive', 'a false positive'],
  ['Fixed', 'fixed', 'fixed'],
  ['Needs review', 'needs_review', null],
  ['Reopen', 'open', null],
].map(row => Object.freeze(row)));

export async function prepareBulkFindingSelection({ page, surface, selected, assertCurrent, remaining, timeout = 15000 }) {
  const owner = bulkActionOwner({ assertCurrent, remaining, timeout });
  require(Array.isArray(selected) && selected.length === 2 && new Set(selected.map(row => row.id)).size === 2
    && selected.every(row => Number.isSafeInteger(row.id) && row.id > 0
      && /^S\d+-F\d{3,5}$/u.test(row.display_id)), 'two exact visible findings required');
  await owner.current();
  const bulk = surface.getByRole('region', { name: 'Bulk finding actions', exact: true, includeHidden: true });
  const details = surface.locator('.bulk-action-disclosure');
  if (await owner.call(() => bulk.isVisible()) && await owner.call(timeout => details.getAttribute('open', { timeout })) === null)
    await owner.call(timeout => details.locator('summary').click({ timeout }));
  for (const name of [...BULK_LIFECYCLE_ACTIONS.map(row => row[0]), 'Delete'])
    require(!await owner.call(timeout => bulk.getByRole('button', { name, exact: true, includeHidden: true }).isEnabled({ timeout })), 'empty selection action is enabled');
  require((await owner.call(timeout => surface.locator('#bulk-lifecycle-disabled-reason').textContent({ timeout }))).includes('Select one or more findings'),
    'missing empty-selection explanation');
  for (const row of selected) {
    await owner.call(timeout => surface.getByLabel(`Select ${row.display_id}`, { exact: true }).check({ timeout }));
  }
  await owner.call(timeout => bulk.waitFor({ state: 'visible', timeout }));
  if (await owner.call(timeout => details.getAttribute('open', { timeout })) === null)
    await owner.call(timeout => details.locator('summary').click({ timeout }));
  await waitForBulkSelection({ page, selected, assertCurrent, remaining, timeout });
  return bulk;
}

export async function waitForBulkSelection({ page, selected, assertCurrent, remaining, timeout = 15000, status = null }) {
  const owner = bulkActionOwner({ assertCurrent, remaining, timeout });
  await owner.call(timeout => page.waitForFunction(({ names, status }) => {
    const bulk = document.querySelector('[aria-label="Bulk finding actions"]');
    if (bulk?.querySelector('strong')?.textContent?.trim() !== '2 selected') return false;
    return names.every(({ name, expectedStatus }) => {
      const input = [...document.querySelectorAll('input[type="checkbox"]')]
        .find(node => node.getAttribute('aria-label') === `Select ${name}`);
      return input?.checked && (!expectedStatus || input.closest('.finding-list-item')
        ?.querySelector(`.finding-list-lifecycle.lifecycle-${expectedStatus === 'gate_exempt' ? 'non-blocking'
          : expectedStatus === 'ignore' ? 'ignored' : expectedStatus.replaceAll('_', '-')}`)?.textContent?.trim());
    }) && !document.querySelector('section[data-route-surface="findings"][aria-busy="true"]')
      && [...bulk.querySelectorAll('button')].some(button => button.textContent?.trim() === 'Reopen' && !button.disabled);
  }, { names: selected.map(row => ({ name: row.display_id, expectedStatus: status ?? row.status ?? null })), status }, { timeout }));
}

/** Cancellation deliberately creates no response wait and no mutation request.
 * Successful/rejected submissions are returned with their exact request body;
 * callers must join these observations to independently read persisted state. */
export async function performBulkFindingAction({ page, surface, endpoint, action, reason = null,
  cancel = false, assertCurrent, remaining, timeout = 15000 }) {
  const owner = bulkActionOwner({ assertCurrent, remaining, timeout });
  const choice = BULK_LIFECYCLE_ACTIONS.find(row => row[1] === action);
  require(choice || action === 'delete', 'unsupported action');
  require(typeof cancel === 'boolean' && (!cancel || action === 'delete' || choice?.[2]), 'unsupported cancellation');
  require(choice?.[2] ? typeof reason === 'string' && reason.trim() && reason.length <= 500 : reason === null,
    'explicit bounded audit reason required');
  const bulk = surface.getByRole('region', { name: 'Bulk finding actions', exact: true });
  const trigger = () => owner.call(timeout => bulk.getByRole('button', { name: choice?.[0] ?? 'Delete', exact: true }).click({ timeout }));
  let submit = trigger;
  if (choice?.[2] || action === 'delete') {
    await trigger();
    const title = choice?.[2] ? `Reason required: ${choice[2]}` : 'Delete 2 selected findings?';
    const dialog = page.getByRole('dialog', { name: title, exact: true });
    await owner.call(timeout => dialog.waitFor({ state: 'visible', timeout }));
    if (choice?.[2]) {
      const confirm = dialog.getByRole('button', { name: `Mark ${choice[2]}`, exact: true });
      const field = dialog.getByRole('textbox', { name: 'Local audit reason', exact: true });
      require(await owner.call(timeout => field.inputValue({ timeout })) === '', 'reason unexpectedly prefilled');
      await owner.call(timeout => confirm.click({ timeout }));
      await owner.call(timeout => dialog.getByRole('alert').filter({ hasText: /^Local audit reason is required\. No change was made\.$/u })
        .waitFor({ state: 'visible', timeout }));
      require(await owner.call(timeout => field.getAttribute('aria-invalid', { timeout })) === 'true', 'blank reason has no accessible validation error');
      await owner.call(timeout => field.fill(reason, { timeout }));
      submit = () => owner.call(timeout => confirm.click({ timeout }));
    } else submit = () => owner.call(timeout => dialog.getByRole('button', { name: 'Delete selected findings', exact: true }).click({ timeout }));
    if (cancel) {
      await owner.call(timeout => dialog.getByRole('button', { name: action === 'delete' ? 'Keep findings' : 'Keep unchanged', exact: true }).click({ timeout }));
      await owner.call(timeout => dialog.waitFor({ state: 'hidden', timeout }));
      return { action, cancelled: true };
    }
  }
  await owner.current();
  const [response] = await Promise.all([
    page.waitForResponse(value => value.url() === new URL('/v1/findings/bulk', endpoint).href
      && value.request().method() === 'POST', { timeout: owner.budget() }),
    submit(),
  ]);
  owner.budget();
  require(await response.finished() === null, 'response transport failed');
  owner.budget();
  const body = await response.json(); owner.budget();
  return { action, cancelled: false, status: response.status(), request: response.request().postDataJSON(),
    response: body };
}

export function verifyBulkFindingRequest(observed, { selected, action, reason = null, scanId, conflict = null }) {
  require(Array.isArray(selected) && selected.length === 2 && new Set(selected.map(row => row.id)).size === 2
    && selected.every(row => Number.isSafeInteger(row.id) && row.id > 0 && Number.isSafeInteger(row.revision) && row.revision > 0)
    && Number.isSafeInteger(scanId) && scanId > 0
    && (BULK_LIFECYCLE_ACTIONS.some(row => row[1] === action) || action === 'delete'), 'two exact revisions and scan required');
  const ids = selected.map(row => row.id);
  const expected = { finding_ids: ids, action,
    ...(reason === null ? {} : { reason }), expected_revisions: Object.fromEntries(selected.map(row => [row.id, row.revision])) };
  require(observed.cancelled === false && observed.action === action && equal(observed.request, expected), 'request scope or revisions differ');
  if (conflict) {
    require(observed.status === 409 && observed.response?.detail?.code === 'revision_conflict'
      && equal(observed.response.detail.revisions, conflict), 'missing exact handled revision conflict');
  } else require(observed.status === 200 && equal(observed.response,
    { updated: action === 'delete' ? 0 : ids.length, deleted: action === 'delete' ? ids.length : 0, scan_ids: [scanId] }),
  'response or affected scan scope differs');
  return { status: 'PASS', action, request: observed.request, response: observed.response };
}
