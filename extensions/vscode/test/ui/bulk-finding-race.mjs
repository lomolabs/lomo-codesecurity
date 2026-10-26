import { isDeepStrictEqual as equal } from 'node:util';
import { bulkActionOwner } from './bulk-finding-actions.mjs';

const require = (value, message) => { if (!value) throw Error(`Bulk finding race: ${message}`); };

/** Hold one exact UI bulk request while a single explicit competing lifecycle
 * PATCH commits through that same authenticated browser transport. This fault
 * grants no authority and never substitutes credentials, retries or follows
 * redirects. The caller independently verifies the competing persisted effect. */
export async function armBulkFindingRace({ page, endpoint, selected, assertCurrent, remaining,
  timeout = 15000, observeCompeting }) {
  require(Array.isArray(selected) && selected.length === 2
    && new Set(selected.map(row => row.id)).size === 2
    && selected.every(row => Number.isSafeInteger(row.id) && row.id > 0
      && Number.isSafeInteger(row.revision) && row.revision > 0)
    && typeof observeCompeting === 'function', 'two exact revisions and effect observer required');
  const owner = bulkActionOwner({ assertCurrent, remaining, timeout });
  const url = new URL('/v1/findings/bulk', endpoint).href;
  const expected = { action: 'needs_review', finding_ids: selected.map(row => row.id),
    expected_revisions: Object.fromEntries(selected.map(row => [row.id, row.revision])) };
  let held = 0, failure = null, effect = null, closed = false, closePromise;
  const pending = new Set();
  const active = () => { require(!closed, 'race owner closed'); return owner.budget(); };
  const run = async route => {
    try {
      active();
      require(++held === 1 && route.request().method() === 'POST'
        && equal(route.request().postDataJSON(), expected), 'unexpected intercepted request');
      await owner.current(); active();
      const response = await route.fetch({ url: `${endpoint}/v1/findings/${selected[0].id}/lifecycle`, method: 'PATCH',
        postData: JSON.stringify({ action: 'needs_review', expected_revision: selected[0].revision }),
        timeout: active(), maxRetries: 0, maxRedirects: 0 });
      active(); require(response.status() === 200, 'controlled competing lifecycle did not succeed');
      effect = await observeCompeting({ kind: 'controlled-api-race-fault', mutation_requests: 1,
        finding_id: selected[0].id, expected_revision: selected[0].revision });
      active(); require(effect?.status === 'PASS', 'competing persisted effect not accepted');
      await owner.current(); active(); await route.continue(); active();
    } catch (error) {
      failure = error;
      await route.abort('failed').catch(() => {});
    }
  };
  const handler = route => {
    const work = run(route); pending.add(work);
    work.then(() => pending.delete(work), () => pending.delete(work));
    return work;
  };
  const close = () => {
    if (closePromise) return closePromise;
    closed = true;
    // Releasing the exact interception is transport cleanup, not new work.
    // Join entered callbacks; a close must never release a paused callback
    // into another PATCH, observer or continuation after its awaited fence.
    closePromise = (async () => {
      await page.unroute(url, handler);
      await Promise.allSettled([...pending]);
    })();
    return closePromise;
  };
  try { await owner.call(() => page.route(url, handler)); }
  catch (cause) {
    // Registration may already have taken effect before an awaited fence fails.
    // Retire this exact callback before the caller can lose its cleanup handle.
    try { await close(); }
    catch (cleanupError) { throw new AggregateError([cause, cleanupError], 'Bulk finding race: registration cleanup unresolved'); }
    throw cause;
  }
  return {
    observed() {
      active(); if (failure) throw failure;
      require(held === 1 && pending.size === 0 && effect?.status === 'PASS', 'competing action has not settled');
      return { status: 'PASS', held_requests: 1, automatic_retry: false, effect };
    },
    close,
  };
}
