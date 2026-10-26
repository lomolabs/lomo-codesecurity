import { expect, type Page, type Disposable } from '@playwright/test';
import {
  assertRequiredQualityObservers,
  installQualityObservers,
  installRuntimeObservationGuards,
  runIsolatedNavigationPass,
  type NavigationPassResult,
} from './quality.js';

const routes = ['Projects', 'Jobs', 'Scans', 'Findings', 'Tools', 'Settings', 'Overview']
  .map(label => ({ label, view: label.toLowerCase() }));

/** Delay only the real read response in the owned page. The selected project's
 * snapshot identity and every backend response remain genuine and unchanged. */
export async function reviewRetainedSnapshotGuidance(page: Page, owner: {
  assertCurrent: () => void | Promise<void>; remaining: () => number;
}) {
  await owner.assertCurrent();
  expect(owner.remaining()).toBeGreaterThan(30000);
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const handler = async (route: import('@playwright/test').Route) => { await held; await route.fallback(); };
  await page.route('**/v1/config', handler);
  const step = page.getByLabel('Step 2: Source authorization and registration');
  let before: Awaited<ReturnType<typeof step.boundingBox>>;
  let text = '';
  try {
    const observed = page.waitForRequest(request => new URL(request.url()).pathname === '/v1/config',
      {timeout: Math.min(5000, owner.remaining())});
    await Promise.all([observed,
      page.getByRole('navigation').getByRole('button', {name:'Projects',exact:true}).click()]);
    await expect(step.getByText('VS Code required', {exact:true})).toBeVisible({timeout:5000});
    await expect(page.getByRole('button', {name:'Scan',exact:true})).toBeDisabled();
    before = await step.boundingBox(); text = await step.innerText();
  } finally { release(); }
  try {
    await page.waitForLoadState('networkidle', {timeout:Math.min(10000,owner.remaining())});
    await expect(step).toHaveText(text, {useInnerText:true});
    const after = await step.boundingBox();
    expect(after).toEqual(before!);
    await expect(step).toHaveAttribute('data-complete','false');
    await expect(page.getByRole('button', {name:'Scan',exact:true})).toBeDisabled();
    await owner.assertCurrent();
    return {schema:'lomo-retained-snapshot-guidance/v1',text,before:before!,after,
      response:'delayed real GET /v1/config',scan_disabled:true,source_authority_changed:false};
  } finally { await page.unroute('**/v1/config',handler); }
}

/** Measure an already authenticated owned page. Never enroll or reset a backend.
 * The caller owns profile/runtime admission, exclusive measurements and cleanup.
 * Reloaded documents retain cookies/storage; these are not pristine profiles.
 */
export async function measureRetainedNavigation(
  page: Page,
  origin: string,
  record: (label: string, result: NavigationPassResult) => Promise<void>,
  owner?: { assertCurrent: () => void | Promise<void>; remaining: () => number },
) {
  const admit = async () => {
    await owner?.assertCurrent();
    if (owner && owner.remaining() <= 0) throw new Error('Retained navigation owner deadline expired.');
  };
  const bounded = (maximum: number) => {
    const budget = Math.min(maximum, owner?.remaining() ?? maximum);
    if (budget <= 0) throw new Error('Retained navigation owner deadline expired.');
    return budget;
  };
  await admit();
  const url = new URL(origin);
  if (url.origin !== origin || url.protocol !== 'http:' || url.hostname !== '127.0.0.1'
    || !url.port || new URL(page.url()).origin !== origin) {
    throw new Error('Retained navigation requires the exact owned loopback origin.');
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await installQualityObservers(page, true);
  const guards = installRuntimeObservationGuards(page, origin);
  const writes: string[] = [];
  const observeMethod = (request: import('@playwright/test').Request) => {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method())) {
      writes.push(`${request.method()} ${new URL(request.url()).pathname}`);
    }
  };
  page.on('request', observeMethod);
  const samples: NavigationPassResult['routeReadiness'] = [];
  try {
    for (const mode of ['reloaded-document', 'persistent-document']) {
      for (let pass = 1; pass <= 5; pass += 1) {
        await admit();
        if (mode === 'reloaded-document' || pass === 1) {
          await page.goto(`${origin}/?view=overview`, { timeout: bounded(30_000) });
          await expect(page.getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible({ timeout: bounded(5_000) });
          await page.waitForLoadState('networkidle', { timeout: bounded(10_000) });
        }
        const bindings: Disposable[] = [];
        const registerBridge: Page['exposeFunction'] = async (name, callback) => {
          const binding = await page.exposeFunction(name, callback);
          bindings.push(binding);
          return binding;
        };
        let settled = false;
        let result: NavigationPassResult;
        try {
          result = await runIsolatedNavigationPass(page, routes, bounded(12_000), false, undefined,
            owner ? async () => { await admit(); } : undefined, registerBridge);
          settled = true;
          await record(`${mode}-${pass}`, result);
        } finally {
          if (settled) {
            const cleanup = await Promise.allSettled(bindings.map(binding => binding.dispose()));
            const failures = cleanup.filter(item => item.status === 'rejected');
            if (failures.length) throw new AggregateError(failures.map(item => item.reason), 'Navigation binding cleanup failed.');
          }
        }
        assertRequiredQualityObservers(result.quality);
        expect(result.routeReadiness.map(row => row.route)).toEqual(routes.map(row => row.view));
        expect(result.routeSurfaces).toEqual(routes.map(({ view: route }) => ({ route, ariaBusy: false, inert: false })));
        expect(result.finalRoute).toBe('overview');
        expect(result.domSamples.filter(row => row.current > 2_500)).toEqual([]);
        expect(result.quality.domBoundaryPeak).toBeLessThanOrEqual(2_750);
        expect(result.quality.layoutShift).toBe(0);
        expect(result.quality.longTasks.filter(row => row.duration > 50).length).toBeLessThanOrEqual(2);
        expect(result.quality.longTasks.filter(row => row.duration > 100)).toEqual([]);
        for (const row of result.routeReadiness) {
          expect(row.acknowledgementMs).toBeGreaterThanOrEqual(0);
          expect(row.acknowledgementMs).toBeLessThanOrEqual(100);
        }
        guards.assertClean();
        expect(writes, 'navigation must not issue mutations').toEqual([]);
        samples.push(...result.routeReadiness);
      }
    }
    expect(samples).toHaveLength(70);
    const ordered = samples.map(row => row.inputToReadyMs).sort((a, b) => a - b);
    const p95 = ordered[Math.ceil(ordered.length * 0.95) - 1];
    // The caller retains this result before enforcing the final p95 gate.
    return { samples, p95_input_to_ready_ms: p95, p95_budget_ms: 187.5,
      acknowledgement_budget_ms: 100, pass_deadline_ms: 12_000,
      scope: 'retained authenticated backend; five reloaded and five persistent document passes',
      timing_basis: 'Trusted click capture to stable ready paint/task fence; acknowledgment is event timestamp to capture, not physical input latency.' };
  } finally {
    page.off('request', observeMethod);
    // On failure the caller must close its owned editor/browser before reuse.
    // Partial pass bindings and uncertain renderer work must never be replayed.
  }
}
