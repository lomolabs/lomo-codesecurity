import { expect, test, type Page, type CDPSession } from '@playwright/test';
import { performance } from 'node:perf_hooks';
import assert from 'node:assert/strict';
import {
  assertRequiredQualityObservers,
  installQualityObservers,
  installRuntimeGuards,
  qualitySnapshot,
  resetQualityWindow,
} from './support/quality.js';
import { qualificationMilliseconds, qualificationPerformanceBudgetMode } from '../timing.js';

type FindingPage = {
  items: Array<{ id: number; scan_finding_number: number }>;
  total: number;
  revision: number;
  truncated: boolean;
  next_cursor: string | null;
};
type HeapSample = {
  status: 'available' | 'unavailable';
  usedBytes: number | null;
  totalBytes: number | null;
  basis: string;
  reason: 'captured' | 'CDP_heap_capture_unavailable';
  sessionCleanup: 'not_created' | 'detached' | 'detach_failed';
};
type InputObservation = {
  acknowledgementMs: number;
  inputToPostPaintReadyMs: number;
  trusted: boolean;
  selectedRows: number;
};
declare global {
  interface Window { __kodesecScaleInput?: Promise<InputObservation> }
}

async function heapSample(page: Page): Promise<HeapSample> {
  const sample: HeapSample = {
    status: 'unavailable',
    usedBytes: null,
    totalBytes: null,
    basis: 'CDP Runtime.getHeapUsage JavaScript heap snapshot; not RSS or peak memory',
    reason: 'CDP_heap_capture_unavailable',
    sessionCleanup: 'not_created',
  };
  let session: CDPSession | undefined;
  try {
    session = await page.context().newCDPSession(page);
    const value = await session.send('Runtime.getHeapUsage');
    if (!Number.isFinite(value.usedSize) || !Number.isFinite(value.totalSize)
        || value.usedSize < 0 || value.totalSize < value.usedSize) {
      throw new Error('Invalid heap sample');
    }
    sample.status = 'available';
    sample.usedBytes = value.usedSize;
    sample.totalBytes = value.totalSize;
    sample.reason = 'captured';
  } catch {
    // Optional heap telemetry never claims RSS/peak or fabricates a zero sample.
  } finally {
    if (session) {
      try {
        await session.detach();
        sample.sessionCleanup = 'detached';
      } catch {
        // Preserve capture classification and explicit cleanup diagnostics.
        // The runner still owns and closes the surrounding browser context.
        sample.sessionCleanup = 'detach_failed';
      }
    }
  }
  return sample;
}

async function armInput(page: Page, buttonName: string, selectedRows: number) {
  await page.evaluate(({ name, expectedRows, boundMs }) => {
    const surface = document.querySelector('section[data-route-surface="findings"]');
    if (!surface) throw new Error('Findings surface missing');
    window.__kodesecScaleInput = new Promise((resolve, reject) => {
      let frame = 0;
      let timer = 0;
      let settled = false;
      const cleanup = () => {
        surface.removeEventListener('click', observe, true);
        cancelAnimationFrame(frame);
        clearTimeout(timer);
      };
      const refuse = (message: string) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(new Error(message));
      };
      const observe = (event: Event) => {
        const button = event.target instanceof Element ? event.target.closest('button') : null;
        if (button?.textContent?.trim() !== name) return;
        surface.removeEventListener('click', observe, true);
        const deliveredAt = performance.now();
        if (!event.isTrusted || !Number.isFinite(event.timeStamp)
            || event.timeStamp < 0 || event.timeStamp > deliveredAt) {
          refuse('Input timestamp or trust refused');
          return;
        }
        const acknowledgementMs = deliveredAt - event.timeStamp;
        const selectedCount = () => surface.querySelectorAll('.finding-list-item.selected').length;
        const ready = () => {
          if (settled) return;
          if (selectedCount() !== expectedRows
              || surface.getAttribute('data-findings-render-stage') !== 'ready') {
            frame = requestAnimationFrame(ready);
            return;
          }
          frame = requestAnimationFrame(() => {
            frame = requestAnimationFrame(() => {
              if (selectedCount() !== expectedRows) {
                frame = requestAnimationFrame(ready);
                return;
              }
              settled = true;
              cleanup();
              resolve({
                acknowledgementMs,
                inputToPostPaintReadyMs: performance.now() - event.timeStamp,
                trusted: true,
                selectedRows: expectedRows,
              });
            });
          });
        };
        frame = requestAnimationFrame(ready);
      };
      surface.addEventListener('click', observe, true);
      timer = window.setTimeout(() => refuse('Input measurement deadline'), boundMs);
    });
    void window.__kodesecScaleInput.catch(() => undefined);
  }, { name: buttonName, expectedRows: selectedRows, boundMs: qualificationMilliseconds(2_000) });
}

async function awaitColdPublishedPaint(page: Page) {
  const surface = page.locator('section[data-route-surface="findings"]');
  await expect(surface.locator('.list-head strong')).toBeVisible();
  await expect(surface.locator('.finding-detail h2')).toBeVisible();
  await page.evaluate(({ boundMs }) => new Promise<void>((resolve, reject) => {
    const surface = document.querySelector<HTMLElement>('section[data-route-surface="findings"]');
    const listHeading = surface?.querySelector<HTMLElement>('.list-head strong');
    const detailHeading = surface?.querySelector<HTMLElement>('.finding-detail h2');
    const workspace = surface?.querySelector<HTMLElement>('.finding-workspace');
    const pageIdentity = workspace?.getAttribute('data-findings-page');
    const findingIdentity = detailHeading?.closest('.finding-detail')?.getAttribute('data-finding-id');
    const positiveIdentity = (value: string | null | undefined) => Boolean(value
      && /^[1-9][0-9]*$/.test(value) && Number.isSafeInteger(Number(value)));
    let firstFrame = 0;
    let secondFrame = 0;
    let task = 0;
    let deadline = 0;
    const cleanup = () => {
      cancelAnimationFrame(firstFrame);
      cancelAnimationFrame(secondFrame);
      clearTimeout(task);
      clearTimeout(deadline);
    };
    const visible = (node: HTMLElement | null | undefined) => Boolean(node?.isConnected
      && !node.closest('[aria-hidden="true"], [inert]')
      && getComputedStyle(node).visibility === 'visible'
      && node.getBoundingClientRect().width > 0 && node.getBoundingClientRect().height > 0);
    const ready = () => Boolean(surface?.isConnected && workspace?.isConnected
      && positiveIdentity(pageIdentity) && positiveIdentity(findingIdentity)
      && surface.querySelector('.finding-workspace') === workspace
      && surface.getAttribute('data-findings-render-stage') === 'ready'
      && surface.getAttribute('aria-busy') !== 'true'
      && workspace.getAttribute('data-findings-page') === pageIdentity
      && surface.querySelector('.list-head strong') === listHeading
      && surface.querySelector('.finding-detail h2') === detailHeading
      && detailHeading?.closest('.finding-detail')?.getAttribute('data-finding-id') === findingIdentity
      && visible(listHeading) && visible(detailHeading));
    const refuse = (message: string) => { cleanup(); reject(new Error(message)); };
    if (!ready()) { refuse('Cold Findings content is not visibly published and ready'); return; }
    deadline = window.setTimeout(() => refuse('Cold Findings paint fence exceeded its deadline'), boundMs);
    // Keep the cold observer window active through the first visible paint.
    // Match the maintained navigation fence: two frames, then a task boundary.
    firstFrame = requestAnimationFrame(() => {
      secondFrame = requestAnimationFrame(() => {
        task = window.setTimeout(() => {
          if (!ready()) { refuse('Cold Findings identity or readiness changed during the paint fence'); return; }
          cleanup();
          resolve();
        }, 0);
      });
    });
  }), { boundMs: qualificationMilliseconds(2_000) });
}

for (const total of [1_000, 5_000, 10_000]) {
  test(`synthetic Findings display ${total}: complete pagination, cold hydration and bounded interaction`, async ({ page, request, baseURL, browser }, testInfo) => {
    test.setTimeout(30_000);
    if (!baseURL) throw new Error('Fixture baseURL required');
    testInfo.annotations.push({
      type: 'synthetic-display',
      description: 'Targeted tier; not scanner throughput or platform qualification.',
    });
    const profile = `findings-scale-${total}`;
    expect((await request.post('/__test/reset', { data: { profile, generation: 1 } })).status()).toBe(200);
    const stale = await request.get('/v1/scans/41/findings?limit=200&expected_revision=2');
    expect(stale.status()).toBe(409);
    expect(await stale.json()).toMatchObject({ detail: { code: 'revision_conflict', revision: 1 } });
    const ids = new Set<number>();
    const numbers = new Set<number>();
    const paginationStarted = performance.now();
    const apiPageRequestMs: number[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const requestStarted = performance.now();
      const response = await request.get('/v1/scans/41/findings', {
        params: { limit: 200, expected_revision: 1, ...(cursor ? { cursor } : {}) },
      });
      const value = await response.json() as FindingPage;
      apiPageRequestMs.push(performance.now() - requestStarted);
      expect(response.status()).toBe(200);
      expect(value.total).toBe(total);
      expect(value.revision).toBe(1);
      expect(value.items).toHaveLength(200);
      for (const item of value.items) {
        const rowContext = `page ${pages + 1}, finding ordinal ${numbers.size + 1}`;
        assert.equal(Number.isSafeInteger(item.id), true, `${rowContext}: id must be a safe integer`);
        assert.equal(item.scan_finding_number, numbers.size + 1,
          `${rowContext}: scan finding number must remain contiguous`);
        assert.equal(ids.has(item.id), false, `${rowContext}: duplicate id ${item.id}`);
        assert.equal(numbers.has(item.scan_finding_number), false,
          `${rowContext}: duplicate scan finding number`);
        ids.add(item.id);
        numbers.add(item.scan_finding_number);
      }
      cursor = value.next_cursor;
      expect(value.truncated).toBe(cursor !== null);
      pages += 1;
      expect(pages).toBeLessThanOrEqual(total / 200);
    } while (cursor);
    const apiPaginationMs = performance.now() - paginationStarted;
    expect(pages).toBe(total / 200);
    expect(ids.size).toBe(total);
    expect(numbers.size).toBe(total);
    expect(Math.min(...numbers)).toBe(1);
    expect(Math.max(...numbers)).toBe(total);
    const anchored = await request.get('/v1/scans/41/findings?limit=200&anchor_scan_finding_number=250&expected_revision=1');
    expect(anchored.status()).toBe(200);
    const anchorPage = await anchored.json() as FindingPage;
    expect(anchorPage.revision).toBe(1);
    expect(anchorPage.items[0].scan_finding_number).toBe(201);
    expect(anchorPage.items.at(-1)?.scan_finding_number).toBe(400);

    expect((await request.post('/__test/reset', { data: { profile, generation: 1 } })).status()).toBe(200);
    await installQualityObservers(page);
    const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
    const beforeHydrationHeap = await heapSample(page);
    const coldStarted = performance.now();
    await page.goto('/?view=findings&scan=41&finding=250');
    const surface = page.locator('section[data-route-surface="findings"]');
    await expect(surface).toHaveAttribute('data-findings-render-stage', 'ready');
    await expect(surface).not.toHaveAttribute('aria-busy', 'true');
    await expect(surface.locator('.list-head strong')).toHaveText(`${total} findings`);
    await expect(surface.locator('.finding-list-item')).toHaveCount(25);
    await expect(surface.locator('.finding-list .pager span')).toHaveText(`10 / ${total / 25}`);
    await expect(surface.locator('.finding-detail h2')).toHaveText('S41-F250');
    await awaitColdPublishedPaint(page);
    const coldLoadToReadyMs = performance.now() - coldStarted;
    const counts = await (await request.get('/__test/requests')).json() as {
      findings: number; findingDetails: number; scanSummaries: number; artifacts: number;
    };
    expect(counts).toMatchObject({ findings: total / 200 + 1, findingDetails: 1, scanSummaries: 2, artifacts: 1 });
    const coldQuality = await qualitySnapshot(page);
    assertRequiredQualityObservers(coldQuality);
    expect(coldQuality.domCurrent).toBeLessThanOrEqual(2_500);
    expect(coldQuality.domBoundaryPeak).toBeLessThanOrEqual(2_750);
    const afterHydrationHeap = await heapSample(page);
    await resetQualityWindow(page);
    const interactions: InputObservation[] = [];
    for (const [name, selectedRows] of [['Select visible', 25], ['Clear selection', 0]] as const) {
      await armInput(page, name, selectedRows);
      await surface.getByRole('button', { name, exact: true }).click();
      const observation = await page.evaluate(() => {
        if (!window.__kodesecScaleInput) throw new Error('Input observer missing');
        return window.__kodesecScaleInput;
      });
      expect(observation.trusted).toBe(true);
      expect(observation.selectedRows).toBe(selectedRows);
      expect(observation.acknowledgementMs).toBeGreaterThanOrEqual(0);
      expect(observation.acknowledgementMs).toBeLessThanOrEqual(100);
      interactions.push(observation);
    }
    await expect(surface.locator('.finding-detail h2')).toHaveText('S41-F250');
    const interactionQuality = await qualitySnapshot(page);
    assertRequiredQualityObservers(interactionQuality);
    expect(interactionQuality.domCurrent).toBeLessThanOrEqual(2_500);
    expect(interactionQuality.domBoundaryPeak).toBeLessThanOrEqual(2_750);
    expect(interactionQuality.layoutShift).toBe(0);
    expect(interactionQuality.longTasks.filter(({ duration }) => duration > 50)).toEqual([]);
    const afterInteractionHeap = await heapSample(page);
    guards.assertClean();
    await testInfo.attach('synthetic-findings-scale.json', {
      contentType: 'application/json',
      body: Buffer.from(JSON.stringify({
        scope: 'synthetic Findings display; not scanner scale, real API/database performance or platform qualification',
        fixture: { profile, generation: 1, findings: total, apiPages: pages, apiPageSize: 200, visibleRows: 25, anchor: 250 },
        environment: {
          browser: browser.browserType().name(), browserVersion: browser.version(),
          viewport: page.viewportSize(), headed: testInfo.project.use.headless === false,
        },
        performanceBudgetMode: qualificationPerformanceBudgetMode,
        scaleBudgetMode: 'blocking',
        observations: {
          apiPaginationMs, apiPageRequestMs, coldLoadToReadyMs, interactions,
          apiTimingBasis: 'Controller monotonic sequential synthetic API pagination including assertions; excludes browser hydration.',
          apiPageTimingBasis: 'Per-page controller request through JSON decode; transport/fixture work/decode included, validation assertions excluded.',
          coldTimingBasis: 'Controller monotonic navigation through visibly published exact ready content and two paint frames plus a task boundary; transport/bundle/hydration included; one sample, not p95.',
          acknowledgementBasis: 'Trusted click timestamp to capture delivery; not physical-device or host transport latency.',
          interactionBasis: 'Trusted click timestamp through ready DOM/two paint frames; two samples, not p95.',
        },
        memory: { beforeHydrationHeap, afterHydrationHeap, afterInteractionHeap, forcedGc: false, rss: null, peakMemory: null },
        qualityGateScope: 'DOM bounds apply to cold and interaction; zeroCLS/no tasks>50ms apply only to interaction. Raw cold quality retained.',
        requests: counts, coldQuality, interactionQuality,
      }, null, 2)),
    });
  });
}
