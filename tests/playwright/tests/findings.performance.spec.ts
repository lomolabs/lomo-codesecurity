import { referenceTest } from './support/reference-viewport.js';
import { expect, test, type Browser, type Page, type TestInfo } from '@playwright/test';

import {
  assertRequiredQualityObservers,
  installQualityObservers,
  installRuntimeGuards,
} from './support/quality.js';
import {
  qualificationMilliseconds,
  qualificationPerformanceBudgetsAreBlocking,
} from '../timing.js';

type FixtureFinding = {
  id: number;
  ai_verdict?: string;
  ai_confidence?: number;
  ai_reasoning?: string;
  ai_fix?: string;
} & Record<string, unknown>;

const targetFindingId = 514;
const targetDisplayId = 'S41-F014';
const pollIntervalMs = 8_000;
const journeyTimeoutMs = pollIntervalMs + 6_000;
const renderingDiagnostic = process.env.KODESEC_FINDINGS_RENDER_DIAGNOSTIC === '1';
const renderingMarker = 'kodesec-findings-measurement-start';
const renderingCategories = ['-*', 'devtools.timeline', 'v8.execute', 'toplevel', 'blink.user_timing', 'blink'];
const renderingEventNames = new Set([
  renderingMarker, 'RunTask', 'ThreadControllerImpl::RunTask', 'ThreadPool_RunTask',
  'TaskQueueManager::ProcessTaskFromWorkQueue', 'FunctionCall', 'EvaluateScript',
  'EventDispatch', 'TimerFire', 'FireAnimationFrame', 'UpdateLayoutTree', 'Layout',
  'PrePaint', 'Paint', 'Layerize', 'CompositeLayers', 'Commit', 'DrawFrame', 'RasterTask', 'V8.Execute',
  'EventHandler::handleMouseMoveEvent', 'EventHandler::HitTestResultAtLocation',
]);

// Supporting diagnosis only: no raw trace path/attachment, arbitrary event
// names, arguments, URLs, stacks, or screenshots. Chromium tracing changes
// workload cost, so this mode always fails after capture and cannot qualify.
function normalizeRenderingTrace(raw: Buffer) {
  const maxRawBytes = 16 * 1024 * 1024;
  const maxEvents = 20_000;
  if (raw.byteLength > maxRawBytes) return { status: 'raw_byte_limit', rawBytes: raw.byteLength, maxRawBytes, maxEvents };
  let parsed: unknown;
  try { parsed = JSON.parse(raw.toString('utf8')); } catch { return { status: 'invalid_trace_json', rawBytes: raw.byteLength }; }
  if (!parsed || typeof parsed !== 'object' || !('traceEvents' in parsed) || !Array.isArray(parsed.traceEvents)) {
    return { status: 'invalid_trace_envelope', rawBytes: raw.byteLength };
  }
  const finiteTime = (value: unknown): value is number => typeof value === 'number'
    && Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER;
  const marker = parsed.traceEvents.filter((event: unknown) => {
    if (!event || typeof event !== 'object') return false;
    const candidate = event as Record<string, unknown>;
    return candidate.name === renderingMarker && candidate.cat === 'blink.user_timing' && finiteTime(candidate.ts);
  });
  if (marker.length !== 1) return { status: 'measurement_marker_not_unique', rawBytes: raw.byteLength, markerCount: marker.length };
  const markerTime = marker[0].ts as number;
  const events: Array<{ name: string; categories: string[]; phase: string; startMs: number; durationMs?: number; threadTimestampMs?: number; threadDurationMs?: number; processId: number; threadId: number }> = [];
  let omittedEvents = 0;
  for (const input of parsed.traceEvents) {
    if (!input || typeof input !== 'object') continue;
    const event = input as Record<string, unknown>;
    if (typeof event.name !== 'string' || !renderingEventNames.has(event.name)
      || typeof event.cat !== 'string' || typeof event.ph !== 'string' || !['X', 'B', 'E', 'I', 'R'].includes(event.ph)
      || !finiteTime(event.ts) || !Number.isSafeInteger(event.pid) || !Number.isSafeInteger(event.tid)
      || (event.pid as number) < 0 || (event.tid as number) < 0
      || (event.dur !== undefined && !finiteTime(event.dur))) continue;
    const categories = renderingCategories.filter((category) => category !== '-*' && event.cat!.toString().split(',').includes(category));
    if (categories.length === 0) continue;
    if (events.length === maxEvents) { omittedEvents += 1; continue; }
    events.push({
      name: event.name, categories, phase: event.ph, startMs: (event.ts - markerTime) / 1_000,
      ...(event.dur === undefined ? {} : { durationMs: (event.dur as number) / 1_000 }),
      // Optional thread CPU clock fields: unavailable is unknown, not zero.
      // tts has its own per-thread origin; do not subtract the wall-clock marker.
      ...(finiteTime(event.tts) ? { threadTimestampMs: event.tts / 1_000 } : {}),
      ...(finiteTime(event.tdur) ? { threadDurationMs: event.tdur / 1_000 } : {}),
      processId: event.pid as number, threadId: event.tid as number,
    });
  }
  return { status: omittedEvents ? 'event_limit' : 'captured', rawBytes: raw.byteLength, maxRawBytes, maxEvents, omittedEvents, events };
}

async function withRenderingDiagnostic<T>(browser: Browser, page: Page, testInfo: TestInfo, action: () => Promise<T>): Promise<T> {
  if (!renderingDiagnostic) return action();
  testInfo.annotations.push({ type: 'non-qualifying-diagnostic', description: 'Opt-in Chromium rendering capture; timing gates remain unchanged and this case must fail.' });
  let raw: Buffer | undefined;
  let capture: ReturnType<typeof normalizeRenderingTrace> | { status: string } = { status: 'capture_not_completed' };
  try {
    await browser.startTracing(page, { categories: renderingCategories, screenshots: false });
    return await action();
  } finally {
    // stopTracing reads and deletes Playwright's internal artifact. Omitting
    // path prevents its raw buffer from being copied into retained evidence.
    // Attempt stop even when start/action fails; browser teardown remains owned
    // by the maintained runner. Never mask the original action error.
    try { raw = await browser.stopTracing(); capture = normalizeRenderingTrace(raw); } catch { capture = { status: 'capture_failed' }; }
    finally { raw?.fill(0); }
    try {
      await testInfo.attach('findings-rendering-diagnostic.json', {
        body: Buffer.from(JSON.stringify({ qualificationEligible: false, clock: 'milliseconds relative to fixed measurement mark', ...capture })),
        contentType: 'application/json',
      });
    } catch { expect.soft(false, 'Supporting rendering diagnostic attachment failed.').toBe(true); }
    expect.soft(false, 'Opt-in rendering diagnostic is supporting evidence only; this profiled run cannot qualify.').toBe(true);
  }
}

// Keep recorder DOM/raster work outside the renderer measurement. The trace
// still retains actions, sources, and the bounded JSON attachments on failure.
test.use({
  trace: {
    mode: 'retain-on-failure',
    screenshots: false,
    snapshots: false,
    sources: true,
    attachments: true,
  },
});

referenceTest('Findings list/detail scroll and poll update stay within the reference budget', async ({ browser, page, request, baseURL }, testInfo) => {
  test.setTimeout(qualificationMilliseconds(journeyTimeoutMs + 16_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');

  const reset = await request.post('/__test/reset', { data: { profile: 'focus', generation: 1 } });
  expect(reset.ok(), 'focus fixture reset').toBe(true);
  await installQualityObservers(page, true);
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);

  let updateArmed = false;
  let deliveredAdvisorRevision = 1;
  let revisedSummaryResponses = 0;
  let findingsResponses = 0;
  let updatedResponses = 0;
  await page.route('**/v1/scans/41/summary', async (route) => {
    const response = await route.fetch();
    const summary = await response.json() as { revision: number; findings_revision: number };
    if (updateArmed) revisedSummaryResponses += 1;
    await route.fulfill({
      response,
      json: updateArmed ? {
        ...summary,
        revision: summary.revision + 1,
        findings_revision: summary.findings_revision + 1,
      } : summary,
    });
  });
  await page.route('**/v1/scans/41/findings?*', async (route) => {
    const response = await route.fetch();
    const page = await response.json() as { items: FixtureFinding[]; revision: number };
    findingsResponses += 1;
    const withVisibleAdvisorState = page.items.map((finding) => finding.id === targetFindingId
      ? {
          ...finding,
          advisor_verdict: 'generated_review',
          advisor_confidence: updateArmed ? 0.6 : 0.5,
          revision: updateArmed ? 2 : 1,
        }
      : finding);
    if (updateArmed) {
      updatedResponses += 1;
      deliveredAdvisorRevision = 2;
    }
    await route.fulfill({ response, json: {
      ...page,
      items: withVisibleAdvisorState,
      revision: updateArmed ? page.revision + 1 : page.revision,
    } });
  });
  await page.route(/\/v1\/scans\/41\/findings\/14(?:\?|$)/, async (route) => {
    const baselineUrl = new URL(route.request().url());
    expect(baselineUrl.searchParams.get('expected_revision')).toBe(String(deliveredAdvisorRevision));
    expect(baselineUrl.searchParams.get('expected_findings_revision')).toBe(String(deliveredAdvisorRevision));
    // Only this overlay advances the fixture. Read its unchanged baseline with
    // the baseline fences, then project the same item/collection revision as
    // the list instead of forwarding revision 2 to the revision-1 server.
    baselineUrl.searchParams.set('expected_revision', '1');
    baselineUrl.searchParams.set('expected_findings_revision', '1');
    const response = await route.fetch({ url: baselineUrl.toString() });
    expect(response.status(), 'unchanged baseline finding detail').toBe(200);
    const finding = await response.json() as FixtureFinding;
    await route.fulfill({ response, json: {
      ...finding,
      ai_verdict: 'generated_review',
      ai_confidence: deliveredAdvisorRevision === 2 ? 0.6 : 0.5,
      ai_reasoning: 'Generated focus evidence remains local and deterministic.',
      ai_fix: 'Validate the generated input before it reaches the sink.',
      revision: deliveredAdvisorRevision,
      findings_revision: deliveredAdvisorRevision,
    } });
  });

  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await page.goto('/?view=findings&scan=41&finding=14');
  await expect(page.getByRole('heading', { level: 1, name: 'Findings' })).toBeVisible();
  await page.waitForLoadState('networkidle');

  const targetItem = page.locator('.finding-list-item', { hasText: targetDisplayId });
  const targetButton = targetItem.locator('.finding-list-main');
  const targetCode = page.getByLabel('Code evidence for src/generated-14.ts');
  await expect(page.locator('.finding-list-track')).toHaveAttribute('aria-label', 'Findings in the current page');
  expect(await page.locator('.finding-list-item').count(), 'bounded initial findings page').toBe(14);
  await expect(targetItem).toHaveClass(/active/);
  await expect(targetButton).toBeFocused();
  await expect(targetCode).toHaveAttribute('data-line-count', '41');
  await expect(targetCode.locator('.code-row.offender .code-line-number')).toHaveText('44');
  await expect(page.locator('.advisor-verdict small')).toHaveText('Confidence 50%');
  expect(findingsResponses, 'one initial Findings response before the measured poll').toBe(1);

  // The default compact preview can fit the whole detail without scrolling.
  // Explicitly expand through the real control to retain the existing 500px
  // nested-scroll workload; compact presentation has its own browser checks.
  await expect(page.getByLabel('Max height')).toHaveValue('220');
  await page.getByRole('button', { name: 'More code', exact: true }).click();
  await expect(page.getByLabel('Max height')).toHaveValue('500');

  const environment = await page.evaluate(() => ({
    userAgent: navigator.userAgent,
    reportedHardwareConcurrency: navigator.hardwareConcurrency,
    reportedDeviceMemoryGiB: 'deviceMemory' in navigator
      ? (navigator as Navigator & { deviceMemory?: number }).deviceMemory ?? null
      : null,
    reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches,
    viewport: { width: innerWidth, height: innerHeight, devicePixelRatio },
  }));
  await testInfo.attach('findings-performance-environment.json', {
    body: Buffer.from(JSON.stringify({
      runner: {
        platform: process.platform,
        architecture: process.arch,
        node: process.version,
        project: testInfo.project.name,
        browser: browser.browserType().name(),
        browserVersion: browser.version(),
      },
      browser: environment,
      resourceNote: 'Browser-reported capability hints only; this journey does not claim measured CPU, RSS, or cgroup allocation.',
      fixture: {
        profile: 'focus',
        generation: 1,
        scanId: 41,
        findingCount: 14,
        targetFindingId,
        targetDisplayId,
        snippetLines: 41,
        snippetViewportHeight: 500,
        pollIntervalMs,
        pollUpdate: { field: 'ai_confidence', from: 0.5, to: 0.6 },
      },
      budgets: { longTaskMs: 50, layoutShift: 0, domCurrent: 2_500, domBoundaryPeak: 2_750 },
    }, null, 2)),
    contentType: 'application/json',
  });

  // The next real application poll receives the one-field fixture revision.
  // Arming happens only after the initial deep link and exact fixture checks.
  updateArmed = true;
  const viewport = page.viewportSize();
  if (!viewport) throw new Error('Findings performance journey requires a fixed viewport.');
  await page.exposeFunction('__kodesecDispatchTrustedClick', async (x: number, y: number) => {
    if (
      !Number.isFinite(x)
      || !Number.isFinite(y)
      || x < 0
      || y < 0
      || x >= viewport.width
      || y >= viewport.height
    ) throw new Error('Trusted Findings click point is outside the fixed viewport.');
    await page.mouse.click(x, y);
  });
  await page.exposeFunction('__kodesecDispatchTrustedWheel', async (x: number, y: number, deltaY: number) => {
    if (
      !Number.isFinite(x)
      || !Number.isFinite(y)
      || !Number.isFinite(deltaY)
      || x < 0
      || y < 0
      || x >= viewport.width
      || y >= viewport.height
      || Math.abs(deltaY) > 720
    ) throw new Error('Trusted Findings wheel input exceeded its viewport or delta bound.');
    await page.mouse.move(x, y);
    await page.mouse.wheel(0, deltaY);
  });
  const result = await withRenderingDiagnostic(browser, page, testInfo, () => page.evaluate(async ({ timeoutMs, exactTargetDisplayId, diagnosticMarker }) => {
    const afterTask = () => new Promise<void>((resolve) => window.setTimeout(resolve, 0));
    const afterTwoFrames = () => new Promise<void>((resolve) => {
      requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
    });
    const waitForMutation = async (
      target: Node,
      predicate: () => boolean,
      label: string,
      timeout: number,
      options: MutationObserverInit = { attributes: true, characterData: true, childList: true, subtree: true },
    ) => {
      if (predicate()) return;
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const finish = (error?: Error) => {
          if (settled) return;
          settled = true;
          observer.disconnect();
          window.clearTimeout(timer);
          if (error) reject(error);
          else resolve();
        };
        const observer = new MutationObserver(() => {
          try {
            if (predicate()) finish();
          } catch (error) {
            finish(error instanceof Error ? error : new Error(`${label} predicate failed.`));
          }
        });
        const timer = window.setTimeout(() => finish(new Error(`${label} exceeded ${timeout} ms.`)), timeout);
        observer.observe(target, options);
        if (predicate()) finish();
      });
    };
    const intersect = (left: DOMRect, right: DOMRect) => ({
      left: Math.max(left.left, right.left),
      top: Math.max(left.top, right.top),
      right: Math.min(left.right, right.right),
      bottom: Math.min(left.bottom, right.bottom),
    });
    const paintedInside = (element: HTMLElement, clips: HTMLElement[], hitOwner: HTMLElement = element) => {
      const style = getComputedStyle(element);
      const opacity = Number.parseFloat(style.opacity);
      const elementRect = element.getBoundingClientRect();
      if (
        style.display === 'none'
        || style.visibility === 'hidden'
        || style.visibility === 'collapse'
        || (Number.isFinite(opacity) && opacity <= 0)
        || elementRect.width < 2
        || elementRect.height < 2
      ) return false;
      let visible = {
        left: Math.max(0, elementRect.left),
        top: Math.max(0, elementRect.top),
        right: Math.min(innerWidth, elementRect.right),
        bottom: Math.min(innerHeight, elementRect.bottom),
      };
      for (const clip of clips) visible = intersect(visible as DOMRect, clip.getBoundingClientRect());
      if (visible.right - visible.left < 2 || visible.bottom - visible.top < 2) return false;
      const x = visible.left + (visible.right - visible.left) / 2;
      const y = visible.top + (visible.bottom - visible.top) / 2;
      const hit = document.elementFromPoint(x, y);
      return Boolean(hit && (hit === hitOwner || hitOwner.contains(hit)));
    };
    const overlayPaintEvidence = (element: HTMLElement, clips: HTMLElement[], hitOwner: HTMLElement) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      const computedTop = Number.parseFloat(style.top);
      const computedHeight = Number.parseFloat(style.height);
      const hasVisiblePaint = !['transparent', 'rgba(0, 0, 0, 0)'].includes(style.backgroundColor)
        || style.boxShadow !== 'none';
      const visiblyPainted = style.position === 'absolute'
        && Number.isFinite(computedTop)
        && computedTop >= 0
        && Number.isFinite(computedHeight)
        && computedHeight > 0
        && rect.width >= 2
        && rect.height >= 2
        && hasVisiblePaint
        && paintedInside(element, clips, hitOwner);
      return {
        visiblyPainted,
        computedTop,
        computedHeight,
        rect: { left: rect.left, top: rect.top, width: rect.width, height: rect.height },
        style: {
          display: style.display,
          visibility: style.visibility,
          opacity: style.opacity,
          position: style.position,
          backgroundColor: style.backgroundColor,
          boxShadow: style.boxShadow,
        },
      };
    };
    const desiredScrollTop = (container: HTMLElement, element: HTMLElement, block: 'start' | 'center') => {
      const containerRect = container.getBoundingClientRect();
      const elementRect = element.getBoundingClientRect();
      const elementTop = container.scrollTop + elementRect.top - containerRect.top;
      const desiredTop = block === 'center'
        ? elementTop - Math.max(0, (container.clientHeight - elementRect.height) / 2)
        : elementTop - 18;
      const maximumTop = Math.max(0, container.scrollHeight - container.clientHeight);
      return Math.min(maximumTop, Math.max(0, desiredTop));
    };
    const waitForStableScroll = async (containers: HTMLElement[], label: string, stableMs: number, timeout: number) => {
      const deadline = performance.now() + timeout;
      let positions = containers.map((container) => container.scrollTop);
      let stableSince = performance.now();
      while (performance.now() - stableSince < stableMs) {
        if (performance.now() >= deadline) throw new Error(`${label} did not settle within ${timeout} ms.`);
        await new Promise<void>((resolve) => window.setTimeout(resolve, 16));
        const nextPositions = containers.map((container) => container.scrollTop);
        if (nextPositions.some((position, index) => position !== positions[index])) {
          positions = nextPositions;
          stableSince = performance.now();
        }
      }
    };
    const required = <T extends Element>(selector: string) => {
      const element = document.querySelector<T>(selector);
      if (!element) throw new Error(`Required Findings element is missing: ${selector}`);
      return element;
    };
    const exactFindingItem = (displayId: string) => {
      const item = [...document.querySelectorAll<HTMLElement>('.finding-list-item')]
        .find((candidate) => candidate.querySelector('.finding-number')?.textContent === displayId);
      if (!item) throw new Error(`Required exact finding is missing: ${displayId}`);
      return item;
    };
    const waitForExactFindingItem = async (displayId: string, label: string) => {
      const listTrack = required<HTMLElement>('.finding-list-track');
      await waitForMutation(
        listTrack,
        () => [...document.querySelectorAll<HTMLElement>('.finding-list-item')]
          .some((candidate) => candidate.querySelector('.finding-number')?.textContent === displayId),
        label,
        1_500,
      );
      return exactFindingItem(displayId);
    };
    const sampleDom = (stage: string) => {
      if (!window.__kodesecSampleDomBoundary) throw new Error('DOM boundary sampling was not installed.');
      return { stage, current: window.__kodesecSampleDomBoundary() };
    };
    const trustedClickToReady = async (
      element: HTMLElement,
      readyRoot: Node,
      ready: () => boolean,
      label: string,
      timeout: number,
    ) => {
      const dispatch = (window as Window & {
        __kodesecDispatchTrustedClick?: (x: number, y: number) => Promise<void>;
      }).__kodesecDispatchTrustedClick;
      if (!dispatch) throw new Error('Trusted input bridge was not installed.');
      const rect = element.getBoundingClientRect();
      let trustedClickReceived = false;
      let inputStarted: number | null = null;
      let resolveInputStarted: (() => void) | undefined;
      const inputStartedPromise = new Promise<void>((resolve) => { resolveInputStarted = resolve; });
      const verifyTrustedClick = (event: MouseEvent) => {
        if (!event.isTrusted || inputStarted !== null) return;
        trustedClickReceived = true;
        inputStarted = performance.now();
        resolveInputStarted?.();
      };
      element.addEventListener('click', verifyTrustedClick, { capture: true, once: true });
      try {
        const readyPromise = (async () => {
          await inputStartedPromise;
          await waitForMutation(readyRoot, ready, label, timeout);
          if (inputStarted === null) throw new Error(`${label} input timing was not captured.`);
          return performance.now() - inputStarted;
        })();
        await dispatch(rect.left + rect.width / 2, rect.top + rect.height / 2);
        if (!trustedClickReceived) throw new Error('Findings input was not a trusted click.');
        return await readyPromise;
      } finally {
        element.removeEventListener('click', verifyTrustedClick, { capture: true });
      }
    };
    const wheelPoint = (container: HTMLElement) => {
      const rect = container.getBoundingClientRect();
      const left = Math.max(1, rect.left + 2);
      const top = Math.max(1, rect.top + 2);
      const right = Math.min(innerWidth - 1, rect.right - 2);
      const bottom = Math.min(innerHeight - 1, rect.bottom - 2);
      if (right <= left || bottom <= top) throw new Error('Findings scrollport is outside the fixed viewport.');
      const fractions = [0.1, 0.25, 0.5, 0.75, 0.9];
      for (const yFraction of fractions) {
        for (const xFraction of fractions) {
          const x = left + (right - left) * xFraction;
          const y = top + (bottom - top) * yFraction;
          const hit = document.elementFromPoint(x, y);
          if (!hit || !container.contains(hit)) continue;
          let candidate: Element | null = hit;
          let nestedScrollport = false;
          while (candidate && candidate !== container) {
            if (candidate instanceof HTMLElement) {
              const style = getComputedStyle(candidate);
              if (
                /(auto|scroll)/.test(style.overflowY)
                && candidate.scrollHeight > candidate.clientHeight + 1
              ) {
                nestedScrollport = true;
                break;
              }
            }
            candidate = candidate.parentElement;
          }
          if (!nestedScrollport) return { x, y };
        }
      }
      throw new Error('No painted point targets the intended Findings scrollport.');
    };
    const trustedScrollWithin = async (
      container: HTMLElement,
      element: HTMLElement,
      block: 'start' | 'center',
      label: string,
    ) => {
      const dispatch = (window as Window & {
        __kodesecDispatchTrustedWheel?: (x: number, y: number, deltaY: number) => Promise<void>;
      }).__kodesecDispatchTrustedWheel;
      if (!dispatch) throw new Error('Trusted wheel input bridge was not installed.');
      const targetTop = desiredScrollTop(container, element, block);
      for (let step = 0; step < 24; step += 1) {
        const remaining = targetTop - container.scrollTop;
        if (Math.abs(remaining) <= 1) return;
        const { x, y } = wheelPoint(container);
        const deltaY = Math.max(-720, Math.min(720, remaining));
        let trustedWheelReceived = false;
        let resolveWheelDelivery: (() => void) | undefined;
        let deliveryTimer: number | undefined;
        const verifyTrustedWheel = (event: WheelEvent) => {
          trustedWheelReceived = event.isTrusted;
          resolveWheelDelivery?.();
        };
        container.addEventListener('wheel', verifyTrustedWheel, { capture: true, once: true, passive: true });
        try {
          const deliveryDeadline = measurementStart + timeoutMs;
          const deliveryRemainingMs = deliveryDeadline - performance.now();
          if (deliveryRemainingMs <= 0) throw new Error(`${label} wheel delivery exceeded the journey deadline.`);
          const wheelDelivered = new Promise<void>((resolve, reject) => {
            resolveWheelDelivery = resolve;
            deliveryTimer = window.setTimeout(() => reject(new Error(`${label} wheel delivery exceeded the journey deadline.`)), deliveryRemainingMs);
          });
          // Observe delivery separately: passive input dispatch can acknowledge
          // before the event. Promise.all handles either rejection immediately.
          await Promise.all([wheelDelivered, dispatch(x, y, deltaY)]);
          if (performance.now() >= deliveryDeadline) throw new Error(`${label} wheel delivery exceeded the journey deadline.`);
          if (!trustedWheelReceived) throw new Error(`${label} input was not a trusted wheel event.`);
          await afterTwoFrames();
        } finally {
          window.clearTimeout(deliveryTimer);
          container.removeEventListener('wheel', verifyTrustedWheel, { capture: true });
        }
      }
      throw new Error(`${label} did not reach its bounded target after trusted wheel input.`);
    };

    // Cross a task boundary so the Playwright evaluate setup is excluded, then
    // reset immediately before the first genuine list scroll/focus/click.
    await afterTask();
    if (!window.__kodesecResetQualityWindow) throw new Error('Quality observers were not installed.');
    window.__kodesecResetQualityWindow();
    const measurementStart = performance.now();
    if (diagnosticMarker) performance.mark(diagnosticMarker, { startTime: measurementStart });
    const timings: Record<string, number> = {};
    const domSamples: Array<{ stage: string; current: number }> = [];

    const main = required<HTMLElement>('main');
    const workspace = required<HTMLElement>('.finding-workspace');
    const list = required<HTMLElement>('.finding-list-scroll');
    let targetItem = exactFindingItem(exactTargetDisplayId);
    let targetButton = targetItem.querySelector<HTMLButtonElement>('.finding-list-main');
    const findingsSurface = required<HTMLElement>('section[data-route-surface="findings"]');
    if (!targetButton) throw new Error('Exact target finding control is missing.');

    const firstScrollStarted = performance.now();
    // Align the desktop `main` owner if the workspace is not already at its
    // target; this journey does not claim that optional alignment moved it.
    // Each bounded child scrollport below must move without chaining into its
    // parent or a sibling scroll owner.
    await trustedScrollWithin(main, workspace, 'start', 'outer Findings scroll');
    const firstListStepBefore = { main: main.scrollTop, list: list.scrollTop };
    const scrollToLogicalIndex = async (index: number, rowHeight: number, label: string) => {
      const maximumTop = Math.max(0, list.scrollHeight - list.clientHeight);
      const targetTop = Math.min(maximumTop, Math.max(
        0,
        index * 138 - Math.max(0, (list.clientHeight - rowHeight) / 2),
      ));
      const dispatch = (window as Window & {
        __kodesecDispatchTrustedWheel?: (x: number, y: number, deltaY: number) => Promise<void>;
      }).__kodesecDispatchTrustedWheel;
      if (!dispatch) throw new Error('Trusted input bridge was not installed.');
      for (let step = 0; step < 24; step += 1) {
        const remaining = targetTop - list.scrollTop;
        if (Math.abs(remaining) <= 1) return;
        const { x, y } = wheelPoint(list);
        let trustedWheelReceived = false;
        let resolveWheelDelivery: (() => void) | undefined;
        let deliveryTimer: number | undefined;
        const verifyTrustedWheel = (event: WheelEvent) => {
          trustedWheelReceived = event.isTrusted;
          resolveWheelDelivery?.();
        };
        list.addEventListener('wheel', verifyTrustedWheel, { capture: true, once: true, passive: true });
        try {
          const deliveryDeadline = measurementStart + timeoutMs;
          const deliveryRemainingMs = deliveryDeadline - performance.now();
          if (deliveryRemainingMs <= 0) throw new Error(`${label} wheel delivery exceeded the journey deadline.`);
          const wheelDelivered = new Promise<void>((resolve, reject) => {
            resolveWheelDelivery = resolve;
            deliveryTimer = window.setTimeout(() => reject(new Error(`${label} wheel delivery exceeded the journey deadline.`)), deliveryRemainingMs);
          });
          // Observe delivery separately: passive input dispatch can acknowledge
          // before the event. Promise.all handles either rejection immediately.
          await Promise.all([wheelDelivered, dispatch(x, y, Math.max(-720, Math.min(720, remaining)))]);
          if (performance.now() >= deliveryDeadline) throw new Error(`${label} wheel delivery exceeded the journey deadline.`);
          if (!trustedWheelReceived) throw new Error(`${label} input was not a trusted wheel event.`);
          await afterTwoFrames();
        } finally {
          window.clearTimeout(deliveryTimer);
          list.removeEventListener('wheel', verifyTrustedWheel, { capture: true });
        }
      }
      throw new Error(`${label} did not reach its bounded target after trusted wheel input.`);
    };
    await scrollToLogicalIndex(0, 128, 'first finding scroll');
    const firstItem = await waitForExactFindingItem('S41-F001', 'first finding virtualization');
    const firstButton = firstItem.querySelector<HTMLButtonElement>('.finding-list-main');
    if (!firstButton) throw new Error('First finding control is missing after virtualization.');
    const firstListStepAfter = { main: main.scrollTop, list: list.scrollTop };
    if (firstListStepAfter.list === firstListStepBefore.list) throw new Error('The intended Findings list scrollport did not move toward S41-F001.');
    if (firstListStepAfter.main !== firstListStepBefore.main) throw new Error('S41-F001 list wheel input chained into the desktop main scroll owner.');
    await afterTwoFrames();
    await afterTask();
    if (!paintedInside(firstButton, [firstItem, list, workspace, main])) throw new Error('S41-F001 was not visibly painted before selection.');
    timings.firstListPaintMs = performance.now() - firstScrollStarted;
    timings.firstInputToReadyMs = await trustedClickToReady(
      firstButton,
      findingsSurface,
      () => firstItem.classList.contains('active') && document.querySelector('.finding-detail h2')?.textContent === 'S41-F001',
      'first finding selection',
      1_500,
    );
    // Include selection rendering and any resulting scroll work in the
    // measured window before starting the opposite-end list journey.
    await waitForStableScroll([main, list], 'first finding scroll', 400, 1_500);
    timings.firstScrollFocusSettleMs = performance.now() - firstScrollStarted;
    domSamples.push(sampleDom('first-selected'));

    const targetScrollStarted = performance.now();
    await trustedScrollWithin(main, workspace, 'start', 'outer Findings scroll');
    const targetListStepBefore = { main: main.scrollTop, list: list.scrollTop };
    const targetPosition = Number(targetItem.getAttribute('aria-posinset')) - 1;
    await scrollToLogicalIndex(targetPosition, 128, 'target finding scroll');
    targetItem = await waitForExactFindingItem(exactTargetDisplayId, 'target finding virtualization');
    targetButton = targetItem.querySelector<HTMLButtonElement>('.finding-list-main');
    if (!targetButton) throw new Error('Target finding control is missing after virtualization.');
    const targetListStepAfter = { main: main.scrollTop, list: list.scrollTop };
    if (targetListStepAfter.list === targetListStepBefore.list) throw new Error('The intended Findings list scrollport did not move toward S41-F014.');
    if (targetListStepAfter.main !== targetListStepBefore.main) throw new Error('S41-F014 list wheel input chained into the desktop main scroll owner.');
    await afterTwoFrames();
    await afterTask();
    if (!paintedInside(targetButton, [targetItem, list, workspace, main])) throw new Error('S41-F014 was not visibly painted before selection.');
    timings.targetListPaintMs = performance.now() - targetScrollStarted;
    timings.targetInputToReadyMs = await trustedClickToReady(
      targetButton,
      findingsSurface,
      () => targetItem.classList.contains('active') && document.querySelector('.finding-detail h2')?.textContent === 'S41-F014',
      'target finding selection',
      1_500,
    );
    if (document.activeElement !== targetButton) throw new Error('Trusted target selection did not leave focus on S41-F014.');
    await waitForStableScroll([main, list], 'target finding scroll', 400, 1_500);
    if (!paintedInside(targetButton, [targetItem, list, workspace, main])) throw new Error('S41-F014 did not remain visibly painted after selection settled.');
    timings.targetScrollFocusSettleMs = performance.now() - targetScrollStarted;
    domSamples.push(sampleDom('target-selected'));

    const evidence = required<HTMLElement>('[aria-label="Code evidence for src/generated-14.ts"]');
    const offender = required<HTMLElement>('[aria-label="Code evidence for src/generated-14.ts"] .code-row.offender');
    const detail = required<HTMLElement>('.finding-detail');
    // Reveal the nested evidence scrollport through its detail owner first;
    // then move the evidence pane itself. Record every owner around each input
    // so nested wheel input cannot silently chain into a parent or sibling.
    const detailStepBefore = { main: main.scrollTop, list: list.scrollTop, detail: detail.scrollTop, evidence: evidence.scrollTop };
    await trustedScrollWithin(detail, evidence, 'center', 'finding detail scroll');
    const detailStepAfter = { main: main.scrollTop, list: list.scrollTop, detail: detail.scrollTop, evidence: evidence.scrollTop };
    if (detailStepAfter.detail === detailStepBefore.detail) throw new Error('The intended finding detail scrollport did not move.');
    if (detailStepAfter.main !== detailStepBefore.main || detailStepAfter.list !== detailStepBefore.list || detailStepAfter.evidence !== detailStepBefore.evidence) {
      throw new Error('Finding detail wheel input chained into an unintended scroll owner.');
    }
    const evidenceStepBefore = { main: main.scrollTop, list: list.scrollTop, detail: detail.scrollTop, evidence: evidence.scrollTop };
    await trustedScrollWithin(evidence, offender, 'center', 'offender evidence scroll');
    const evidenceStepAfter = { main: main.scrollTop, list: list.scrollTop, detail: detail.scrollTop, evidence: evidence.scrollTop };
    if (evidenceStepAfter.evidence === evidenceStepBefore.evidence) throw new Error('The intended evidence scrollport did not move.');
    if (evidenceStepAfter.main !== evidenceStepBefore.main || evidenceStepAfter.list !== evidenceStepBefore.list || evidenceStepAfter.detail !== evidenceStepBefore.detail) {
      throw new Error('Evidence wheel input chained into an unintended scroll owner.');
    }
    await afterTwoFrames();
    await afterTask();
    const offenderPaintEvidenceBeforePoll = overlayPaintEvidence(offender, [evidence, detail, workspace, main], evidence);
    const offenderPaintedBeforePoll = offenderPaintEvidenceBeforePoll.visiblyPainted;
    if (!offenderPaintedBeforePoll) throw new Error('S41-F014 offender evidence was not visibly painted.');
    timings.offenderPaintMs = performance.now() - targetScrollStarted;
    const preservedListScroll = list.scrollTop;
    const preservedMainScroll = main.scrollTop;
    const preservedDetailScroll = detail.scrollTop;
    const preservedEvidenceScroll = evidence.scrollTop;
    if (preservedListScroll <= 0) throw new Error('The measured target scroll did not produce a bounded list offset.');

    const pollWaitStarted = performance.now();
    const confidenceElement = required<HTMLElement>('.advisor-verdict small');
    await waitForMutation(
      confidenceElement,
      () => document.querySelector('.advisor-verdict small')?.textContent === 'Confidence 60%',
      'bounded Findings poll update',
      timeoutMs,
      { characterData: true, childList: true, subtree: true },
    );
    await waitForMutation(
      detail,
      () => detail.getAttribute('aria-busy') === 'false'
        && detail.dataset.findingId === '514'
        && detail.querySelector('[role="alert"]') === null,
      'settled revision-bound finding detail after poll',
      Math.max(1, timeoutMs - (performance.now() - pollWaitStarted)),
      { attributes: true, childList: true, subtree: true },
    );
    timings.pollUpdateMs = performance.now() - pollWaitStarted;
    await afterTwoFrames();
    await afterTask();
    window.__kodesecDrainQualityObservers?.();
    await afterTask();
    window.__kodesecDrainQualityObservers?.();
    if (!window.__kodesecQualitySnapshot) throw new Error('Quality snapshot support was not installed.');
    const quality = window.__kodesecQualitySnapshot();
    domSamples.push(sampleDom('poll-updated'));
    const offenderPaintEvidenceAfterPoll = overlayPaintEvidence(offender, [evidence, detail, workspace, main], evidence);

    return {
      timings: { ...timings, totalMs: performance.now() - measurementStart },
      domSamples,
      quality,
      state: {
        findingCount: document.querySelectorAll('.finding-list-item').length,
        snippetLines: Number(evidence.dataset.lineCount || 0),
        offenderLine: offender.querySelector('.code-line-number')?.textContent || '',
        targetActive: targetItem.classList.contains('active'),
        targetSelected: targetButton.getAttribute('aria-pressed') === 'true',
        targetFocused: document.activeElement === targetButton,
        listScrollBeforePoll: preservedListScroll,
        listScrollAfterPoll: list.scrollTop,
        mainScrollBeforePoll: preservedMainScroll,
        mainScrollAfterPoll: main.scrollTop,
        detailScrollBeforePoll: preservedDetailScroll,
        detailScrollAfterPoll: detail.scrollTop,
        evidenceScrollBeforePoll: preservedEvidenceScroll,
        evidenceScrollAfterPoll: evidence.scrollTop,
        firstListScrollStepBefore: firstListStepBefore,
        firstListScrollStepAfter: firstListStepAfter,
        targetListScrollStepBefore: targetListStepBefore,
        targetListScrollStepAfter: targetListStepAfter,
        detailScrollStepBefore: detailStepBefore,
        detailScrollStepAfter: detailStepAfter,
        evidenceScrollStepBefore: evidenceStepBefore,
        evidenceScrollStepAfter: evidenceStepAfter,
        targetPaintedAfterPoll: paintedInside(targetButton, [targetItem, list, workspace, main]),
        offenderPaintedBeforePoll,
        offenderPaintedAfterPoll: offenderPaintEvidenceAfterPoll.visiblyPainted,
        offenderPaintEvidenceBeforePoll,
        offenderPaintEvidenceAfterPoll,
        targetNodePreservedAfterPoll: document.querySelector('.finding-list-item.active') === targetItem && targetItem.isConnected,
        evidenceNodePreservedAfterPoll: document.querySelector('[aria-label="Code evidence for src/generated-14.ts"]') === evidence && evidence.isConnected,
        confidence: document.querySelector('.advisor-verdict small')?.textContent || '',
        detailReady: detail.getAttribute('aria-busy') === 'false',
        detailErrorCount: detail.querySelectorAll('[role="alert"]').length,
      },
    };
  }, { timeoutMs: qualificationMilliseconds(journeyTimeoutMs), exactTargetDisplayId: targetDisplayId, diagnosticMarker: renderingDiagnostic ? renderingMarker : null }));

  await testInfo.attach('findings-performance-quality.json', {
    body: Buffer.from(JSON.stringify({ ...result, findingsResponses, revisedSummaryResponses, updatedResponses }, null, 2)),
    contentType: 'application/json',
  });

  assertRequiredQualityObservers(result.quality);
  expect(revisedSummaryResponses, 'one authoritative before/after summary pair for the bounded poll').toBe(2);
  expect(updatedResponses, 'one fixture revision delivered by the bounded poll').toBe(1);
  expect(findingsResponses, 'one initial load plus one bounded poll response').toBe(2);
  expect(result.state).toMatchObject({
    snippetLines: 41,
    offenderLine: '44',
    targetActive: true,
    targetSelected: true,
    targetFocused: true,
    targetPaintedAfterPoll: true,
    offenderPaintedBeforePoll: true,
    offenderPaintedAfterPoll: true,
    targetNodePreservedAfterPoll: true,
    evidenceNodePreservedAfterPoll: true,
    confidence: 'Confidence 60%',
    detailReady: true,
    detailErrorCount: 0,
  });
  expect(result.state.findingCount, 'bounded findings page after poll').toBe(14);
  expect(result.state.listScrollBeforePoll, 'measured Findings list scroll offset').toBeGreaterThan(0);
  expect(result.state.listScrollAfterPoll, 'poll preserves the exact Findings list scroll offset').toBe(result.state.listScrollBeforePoll);
  expect(result.state.mainScrollAfterPoll, 'poll preserves the exact desktop main scroll offset').toBe(result.state.mainScrollBeforePoll);
  expect(result.state.detailScrollAfterPoll, 'poll preserves the exact Findings detail scroll offset').toBe(result.state.detailScrollBeforePoll);
  expect(result.state.evidenceScrollAfterPoll, 'poll preserves the exact evidence scroll offset').toBe(result.state.evidenceScrollBeforePoll);
  expect(result.domSamples).toHaveLength(3);
  expect(result.domSamples.filter(({ current }) => current > 2_500), 'exact Findings DOM boundary bounds').toEqual([]);
  expect(result.quality.domCurrent, 'current Findings DOM bound').toBeLessThanOrEqual(2_500);
  expect(result.quality.domBoundaryPeak, 'Findings boundary-sampled DOM peak bound').toBeLessThanOrEqual(2_750);
  if (qualificationPerformanceBudgetsAreBlocking) {
    expect(result.quality.longTasks.filter(({ duration }) => duration > qualificationMilliseconds(50)), 'Findings scroll/update long tasks').toEqual([]);
  }
  expect(result.quality.layoutShift, 'Findings scroll/update layout shifts without recent input').toBe(0);
  guards.assertClean();
});

referenceTest('compact code evidence normalizes hostile line metadata and remains keyboard usable', async ({ page, request, baseURL }, testInfo) => {
  if (!baseURL) throw new Error('Playwright baseURL is required.');

  type SnippetVariant = {
    code: string;
    startLine: number | null;
    endLine: number | null;
    snippetStartLine: number;
  };
  const hostileLines = [
    '<script>globalThis.__kodesecSnippetExecuted = true</script>',
    '',
    'const label = "<img src=x onerror=globalThis.__kodesecSnippetExecuted=true>";',
    'unsafeSink(label);',
    ...Array.from({ length: 37 }, (_value, index) => `const generated${index + 5} = ${index + 5};`),
  ];
  const hostileCode = `${hostileLines.join('\r\n')}\r\n`;
  let variant: SnippetVariant = {
    code: hostileCode,
    startLine: 40,
    endLine: 46,
    snippetStartLine: 43.9,
  };

  const reset = await request.post('/__test/reset', { data: { profile: 'focus', generation: 1 } });
  expect(reset.ok(), 'focus fixture reset').toBe(true);
  const guards = await installRuntimeGuards(page, new URL(baseURL).origin);
  await page.route('**/v1/scans/41/findings?*', async (route) => {
    const response = await route.fetch();
    const findingPage = await response.json() as { items: FixtureFinding[] } & Record<string, unknown>;
    await route.fulfill({
      response,
      json: {
        ...findingPage,
        items: findingPage.items.map((finding) => finding.id === targetFindingId ? {
          ...finding,
          file_path: 'src/edge-case.ts',
          start_line: variant.startLine,
          end_line: variant.endLine,
        } : finding),
      },
    });
  });
  await page.route(/\/v1\/scans\/41\/findings\/14(?:\?|$)/, async (route) => {
    const response = await route.fetch();
    const finding = await response.json() as FixtureFinding;
    await route.fulfill({
      response,
      json: {
        ...finding,
        file_path: 'src/edge-case.ts',
        code_snippet: variant.code,
        start_line: variant.startLine,
        end_line: variant.endLine,
        metadata_json: { snippet_start_line: variant.snippetStartLine },
      },
    });
  });

  const openVariant = async () => {
    await page.goto('/?view=findings&scan=41&finding=14');
    await expect(page.getByRole('heading', { level: 1, name: 'Findings' })).toBeVisible();
    await page.waitForLoadState('networkidle');
    return page.getByLabel('Code evidence for src/edge-case.ts', { exact: true });
  };

  let evidence = await openVariant();
  await expect(evidence).toHaveAccessibleDescription('Offender lines 40 through 46.');
  await expect(evidence).toHaveAttribute('aria-describedby', /\S+/);
  await expect(evidence).toHaveAttribute('data-line-count', '42');
  await expect(evidence.locator('.code-line-numbers')).toHaveText(`43\n${Array.from({ length: 40 }, (_value, index) => index + 44).join('\n')}\n84`);
  const source = evidence.locator('.code-source');
  await expect(source).toHaveText(hostileCode.replace(/\r\n?/g, '\n'));
  await expect(source.locator('script, img')).toHaveCount(0);
  expect(await page.evaluate(() => (globalThis as typeof globalThis & { __kodesecSnippetExecuted?: boolean }).__kodesecSnippetExecuted)).toBeUndefined();

  const overlay = evidence.locator('.code-row.offender');
  await expect(overlay).toHaveAttribute('aria-hidden', 'true');
  await expect(overlay.locator('.code-line-number')).toHaveText('43');
  const overlayEvidence = await overlay.evaluate((element) => {
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return {
      display: style.display,
      visibility: style.visibility,
      opacity: Number.parseFloat(style.opacity),
      position: style.position,
      top: Number.parseFloat(style.top),
      height: Number.parseFloat(style.height),
      rectWidth: rect.width,
      rectHeight: rect.height,
      backgroundColor: style.backgroundColor,
      boxShadow: style.boxShadow,
    };
  });
  expect(overlayEvidence).toMatchObject({
    display: 'grid',
    visibility: 'visible',
    opacity: 1,
    position: 'absolute',
    top: 0,
    height: 88,
    rectHeight: 88,
  });
  expect(overlayEvidence.rectWidth, 'offender overlay has a painted width').toBeGreaterThan(2);
  expect(
    overlayEvidence.backgroundColor !== 'rgba(0, 0, 0, 0)' || overlayEvidence.boxShadow !== 'none',
    'offender overlay has computed paint',
  ).toBe(true);

  await evidence.focus();
  await expect(evidence).toBeFocused();
  expect(await source.evaluate((element) => getComputedStyle(element).userSelect), 'source remains selectable').not.toBe('none');
  const sourceText = hostileCode.replace(/\r\n?/g, '\n');
  expect(await source.evaluate((element) => element.textContent), 'source DOM preserves normalized blank and trailing lines').toBe(sourceText);
  expect(await source.evaluate((element) => {
    const range = document.createRange();
    range.selectNodeContents(element);
    const selection = getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
    const selected = selection?.toString() || '';
    selection?.removeAllRanges();
    return selected;
  }), 'source contents remain selectable').toBe(sourceText.slice(0, -1));

  const resizeControl = page.getByLabel('Max height');
  const initialHeight = await evidence.evaluate((element) => element.clientHeight);
  await resizeControl.focus();
  await resizeControl.press('End');
  await expect(resizeControl).toHaveValue('900');
  expect(await evidence.evaluate((element) => element.clientHeight), 'keyboard resize enlarges edge evidence').toBeGreaterThan(initialHeight);
  await resizeControl.press('Home');
  await expect(resizeControl).toHaveValue('180');
  expect(await evidence.evaluate((element) => element.clientHeight), 'keyboard resize contracts edge evidence').toBeLessThan(initialHeight);

  variant = { code: 'first\r\n\r\nlast\r\n', startLine: null, endLine: null, snippetStartLine: -9.4 };
  evidence = await openVariant();
  await expect(evidence).not.toHaveAttribute('aria-describedby', /.+/);
  await expect(evidence).toHaveAccessibleDescription('');
  await expect(evidence).toHaveAttribute('data-line-count', '4');
  await expect(evidence.locator('.code-line-numbers')).toHaveText('1\n2\n3\n4');
  await expect(evidence.locator('.code-row.offender')).toHaveCount(0);
  await expect(evidence.locator('.code-source')).toHaveText('first\n\nlast\n');

  variant = { code: 'before\r\noffender\r\nafter', startLine: 9, endLine: 9, snippetStartLine: 8.8 };
  evidence = await openVariant();
  await expect(evidence).toHaveAccessibleDescription('Offender line 9.');
  await expect(evidence.locator('.code-line-numbers')).toHaveText('8\n9\n10');
  await expect(evidence.locator('.code-row.offender')).toHaveCSS('top', '22px');
  await expect(evidence.locator('.code-row.offender')).toHaveCSS('height', '22px');
  await expect(evidence.locator('.code-row.offender .code-line-number')).toHaveText('9');

  const maximumSafeLine = Number.MAX_SAFE_INTEGER;
  variant = {
    code: 'penultimate\r\nlast',
    startLine: maximumSafeLine,
    endLine: maximumSafeLine,
    snippetStartLine: maximumSafeLine + 4_096,
  };
  evidence = await openVariant();
  await expect(evidence).toHaveAccessibleDescription(`Offender line ${maximumSafeLine}.`);
  await expect(evidence.locator('.code-line-numbers')).toHaveText(`${maximumSafeLine - 1}\n${maximumSafeLine}`);
  await expect(evidence.locator('.code-row.offender')).toHaveCSS('top', '22px');
  await expect(evidence.locator('.code-row.offender')).toHaveCSS('height', '22px');
  await expect(evidence.locator('.code-row.offender .code-line-number')).toHaveText(`${maximumSafeLine}`);
  const gutterGeometry = await evidence.evaluate((element) => {
    const numbers = element.querySelector('.code-line-numbers');
    const marker = element.querySelector('.code-marker');
    const offenderNumber = element.querySelector('.code-line-number');
    if (!numbers || !marker || !offenderNumber) throw new Error('Complete code gutter is unavailable.');
    const numberRange = document.createRange();
    numberRange.selectNodeContents(numbers);
    const offenderRange = document.createRange();
    offenderRange.selectNodeContents(offenderNumber);
    return {
      gutterLeft: numbers.getBoundingClientRect().left,
      gutterRight: numbers.getBoundingClientRect().right,
      lineNumberLeft: numberRange.getBoundingClientRect().left,
      lineNumberRight: numberRange.getBoundingClientRect().right,
      markerRight: marker.getBoundingClientRect().right,
      offenderNumberLeft: offenderRange.getBoundingClientRect().left,
      offenderNumberRight: offenderRange.getBoundingClientRect().right,
    };
  });
  expect(gutterGeometry.lineNumberLeft, 'all accepted line digits remain within the gutter').toBeGreaterThanOrEqual(gutterGeometry.gutterLeft);
  expect(gutterGeometry.lineNumberRight, 'line digits do not overlap code').toBeLessThanOrEqual(gutterGeometry.gutterRight);
  expect(gutterGeometry.offenderNumberLeft, 'offender digits do not overlap the marker').toBeGreaterThanOrEqual(gutterGeometry.markerRight);
  expect(gutterGeometry.offenderNumberRight, 'offender digits do not overlap code').toBeLessThanOrEqual(gutterGeometry.gutterRight);
  await testInfo.attach('large-line-number-evidence.png', { body: await evidence.screenshot(), contentType: 'image/png' });

  await page.setViewportSize({ width: 320, height: 844 });
  await evidence.scrollIntoViewIfNeeded();
  const narrowGeometry = await evidence.evaluate((element) => {
    const bounds = element.getBoundingClientRect();
    return {
      left: bounds.left,
      right: bounds.right,
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
      documentOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    };
  });
  expect(narrowGeometry.left).toBeGreaterThanOrEqual(0);
  expect(narrowGeometry.right).toBeLessThanOrEqual(320);
  expect(narrowGeometry.documentOverflow).toBeLessThanOrEqual(1);
  expect(narrowGeometry.scrollWidth, 'wide code owns its horizontal overflow at 320px').toBeGreaterThan(narrowGeometry.clientWidth);
  await evidence.focus();
  await evidence.press('ArrowRight');
  await expect.poll(() => evidence.evaluate((element) => element.scrollLeft), { message: 'keyboard users can reach code beyond the narrow viewport' }).toBeGreaterThan(0);
  await evidence.evaluate((element) => { element.scrollLeft = 0; });
  await expect(page.getByRole('button', { name: 'Copy evidence', exact: true })).toBeEnabled();
  await testInfo.attach('populated-evidence-320.png', { body: await evidence.screenshot(), contentType: 'image/png' });

  guards.assertClean();
});
