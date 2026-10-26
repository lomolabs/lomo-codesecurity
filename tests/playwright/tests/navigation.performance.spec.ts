import { referenceTest } from './support/reference-viewport.js';
import { APIRequestContext, Browser, expect, Request, test, TestInfo } from '@playwright/test';
import { exactProxyContextOptions, startExactOriginProxy, type ProxySnapshot } from '../scripts/exact-origin-proxy.mjs';

import {
  assertRequiredQualityObservers,
  installQualityObservers,
  installRuntimeGuards,
  installRuntimeObservationGuards,
  runIsolatedNavigationPass,
  type NavigationControllerPhase,
} from './support/quality.js';
import {
  qualificationMilliseconds,
  qualificationPerformanceBudgetMode,
  qualificationPerformanceBudgetsAreBlocking,
} from '../timing.js';

const navigationRoutes = ['Projects', 'Jobs', 'Scans', 'Findings', 'Tools', 'Settings', 'Overview']
  .map((label) => ({ label, view: label.toLowerCase() }));
const navigationPassTimeoutMs = qualificationMilliseconds(12_000);
// D-015: owner-approved 50% increase from the original 125 ms p95 budget.
const navigationReadyP95BudgetMs = qualificationMilliseconds(125) * 1.5;
const passesPerProfile = 5;
const navigationPassCount = passesPerProfile * 2;
const proxyAbDiagnostic = process.env.KODESEC_NAVIGATION_PROXY_AB_DIAGNOSTIC === '1';
const renderingDiagnostic = process.env.KODESEC_FINDINGS_RENDER_DIAGNOSTIC === '1';
const rendererMetricsDiagnostic = process.env.KODESEC_NAVIGATION_RENDERER_METRICS_DIAGNOSTIC === '1';
const relativeTimingKeys = [
  'domainLookupStart', 'domainLookupEnd', 'connectStart', 'secureConnectionStart',
  'connectEnd', 'requestStart', 'responseStart', 'responseEnd',
] as const;
type RelativeRequestTiming = Record<typeof relativeTimingKeys[number], number | null>;
const controllerPhaseNames: NavigationControllerPhase[] = [
  'dispatch-start', 'dispatch-complete', 'admission-start', 'admission-complete',
];

// Trace actions, source and bounded JSON attachments remain available when
// this benchmark fails. DOM and raster capture are excluded from its measured
// renderer work; ordinary and diagnostic tests retain the default full trace.
test.use({
  trace: {
    mode: 'retain-on-failure',
    screenshots: false,
    snapshots: false,
    sources: true,
    attachments: true,
  },
});


type WorkerCpuPhaseCollector = (pass: string, event: NavigationControllerPhase, route: string, atMs: number) => void;

// Clock-neutral worker sampling: correlation requires separate reviewed post-analysis.
// The returned native profile is in memory before these normalization/output caps.
async function withWorkerCpuDiagnostic(testInfo: TestInfo, run: (collectPhase?: WorkerCpuPhaseCollector) => Promise<void>) {
  if (process.env.KODESEC_NAVIGATION_WORKER_CPU_DIAGNOSTIC !== '1') return run();
  if (!renderingDiagnostic) throw new Error('Worker CPU capture requires the non-qualifying rendering diagnostic.');
  const { Session } = await import('node:inspector');
  const { fileURLToPath } = await import('node:url');
  const session = new Session();
  const sourceLabels = new Map<string, string>();
  for (const [relative, label] of [
    ['../node_modules/playwright/node_modules/playwright-core/lib/coreBundle.js', 'playwright-core/coreBundle.js'],
    ['../node_modules/playwright/lib/index.js', 'playwright/index.js'],
    ['../node_modules/playwright/lib/worker/workerProcessEntry.js', 'playwright/workerProcessEntry.js'],
    ['../node_modules/playwright/lib/common/index.js', 'playwright/common/index.js'],
    ['../node_modules/playwright/lib/transform/babelBundle.js', 'playwright/babelBundle.js'],
    ['../node_modules/playwright/lib/transform/esmLoader.js', 'playwright/esmLoader.js'],
    ['./navigation.performance.spec.ts', 'navigation.performance.spec.ts'],
    ['./support/quality.ts', 'support/quality.ts'],
  ]) {
    const url = new URL(relative, import.meta.url);
    sourceLabels.set(url.href, label);
    sourceLabels.set(fileURLToPath(url), label);
  }
  for (const name of ['node:events', 'node:fs', 'node:async_hooks', 'node:inspector', 'node:internal/timers', 'node:internal/process/task_queues', 'node:internal/async_hooks', 'node:internal/errors']) sourceLabels.set(name, name);
  const limits = { nodes: 8192, samples: 200_000, edges: 8192, outputBytes: 2 * 1024 * 1024 };
  const brackets = { startBeforeMs: 0, startAfterMs: 0, stopBeforeMs: 0, stopAfterMs: 0 };
  const phaseEvents: Array<{ pass: string; event: NavigationControllerPhase; route: string; atMs: number }> = [];
  let phaseCaptureInvalid = false;
  const collectPhase: WorkerCpuPhaseCollector = (pass, event, route, atMs) => {
    if (phaseEvents.length >= 280 || !/^(fresh|persistent)-[1-5]$/.test(pass)
      || !controllerPhaseNames.includes(event) || !navigationRoutes.some(({ view }) => view === route)
      || !Number.isFinite(atMs) || atMs < brackets.startAfterMs
      || (phaseEvents.length > 0 && atMs < phaseEvents[phaseEvents.length - 1].atMs)) {
      phaseCaptureInvalid = true;
      return;
    }
    phaseEvents.push({ pass, event, route, atMs });
  };
  const post = (method: string, parameters = {}) => new Promise<object>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Worker CPU profiler command did not complete.')), 2_000);
    try {
      session.post(method, parameters, (error, value) => {
        clearTimeout(timer);
        if (error) reject(new Error('Worker CPU profiler command failed.'));
        else {
          if (method === 'Profiler.start') brackets.startAfterMs = performance.now();
          if (method === 'Profiler.stop') brackets.stopAfterMs = performance.now();
          resolve(value ?? {});
        }
      });
    } catch {
      clearTimeout(timer);
      reject(new Error('Worker CPU profiler command failed.'));
    }
  });
  let connected = false;
  let started = false;
  let workFailed = false;
  let workError: unknown;
  let captureFailed = false;
  let disconnected = false;
  let result: Record<string, unknown> = { status: 'not_started' };
  try {
    session.connect(); // Current worker only; never open a listening endpoint.
    connected = true;
    await post('Profiler.enable');
    await post('Profiler.setSamplingInterval', { interval: 1_000 });
    brackets.startBeforeMs = performance.now();
    await post('Profiler.start');
    started = true;
    await run(collectPhase);
  } catch (error) {
    workFailed = true;
    workError = error;
  } finally {
    try {
      if (!started) throw new Error('Worker CPU profiler did not start.');
      brackets.stopBeforeMs = performance.now();
      const { profile } = await post('Profiler.stop') as { profile: import('node:inspector').Profiler.Profile };
      const samples = profile.samples;
      const deltas = profile.timeDeltas;
      const durationUs = profile.endTime - profile.startTime;
      if (!Array.isArray(profile.nodes) || profile.nodes.length > limits.nodes
        || !Array.isArray(samples) || samples.length === 0 || samples.length > limits.samples
        || !Array.isArray(deltas) || deltas.length !== samples.length
        || !Number.isFinite(durationUs) || durationUs <= 0 || durationUs > testInfo.timeout * 1_000) throw new Error('Worker CPU profile exceeds its shape or size bounds.');
      if (phaseCaptureInvalid || (!workFailed && phaseEvents.length !== 280)
        || !Object.values(brackets).every(Number.isFinite)
        || brackets.startBeforeMs > brackets.startAfterMs || brackets.startAfterMs > brackets.stopBeforeMs
        || brackets.stopBeforeMs > brackets.stopAfterMs
        || brackets.stopAfterMs - brackets.startBeforeMs > testInfo.timeout
        || phaseEvents.some(({ atMs }) => atMs > brackets.stopBeforeMs)) throw new Error('Worker CPU phase capture is invalid.');
      const counts = new Map<number, number>();
      const parents = new Map<number, number>();
      const ids = new Set<number>();
      let edges = 0;
      for (const node of profile.nodes) {
        if (!Number.isSafeInteger(node.id) || node.id < 1 || ids.has(node.id)) throw new Error('Worker CPU node identity is invalid.');
        ids.add(node.id);
        for (const child of node.children ?? []) {
          if (!Number.isSafeInteger(child) || child < 1 || parents.has(child) || ++edges > limits.edges) throw new Error('Worker CPU node edges are invalid.');
          parents.set(child, node.id);
        }
      }
      if ([...parents.keys()].some((id) => !ids.has(id))) throw new Error('Worker CPU profile has missing nodes.');
      for (let index = 0; index < samples.length; index += 1) {
        if (!ids.has(samples[index]) || !Number.isSafeInteger(deltas[index]) || deltas[index] < 0 || deltas[index] > durationUs) throw new Error('Worker CPU samples are invalid.');
        counts.set(samples[index], (counts.get(samples[index]) ?? 0) + 1);
      }
      const nodes = profile.nodes.map((node) => {
        const frame = node.callFrame;
        const source = sourceLabels.get(frame.url) ?? (frame.url === '' && frame.functionName === '(idle)' ? 'idle' : frame.url === '' && frame.functionName === '(garbage collector)' ? 'garbage-collector' : 'unmapped');
        const location = (value: number) => source !== 'unmapped' && Number.isSafeInteger(value) && value >= -1 && value <= 10_000_000 ? value : null;
        return { id: node.id, parentId: parents.get(node.id) ?? null, source, line: location(frame.lineNumber), column: location(frame.columnNumber), selfSamples: counts.get(node.id) ?? 0 };
      });
      const sampleDeltaUs = deltas.reduce((sum, value) => sum + value, 0);
      if (!Number.isSafeInteger(sampleDeltaUs) || sampleDeltaUs > durationUs) throw new Error('Worker CPU sample timeline is invalid.');
      const timeline = {
        clock: 'Profiler deltas are relative microseconds; worker times are milliseconds from the pre-start-command observation. No clock equality or sample-phase assignment is claimed.',
        controllerPhaseLimit: 280,
        commandBrackets: Object.fromEntries(Object.entries(brackets).map(([key, value]) => [key, value - brackets.startBeforeMs])),
        controllerPhases: phaseEvents.map(({ atMs, ...event }) => ({ ...event, atMs: atMs - brackets.startBeforeMs })),
        sampleNodeIds: samples,
        timeDeltasUs: deltas,
      };
      result = { status: 'captured', timeline, durationUs, sampleCount: samples.length, sampleDeltaUs: deltas.reduce((sum, value) => sum + value, 0), unmappedSelfSamples: nodes.filter((node) => node.source === 'unmapped').reduce((sum, node) => sum + node.selfSamples, 0), nodes };
    } catch {
      captureFailed = true;
      result = { status: 'capture_failed', code: 'worker_cpu_capture_unavailable' };
    } finally {
      if (connected) {
        try { session.disconnect(); disconnected = true; }
        catch { captureFailed = true; result = { status: 'capture_failed', code: 'worker_cpu_disconnect_failed' }; }
      }
    }
    const envelope = { scope: 'non-qualifying-worker-cpu-diagnostic', clock: 'Clock-neutral numeric timeline; reviewed external calibration is required for phase correlation. No renderer alignment.', captureWindow: 'Ten-pass wrapper including fixture resets, context setup, clicks, admission, assertions and context close.', commandTimeout: 'Two-second event-loop timer; not a hard wall-clock bound when this worker is blocked.', samplingIntervalUs: 1_000, locationBasis: 'Zero-based generated-script line and column; no source-map resolution.', limits, workFailed, disconnected, ...result };
    let body = Buffer.from(JSON.stringify(envelope));
    if (body.byteLength > limits.outputBytes) {
      captureFailed = true;
      body = Buffer.from(JSON.stringify({ scope: envelope.scope, status: 'capture_failed', code: 'worker_cpu_output_overflow', workFailed, disconnected, limits }));
    }
    try { await testInfo.attach('navigation-worker-cpu.json', { body, contentType: 'application/json' }); }
    catch { captureFailed = true; }
    expect.soft(captureFailed, 'Worker CPU capture must be complete and disconnected; diagnostic runs never qualify.').toBe(false);
  }
  if (workFailed) throw workError;
}

type ProxyArm = 'route' | 'proxy-only';
type ReadinessRow = { route: string; inputToReadyMs: number; dispatchLatencyMs: number };
type ProxyComparison = { arm: ProxyArm; proxyUrl: string; captureRows: (rows: ReadinessRow[]) => void };

async function navigationPass(browser: Browser, baseURL: string, testInfo: TestInfo, label: string, collectWorkerPhase?: WorkerCpuPhaseCollector, comparison?: ProxyComparison) {
  const context = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 }, locale: 'en-US', timezoneId: 'UTC', colorScheme: 'dark', reducedMotion: 'reduce', serviceWorkers: 'block', ...(comparison ? { proxy: exactProxyContextOptions(comparison.proxyUrl) } : {}) });
  const page = await context.newPage();
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await installQualityObservers(page);
  const guards = comparison?.arm === 'proxy-only'
    ? installRuntimeObservationGuards(page, new URL(baseURL).origin)
    : await installRuntimeGuards(page, new URL(baseURL).origin);
  const requestOrigin = new URL(baseURL).origin;
  const knownRoutes = new Set(navigationRoutes.map(({ view }) => view));
  const requestTimingStarted = performance.now();
  const requestTimings: Array<{
    id: number;
    event: 'start' | 'finished' | 'failed';
    method: string;
    pathname: string;
    route: string;
    elapsed_ms: number;
    failure?: 'aborted' | 'request_failed';
    relative_timing_ms?: RelativeRequestTiming;
  }> = [];
  const pendingRequests = new Map<Request, { id: number; method: string; pathname: string }>();
  let requestSequence = 0;
  let droppedRequestTimings = 0;
  const controllerPhases: Array<{ event: NavigationControllerPhase; route: string; elapsed_ms: number }> = [];
  let droppedControllerPhases = 0;
  const recordControllerPhase = (event: NavigationControllerPhase, route: string) => {
    if (controllerPhases.length >= 28 || requestTimings.length + controllerPhases.length >= 512 || !knownRoutes.has(route) || !controllerPhaseNames.includes(event)) {
      droppedControllerPhases += 1;
      return;
    }
    const observedAtMs = performance.now();
    controllerPhases.push({ event, route, elapsed_ms: observedAtMs - requestTimingStarted });
    collectWorkerPhase?.(label, event, route, observedAtMs);
  };
  const relativeRequestTiming = (request: Request): RelativeRequestTiming => {
    const timing = request.timing();
    return Object.fromEntries(relativeTimingKeys.map((key) => {
      const value = timing[key];
      return [key, Number.isFinite(value) && value >= 0 && value <= navigationPassTimeoutMs ? value : null];
    })) as RelativeRequestTiming;
  };
  const recordRequestTiming = (
    request: Request,
    event: 'start' | 'finished' | 'failed',
  ) => {
    const url = new URL(request.url());
    if (url.origin !== requestOrigin || (!url.pathname.startsWith('/v1/')
      && !(renderingDiagnostic && url.pathname === '/healthz'))) return;
    if (requestTimings.length + controllerPhases.length >= 512) {
      droppedRequestTimings += 1;
      if (event !== 'start') pendingRequests.delete(request);
      return;
    }
    if (event === 'start') {
      pendingRequests.set(request, {
        id: ++requestSequence,
        method: request.method(),
        pathname: url.pathname.slice(0, 256),
      });
    }
    const identity = pendingRequests.get(request);
    if (!identity) return;
    const requestedView = new URL(page.url()).searchParams.get('view') || 'overview';
    requestTimings.push({
      ...identity,
      event,
      route: knownRoutes.has(requestedView) ? requestedView : 'unknown',
      elapsed_ms: performance.now() - requestTimingStarted,
      ...(renderingDiagnostic && event !== 'start' ? { relative_timing_ms: relativeRequestTiming(request) } : {}),
      ...(event === 'failed' ? {
        failure: request.failure()?.errorText === 'net::ERR_ABORTED' ? 'aborted' as const : 'request_failed' as const,
      } : {}),
    });
    if (event !== 'start') pendingRequests.delete(request);
  };
  const onRequest = (request: Request) => recordRequestTiming(request, 'start');
  const onRequestFinished = (request: Request) => recordRequestTiming(request, 'finished');
  const onRequestFailed = (request: Request) => recordRequestTiming(request, 'failed');
  page.on('request', onRequest);
  page.on('requestfinished', onRequestFinished);
  page.on('requestfailed', onRequestFailed);
  const metricNames = ['TaskDuration', 'ScriptDuration', 'LayoutDuration', 'RecalcStyleDuration', 'ThreadTime', 'Timestamp', 'NavigationStart'] as const;
  type MetricSnapshot = Record<typeof metricNames[number], number>;
  let metricsSession: Awaited<ReturnType<typeof context.newCDPSession>> | undefined;
  let metricBaseline: { route: string; values: MetricSnapshot } | undefined;
  let metricFailed = false;
  const metricRows: Array<{ route: string; windowElapsedMs: number; threadCpuMs: Record<string, number> }> = [];
  const readRendererCounters = async (stage: 'before-dispatch' | 'after-ready', route: string) => {
    try {
      if (!metricsSession || !knownRoutes.has(route) || metricRows.length >= navigationRoutes.length) throw new Error();
      const { metrics } = await metricsSession.send('Performance.getMetrics');
      if (metrics.length > 128) throw new Error();
      const values = Object.fromEntries(metricNames.map((name) => {
        const matches = metrics.filter((metric) => metric.name === name);
        if (matches.length !== 1 || !Number.isFinite(matches[0].value) || matches[0].value < 0) throw new Error();
        return [name, matches[0].value];
      })) as MetricSnapshot;
      if (values.NavigationStart <= 0) throw new Error();
      if (stage === 'before-dispatch') {
        if (metricBaseline || route !== navigationRoutes[metricRows.length].view) throw new Error();
        metricBaseline = { route, values };
        return;
      }
      if (!metricBaseline || metricBaseline.route !== route || values.NavigationStart !== metricBaseline.values.NavigationStart) throw new Error();
      const delta = (name: typeof metricNames[number]) => (values[name] - metricBaseline!.values[name]) * 1_000;
      const elapsed = delta('Timestamp');
      const threadCpuMs = Object.fromEntries(metricNames.slice(0, 5).map((name) => [name, delta(name)]));
      if (elapsed <= 0 || elapsed > navigationPassTimeoutMs || Object.values(threadCpuMs).some((value) => !Number.isFinite(value) || value < 0 || value > navigationPassTimeoutMs)) throw new Error();
      metricRows.push({ route, windowElapsedMs: elapsed, threadCpuMs });
      metricBaseline = undefined;
    } catch { metricFailed = true; throw new Error('Renderer counter snapshot is unsupported, reset, incomplete or invalid.'); }
  };
  let requestTimingAttached = false;
  const attachRequestTiming = async () => {
    if (requestTimingAttached) return;
    requestTimingAttached = true;
    await testInfo.attach(`navigation-requests-${label}.json`, {
      body: Buffer.from(JSON.stringify({
        timing_basis: 'controller-monotonic-ms',
        route_basis: 'requested-view-at-event',
        record_limit: 512,
        dropped_records: droppedRequestTimings,
        records: requestTimings,
        ...(renderingDiagnostic ? {
          scope: 'non-qualifying-diagnostic',
          record_limit_basis: 'request records plus controller phases share the512event limit',
          relative_timing_basis: 'Pinned Chromium: requestStart/sendStart and responseStart/receiveHeadersEnd are relative to timing.requestTime; responseEnd is relative to original requestWillBeSent. Do not subtract fields with different bases. Epoch startTime omitted.',
          relative_timing_limit_ms: navigationPassTimeoutMs,
          null_timing: 'unavailable, negative, nonfinite or beyond the timing limit',
          controller_phase_limit: 28,
          dropped_controller_phases: droppedControllerPhases,
          controller_phases: controllerPhases,
          clock_correlation: 'Request events and controller phases share one monotonic origin. Trusted input lies within dispatch start/complete; renderer phases remain a separate clock.',
        } : {}),
      }, null, 2)),
      contentType: 'application/json',
    });
  };
  try {
    if (comparison) {
      const cacheSession = await context.newCDPSession(page);
      await cacheSession.send('Network.enable');
      await cacheSession.send('Network.setCacheDisabled', { cacheDisabled: true });
      // Retain this session until context close in both matched arms.
    }
    await page.goto('/?view=overview');
    await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
    await page.waitForLoadState('networkidle');
    if (rendererMetricsDiagnostic) {
      if (!renderingDiagnostic || process.env.KODESEC_NAVIGATION_WORKER_CPU_DIAGNOSTIC === '1') throw new Error('Renderer counters require the rendering diagnostic without worker CPU sampling.');
      try {
        metricsSession = await context.newCDPSession(page);
        await metricsSession.send('Performance.enable', { timeDomain: 'threadTicks' });
      } catch { metricFailed = true; throw new Error('Renderer thread-time counters are unsupported or unavailable.'); }
    }
    const result = await runIsolatedNavigationPass(
      page, navigationRoutes, navigationPassTimeoutMs, renderingDiagnostic,
      renderingDiagnostic ? recordControllerPhase : undefined,
      rendererMetricsDiagnostic ? readRendererCounters : undefined,
    );
    comparison?.captureRows(result.routeReadiness);
    const { quality } = result;
    await testInfo.attach(`navigation-quality-${label}.json`, {
      body: Buffer.from(JSON.stringify(result, null, 2)),
      contentType: 'application/json',
    });
    if (renderingDiagnostic) {
      expect(result.diagnosticPhaseTimings).toHaveLength(navigationRoutes.length);
      const resource = result.diagnosticResourceTimings;
      const firstDispatch = controllerPhases.find(({ event }) => event === 'dispatch-start')?.elapsed_ms;
      const finalAdmission = controllerPhases.filter(({ event }) => event === 'admission-complete').at(-1)?.elapsed_ms;
      const finishedIds = new Set(requestTimings.filter(({ event }) => event === 'finished').map(({ id }) => id));
      const measuredStarts = requestTimings.filter(({ event, elapsed_ms }) => (
        event === 'start' && firstDispatch !== undefined && finalAdmission !== undefined
        && elapsed_ms >= firstDispatch && elapsed_ms <= finalAdmission
      ));
      const completedReads = measuredStarts.filter(({ id, method }) => method === 'GET' && finishedIds.has(id));
      const countPaths = (paths: string[]) => [...new Set(paths)].sort()
        .map((pathname) => ({ pathname, count: paths.filter((path) => path === pathname).length }));
      const controllerCounts = countPaths(completedReads.map(({ pathname }) => pathname));
      const rendererCounts = countPaths(resource?.records.map(({ pathname }) => pathname) || []);
      const healthReads = completedReads.filter(({ pathname }) => pathname === '/healthz');
      const healthResources = resource?.records.filter(({ pathname }) => pathname === '/healthz') || [];
      const pathCountsMatch = JSON.stringify(controllerCounts) === JSON.stringify(rendererCounts);
      await testInfo.attach(`navigation-resource-coverage-${label}.json`, {
        body: Buffer.from(JSON.stringify({
          scope: 'non-qualifying-diagnostic',
          clock: 'Resource times and phase inputStartedAtMs use renderer performance.now time origin; phase durations are relative to that click.',
          route_basis: 'resource start within captured renderer trusted-click/admission interval; not proof of request ownership',
          limits: 'Future observer entries only. ResourceTiming has no HTTP method; completed controller GET path counts cross-check coverage without cross-clock subtraction or per-request identity matching. Cache/interception may make requestStart unavailable. start-to-requestStart is pre-request elapsed, not a proven queue delay. responseEnd excludes JSON parse and React commit.',
          buffer: 'Global resource buffer is unchanged. Full events are reported separately; they do not prove observer loss. Count agreement cannot prove absence of offsetting omissions or duplicate resources.',
          first_dispatch_observed: firstDispatch !== undefined,
          final_admission_observed: finalAdmission !== undefined,
          controller_completed_gets: completedReads.length,
          controller_non_gets: measuredStarts.filter(({ method }) => method !== 'GET').length,
          controller_unfinished: measuredStarts.filter(({ id }) => !finishedIds.has(id)).length,
          controller_dropped_records: droppedRequestTimings,
          controller_dropped_phases: droppedControllerPhases,
          path_counts_match: pathCountsMatch, controller_counts: controllerCounts, renderer_counts: rendererCounts,
        }, null, 2)), contentType: 'application/json',
      });
      expect(resource?.registration, 'resource observer registered before measured reads').toBe('registered');
      expect(resource?.dropped, 'diagnostic resource retention bound was not exceeded').toBe(0);
      expect(resource?.invalid, 'diagnostic resource paths and times are complete').toBe(0);
      expect(firstDispatch).toBeDefined();
      expect(finalAdmission).toBeDefined();
      expect(measuredStarts.filter(({ method }) => method !== 'GET')).toEqual([]);
      expect(measuredStarts.filter(({ id }) => !finishedIds.has(id))).toEqual([]);
      expect(droppedRequestTimings + droppedControllerPhases).toBe(0);
      expect(pathCountsMatch, 'resource coverage agrees with completed GET counts by exact pathname').toBe(true);
      expect(healthReads, 'each route refresh includes its critical health dependency').toHaveLength(navigationRoutes.length);
      expect(healthResources.map(({ route }) => route), 'each measured route captures its exact health resource').toEqual(
        navigationRoutes.map(({ view }) => view),
      );
    }
    assertRequiredQualityObservers(quality);
    expect(result.routeReadiness).toHaveLength(navigationRoutes.length);
    expect(result.domSamples).toHaveLength(navigationRoutes.length);
    expect(result.routeSurfaces, 'every measured route surface is active and ready').toEqual(
      navigationRoutes.map(({ view: route }) => ({ route, ariaBusy: false, inert: false })),
    );
    expect(result.domSamples.filter(({ current }) => current > 2_500), 'per-route DOM bounds').toEqual([]);
    expect(result.finalRoute, 'completed navigation route').toBe('overview');
    const navigationLongTasks = quality.longTasks.filter(({ duration }) => duration > qualificationMilliseconds(50));
    if (qualificationPerformanceBudgetsAreBlocking) {
      expect(navigationLongTasks.length, 'bounded navigation long-task count').toBeLessThanOrEqual(2);
      expect(navigationLongTasks.filter(({ duration }) => duration > qualificationMilliseconds(100)), 'navigation tasks beyond the interaction budget').toEqual([]);
    }
    expect(quality.layoutShift, 'navigation layout shifts without recent input').toBe(0);
    expect(quality.domBoundaryPeak, 'navigation boundary-sampled DOM peak bound').toBeLessThanOrEqual(2_750);
    guards.assertClean();
    if (renderingDiagnostic) await attachRequestTiming();
    return result.routeReadiness;
  } catch (error) {
    // Node-side event timing explains ownership without renderer probes or raw
    // URLs, headers, bodies, or native error text in the measured window.
    try {
      await attachRequestTiming();
    } finally {
      throw error;
    }
  } finally {
    page.off('request', onRequest);
    page.off('requestfinished', onRequestFinished);
    page.off('requestfailed', onRequestFailed);
    try {
      if (rendererMetricsDiagnostic) {
        const complete = !metricFailed && !metricBaseline && metricRows.length === navigationRoutes.length;
        await testInfo.attach(`navigation-renderer-counters-${label}.json`, { body: Buffer.from(JSON.stringify({ scope: 'non-qualifying-renderer-thread-counters', status: complete ? 'captured' : 'incomplete', timeDomain: 'threadTicks', limit: 7, counterOverlap: 'TaskDuration is an umbrella; ThreadTime overlaps all task categories. Do not add them.', interval: 'Pre-dispatch snapshot to snapshot requested after stable readiness; includes observer and CDP work and after-ready IPC delay. No overhead subtraction.', rows: metricRows })), contentType: 'application/json' }).catch(() => { metricFailed = true; });
        expect.soft(complete && !metricFailed, 'Renderer counter capture must include every route and retain its receipt.').toBe(true);
      }
    } finally { await context.close(); } // The owned page/context also destroys its diagnostic CDP session.
  }
}

// Both arms share one proxy per pair. Only the unchanged page.route installer
// differs; the observation policy, cache setting and navigation pass are shared.
async function navigationProxyComparison(browser: Browser, request: APIRequestContext, baseURL: string, testInfo: TestInfo) {
  if (!renderingDiagnostic || rendererMetricsDiagnostic
    || process.env.KODESEC_NAVIGATION_WORKER_CPU_DIAGNOSTIC === '1'
    || process.env.KODESEC_PLAYWRIGHT_HEADED !== '1'
    || browser.version() !== '149.0.7827.55') throw new Error('Proxy A/B requires the pinned headed rendering diagnostic without other profilers.');
  type ArmResult = { arm: ProxyArm; status: 'not_started' | 'running' | 'complete' | 'incomplete'; elapsed_ms: number | null; proxy_before: ProxySnapshot | null; proxy_after: ProxySnapshot | null; proxy_deltas: Record<string, number> | null; route_rows: ReadinessRow[] };
  const pairs = Array.from({ length: 10 }, (_, index) => ({
    profile: index < 5 ? 'fresh' : 'persistent', pass: index % 5 + 1,
    generation: index < 5 ? index + 1 : 100,
    order: (index % 2 === 0 ? ['route', 'proxy-only'] : ['proxy-only', 'route']) as ProxyArm[],
    arms: [] as ArmResult[], cleanup: false, proxy_final: null as ProxySnapshot | null,
  }));
  for (const pair of pairs) pair.arms = pair.order.map((arm) => ({ arm, status: 'not_started', elapsed_ms: null, proxy_before: null, proxy_after: null, proxy_deltas: null, route_rows: [] }));
  const assertFixture = async (profile: string, generation: number) => {
    const state = await request.get('/__test/state');
    expect(state.status()).toBe(200);
    expect(await state.json()).toEqual({ profile, generation });
    const commands = await request.get('/__test/commands');
    expect(commands.status()).toBe(200);
    expect(await commands.json(), 'navigation must not mutate the fixture through commands').toEqual([]);
  };
  try {
    for (const pair of pairs) {
      if (pair.profile === 'fresh' || pair.pass === 1) {
        const reset = await request.post('/__test/reset', { data: { profile: pair.profile, generation: pair.generation } });
        expect(reset.status()).toBe(200);
        expect(await reset.json()).toEqual({ profile: pair.profile, generation: pair.generation });
      }
      await assertFixture(pair.profile, pair.generation);
      const proxy = await startExactOriginProxy(new URL(baseURL).origin);
      try {
        for (const row of pair.arms) {
          await assertFixture(pair.profile, pair.generation);
          row.status = 'running';
          row.proxy_before = proxy.snapshot();
          const started = performance.now();
          try {
            await navigationPass(browser, baseURL, testInfo, `${pair.profile}-${pair.pass}-${row.arm}`, undefined,
              { arm: row.arm, proxyUrl: proxy.url, captureRows: (rows) => { row.route_rows = rows; } });
            await assertFixture(pair.profile, pair.generation);
            expect(proxy.snapshot().forwarded).toBeGreaterThan(row.proxy_before.forwarded);
            expect(proxy.snapshot()).toMatchObject({ denied: 0, upgradeDenied: 0, socketLimit: 0, limitExceeded: false, upstreamFailed: 0, timedOut: 0 });
            row.status = 'complete';
          } finally {
            row.elapsed_ms = performance.now() - started;
            if (row.status !== 'complete') row.status = 'incomplete';
            row.proxy_after = proxy.snapshot();
            row.proxy_deltas = Object.fromEntries((['requests', 'forwarded', 'denied', 'tunnelDenied', 'upgradeDenied', 'responseBytes', 'upstreamFailed', 'timedOut', 'socketLimit'] as const)
              .map((key) => [key, row.proxy_after![key] - row.proxy_before![key]]));
          }
        }
      } finally {
        await proxy.close();
        pair.proxy_final = proxy.snapshot();
        pair.cleanup = pair.proxy_final.closed && pair.proxy_final.activeSockets === 0 && pair.proxy_final.activeUpstreams === 0;
        expect.soft(pair.cleanup, 'exact pair proxy is closed without owned sockets or upstreams').toBe(true);
      }
    }
    for (const arm of ['route', 'proxy-only'] as const) {
      const rows = pairs.flatMap((pair) => pair.arms.filter((row) => row.arm === arm).flatMap((row) => row.route_rows));
      expect(rows, `${arm} complete route count`).toHaveLength(70);
      const ordered = rows.map(({ inputToReadyMs }) => inputToReadyMs).sort((left, right) => left - right);
      const p95 = ordered[Math.ceil(ordered.length * 0.95) - 1];
      if (qualificationPerformanceBudgetsAreBlocking) expect.soft(p95, `${arm} navigation input-to-ready p95`).toBeLessThanOrEqual(navigationReadyP95BudgetMs);
    }
  } finally {
    const armSummaries = (['route', 'proxy-only'] as const).map((arm) => {
      const passes = pairs.flatMap((pair) => pair.arms.filter((row) => row.arm === arm));
      const values = passes.flatMap((row) => row.route_rows.map(({ inputToReadyMs }) => inputToReadyMs)).sort((left, right) => left - right);
      const complete = passes.length === 10 && passes.every(({ status }) => status === 'complete') && values.length === 70;
      return { arm, complete, complete_passes: passes.filter(({ status }) => status === 'complete').length, samples: values.length,
        p95_input_to_ready_ms: complete ? values[Math.ceil(values.length * 0.95) - 1] : null };
    });
    await testInfo.attach('navigation-proxy-ab.json', { body: Buffer.from(JSON.stringify({
      scope: 'non-qualifying-proxy-interception-comparison', performance_budget_mode: qualificationPerformanceBudgetMode,
      pass_deadline_ms: navigationPassTimeoutMs, p95_budget_ms: navigationReadyP95BudgetMs, outer_timeout_ms: testInfo.timeout,
      cache_disabled: 'Main-page Network.setCacheDisabled true in both arms; CDP session retained until context close.',
      window: 'Per-arm controller elapsed includes context setup, navigation pass, context close and post-pass fixture validation; it is not the trusted-click metric.',
      limits: 'Counts/windows are supporting observations only. Shared proxy introduces an extra hop in both arms; do not subtract historical non-proxy timings. Incomplete or unstarted rows are retained, never treated as fast samples.',
      arm_summaries: armSummaries, pairs,
    }, null, 2)), contentType: 'application/json' });
  }
}

referenceTest('critical navigation repeats five fresh and five persistent passes', async ({ browser, request, baseURL }, testInfo) => {
  test.setTimeout(navigationPassTimeoutMs * navigationPassCount + qualificationMilliseconds(20_000));
  if (!baseURL) throw new Error('Playwright baseURL is required.');
  if (renderingDiagnostic) {
    testInfo.annotations.push({ type: 'non-qualifying-diagnostic', description: 'Opt-in navigation phase timestamps; all gates remain unchanged.' });
    expect.soft(false, 'Navigation phase capture is diagnostic and cannot qualify.').toBe(true);
  }
  if (proxyAbDiagnostic) return navigationProxyComparison(browser, request, baseURL, testInfo);
  const routeReadiness: Array<{ route: string; inputToReadyMs: number; dispatchLatencyMs: number }> = [];
  await withWorkerCpuDiagnostic(testInfo, async (collectWorkerPhase) => {
    for (let pass = 1; pass <= passesPerProfile; pass += 1) {
      await request.post('/__test/reset', { data: { profile: 'fresh', generation: pass } });
      routeReadiness.push(...await navigationPass(browser, baseURL, testInfo, `fresh-${pass}`, collectWorkerPhase));
      expect(await (await request.get('/__test/state')).json()).toEqual({ profile: 'fresh', generation: pass });
    }
    await request.post('/__test/reset', { data: { profile: 'persistent', generation: 100 } });
    for (let pass = 1; pass <= passesPerProfile; pass += 1) {
      routeReadiness.push(...await navigationPass(browser, baseURL, testInfo, `persistent-${pass}`, collectWorkerPhase));
      expect(await (await request.get('/__test/state')).json()).toEqual({ profile: 'persistent', generation: 100 });
    }
  });
  const inputToReadyValues = routeReadiness.map(({ inputToReadyMs }) => inputToReadyMs);
  const ordered = [...inputToReadyValues].sort((left, right) => left - right);
  const p95 = ordered[Math.max(0, Math.ceil(ordered.length * 0.95) - 1)];
  await testInfo.attach('route-readiness.json', {
    body: Buffer.from(JSON.stringify({
      performance_budget_mode: qualificationPerformanceBudgetMode,
      samples: routeReadiness.length,
      p95_input_to_ready_ms: p95,
      p95_budget_ms: navigationReadyP95BudgetMs,
      input_to_ready_ms: inputToReadyValues,
      dispatch_latency_ms: routeReadiness.map(({ dispatchLatencyMs }) => dispatchLatencyMs),
      route_samples: routeReadiness,
    }, null, 2)),
    contentType: 'application/json',
  });
  expect(routeReadiness).toHaveLength(70);
  if (qualificationPerformanceBudgetsAreBlocking) {
    expect(p95, 'navigation input-to-ready p95').toBeLessThanOrEqual(navigationReadyP95BudgetMs);
  }
});
