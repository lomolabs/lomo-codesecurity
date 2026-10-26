import AxeBuilder from '@axe-core/playwright';
import { expect, Page, Request, TestInfo } from '@playwright/test';

type ObserverRegistration = { supported: boolean; registered: boolean };
type NormalizedLoafScript = { duration: number; sourceURL: string; functionName: string };
type RawLoafScript = { duration?: number; sourceURL?: string; sourceFunctionName?: string };

export type Quality = {
  windowStart: number;
  observers: {
    layoutShift: ObserverRegistration;
    longTask: ObserverRegistration;
    longAnimationFrame: ObserverRegistration;
  };
  routeTransitions: Array<{ startTime: number; route: string }>;
  layoutShift: number;
  layoutShiftRecords?: Array<{
    startTime: number;
    value: number;
    hadRecentInput: boolean;
    sources: Array<{
      ancestry: string[];
      previousRect: { x: number; y: number; width: number; height: number };
      currentRect: { x: number; y: number; width: number; height: number };
    }>;
  }>;
  layoutShiftRecordsDropped?: number;
  longTasks: Array<{ duration: number; startTime: number; route: string }>;
  longFrames: Array<{
    duration: number;
    startTime: number;
    blockingDuration: number;
    renderStart: number;
    route: string;
    scripts: NormalizedLoafScript[];
  }>;
  domCurrent: number;
  domBoundaryPeak: number;
};
type NavigationResourceTimings = {
  registration: 'unsupported' | 'registered' | 'failed';
  limit: number;
  matched: number;
  dropped: number;
  invalid: number;
  ignoredOutsideWindow: number;
  globalBufferFullEvents: number;
  records: Array<{
    route: string; pathname: string;
    startMs: number; requestStartMs: number | null; responseEndMs: number;
  }>;
};
type NavigationRoutePhases = {
  route: string;
  inputStartedAtMs: number | null;
  admissionCompletedAtMs: number | null;
  firstDomReadyMs: number | null;
  bridgeSettledMs: number | null;
  finalDomReadyMs: number | null;
  stableReadyMs: number | null;
  fenceAttempts: number;
  fenceRestarts: number;
  observedReadyResets: number;
  paintTaskFenceMs: number;
  admissionWaitMs: number | null;
};
export type NavigationControllerPhase = 'dispatch-start' | 'dispatch-complete' | 'admission-start' | 'admission-complete';
export type NavigationPassResult = {
  routeReadiness: Array<{
    route: string;
    inputToReadyMs: number;
    dispatchLatencyMs: number;
    acknowledgementMs: number;
  }>;
  admissionWaits: Array<{ route: string; waitMs: number }>;
  diagnosticPhaseTimings?: NavigationRoutePhases[];
  diagnosticResourceTimings?: NavigationResourceTimings;
  domSamples: Array<{ route: string; current: number }>;
  routeSurfaces: Array<{ route: string; ariaBusy: boolean; inert: boolean }>;
  finalRoute: string;
  quality: Quality;
};
type NavigationPassCompletion =
  | { ok: true; result: NavigationPassResult }
  | { ok: false; error: string };
type QualityObserverHandle = {
  observer: PerformanceObserver;
  collect: (entries: PerformanceEntry[]) => void;
};
type Failures = { console: string[]; page: string[]; request: string[]; http: string[]; egress: string[]; credentialUrl: string[] };

declare global {
  interface Window {
    __kodesecQuality?: Quality;
    __kodesecQualityObserverHandles?: QualityObserverHandle[];
    __kodesecNormalizeLoafScript?: (script: RawLoafScript) => NormalizedLoafScript;
    __kodesecMarkQualityRoute?: (route: string | null | undefined, startTime?: number) => void;
    __kodesecQualityRouteAt?: (startTime: number) => string;
    __kodesecSampleDomBoundary?: () => number;
    __kodesecDrainQualityObservers?: () => void;
    __kodesecResetQualityWindow?: () => void;
    __kodesecQualitySnapshot?: () => Quality;
    __kodesecCompleteNavigationPass?: (completion: NavigationPassCompletion) => Promise<void>;
    __kodesecDispatchTrustedNavigationClick?: (x: number, y: number, route: string) => Promise<void>;
    __kodesecAwaitNavigationAdmission?: (route: string) => Promise<number>;
    __kodesecCancelNavigationPass?: (reason?: string) => void;
    __kodesecCancelAck?: { duration: number | null };
    __kodesecRetryAck?: { duration: number | null };
  }
}

const safeUrl = (value: string) => {
  try {
    const url = new URL(value);
    return `${url.origin}${url.pathname}`;
  } catch {
    return '<invalid-url>';
  }
};

/**
 * Bridge the two exact, locked Playwright Page declarations used by the test
 * runner and axe. Their runtime object is the same page; only the independently
 * resolved structural declarations differ between the pinned packages.
 */
export function axeBuilder(page: Page): AxeBuilder {
  type AxePage = ConstructorParameters<typeof AxeBuilder>[0]['page'];
  // Keep the full violation evidence used by assertions and attachments, but
  // avoid serializing every matching node for passes, incomplete checks, and
  // inapplicable rules. axe still evaluates the same configured rules.
  return new AxeBuilder({ page: page as unknown as AxePage }).options({ resultTypes: ['violations'] });
}

export async function installQualityObservers(page: Page, captureLayoutShiftSources = false) {
  await page.addInitScript((captureLayoutShiftSources) => {
    const quality: Quality = {
      windowStart: performance.now(),
      observers: {
        layoutShift: { supported: false, registered: false },
        longTask: { supported: false, registered: false },
        longAnimationFrame: { supported: false, registered: false },
      },
      routeTransitions: [],
      layoutShift: 0,
      ...(captureLayoutShiftSources ? { layoutShiftRecords: [], layoutShiftRecordsDropped: 0 } : {}),
      longTasks: [],
      longFrames: [],
      domCurrent: 0,
      domBoundaryPeak: 0,
    };
    window.__kodesecQuality = quality;
    const diagnosticRoute = (value: string | null | undefined) => (
      value && /^[a-z][a-z0-9-]{0,31}$/.test(value) ? value : 'loading'
    );
    const diagnosticPath = (value: string) => {
      try {
        const url = new URL(value, window.location.href);
        if (url.origin !== window.location.origin) return '<external>';
        return url.pathname.length <= 160 ? url.pathname : `${url.pathname.slice(0, 157)}...`;
      } catch {
        return '<invalid-url>';
      }
    };
    const normalizeLoafScript = (script: RawLoafScript): NormalizedLoafScript => {
      const functionName = script.sourceFunctionName || '';
      return {
        duration: Number.isFinite(script.duration) ? Math.max(0, script.duration || 0) : 0,
        sourceURL: script.sourceURL ? diagnosticPath(script.sourceURL) : '',
        functionName: /^[\w$.[\]<>:# -]{0,80}$/.test(functionName) ? functionName : '<redacted>',
      };
    };
    window.__kodesecNormalizeLoafScript = normalizeLoafScript;
    const markRoute = (value: string | null | undefined, candidateStartTime = performance.now()) => {
      const route = diagnosticRoute(value);
      const previous = quality.routeTransitions.at(-1);
      if (previous?.route === route) return;
      const startTime = Number.isFinite(candidateStartTime)
        ? Math.max(previous?.startTime || 0, candidateStartTime)
        : performance.now();
      quality.routeTransitions.push({ startTime, route });
      if (quality.routeTransitions.length > 32) quality.routeTransitions.shift();
    };
    const routeAt = (startTime: number) => {
      for (let index = quality.routeTransitions.length - 1; index >= 0; index -= 1) {
        if (quality.routeTransitions[index].startTime <= startTime) return quality.routeTransitions[index].route;
      }
      return quality.routeTransitions[0]?.route || 'loading';
    };
    window.__kodesecMarkQualityRoute = markRoute;
    window.__kodesecQualityRouteAt = routeAt;
    markRoute('loading', quality.windowStart);
    // This metric intentionally reports exact live-document counts at explicit
    // observation boundaries. It does not claim to reconstruct synchronous
    // transient states between MutationObserver deliveries: queued nodes are
    // live, so record-delta reconstruction can double-count nested appends or
    // count mutations performed after a subtree has been detached.
    const sampleDomBoundary = () => {
      const current = document.querySelectorAll('*').length;
      quality.domCurrent = current;
      quality.domBoundaryPeak = Math.max(quality.domBoundaryPeak, current);
      return current;
    };
    window.__kodesecSampleDomBoundary = sampleDomBoundary;
    sampleDomBoundary();
    const collectDom = (records: MutationRecord[]) => {
      for (const record of records) {
        if (
          record.type === 'attributes'
          && record.target instanceof Element
          && record.target.matches('main[data-rendered-view]')
        ) {
          markRoute(record.target.getAttribute('data-rendered-view'));
        }
      }
      sampleDomBoundary();
    };
    const domObserver = new MutationObserver(collectDom);
    domObserver.observe(document, { attributes: true, attributeFilter: ['data-rendered-view'], childList: true, subtree: true });

    const supportedTypes = new Set(PerformanceObserver.supportedEntryTypes || []);
    const handles: QualityObserverHandle[] = [];
    window.__kodesecQualityObserverHandles = handles;
    quality.observers.layoutShift.supported = supportedTypes.has('layout-shift');
    if (quality.observers.layoutShift.supported) try {
      const collect = (entries: PerformanceEntry[]) => {
        for (const entry of entries) {
          const shift = entry as PerformanceEntry & {
            value?: number;
            hadRecentInput?: boolean;
            sources?: Array<{ node?: Node; previousRect: DOMRectReadOnly; currentRect: DOMRectReadOnly }>;
          };
          // Buffered observers can deliver entries from before the most recent
          // reset. Attribute only work that began inside the active window.
          if (entry.startTime >= quality.windowStart && !shift.hadRecentInput) {
            quality.layoutShift += shift.value || 0;
          }
          if (entry.startTime >= quality.windowStart && quality.layoutShiftRecords && shift.value) {
            if (quality.layoutShiftRecords.length >= 16) {
              quality.layoutShiftRecordsDropped = (quality.layoutShiftRecordsDropped || 0) + 1;
              continue;
            }
            const rect = ({ x, y, width, height }: DOMRectReadOnly) => ({ x, y, width, height });
            quality.layoutShiftRecords.push({
              startTime: entry.startTime,
              value: shift.value,
              hadRecentInput: Boolean(shift.hadRecentInput),
              sources: (shift.sources || []).slice(0, 5).map((source) => {
                const ancestry: string[] = [];
                let node = source.node instanceof Element ? source.node : source.node?.parentElement;
                for (let depth = 0; node && depth < 4; depth += 1, node = node.parentElement) {
                  // Static element/class identity and rectangles only: never text,
                  // source paths, IDs, input values or arbitrary attributes.
                  const classes = [...node.classList].filter((name) => /^[a-zA-Z][\w-]{0,63}$/.test(name)).slice(0, 4);
                  ancestry.push(`${node.tagName.toLowerCase()}${classes.map((name) => `.${name}`).join('')}`);
                }
                return { ancestry, previousRect: rect(source.previousRect), currentRect: rect(source.currentRect) };
              }),
            });
          }
        }
      };
      const observer = new PerformanceObserver((list) => collect(list.getEntries()));
      observer.observe({ type: 'layout-shift', buffered: true });
      handles.push({ observer, collect });
      quality.observers.layoutShift.registered = true;
    } catch { /* required registration is asserted by the test process */ }

    quality.observers.longTask.supported = supportedTypes.has('longtask');
    if (quality.observers.longTask.supported) try {
      const collect = (entries: PerformanceEntry[]) => {
        for (const entry of entries) {
          if (entry.startTime >= quality.windowStart) {
            quality.longTasks.push({
              duration: entry.duration,
              startTime: entry.startTime,
              route: routeAt(entry.startTime),
            });
          }
        }
      };
      const observer = new PerformanceObserver((list) => collect(list.getEntries()));
      observer.observe({ type: 'longtask', buffered: true });
      handles.push({ observer, collect });
      quality.observers.longTask.registered = true;
    } catch { /* required registration is asserted by the test process */ }

    quality.observers.longAnimationFrame.supported = supportedTypes.has('long-animation-frame');
    if (quality.observers.longAnimationFrame.supported) try {
      const collect = (entries: PerformanceEntry[]) => {
        for (const entry of entries) {
          if (entry.startTime < quality.windowStart) continue;
          const frame = entry as PerformanceEntry & {
            blockingDuration?: number;
            renderStart?: number;
            scripts?: RawLoafScript[];
          };
          quality.longFrames.push({
            duration: entry.duration,
            startTime: entry.startTime,
            blockingDuration: frame.blockingDuration || 0,
            renderStart: frame.renderStart || 0,
            route: routeAt(entry.startTime),
            scripts: (frame.scripts || []).slice(0, 4).map(normalizeLoafScript),
          });
          if (quality.longFrames.length > 24) quality.longFrames.shift();
        }
      };
      const observer = new PerformanceObserver((list) => collect(list.getEntries()));
      observer.observe({ type: 'long-animation-frame', buffered: true });
      handles.push({ observer, collect });
      quality.observers.longAnimationFrame.registered = true;
    } catch { /* optional diagnostic; longtask remains the hard assertion */ }

    window.__kodesecDrainQualityObservers = () => {
      for (const handle of handles) handle.collect(handle.observer.takeRecords());
    };
    window.__kodesecResetQualityWindow = () => {
      window.__kodesecDrainQualityObservers?.();
      // Discard prior-window mutation records. The reset's exact count becomes
      // the first explicit boundary of the new measurement window.
      domObserver.takeRecords();
      const currentElementCount = document.querySelectorAll('*').length;
      quality.windowStart = performance.now();
      quality.routeTransitions.length = 0;
      const currentRoute = document.querySelector('main')?.getAttribute('data-rendered-view') || 'loading';
      if (!window.__kodesecMarkQualityRoute) throw new Error('Quality route attribution was not installed.');
      window.__kodesecMarkQualityRoute(currentRoute, quality.windowStart);
      quality.layoutShift = 0;
      if (quality.layoutShiftRecords) {
        quality.layoutShiftRecords.length = 0;
        quality.layoutShiftRecordsDropped = 0;
      }
      quality.longTasks.length = 0;
      quality.longFrames.length = 0;
      quality.domCurrent = currentElementCount;
      quality.domBoundaryPeak = currentElementCount;
    };
    window.__kodesecQualitySnapshot = () => {
      const pendingDomRecords = domObserver.takeRecords();
      if (pendingDomRecords.length > 0) collectDom(pendingDomRecords);
      else sampleDomBoundary();
      return {
        ...quality,
        observers: {
          layoutShift: { ...quality.observers.layoutShift },
          longTask: { ...quality.observers.longTask },
          longAnimationFrame: { ...quality.observers.longAnimationFrame },
        },
        routeTransitions: quality.routeTransitions.map((transition) => ({ ...transition })),
        ...(quality.layoutShiftRecords ? {
          layoutShiftRecords: quality.layoutShiftRecords.map((record) => ({
            ...record,
            sources: record.sources.map((source) => ({
              ...source, ancestry: [...source.ancestry], previousRect: { ...source.previousRect }, currentRect: { ...source.currentRect },
            })),
          })),
        } : {}),
        longTasks: [...quality.longTasks],
        longFrames: quality.longFrames.map((frame) => ({ ...frame, scripts: [...frame.scripts] })),
      };
    };
  }, captureLayoutShiftSources);
}

export async function resetQualityWindow(page: Page) {
  await page.evaluate(() => {
    if (!window.__kodesecResetQualityWindow) throw new Error('Quality observers were not installed.');
    window.__kodesecResetQualityWindow();
  });
}

export async function qualitySnapshot(page: Page): Promise<Quality> {
  return page.evaluate(() => {
    if (!window.__kodesecQualitySnapshot) throw new Error('Quality observers were not installed.');
    window.__kodesecDrainQualityObservers?.();
    return window.__kodesecQualitySnapshot();
  });
}

export function assertRequiredQualityObservers(quality: Quality) {
  expect(quality.observers.layoutShift.supported, 'layout-shift observer support').toBe(true);
  expect(quality.observers.layoutShift.registered, 'layout-shift observer registration').toBe(true);
  expect(quality.observers.longTask.supported, 'longtask observer support').toBe(true);
  expect(quality.observers.longTask.registered, 'longtask observer registration').toBe(true);
}

export function installRuntimeObservationGuards(page: Page, expectedOrigin: string) {
  let canonicalHttpOrigin = false;
  try {
    const parsedOrigin = new URL(expectedOrigin);
    canonicalHttpOrigin = /^https?:$/.test(parsedOrigin.protocol) && parsedOrigin.origin === expectedOrigin;
  } catch { /* Reject invalid origin input below without including it in the error. */ }
  if (!canonicalHttpOrigin) throw new Error('Runtime guards require an exact canonical HTTP(S) origin.');
  const failures: Failures = { console: [], page: [], request: [], http: [], egress: [], credentialUrl: [] };
  page.on('console', (message) => { if (message.type() === 'error') failures.console.push(message.text()); });
  page.on('pageerror', (error) => failures.page.push(error.message));
  page.on('requestfailed', (request) => failures.request.push(`${request.method()} ${safeUrl(request.url())}: ${request.failure()?.errorText || 'failed'}`));
  page.on('response', (response) => { if (response.status() >= 400) failures.http.push(`${response.status()} ${safeUrl(response.url())}`); });
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (/^https?:$/.test(url.protocol) && url.origin !== expectedOrigin) failures.egress.push(`${request.method()} ${safeUrl(request.url())}`);
    for (const name of url.searchParams.keys()) {
      if (/token|secret|password|credential|authorization|api[_-]?key/i.test(name)) failures.credentialUrl.push(`${request.method()} ${url.origin}${url.pathname}?<credential-field>`);
    }
  });
  return {
    failures,
    assertClean() {
      // Show correlated HTTP/request evidence with console errors, retaining
      // one fail-fast assertion and every existing zero-error requirement.
      expect(failures, 'runtime security and error guards').toEqual({
        console: [], page: [], request: [], http: [], egress: [], credentialUrl: [],
      });
    },
  };
}

// The proxy A/B diagnostic uses the same observation policy while its owned
// context proxy supplies denial. Ordinary callers always install this route.
export async function installRuntimeGuards(page: Page, expectedOrigin: string) {
  const guards = installRuntimeObservationGuards(page, expectedOrigin);
  const escapedOrigin = expectedOrigin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Only an exact canonical origin prefix skips the client guard callback.
  // Unusual spellings retain the existing URL-parser and fallback behavior.
  const guardedUrls = new RegExp(`^(?!${escapedOrigin}(?:/|$))`);
  await page.route(guardedUrls, async (route) => {
    const url = new URL(route.request().url());
    if (/^https?:$/.test(url.protocol) && url.origin !== expectedOrigin) return route.abort('blockedbyclient');
    // Preserve the global egress deny while allowing narrower same-origin
    // fixture routes registered earlier by a test to supply deterministic
    // delayed/error/revision responses. `continue()` would bypass those
    // handlers because Playwright evaluates routes in reverse registration
    // order.
    return route.fallback();
  });
  return guards;
}

export async function assertStableSurface(page: Page, testInfo: TestInfo) {
  await page.waitForTimeout(120);
  const quality = await qualitySnapshot(page);
  await testInfo.attach('quality.json', { body: Buffer.from(JSON.stringify(quality, null, 2)), contentType: 'application/json' });
  assertRequiredQualityObservers(quality);
  expect(quality.layoutShift, 'stable-surface layout shift').toBe(0);
  expect(quality.longTasks.filter(({ duration }) => duration > 50), 'long tasks over 50 ms').toEqual([]);
  expect(quality.domCurrent, 'current DOM bound').toBeLessThanOrEqual(2_500);
  expect(quality.domBoundaryPeak, 'boundary-sampled DOM peak bound').toBeLessThanOrEqual(2_750);
  const overflow = await page.evaluate(() => Math.max(
    document.documentElement.scrollWidth - document.documentElement.clientWidth,
    document.body.scrollWidth - document.body.clientWidth,
  ));
  expect(overflow, 'horizontal page overflow').toBeLessThanOrEqual(1);
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
}

export async function runIsolatedNavigationPass(
  page: Page,
  routes: ReadonlyArray<{ label: string; view: string }>,
  timeoutMs: number,
  diagnosticPhases = false,
  onDiagnosticControllerPhase?: (event: NavigationControllerPhase, route: string) => void,
  onDiagnosticCounterBoundary?: (stage: 'before-dispatch' | 'after-ready', route: string) => void | Promise<void>,
  registerBridge: Page['exposeFunction'] = page.exposeFunction.bind(page),
): Promise<NavigationPassResult> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('Navigation pass timeout must be positive.');
  if (diagnosticPhases && routes.length > 7) throw new Error('Navigation phase diagnosis is bounded to seven routes.');

  // Prove every control is uniquely addressable and Playwright-actionable
  // before opening the measured window. Repeated journey timing then contains
  // only the product's real DOM click handlers and rendering work, not utility
  // world selector, actionability, evaluate, or polling tasks.
  for (const route of routes) {
    const control = page.locator(`nav button[data-view-target="${route.view}"]`);
    await expect(control, `${route.label} navigation control`).toHaveCount(1);
    await expect(control, `${route.label} navigation control`).toHaveAccessibleName(route.label);
    await expect(control, `${route.label} navigation control`).toBeVisible();
    await expect(control, `${route.label} navigation control`).toBeEnabled();
    await control.click({ trial: true });
  }

  const viewport = page.viewportSize();
  if (!viewport) throw new Error('Navigation pass requires a fixed viewport.');
  const expectedOrigin = new URL(page.url()).origin;
  const expectedRoutes = new Set(routes.map(({ view }) => view));
  const pendingApiRequests = new Set<Request>();
  let requestLimitExceeded = false;
  let apiQuiescence: { changed: () => void; cancel: () => void } | null = null;
  const cancelApiQuiescence = () => apiQuiescence?.cancel();
  const observeRequest = (request: Request) => {
    const url = new URL(request.url());
    if (url.origin === expectedOrigin && (url.pathname.startsWith('/v1/') || url.pathname === '/healthz')) {
      if (pendingApiRequests.size === 512) requestLimitExceeded = true;
      else pendingApiRequests.add(request);
      apiQuiescence?.changed();
    }
  };
  const finishRequest = (request: Request) => {
    if (pendingApiRequests.delete(request)) apiQuiescence?.changed();
  };
  // navigationPass owns a fresh context and closes it in finally, including
  // failures during bridge/evaluate setup before the pass cleanup below.
  page.on('request', observeRequest);
  page.on('requestfinished', finishRequest);
  page.on('requestfailed', finishRequest);
  let hostDeadline = 0;
  let passEnded = false;
  let nextAdmission: { route: string; settled: Promise<void> } | null = null;
  const remainingMs = () => {
    const remaining = hostDeadline - performance.now();
    if (passEnded || remaining <= 0) throw new Error('Navigation admission exceeded the original pass deadline.');
    return remaining;
  };
  const boundedAdmission = async <T>(operation: Promise<T>): Promise<T> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        operation,
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => reject(new Error('Navigation admission exceeded the original pass deadline.')), remainingMs());
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
  const waitForApiQuiescence = (): Promise<void> => {
    const remaining = remainingMs();
    if (apiQuiescence) throw new Error('Navigation API quiescence already has an owner.');
    return new Promise<void>((resolve, reject) => {
      let quietTimer: ReturnType<typeof setTimeout> | undefined;
      let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
      let finished = false;
      const finish = (error?: Error) => {
        if (finished) return;
        finished = true;
        if (quietTimer) clearTimeout(quietTimer);
        if (deadlineTimer) clearTimeout(deadlineTimer);
        if (apiQuiescence === owner) apiQuiescence = null;
        if (error) reject(error);
        else resolve();
      };
      const changed = () => {
        if (quietTimer) clearTimeout(quietTimer);
        quietTimer = undefined;
        if (passEnded || performance.now() >= hostDeadline) {
          finish(new Error('Navigation admission exceeded the original pass deadline.'));
        } else if (requestLimitExceeded) {
          finish(new Error('Navigation admission exceeded its concurrent request bound.'));
        } else if (pendingApiRequests.size === 0) {
          // Match networkidle's 500 ms interval, but observe a fresh API-idle
          // window instead of a previously recorded document lifecycle event.
          quietTimer = setTimeout(() => {
            if (passEnded || performance.now() >= hostDeadline) {
              finish(new Error('Navigation admission exceeded the original pass deadline.'));
            } else if (pendingApiRequests.size === 0) finish();
          }, 500);
        }
      };
      const owner = {
        changed,
        cancel: () => finish(new Error('Navigation API quiescence was cancelled.')),
      };
      apiQuiescence = owner;
      deadlineTimer = setTimeout(() => finish(new Error('Navigation admission exceeded the original pass deadline.')), remaining);
      changed();
    });
  };
  await registerBridge('__kodesecAwaitNavigationAdmission', async (route: string) => {
    if (!nextAdmission || nextAdmission.route !== route) throw new Error('Navigation admission owner does not match the visible route.');
    const counterRead = onDiagnosticCounterBoundary?.('after-ready', route);
    if (counterRead) await boundedAdmission(counterRead);
    const waitStarted = performance.now();
    if (diagnosticPhases) onDiagnosticControllerPhase?.('admission-start', route);
    await boundedAdmission(nextAdmission.settled);
    await waitForApiQuiescence();
    if (requestLimitExceeded || pendingApiRequests.size !== 0) throw new Error('Navigation admission has unfinished API requests or exceeded its concurrent request bound.');
    nextAdmission = null;
    if (diagnosticPhases) onDiagnosticControllerPhase?.('admission-complete', route);
    return performance.now() - waitStarted;
  });
  await registerBridge('__kodesecDispatchTrustedNavigationClick', async (x: number, y: number, route: string) => {
    if (
      !Number.isFinite(x)
      || !Number.isFinite(y)
      || x < 0
      || y < 0
      || x >= viewport.width
      || y >= viewport.height
    ) throw new Error('Trusted navigation click point is outside the fixed viewport.');
    if (!expectedRoutes.has(route) || nextAdmission) throw new Error('Navigation admission was not completed before the next click.');
    const counterRead = onDiagnosticCounterBoundary?.('before-dispatch', route);
    if (counterRead) await boundedAdmission(counterRead);
    // Arm before input and require this new route's exact health request.
    // A previously idle document cannot satisfy this navigation's admission.
    const healthRead = page.waitForRequest((request) => (
      request.method() === 'GET'
      && request.url() === `${expectedOrigin}/healthz`
      && (new URL(page.url()).searchParams.get('view') || 'overview') === route
    ), { timeout: remainingMs() });
    const settled = (async () => {
      const request = await healthRead;
      const response = await boundedAdmission(request.response());
      if (!response || response.status() !== 200) throw new Error('Navigation health admission did not succeed.');
      if (await boundedAdmission(response.finished()) !== null) throw new Error('Navigation health admission did not finish.');
      // API quiescence is measured separately after this exact health read;
      // a document lifecycle event cannot establish fresh SPA reconciliation.
    })();
    void settled.catch(() => undefined);
    nextAdmission = { route, settled };
    if (diagnosticPhases) onDiagnosticControllerPhase?.('dispatch-start', route);
    await page.mouse.click(x, y);
    if (diagnosticPhases) onDiagnosticControllerPhase?.('dispatch-complete', route);
  });

  let resolveCompletion: (result: NavigationPassResult) => void;
  let rejectCompletion: (error: Error) => void;
  const completion = new Promise<NavigationPassResult>((resolve, reject) => {
    resolveCompletion = resolve;
    rejectCompletion = reject;
  });
  await registerBridge('__kodesecCompleteNavigationPass', (message: NavigationPassCompletion) => {
    if (message.ok) resolveCompletion(message.result);
    else rejectCompletion(new Error(`In-page navigation pass failed: ${message.error}`));
  });

  // This evaluate installs the in-page orchestration. During the measured
  // window, the only Playwright renderer input is the bounded page.mouse bridge
  // above: selectors, role lookup, actionability, and locator polling stay out
  // of the window. The two timers keep the first trusted click in a distinct,
  // fully measured task after this evaluate returns.
  hostDeadline = performance.now() + timeoutMs;
  await page.evaluate(({ scheduledRoutes, diagnosticPhases, diagnosticTimeoutMs }) => {
    const controller = new AbortController();
    const { signal } = controller;
    let completionSent = false;
    const resourceWindowStart = diagnosticPhases ? performance.now() : 0;
    const resourceOwners: Array<{ route: string; inputStartedAtMs: number; admissionCompletedAtMs: number | null }> = [];
    const diagnosticResourceTimings: NavigationResourceTimings | undefined = diagnosticPhases ? {
      registration: 'unsupported', limit: 256, matched: 0, dropped: 0, invalid: 0,
      ignoredOutsideWindow: 0, globalBufferFullEvents: 0, records: [],
    } : undefined;
    let resourceObserver: PerformanceObserver | undefined;
    const resourceBufferFull = () => {
      if (diagnosticResourceTimings) diagnosticResourceTimings.globalBufferFullEvents += 1;
    };
    const collectResources = (entries: PerformanceEntry[]) => {
      if (!diagnosticResourceTimings) return;
      for (const entry of entries) {
        if (entry.entryType !== 'resource') continue;
        const resource = entry as PerformanceResourceTiming;
        if (resource.initiatorType !== 'fetch') continue;
        let url: URL;
        try { url = new URL(resource.name); } catch { continue; }
        if (url.origin !== location.origin
          || (!url.pathname.startsWith('/v1/') && url.pathname !== '/healthz')) continue;
        let owner: typeof resourceOwners[number] | undefined;
        for (let index = resourceOwners.length - 1; index >= 0; index -= 1) {
          const candidate = resourceOwners[index];
          if (candidate.inputStartedAtMs <= resource.startTime
            && (candidate.admissionCompletedAtMs === null || resource.startTime <= candidate.admissionCompletedAtMs)) {
            owner = candidate;
            break;
          }
        }
        if (!owner) { diagnosticResourceTimings.ignoredOutsideWindow += 1; continue; }
        diagnosticResourceTimings.matched += 1;
        const boundedTime = (value: number) => Number.isFinite(value)
          && value >= resourceWindowStart && value <= resourceWindowStart + diagnosticTimeoutMs;
        if ((url.pathname !== '/healthz' && !/^\/v1\/[A-Za-z0-9_/-]+$/.test(url.pathname)) || url.pathname.length > 256
          || !boundedTime(resource.startTime) || !boundedTime(resource.responseEnd)
          || resource.responseEnd < resource.startTime) {
          diagnosticResourceTimings.invalid += 1;
          continue;
        }
        if (diagnosticResourceTimings.records.length >= diagnosticResourceTimings.limit) {
          diagnosticResourceTimings.dropped += 1;
          continue;
        }
        // Same renderer performance clock as the trusted click and ready phases.
        // No query, body, headers, serverTiming, epoch or raw resource name is kept.
        diagnosticResourceTimings.records.push({
          route: owner.route, pathname: url.pathname,
          startMs: resource.startTime,
          requestStartMs: boundedTime(resource.requestStart)
            && resource.requestStart >= resource.startTime && resource.requestStart <= resource.responseEnd
            ? resource.requestStart : null,
          responseEndMs: resource.responseEnd,
        });
      }
    };
    if (diagnosticResourceTimings && PerformanceObserver.supportedEntryTypes.includes('resource')) {
      try {
        resourceObserver = new PerformanceObserver((list) => collectResources(list.getEntries()));
        // Future entries only; the global resource timing buffer is not changed.
        resourceObserver.observe({ type: 'resource', buffered: false });
        performance.addEventListener('resourcetimingbufferfull', resourceBufferFull);
        diagnosticResourceTimings.registration = 'registered';
      } catch { diagnosticResourceTimings.registration = 'failed'; }
    }
    const drainResources = () => {
      if (resourceObserver) collectResources(resourceObserver.takeRecords());
    };
    const abortMessage = () => typeof signal.reason === 'string'
      ? signal.reason.slice(0, 200)
      : 'Navigation pass was cancelled.';
    const throwIfAborted = () => {
      if (signal.aborted) throw new DOMException(abortMessage(), 'AbortError');
    };
    function cleanupLifecycle() {
      drainResources();
      resourceObserver?.disconnect();
      resourceObserver = undefined;
      performance.removeEventListener('resourcetimingbufferfull', resourceBufferFull);
      window.removeEventListener('pagehide', handlePageHide);
      delete window.__kodesecCancelNavigationPass;
    }
    function cancel(reason = 'Navigation pass was cancelled.') {
      if (!signal.aborted) controller.abort(reason);
      cleanupLifecycle();
    }
    function handlePageHide() {
      cancel('Navigation page or context was closed.');
    }
    window.__kodesecCancelNavigationPass = cancel;
    window.addEventListener('pagehide', handlePageHide, { once: true });
    const send = async (message: NavigationPassCompletion) => {
      if (completionSent) return;
      completionSent = true;
      cleanupLifecycle();
      if (!window.__kodesecCompleteNavigationPass) throw new Error('Navigation completion bridge is unavailable.');
      await window.__kodesecCompleteNavigationPass(message);
    };
    const afterTwoFrames = () => new Promise<void>((resolve, reject) => {
      let firstFrame = 0;
      let secondFrame = 0;
      const handleAbort = () => {
        cancelAnimationFrame(firstFrame);
        cancelAnimationFrame(secondFrame);
        reject(new DOMException(abortMessage(), 'AbortError'));
      };
      signal.addEventListener('abort', handleAbort, { once: true });
      firstFrame = requestAnimationFrame(() => {
        secondFrame = requestAnimationFrame(() => {
          signal.removeEventListener('abort', handleAbort);
          try {
            throwIfAborted();
            resolve();
          } catch (error) {
            reject(error);
          }
        });
      });
    });
    const afterTask = () => new Promise<void>((resolve, reject) => {
      const timer = window.setTimeout(() => {
        signal.removeEventListener('abort', handleAbort);
        try {
          throwIfAborted();
          resolve();
        } catch (error) {
          reject(error);
        }
      }, 0);
      const handleAbort = () => {
        window.clearTimeout(timer);
        reject(new DOMException(abortMessage(), 'AbortError'));
      };
      signal.addEventListener('abort', handleAbort, { once: true });
    });
    const trustedClick = async (target: HTMLButtonElement, route: string) => {
      throwIfAborted();
      const dispatch = window.__kodesecDispatchTrustedNavigationClick;
      if (!dispatch) throw new Error('Trusted navigation input bridge is unavailable.');
      const rect = target.getBoundingClientRect();
      const x = rect.left + rect.width / 2;
      const y = rect.top + rect.height / 2;
      if (
        rect.width < 1
        || rect.height < 1
        || x < 0
        || y < 0
        || x >= innerWidth
        || y >= innerHeight
      ) throw new Error('Navigation control is outside the measured viewport.');
      await dispatch(x, y, route);
      throwIfAborted();
    };

    const run = async () => {
      try {
        const routeReadiness: Array<{
          route: string;
          inputToReadyMs: number;
          dispatchLatencyMs: number;
          acknowledgementMs: number;
        }> = [];
        const admissionWaits: Array<{ route: string; waitMs: number }> = [];
        const diagnosticPhaseTimings: NavigationRoutePhases[] | undefined = diagnosticPhases ? [] : undefined;
        const domSamples: Array<{ route: string; current: number }> = [];
        const routeSurfaces: Array<{ route: string; ariaBusy: boolean; inert: boolean }> = [];
        for (const route of scheduledRoutes) {
          throwIfAborted();
          const target = document.querySelector<HTMLButtonElement>(`nav button[data-view-target="${route.view}"]`);
          const main = document.querySelector<HTMLElement>('main[data-rendered-view]');
          const routeOwner = main?.parentElement;
          if (!target || !main || !routeOwner) throw new Error(`Navigation control or route surface missing: ${route.view}`);
          if (!window.__kodesecMarkQualityRoute) throw new Error('Quality route attribution was not installed.');

          let inputStarted: number | null = null;
          let dispatchLatencyMs: number | null = null;
          let acknowledgementMs: number | null = null;
          let dispatchRequestedAt: number | null = null;
          const phase: NavigationRoutePhases | undefined = diagnosticPhases ? {
            route: route.view, inputStartedAtMs: null, admissionCompletedAtMs: null,
            firstDomReadyMs: null, bridgeSettledMs: null,
            finalDomReadyMs: null, stableReadyMs: null, fenceAttempts: 0,
            fenceRestarts: 0, observedReadyResets: 0, paintTaskFenceMs: 0,
            admissionWaitMs: null,
          } : undefined;
          let lastObservedReady = false;
          let readinessGeneration = 0;
          let observedReadyNodes: Array<Element | null> = [null, null, null];
          let complete = () => false;
          const routeIsReady = () => {
            if (inputStarted === null || signal.aborted) return false;
            // A committed route replaces the keyed main node. Observe its
            // stable owner and resolve readiness against the current node.
            const currentMain = routeOwner.querySelector<HTMLElement>(':scope > main[data-rendered-view]');
            const heading = currentMain?.querySelector(`h1[data-view-title="${route.view}"]`);
            const surface = currentMain?.querySelector<HTMLElement>(`section[data-route-surface="${route.view}"]`);
            const isReady = Boolean(
              currentMain?.isConnected
              && currentMain.getAttribute('data-rendered-view') === route.view
              && heading
              && surface
              && !surface.hasAttribute('inert')
              && surface.getAttribute('aria-busy') !== 'true'
            );
            const readyNodes = [currentMain, heading ?? null, surface ?? null];
            if (isReady !== lastObservedReady || readyNodes.some((node, index) => node !== observedReadyNodes[index])) {
              readinessGeneration += 1;
            }
            observedReadyNodes = readyNodes;
            // Fixed numeric phases from the existing readiness checks only.
            // A DOM predicate is not itself proof that pixels have painted.
            if (phase && isReady !== lastObservedReady) {
              if (isReady) {
                const elapsed = performance.now() - inputStarted;
                phase.firstDomReadyMs ??= elapsed;
                phase.finalDomReadyMs = elapsed;
              } else phase.observedReadyResets += 1;
            }
            lastObservedReady = isReady;
            return isReady;
          };
          const waitForReady = () => new Promise<void>((resolve, reject) => {
            throwIfAborted();
            const handleAbort = () => reject(new DOMException(abortMessage(), 'AbortError'));
            signal.addEventListener('abort', handleAbort, { once: true });
            complete = () => {
              if (!routeIsReady()) return false;
              signal.removeEventListener('abort', handleAbort);
              resolve();
              return true;
            };
          });
          let ready = waitForReady();
          const observeReadinessMutations = (records: MutationRecord[]) => {
            // A busy -> ready cycle can be batched into one observer callback.
            // Invalidate a painted candidate even if the final predicate is true.
            if (records.some((record) => (
              record.type === 'attributes' && observedReadyNodes.includes(record.target as Element)
            ) || (
              record.type === 'childList' && Array.from(record.removedNodes).some((removed) => (
                observedReadyNodes.some((node) => node !== null && (removed === node || removed.contains(node)))
              ))
            ))) readinessGeneration += 1;
            complete();
          };
          const observer = new MutationObserver(observeReadinessMutations);
          observer.observe(routeOwner, {
            attributes: true,
            attributeFilter: ['aria-busy', 'data-rendered-view', 'data-view-title', 'data-route-surface', 'inert'],
            characterData: true,
            childList: true,
            subtree: true,
          });
          let trustedClickReceived = false;
          const captureTrustedClickStart = (event: MouseEvent) => {
            if (!event.isTrusted || inputStarted !== null) return;
            trustedClickReceived = true;
            inputStarted = performance.now();
            if (!Number.isFinite(event.timeStamp) || event.timeStamp < 0 || event.timeStamp > inputStarted) {
              cancel('Trusted navigation event timestamp is invalid.');
              return;
            }
            acknowledgementMs = inputStarted - event.timeStamp;
            if (phase) {
              phase.inputStartedAtMs = inputStarted;
              resourceOwners.push({ route: route.view, inputStartedAtMs: inputStarted, admissionCompletedAtMs: null });
            }
            if (dispatchRequestedAt === null) throw new Error(`Navigation dispatch started without timing: ${route.view}`);
            dispatchLatencyMs = inputStarted - dispatchRequestedAt;
            window.__kodesecMarkQualityRoute?.(route.view, inputStarted);
            complete();
          };
          target.addEventListener('click', captureTrustedClickStart, { capture: true });
          const observeStableReady = async () => {
            while (true) {
              await ready;
              throwIfAborted();
              observeReadinessMutations(observer.takeRecords());
              if (!routeIsReady()) {
                ready = waitForReady();
                complete();
                continue;
              }
              const generation = readinessGeneration;
              const fenceStart = phase ? performance.now() : 0;
              if (phase) phase.fenceAttempts += 1;
              // Observe the existing paint/task fence in the renderer while the
              // trusted input bridge is outstanding, without serial bridge delay.
              await afterTwoFrames();
              await afterTask();
              if (phase) phase.paintTaskFenceMs += performance.now() - fenceStart;
              observeReadinessMutations(observer.takeRecords());
              if (routeIsReady() && generation === readinessGeneration) {
                if (inputStarted === null) throw new Error(`Navigation input timing was not captured: ${route.view}`);
                return { generation, inputToReadyMs: performance.now() - inputStarted };
              }
              if (phase) phase.fenceRestarts += 1;
              ready = waitForReady();
              complete();
            }
          };
          let routeObservationCompleted = false;
          try {
            dispatchRequestedAt = performance.now();
            let [candidate] = await Promise.all([
              observeStableReady(),
              (async () => {
                await trustedClick(target, route.view);
                if (phase && inputStarted !== null) phase.bridgeSettledMs = performance.now() - inputStarted;
                if (!trustedClickReceived) throw new Error(`Navigation input was not a trusted click: ${route.view}`);
                complete();
              })(),
            ]);
            // Never accept a candidate invalidated before bridge acknowledgement.
            // Re-fence the current generation; do not subtract any nominal delay.
            while (true) {
              observeReadinessMutations(observer.takeRecords());
              if (routeIsReady() && candidate.generation === readinessGeneration) break;
              if (phase) phase.fenceRestarts += 1;
              ready = waitForReady();
              complete();
              candidate = await observeStableReady();
            }
            const inputToReadyMs = candidate.inputToReadyMs;
            if (phase) phase.stableReadyMs = inputToReadyMs;
            if (dispatchLatencyMs === null) throw new Error(`Navigation dispatch timing was not captured: ${route.view}`);
            if (acknowledgementMs === null) throw new Error(`Navigation acknowledgment timing was not captured: ${route.view}`);
            routeReadiness.push({ route: route.view, inputToReadyMs, dispatchLatencyMs, acknowledgementMs });
            routeObservationCompleted = true;
          } finally {
            if (!routeObservationCompleted) cancel('Navigation route observation failed.');
            target.removeEventListener('click', captureTrustedClickStart, { capture: true });
            observer.disconnect();
          }
          const readySurface = routeOwner.querySelector<HTMLElement>(`main[data-rendered-view="${route.view}"] > section[data-route-surface="${route.view}"]`);
          if (!readySurface) throw new Error(`Ready route surface missing: ${route.view}`);
          routeSurfaces.push({
            route: route.view,
            ariaBusy: readySurface.getAttribute('aria-busy') === 'true',
            inert: readySurface.hasAttribute('inert'),
          });
          if (!window.__kodesecSampleDomBoundary) throw new Error('DOM boundary sampling was not installed.');
          domSamples.push({ route: route.view, current: window.__kodesecSampleDomBoundary() });
          throwIfAborted();
          if (!window.__kodesecAwaitNavigationAdmission) throw new Error('Navigation admission bridge is unavailable.');
          const waitMs = await window.__kodesecAwaitNavigationAdmission(route.view);
          throwIfAborted();
          admissionWaits.push({ route: route.view, waitMs });
          const resourceOwner = resourceOwners.at(-1);
          if (phase && resourceOwner) {
            phase.admissionCompletedAtMs = performance.now();
            resourceOwner.admissionCompletedAtMs = phase.admissionCompletedAtMs;
          }
          drainResources();
          if (phase && diagnosticPhaseTimings) {
            phase.admissionWaitMs = waitMs;
            diagnosticPhaseTimings.push(phase);
          }
        }

        // Give the final render two paints and a task boundary, consume any
        // observer records still queued, then cross one more boundary and drain
        // again. The final snapshot therefore includes every >50 ms product
        // task in the window without counting later bridge/Playwright work.
        await afterTwoFrames();
        await afterTask();
        window.__kodesecDrainQualityObservers?.();
        await afterTask();
        window.__kodesecDrainQualityObservers?.();
        if (!window.__kodesecQualitySnapshot) throw new Error('Quality snapshot support was not installed.');
        const quality = window.__kodesecQualitySnapshot();
        const finalRoute = document.querySelector('main')?.getAttribute('data-rendered-view') || 'missing';
        await send({ ok: true, result: { routeReadiness, admissionWaits, ...(diagnosticPhaseTimings ? { diagnosticPhaseTimings, diagnosticResourceTimings } : {}), domSamples, routeSurfaces, finalRoute, quality } });
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown in-page navigation failure.';
        await send({ ok: false, error: message.slice(0, 300) });
      }
    };

    const setupTimer = window.setTimeout(() => {
      try {
        throwIfAborted();
        if (!window.__kodesecResetQualityWindow) throw new Error('Quality observers were not installed.');
        window.__kodesecResetQualityWindow();
        const runTimer = window.setTimeout(() => { void run(); }, 0);
        signal.addEventListener('abort', () => window.clearTimeout(runTimer), { once: true });
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown quality-window failure.';
        void send({ ok: false, error: message.slice(0, 300) });
      }
    }, 0);
    signal.addEventListener('abort', () => window.clearTimeout(setupTimer), { once: true });
  }, { scheduledRoutes: routes, diagnosticPhases, diagnosticTimeoutMs: timeoutMs });

  let timeout: ReturnType<typeof setTimeout> | undefined;
  let timedOut = false;
  const bounded = new Promise<NavigationPassResult>((_resolve, reject) => {
    timeout = setTimeout(() => {
      timedOut = true;
      reject(new Error(`Navigation pass exceeded ${timeoutMs} ms.`));
    }, Math.max(0, hostDeadline - performance.now()));
  });
  let rejectClosed: ((error: Error) => void) | undefined;
  const handlePageClose = () => rejectClosed?.(new Error('Navigation page or context closed before route readiness completed.'));
  const closed = new Promise<NavigationPassResult>((_resolve, reject) => {
    rejectClosed = reject;
    page.once('close', handlePageClose);
  });
  try {
    return await Promise.race([completion, bounded, closed]);
  } finally {
    passEnded = true;
    cancelApiQuiescence();
    page.off('request', observeRequest);
    page.off('requestfinished', finishRequest);
    page.off('requestfailed', finishRequest);
    pendingApiRequests.clear();
    if (timeout) clearTimeout(timeout);
    page.off('close', handlePageClose);
    if (!page.isClosed()) {
      // A renderer or input bridge that caused the pass timeout may also keep a
      // follow-up evaluate queued indefinitely. Start best-effort cancellation,
      // absorb its eventual rejection, and await it only inside the original
      // host deadline. The caller can then close the context to terminate any
      // command that remained queued after the deadline.
      const cancelAttempt = page.evaluate((reason) => window.__kodesecCancelNavigationPass?.(reason), timedOut
        ? `Navigation pass exceeded ${timeoutMs} ms.`
        : 'Navigation pass host orchestration completed.').then(
        () => undefined,
        () => undefined,
      );
      const cleanupRemainingMs = Math.max(0, hostDeadline - performance.now());
      if (cleanupRemainingMs > 0) {
        let cleanupTimeout: ReturnType<typeof setTimeout> | undefined;
        await Promise.race([
          cancelAttempt,
          new Promise<void>((resolve) => {
            cleanupTimeout = setTimeout(resolve, cleanupRemainingMs);
          }),
        ]);
        if (cleanupTimeout) clearTimeout(cleanupTimeout);
      }
    }
  }
}
