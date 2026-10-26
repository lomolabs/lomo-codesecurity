export type SettingsDeepLinkLoadState = 'loading' | 'success' | 'error';

export type SettingsDeepLinkBrowser = {
  location: { hash: string };
  requestAnimationFrame(callback: FrameRequestCallback): number;
  cancelAnimationFrame(frame: number): void;
  addEventListener(type: 'hashchange', listener: () => void): void;
  removeEventListener(type: 'hashchange', listener: () => void): void;
};

export type SettingsDeepLinkTarget = {
  scrollIntoView(options: ScrollIntoViewOptions): void;
  focus(options: FocusOptions): void;
};

export type SettingsDeepLinkSubscription = {
  setReady(ready: boolean): void;
  dispose(): void;
};

export function settingsDeepLinkReady(
  routeReady: boolean,
  routeInert: boolean,
  loadState: SettingsDeepLinkLoadState,
) {
  return routeReady && !routeInert && loadState !== 'loading';
}

export function subscribeToExactSettingsDeepLink(
  browser: SettingsDeepLinkBrowser,
  expectedHash: string,
  target: () => SettingsDeepLinkTarget | null,
): SettingsDeepLinkSubscription {
  let ready = false;
  let entryActive = browser.location.hash === expectedHash;
  let entryConsumed = false;
  let pendingFrame: number | null = null;

  function cancelPendingFrame() {
    if (pendingFrame === null) return;
    browser.cancelAnimationFrame(pendingFrame);
    pendingFrame = null;
  }

  function scheduleCurrentEntry() {
    if (!ready || !entryActive || entryConsumed || pendingFrame !== null) return;
    pendingFrame = browser.requestAnimationFrame(() => {
      pendingFrame = null;
      if (
        !ready
        || !entryActive
        || entryConsumed
        || browser.location.hash !== expectedHash
      ) return;
      const element = target();
      if (!element) return;
      entryConsumed = true;
      element.scrollIntoView({ block: 'start' });
      element.focus({ preventScroll: true });
    });
  }

  function reconcileHashEntry() {
    const exactEntry = browser.location.hash === expectedHash;
    if (!exactEntry) {
      entryActive = false;
      entryConsumed = false;
      cancelPendingFrame();
      return;
    }
    if (!entryActive) {
      entryActive = true;
      entryConsumed = false;
    }
    scheduleCurrentEntry();
  }

  browser.addEventListener('hashchange', reconcileHashEntry);

  return Object.freeze({
    setReady(nextReady: boolean) {
      if (ready === nextReady) return;
      ready = nextReady;
      if (!ready) {
        cancelPendingFrame();
        return;
      }
      reconcileHashEntry();
    },
    dispose() {
      ready = false;
      cancelPendingFrame();
      browser.removeEventListener('hashchange', reconcileHashEntry);
    },
  });
}
