import assert from 'node:assert/strict';
import test from 'node:test';

import {
  settingsDeepLinkReady,
  subscribeToExactSettingsDeepLink,
} from '../src/settingsDeepLink.ts';
import type { SettingsDeepLinkBrowser } from '../src/settingsDeepLink.ts';


function fakeBrowser(initialHash: string) {
  const listeners = new Set<() => void>();
  const frames = new Map<number, FrameRequestCallback>();
  const cancelledFrames: number[] = [];
  let nextFrame = 1;
  const browser: SettingsDeepLinkBrowser = {
    location: { hash: initialHash },
    requestAnimationFrame(callback) {
      const frame = nextFrame;
      nextFrame += 1;
      frames.set(frame, callback);
      return frame;
    },
    cancelAnimationFrame(frame) {
      cancelledFrames.push(frame);
      frames.delete(frame);
    },
    addEventListener(_type, listener) {
      listeners.add(listener);
    },
    removeEventListener(_type, listener) {
      listeners.delete(listener);
    },
  };
  return {
    browser,
    cancelledFrames,
    dispatchHashChange: () => listeners.forEach((listener) => listener()),
    flushFrame() {
      assert.equal(frames.size, 1);
      const [[frame, callback]] = frames;
      frames.delete(frame);
      callback(0);
    },
    frameCount: () => frames.size,
    listenerCount: () => listeners.size,
  };
}


test('Advisor Settings deep-link settles each exact ready anchor entry once', () => {
  assert.equal(settingsDeepLinkReady(false, false, 'success'), false);
  assert.equal(settingsDeepLinkReady(true, true, 'success'), false);
  assert.equal(settingsDeepLinkReady(true, false, 'loading'), false);
  assert.equal(settingsDeepLinkReady(true, false, 'success'), true);
  assert.equal(settingsDeepLinkReady(true, false, 'error'), true);

  const fixture = fakeBrowser('#advisor-providers');
  const effects: string[] = [];
  const subscription = subscribeToExactSettingsDeepLink(
    fixture.browser,
    '#advisor-providers',
    () => ({
      scrollIntoView: (options) => effects.push(`scroll:${options.block}`),
      focus: (options) => effects.push(`focus:${String(options.preventScroll)}`),
    }),
  );

  assert.equal(fixture.listenerCount(), 1);
  assert.equal(fixture.frameCount(), 0, 'the exact initial hash waits for authoritative readiness');
  subscription.setReady(true);
  assert.equal(fixture.frameCount(), 1);
  fixture.dispatchHashChange();
  assert.equal(fixture.frameCount(), 1, 'the same anchor entry keeps one pending frame');
  fixture.flushFrame();
  assert.deepEqual(effects, ['scroll:start', 'focus:true']);

  fixture.dispatchHashChange();
  subscription.setReady(false);
  subscription.setReady(true);
  assert.equal(fixture.frameCount(), 0, 'same-hash rerenders and reloads do not steal focus');

  fixture.browser.location.hash = '#source-boundary';
  fixture.dispatchHashChange();
  assert.equal(fixture.frameCount(), 0, 'an unrelated hash is a no-op');
  fixture.browser.location.hash = '#advisor-providers';
  fixture.dispatchHashChange();
  fixture.dispatchHashChange();
  assert.equal(fixture.frameCount(), 1, 'leaving and re-entering creates one new anchor entry');
  subscription.setReady(false);
  assert.equal(fixture.frameCount(), 0);
  assert.deepEqual(fixture.cancelledFrames, [2]);
  subscription.setReady(true);
  assert.equal(fixture.frameCount(), 1);
  fixture.flushFrame();
  assert.deepEqual(effects, ['scroll:start', 'focus:true', 'scroll:start', 'focus:true']);

  fixture.browser.location.hash = '#source-boundary';
  fixture.dispatchHashChange();
  fixture.browser.location.hash = '#advisor-providers';
  fixture.dispatchHashChange();
  assert.equal(fixture.frameCount(), 1);
  subscription.dispose();
  assert.equal(fixture.frameCount(), 0);
  assert.equal(fixture.listenerCount(), 0);
  assert.deepEqual(fixture.cancelledFrames, [2, 4]);
});
