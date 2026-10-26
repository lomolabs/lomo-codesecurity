import assert from 'node:assert/strict';
import test from 'node:test';

import {
  browserSessionRenewalDelayMilliseconds,
  sessionFailureRequiresPairing,
} from '../src/authSession.ts';


test('browser session renewal is scheduled at half the server-directed lifetime', () => {
  assert.equal(browserSessionRenewalDelayMilliseconds(43_200), 21_600_000);
  assert.equal(browserSessionRenewalDelayMilliseconds(1), 500);
});


test('browser session renewal rejects missing, fractional, and non-positive lifetimes', () => {
  for (const value of [Number.NaN, 0, -1, 30.5]) {
    assert.throws(
      () => browserSessionRenewalDelayMilliseconds(value),
      /invalid browser-session lifetime/u,
    );
  }
});


test('only an unauthorized session response requires browser pairing', () => {
  assert.equal(sessionFailureRequiresPairing(401), true);
  for (const status of [undefined, 0, 403, 408, 429, 500, 503]) {
    assert.equal(sessionFailureRequiresPairing(status), false);
  }
});
