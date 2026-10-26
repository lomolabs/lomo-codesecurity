import assert from 'node:assert/strict';
import test from 'node:test';

import { pairingKeyExpiryDelay, pairingKeyIsExpired } from '../src/pairingKeyState.ts';

test('browser pairing plaintext expires at its authoritative deadline', () => {
  const expiresAt = '2026-08-30T10:10:00.000Z';
  const before = Date.parse('2026-08-30T10:09:59.500Z');
  const atDeadline = Date.parse(expiresAt);

  assert.equal(pairingKeyIsExpired(expiresAt, before), false);
  assert.equal(pairingKeyExpiryDelay(expiresAt, before), 500);
  assert.equal(pairingKeyIsExpired(expiresAt, atDeadline), true);
  assert.equal(pairingKeyExpiryDelay(expiresAt, atDeadline), 0);
  assert.equal(pairingKeyIsExpired('invalid', before), true);
});
