import assert from 'node:assert/strict';
import test from 'node:test';

import { schemaInitIsVerified, type SchemaInitStatus } from '../src/schemaStatus.ts';


const verified: SchemaInitStatus = {
  startable: false,
  state: 'completed',
  schema_id: 'lomo-kodesec-0.1.0-initial',
  schema_fingerprint: 'a'.repeat(64),
  initialized_at: '2026-08-28T12:00:00Z',
  evidence: 'schema-identity-and-api-startup-verification',
};

test('initial schema status requires the complete identity and startup proof', () => {
  assert.equal(schemaInitIsVerified(verified), true);
  assert.equal(schemaInitIsVerified({ ...verified, state: 'unverified' }), false);
  assert.equal(schemaInitIsVerified({ ...verified, schema_id: null }), false);
  assert.equal(schemaInitIsVerified({ ...verified, schema_fingerprint: 'not-a-digest' }), false);
  assert.equal(schemaInitIsVerified({ ...verified, initialized_at: null }), false);
  assert.equal(schemaInitIsVerified({ ...verified, evidence: null }), false);
});
