import assert from 'node:assert/strict';
import test from 'node:test';

import type { AdvisorProviderCollection } from '../src/api.ts';
import { invalidAdvisorProviderReadMessage, requireAdvisorProviderCollection } from '../src/advisorProviderResponse.ts';

const collection: AdvisorProviderCollection = {
  revision: 3,
  active_provider_id: null,
  providers: [{
    id: 'local-default', name: 'Local Ollama', transport: 'local', priority: 0, enabled: true,
    base_url: null, model: 'fixture:latest', model_digest: 'a'.repeat(64),
    ssh_host: null, ssh_port: null, ssh_user: null, authorization: 'not_required',
    status: 'idle', reason: null, reason_code: null, remediation: 'test', last_activity_at: null,
    content_disclosure_approved: false, config_revision: 2, config_digest: 'b'.repeat(64), eligible: false,
  }],
  resolution: { provider_id: null, transport: 'unavailable', reason: 'No eligible provider.', eligible_provider_ids: [] },
};

test('valid provider responses retain exact identities and permit an empty provider collection', () => {
  assert.equal(requireAdvisorProviderCollection(collection), collection);
  assert.deepEqual(requireAdvisorProviderCollection({ ...collection, providers: [] }).providers, []);
  for (const transport of ['local', 'direct', 'ssh'] as const) {
    const value = { ...collection, providers: [{ ...collection.providers[0], transport, last_activity_at: '2026-10-13T13:00:00.123456+00:00' }] };
    assert.equal(requireAdvisorProviderCollection(value), value);
  }
});

for (const [label, value] of Object.entries({
  absent: null,
  empty: {},
  revision: { ...collection, revision: 0 },
  fractionalRevision: { ...collection, revision: 1.5 },
  resolution: { ...collection, resolution: null },
  resolutionIds: { ...collection, resolution: { ...collection.resolution, eligible_provider_ids: [null] } },
  resolutionTransport: { ...collection, resolution: { ...collection.resolution, transport: 'unknown' } },
  providers: { ...collection, providers: {} },
  providerLimit: { ...collection, providers: Array(9).fill(collection.providers[0]) },
  provider: { ...collection, providers: [null] },
  authorization: { ...collection, providers: [{ ...collection.providers[0], authorization: null }] },
  name: { ...collection, providers: [{ ...collection.providers[0], name: 42 }] },
  eligibility: { ...collection, providers: [{ ...collection.providers[0], eligible: 'true' }] },
  priority: { ...collection, providers: [{ ...collection.providers[0], priority: 8 }] },
  providerRevision: { ...collection, providers: [{ ...collection.providers[0], config_revision: 0 }] },
  reason: { ...collection, providers: [{ ...collection.providers[0], reason: {} }] },
  invalidActivity: { ...collection, providers: [{ ...collection.providers[0], last_activity_at: 'not-a-date' }] },
  outOfRangeActivity: { ...collection, providers: [{ ...collection.providers[0], last_activity_at: '999999-01-01T00:00:00Z' }] },
})) {
  test(`invalid provider response is a handled load error: ${label}`, () => {
    assert.throws(() => requireAdvisorProviderCollection(value), { message: invalidAdvisorProviderReadMessage });
  });
}
