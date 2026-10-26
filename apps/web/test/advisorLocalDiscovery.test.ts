import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import type { AdvisorLocalCatalog, AdvisorLocalModel, AdvisorProvider, AdvisorProviderCollection } from '../src/api.ts';
import {
  advisorLocalCatalogSummary,
  advisorProviderDisableReason,
  advisorProviderOperationLabel,
  consumeLocalAdvisorDiscoveryPollAttempt,
  detectedLocalProviderAction,
  detectedLocalProviderInput,
  detectedLocalProviderIsReady,
  exactEnabledLocalProvider,
  localModelSelectorDisabled,
  localAdvisorAutoDetectionKey,
  LOCAL_ADVISOR_DISCOVERY_POLL_LIMIT,
  localAdvisorDiscoveryPollAllowed,
  localAdvisorDiscoveryPollPending,
  localProviderWriteReconciliationReason,
  normalizeAdvisorLocalCatalog,
  selectedLocalModel,
} from '../src/advisorLocalDiscovery.ts';

test('local Advisor autodetection retries only on authoritative worker readiness changes', () => {
  const unavailable = {
    ok: false,
    version: '0.1.0',
    db: true,
    scanner: true,
    worker: false,
    ai: {
      mode: 'auto' as const,
      available: false,
      base_url: 'http://host.docker.internal:11434',
      model: 'qwen3:8b',
      thinking: false,
      models: [],
      reason: 'work_processing_unavailable',
    },
  };
  assert.equal(localAdvisorAutoDetectionKey(1, unavailable), null);
  assert.equal(
    localAdvisorDiscoveryPollPending(unavailable),
    true,
    'the first healthy database response must keep polling until the worker publishes its first heartbeat',
  );
  assert.equal(localAdvisorDiscoveryPollPending({
    ...unavailable,
    db: false,
  }), false, 'database unavailability is terminal for this bounded startup poll');

  const waiting = {
    ...unavailable,
    worker: true,
    ai: { ...unavailable.ai, reason: 'not_checked_by_worker' },
  };
  const waitingKey = localAdvisorAutoDetectionKey(1, waiting);
  assert.ok(waitingKey);
  assert.equal(localAdvisorAutoDetectionKey(1, waiting), waitingKey);
  assert.equal(localAdvisorDiscoveryPollPending(waiting), true);
  assert.equal(localAdvisorDiscoveryPollPending({
    ...waiting,
    ai: { ...waiting.ai, reason: 'worker_advisor_catalog_stale' },
  }), true);

  const ready = {
    ...waiting,
    ok: true,
    ai: { ...waiting.ai, models: ['qwen3:8b'], reason: 'no_provider_configured' },
  };
  assert.notEqual(localAdvisorAutoDetectionKey(1, ready), waitingKey);
  assert.notEqual(localAdvisorAutoDetectionKey(2, ready), localAdvisorAutoDetectionKey(1, ready));
  assert.equal(localAdvisorDiscoveryPollPending(ready), false);
  assert.equal(localAdvisorDiscoveryPollPending({
    ...waiting,
    ai: { ...waiting.ai, reason: 'advisor_connector_unreachable' },
  }), false);
  assert.equal(localAdvisorDiscoveryPollPending({
    ...unavailable,
    ai: { ...unavailable.ai, reason: 'advisor_connector_unreachable' },
  }), false, 'a typed connector failure must not become an endless startup poll');
  assert.equal(localAdvisorDiscoveryPollAllowed(unavailable, 0), true);
  assert.equal(
    localAdvisorDiscoveryPollAllowed(unavailable, LOCAL_ADVISOR_DISCOVERY_POLL_LIMIT - 1),
    true,
  );
  assert.equal(
    localAdvisorDiscoveryPollAllowed(unavailable, LOCAL_ADVISOR_DISCOVERY_POLL_LIMIT),
    false,
    'the existing timer must stop after one bounded startup-discovery budget',
  );
  assert.equal(
    localAdvisorDiscoveryPollAllowed(unavailable, 0),
    true,
    'an explicit retry or new readiness generation restores one bounded budget',
  );
  assert.equal(localAdvisorDiscoveryPollAllowed(ready, 0), false);
  let attempts = 0;
  for (let index = 0; index < LOCAL_ADVISOR_DISCOVERY_POLL_LIMIT; index += 1) {
    attempts = consumeLocalAdvisorDiscoveryPollAttempt(unavailable, attempts, true);
    assert.equal(attempts, index + 1);
  }
  assert.equal(localAdvisorDiscoveryPollAllowed(unavailable, attempts), false);
  assert.equal(
    consumeLocalAdvisorDiscoveryPollAttempt(unavailable, attempts, true),
    LOCAL_ADVISOR_DISCOVERY_POLL_LIMIT,
    'other active work must not let the shared timer overrun the discovery budget',
  );
  assert.equal(
    consumeLocalAdvisorDiscoveryPollAttempt(unavailable, 2, false),
    2,
    'hidden tabs do not consume the discovery budget',
  );
  assert.equal(
    consumeLocalAdvisorDiscoveryPollAttempt(ready, 2, true),
    2,
    'terminal readiness does not consume the discovery budget',
  );
  attempts = 0;
  assert.equal(localAdvisorDiscoveryPollAllowed(unavailable, attempts), true);
  assert.equal(consumeLocalAdvisorDiscoveryPollAttempt(unavailable, attempts, true), 1);
});

const local: AdvisorLocalModel = {
  name: 'qwen3:8b',
  digest: 'a'.repeat(64),
  size_bytes: 5_200_000_000,
  storage: 'local_weights',
};
const cloud: AdvisorLocalModel = {
  name: 'minimax-m3:cloud',
  digest: 'b'.repeat(64),
  size_bytes: 301,
  storage: 'cloud_stub',
};
const catalog: AdvisorLocalCatalog = {
  schema: 'lomo-advisor-local-catalog/v1',
  source: 'dedicated_local_connector',
  models: [local, cloud],
  recommended_model: local.name,
};

test('local discovery keeps cloud stubs visible but pins only true local weights', () => {
  const normalized = normalizeAdvisorLocalCatalog(catalog);
  assert.deepEqual(normalized.models, [local, cloud]);
  assert.equal(advisorLocalCatalogSummary(normalized), 'Detected model details · 1 local · 1 cloud-only');
  assert.equal(selectedLocalModel(normalized, null)?.name, 'qwen3:8b');
  assert.equal(selectedLocalModel(normalized, cloud.name)?.name, 'qwen3:8b');
  assert.deepEqual(detectedLocalProviderInput(local, []), {
    id: 'local-ollama',
    name: 'Local Ollama',
    transport: 'local',
    priority: 0,
    enabled: true,
    base_url: null,
    model: 'qwen3:8b',
    model_digest: 'a'.repeat(64),
    ssh_host: null,
    ssh_port: null,
    ssh_user: null,
  });
  assert.throws(() => detectedLocalProviderInput(cloud, []), /verified local weights/u);
});

test('local-first setup precedes and visually demotes advanced manual provider setup', () => {
  const component = readFileSync(new URL('../src/AdvisorProviders.tsx', import.meta.url), 'utf8');
  const detectIndex = component.indexOf("'Detect local Ollama'");
  const selectorIndex = component.indexOf('advisor-local-model-select');
  const useIndex = component.indexOf('`Use ${detectedModel.name} locally`');
  const detailsIndex = component.indexOf('<details className="advisor-local-catalog">');
  const fullCatalogIndex = component.indexOf('Detected local Ollama model details');
  const advancedIndex = component.indexOf('Advanced: configure a provider manually');
  const addIndex = component.indexOf('<Plus size={16} /> Add provider');
  assert(detectIndex >= 0 && selectorIndex > detectIndex && useIndex > selectorIndex);
  assert(detailsIndex > useIndex && fullCatalogIndex > detailsIndex);
  assert(advancedIndex > fullCatalogIndex && addIndex > advancedIndex);
  assert.match(component.slice(selectorIndex, useIndex), /Full SHA-256 digest/u);
  assert.match(component.slice(fullCatalogIndex, advancedIndex), /full SHA-256 digest/u);
  assert.match(component, /<section className="advisor-provider-advanced advisor-provider-manual"/u);
  assert.match(component.slice(advancedIndex, addIndex), /className="secondary-action"/u);
});

test('local discovery rejects contradictory or unpinned catalog evidence', () => {
  assert.throws(() => normalizeAdvisorLocalCatalog({
    ...catalog,
    models: [{ ...local, size_bytes: 0 }],
  }), /invalid model catalog/u);
  assert.throws(() => normalizeAdvisorLocalCatalog({
    ...catalog,
    recommended_model: cloud.name,
  }), /invalid recommended model/u);
});

test('local model selection stays locked through provider work and re-enables terminally', () => {
  const available = {
    mutationsEnabled: true,
    modelAvailable: true,
    saving: false,
    operationActive: false,
    editorOpen: false,
    detectionLoading: false,
  };
  assert.equal(localModelSelectorDisabled(available), false);
  assert.equal(localModelSelectorDisabled({ ...available, operationActive: true }), true);
  assert.equal(localModelSelectorDisabled({ ...available, editorOpen: true }), true);
  assert.equal(localModelSelectorDisabled({ ...available, saving: true }), true);
  assert.equal(localModelSelectorDisabled({ ...available, mutationsEnabled: false }), true);
  assert.equal(localModelSelectorDisabled(available), false);
});

test('active providers explain the disconnect-before-disable sequence', () => {
  assert.equal(advisorProviderDisableReason(true), 'Disconnect the active provider before disabling it.');
  assert.equal(advisorProviderDisableReason(false), null);
});

test('provider operation labels become terminal with their jobs', () => {
  assert.equal(advisorProviderOperationLabel('test', 'running', true), 'Testing connection');
  assert.equal(advisorProviderOperationLabel('test', 'cancelling', true), 'Cancelling connection test');
  assert.equal(advisorProviderOperationLabel('activate', 'cancelling', true), 'Cancelling activation');
  assert.equal(advisorProviderOperationLabel('disconnect', 'cancelling', true), 'Cancelling disconnect');
  assert.equal(advisorProviderOperationLabel('test', 'completed', false), 'Connection test completed');
  assert.equal(advisorProviderOperationLabel('activate', 'completed', false), 'Provider activated');
  assert.equal(advisorProviderOperationLabel('activate', 'failed', false), 'Activation failed');
});

test('detected local provider uses the first free bounded priority and identity', () => {
  const occupied = [{ id: 'local-ollama', priority: 0 }] as AdvisorProvider[];
  assert.deepEqual(detectedLocalProviderInput(local, occupied), {
    id: 'local-ollama-2',
    name: 'Local Ollama',
    transport: 'local',
    priority: 1,
    enabled: true,
    base_url: null,
    model: 'qwen3:8b',
    model_digest: 'a'.repeat(64),
    ssh_host: null,
    ssh_port: null,
    ssh_user: null,
  });
});

test('detected local model updates the highest-priority local profile without changing its identity', () => {
  const existing = [
    {
      id: 'local-secondary',
      name: 'Secondary local',
      transport: 'local',
      priority: 5,
      enabled: true,
      model: 'old:secondary',
      model_digest: 'c'.repeat(64),
    },
    {
      id: 'local-primary',
      name: 'Private Mac model',
      transport: 'local',
      priority: 2,
      enabled: false,
      model: 'old:primary',
      model_digest: 'd'.repeat(64),
    },
    ...Array.from({ length: 6 }, (_, index) => ({
      id: `remote-${index}`,
      name: `Remote ${index}`,
      transport: 'direct',
      priority: index < 2 ? index : index + 1,
      enabled: true,
      model: 'remote',
      model_digest: 'e'.repeat(64),
    })),
  ] as AdvisorProvider[];

  assert.equal(detectedLocalProviderAction(local, existing), 'update');
  assert.deepEqual(detectedLocalProviderInput(local, existing), {
    id: 'local-primary',
    name: 'Private Mac model',
    transport: 'local',
    priority: 2,
    enabled: true,
    base_url: null,
    model: 'qwen3:8b',
    model_digest: 'a'.repeat(64),
    ssh_host: null,
    ssh_port: null,
    ssh_user: null,
  });
  assert.equal(detectedLocalProviderAction(local, [{
    ...existing[1],
    model: local.name,
    model_digest: local.digest,
  }] as AdvisorProvider[]), 'current');
  assert.equal(detectedLocalProviderAction(local, existing.filter((provider) => provider.transport !== 'local')), 'add');
});

test('detected local model is ready only after the exact enabled provider is active and resolved locally', () => {
  const provider = {
    id: 'local-ollama',
    name: 'Local Ollama',
    transport: 'local',
    priority: 0,
    enabled: true,
    base_url: null,
    model: local.name,
    model_digest: local.digest,
    ssh_host: null,
    ssh_port: null,
    ssh_user: null,
    authorization: 'not_required',
    status: 'active',
    reason: null,
    reason_code: null,
    remediation: 'none',
    last_activity_at: '2026-08-30T10:00:00Z',
    content_disclosure_approved: true,
    config_revision: 2,
    config_digest: 'f'.repeat(64),
    eligible: true,
  } satisfies AdvisorProvider;
  const collection = {
    revision: 3,
    active_provider_id: provider.id,
    providers: [provider],
    resolution: {
      provider_id: provider.id,
      transport: 'local',
      reason: null,
      eligible_provider_ids: [provider.id],
    },
  } satisfies AdvisorProviderCollection;

  assert.equal(detectedLocalProviderIsReady(local, collection), true);
  assert.equal(detectedLocalProviderIsReady(local, {
    ...collection,
    active_provider_id: null,
  }), false);
  assert.equal(detectedLocalProviderIsReady(local, {
    ...collection,
    providers: [{ ...provider, enabled: false }],
  }), false);
  assert.equal(detectedLocalProviderIsReady({ ...local, digest: '9'.repeat(64) }, collection), false);
  assert.equal(exactEnabledLocalProvider(provider.id, local, collection.providers)?.id, provider.id);
  assert.equal(exactEnabledLocalProvider(provider.id, { ...local, digest: '9'.repeat(64) }, collection.providers), null);
});

test('local provider uncertain writes reconcile only typed conflict and transport outcomes', () => {
  const conflict = Object.assign(new Error('Provider revision changed.'), {
    name: 'ApiError',
    status: 409,
    code: 'revision_conflict',
  });
  assert.equal(localProviderWriteReconciliationReason(conflict), 'authority_conflict');
  const unrelatedConflict = Object.assign(new Error('Another command is active.'), {
    name: 'ApiError',
    status: 409,
    code: 'advisor_provider_command_active',
  });
  assert.equal(localProviderWriteReconciliationReason(unrelatedConflict), null);
  assert.equal(localProviderWriteReconciliationReason(new TypeError('Failed to fetch')), 'transport_uncertain');
  const invalid = Object.assign(new Error('Provider is invalid.'), {
    name: 'ApiError',
    status: 422,
    code: 'invalid_provider',
  });
  assert.equal(localProviderWriteReconciliationReason(invalid), null);
  assert.equal(localProviderWriteReconciliationReason(new Error('Application failure')), null);
});
