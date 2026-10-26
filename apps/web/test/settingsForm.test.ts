import assert from 'node:assert/strict';
import test from 'node:test';
import type { RuntimeConfig } from '../src/api.ts';
import { buildScopedSettingsPayload, mergeScopedSettingsResponse, requireLoadedSettingsResponse, requireSavedSettingsResponse, settingsFormFromConfig } from '../src/settingsForm.ts';

const config = {
  ai_mode: 'auto', ollama_base_url: 'http://localhost:11434', ollama_model: 'local-model',
  ollama_thinking: false, auto_triage_limit: 5,
  component_monitoring_enabled: false, component_git_proxy_enabled: false, component_db_admin_enabled: false,
  gate_preset: 'baseline', gate_active: true, gate_max_critical: 0, gate_max_high: -1, gate_block_secrets: true,
} as RuntimeConfig;

const completeConfig: RuntimeConfig = {
  ...config, installation_id: '0123456789ab', allowed_roots: ['/owned/source'], scanner_url: 'http://scanner:8081',
  ollama_available: false, ollama_models: [], component_apply_command: 'make apply-components COMPONENTS=core',
  components: [{ id: 'api', required: true, desired_enabled: true, healthy: true, desired_state: 'enabled',
    observed_state: 'running', reachable: true, reason_code: 'ready', message: 'Ready', url: 'http://localhost:8080',
    profile: 'core', apply_command: 'make apply-components COMPONENTS=core' }],
  schema_init: { id: 'schema-init', lifecycle: 'one-shot', startable: false, state: 'unverified', message: 'Unverified',
    schema_id: null, schema_fingerprint: null, initialized_at: null, evidence: null },
};

test('first runtime read requires valid shape and later reads retain installation identity', () => {
  assert.equal(requireLoadedSettingsResponse(completeConfig), completeConfig);
  assert.equal(requireLoadedSettingsResponse(completeConfig, completeConfig.installation_id), completeConfig);
  assert.throws(() => requireLoadedSettingsResponse({ ...completeConfig, installation_id: 'invalid' }), /could not be verified/u);
  assert.throws(() => requireLoadedSettingsResponse(completeConfig, 'ffffffffffff'), /could not be verified/u);
});

test('save acknowledgment accepts the exact installation and submitted scope without discarding concurrent scopes', () => {
  const payload = buildScopedSettingsPayload('advisor', settingsFormFromConfig(completeConfig));
  const response = { ...completeConfig, component_git_proxy_enabled: true, gate_max_high: 5 };
  assert.equal(requireSavedSettingsResponse(response, payload, completeConfig.installation_id), response);
  for (const target of ['advisor', 'gate', 'components'] as const) {
    const submitted = buildScopedSettingsPayload(target, { ...settingsFormFromConfig(completeConfig), gate_apply_to_existing: true });
    assert.equal(requireSavedSettingsResponse(completeConfig, submitted, completeConfig.installation_id), completeConfig);
  }
});

test('save acknowledgment follows existing Advisor string normalization', () => {
  const payload = buildScopedSettingsPayload('advisor', { ...settingsFormFromConfig(completeConfig),
    ollama_base_url: ` ${completeConfig.ollama_base_url}/// `, ollama_model: ' local-model ' });
  assert.equal(requireSavedSettingsResponse(completeConfig, payload, completeConfig.installation_id), completeConfig);
});

for (const [name, value] of Object.entries({
  absent: null, empty: {}, array: [], 'foreign installation': { ...completeConfig, installation_id: 'ffffffffffff' },
  'missing source roots': { ...completeConfig, allowed_roots: undefined },
  'invalid models': { ...completeConfig, ollama_models: [null] },
  'invalid component boolean': { ...completeConfig, component_git_proxy_enabled: 'false' },
  'missing component command': { ...completeConfig, component_apply_command: null },
  'malformed component': { ...completeConfig, components: [{}] },
  'unknown component state': { ...completeConfig, components: [{ ...completeConfig.components[0], observed_state: 'ready' }] },
  'missing schema state': { ...completeConfig, schema_init: null },
  'startable initializer': { ...completeConfig, schema_init: { ...completeConfig.schema_init, startable: true } },
  'invalid mode': { ...completeConfig, ai_mode: 'enabled' },
  'invalid limit': { ...completeConfig, auto_triage_limit: Number.NaN },
  'out of range gate': { ...completeConfig, gate_max_high: -2 },
  'wrong saved value': { ...completeConfig, auto_triage_limit: completeConfig.auto_triage_limit + 1 },
})) test(`save acknowledgment refuses ${name} without mutating inputs`, () => {
  const payload = buildScopedSettingsPayload('advisor', settingsFormFromConfig(completeConfig));
  const original = structuredClone({ value, payload });
  assert.throws(() => requireSavedSettingsResponse(value, payload, completeConfig.installation_id), /Save could not be confirmed/u);
  if (name !== 'wrong saved value') {
    assert.throws(() => requireLoadedSettingsResponse(value, completeConfig.installation_id), /could not be verified/u);
  }
  assert.deepEqual({ value, payload }, original);
});

test('refresh preserves an unsaved gate section and apply-existing intent while updating untouched sections', () => {
  const draft = { ...settingsFormFromConfig(config), gate_preset: 'custom' as const,
    gate_max_high: 4, gate_apply_to_existing: true };
  const current = { ...config, gate_max_high: 1, ollama_model: 'new-model', component_monitoring_enabled: true };
  const result = mergeScopedSettingsResponse(null, draft, config, current);
  assert.equal(result.gate_preset, 'custom');
  assert.equal(result.gate_max_high, 4);
  assert.equal(result.gate_apply_to_existing, true);
  assert.equal(result.ollama_model, 'new-model');
  assert.equal(result.component_monitoring_enabled, true);
  assert.equal(config.gate_max_high, -1);
  assert.deepEqual(mergeScopedSettingsResponse(null, settingsFormFromConfig(config), config, current),
    settingsFormFromConfig(current));
});

test('refresh retains all edited sections and no runtime-only fields enter the form', () => {
  const draft = { ...settingsFormFromConfig(config), ollama_model: 'draft-model',
    component_db_admin_enabled: true, gate_max_critical: 3 };
  const next = { ...config, ollama_model: 'other-model', component_git_proxy_enabled: true, gate_max_high: 9 };
  assert.deepEqual(mergeScopedSettingsResponse(null, draft, config, next), draft);
  assert.equal('components' in settingsFormFromConfig({ ...config, components: [] }), false);
});

test('saving a section adopts its persisted result and preserves independent drafts on later refresh', () => {
  const draft = { ...settingsFormFromConfig(config), gate_max_high: 4, gate_apply_to_existing: true,
    ollama_model: 'draft-model', component_db_admin_enabled: true };
  const saved = { ...config, gate_max_high: 4 };
  const afterSave = mergeScopedSettingsResponse('gate', draft, config, saved);
  assert.equal(afterSave.gate_apply_to_existing, false);
  assert.equal(afterSave.ollama_model, 'draft-model');
  assert.equal(afterSave.component_db_admin_enabled, true);
  const afterRefresh = mergeScopedSettingsResponse(null, afterSave, saved, { ...saved, gate_max_high: 6 });
  assert.equal(afterRefresh.gate_max_high, 6, 'a saved gate is no longer a dirty draft');
  assert.equal(afterRefresh.ollama_model, 'draft-model');
  assert.deepEqual(Object.keys(buildScopedSettingsPayload('components', afterRefresh)).sort(),
    ['component_db_admin_enabled', 'component_git_proxy_enabled', 'component_monitoring_enabled']);
  for (const target of ['advisor', 'components'] as const) {
    const reconciled = mergeScopedSettingsResponse(target, draft, config, saved);
    assert.equal(reconciled.gate_apply_to_existing, true);
    assert.equal(reconciled.gate_max_high, 4);
  }
});
