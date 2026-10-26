import type { RuntimeConfig, RuntimeConfigScopedUpdate } from './api';

export type SettingsFormState = Pick<RuntimeConfig,
  | 'ai_mode'
  | 'ollama_base_url'
  | 'ollama_model'
  | 'ollama_thinking'
  | 'auto_triage_limit'
  | 'component_monitoring_enabled'
  | 'component_git_proxy_enabled'
  | 'component_db_admin_enabled'
  | 'gate_preset'
  | 'gate_active'
  | 'gate_max_critical'
  | 'gate_max_high'
  | 'gate_block_secrets'
> & { gate_apply_to_existing: boolean };
export type SettingsSaveTarget = 'advisor' | 'gate' | 'components';

export const unconfirmedSettingsSaveMessage = 'Save could not be confirmed. Your edits are still here. Check that the backend is running, then use Reload Settings before saving again.';
export const invalidSettingsReadMessage = 'Runtime configuration could not be verified. Use Reload Settings to try again.';

/** Validate before rendering or reconciling drafts. Once observed, installation
 * identity cannot change underneath an open Settings page. */
export function requireLoadedSettingsResponse(value: unknown, installationId?: string): RuntimeConfig {
  const object = (item: unknown): item is Record<string, unknown> => Boolean(item && typeof item === 'object' && !Array.isArray(item));
  const strings = (item: unknown): item is string[] => Array.isArray(item) && item.every(entry => typeof entry === 'string');
  const oneOf = (item: unknown, choices: readonly string[]) => typeof item === 'string' && choices.includes(item);
  const integer = (item: unknown, min: number, max: number) => typeof item === 'number' && Number.isInteger(item) && item >= min && item <= max;
  const nullableString = (item: unknown) => item === null || typeof item === 'string';
  const valid = object(value)
    && typeof value.installation_id === 'string' && /^[a-f0-9]{12}$/u.test(value.installation_id)
    && (installationId === undefined || value.installation_id === installationId)
    && strings(value.allowed_roots) && strings(value.ollama_models)
    && ['scanner_url', 'ollama_base_url', 'ollama_model', 'component_apply_command'].every(key => typeof value[key] === 'string')
    && (value.ollama_reason === undefined || nullableString(value.ollama_reason))
    && ['ollama_available', 'ollama_thinking', 'component_monitoring_enabled', 'component_git_proxy_enabled',
      'component_db_admin_enabled', 'gate_active', 'gate_block_secrets'].every(key => typeof value[key] === 'boolean')
    && oneOf(value.ai_mode, ['auto', 'on', 'off']) && oneOf(value.gate_preset, ['observe', 'baseline', 'strict', 'custom'])
    && integer(value.auto_triage_limit, 0, 50) && integer(value.gate_max_critical, -1, 999) && integer(value.gate_max_high, -1, 999)
    && Array.isArray(value.components) && value.components.every(row => object(row)
      && ['id', 'url', 'profile', 'apply_command', 'reason_code', 'message'].every(key => typeof row[key] === 'string')
      && ['required', 'desired_enabled', 'reachable', 'healthy'].every(key => typeof row[key] === 'boolean')
      && oneOf(row.desired_state, ['enabled', 'disabled'])
      && oneOf(row.observed_state, ['running', 'running_undesired', 'not_running', 'not_observed', 'disabled', 'unhealthy', 'unknown']))
    && object(value.schema_init) && value.schema_init.id === 'schema-init'
    && value.schema_init.lifecycle === 'one-shot' && value.schema_init.startable === false
    && oneOf(value.schema_init.state, ['completed', 'unverified']) && typeof value.schema_init.message === 'string'
    && ['schema_id', 'schema_fingerprint', 'initialized_at'].every(key => nullableString((value.schema_init as Record<string, unknown>)[key]))
    && (value.schema_init.evidence === null || value.schema_init.evidence === 'schema-identity-and-api-startup-verification');
  if (!valid) throw new Error(invalidSettingsReadMessage);
  return value as RuntimeConfig;
}

/** Other sections may change concurrently; only the submitted section must
 * match, after the API's existing string normalization. */
export function requireSavedSettingsResponse(
  value: unknown, payload: RuntimeConfigScopedUpdate, installationId: string,
): RuntimeConfig {
  let next: RuntimeConfig;
  try { next = requireLoadedSettingsResponse(value, installationId); }
  catch { throw new Error(unconfirmedSettingsSaveMessage); }
  for (const [key, submitted] of Object.entries(payload)) {
    // This command flag is not returned as persisted configuration. The backend
    // owns its transaction and the independent acceptance inspector checks effects.
    if (key === 'gate_apply_to_existing') continue;
    const expected = key === 'ollama_base_url' ? String(submitted).trim().replace(/\/+$/u, '')
      : key === 'ollama_model' ? String(submitted).trim() : submitted;
    if ((next as unknown as Record<string, unknown>)[key] !== expected) throw new Error(unconfirmedSettingsSaveMessage);
  }
  return next;
}

export function buildScopedSettingsPayload(
  target: SettingsSaveTarget,
  draft: SettingsFormState,
): RuntimeConfigScopedUpdate {
  if (target === 'advisor') {
    return {
      ai_mode: draft.ai_mode,
      ollama_base_url: draft.ollama_base_url,
      ollama_model: draft.ollama_model,
      ollama_thinking: draft.ollama_thinking,
      auto_triage_limit: draft.auto_triage_limit,
    };
  }
  if (target === 'gate') {
    return {
      gate_preset: draft.gate_preset,
      gate_active: draft.gate_active,
      gate_max_critical: draft.gate_max_critical,
      gate_max_high: draft.gate_max_high,
      gate_block_secrets: draft.gate_block_secrets,
      gate_apply_to_existing: draft.gate_apply_to_existing,
    };
  }
  return {
    component_monitoring_enabled: draft.component_monitoring_enabled,
    component_git_proxy_enabled: draft.component_git_proxy_enabled,
    component_db_admin_enabled: draft.component_db_admin_enabled,
  };
}

export function mergeScopedSettingsResponse(
  target: SettingsSaveTarget | null,
  draft: SettingsFormState,
  previousPersisted: RuntimeConfig,
  persisted: RuntimeConfig,
): SettingsFormState {
  // A scoped save replaces its saved key family; null denotes a read-only
  // refresh. Reconcile the complete response as a three-way merge: accept newer values in untouched scopes
  // while retaining explicit local drafts for a later scoped save.
  const advisorDrafted = draft.ai_mode !== previousPersisted.ai_mode
    || draft.ollama_base_url !== previousPersisted.ollama_base_url
    || draft.ollama_model !== previousPersisted.ollama_model
    || draft.ollama_thinking !== previousPersisted.ollama_thinking
    || draft.auto_triage_limit !== previousPersisted.auto_triage_limit;
  const gateDrafted = draft.gate_preset !== previousPersisted.gate_preset
    || draft.gate_active !== previousPersisted.gate_active
    || draft.gate_max_critical !== previousPersisted.gate_max_critical
    || draft.gate_max_high !== previousPersisted.gate_max_high
    || draft.gate_block_secrets !== previousPersisted.gate_block_secrets
    || draft.gate_apply_to_existing;
  const componentsDrafted = draft.component_monitoring_enabled !== previousPersisted.component_monitoring_enabled
    || draft.component_git_proxy_enabled !== previousPersisted.component_git_proxy_enabled
    || draft.component_db_admin_enabled !== previousPersisted.component_db_admin_enabled;
  const reconciled: SettingsFormState = {
    ai_mode: advisorDrafted ? draft.ai_mode : persisted.ai_mode,
    ollama_base_url: advisorDrafted ? draft.ollama_base_url : persisted.ollama_base_url,
    ollama_model: advisorDrafted ? draft.ollama_model : persisted.ollama_model,
    ollama_thinking: advisorDrafted ? draft.ollama_thinking : persisted.ollama_thinking,
    auto_triage_limit: advisorDrafted ? draft.auto_triage_limit : persisted.auto_triage_limit,
    component_monitoring_enabled: componentsDrafted ? draft.component_monitoring_enabled : persisted.component_monitoring_enabled,
    component_git_proxy_enabled: componentsDrafted ? draft.component_git_proxy_enabled : persisted.component_git_proxy_enabled,
    component_db_admin_enabled: componentsDrafted ? draft.component_db_admin_enabled : persisted.component_db_admin_enabled,
    gate_preset: gateDrafted ? draft.gate_preset : persisted.gate_preset,
    gate_active: gateDrafted ? draft.gate_active : persisted.gate_active,
    gate_max_critical: gateDrafted ? draft.gate_max_critical : persisted.gate_max_critical,
    gate_max_high: gateDrafted ? draft.gate_max_high : persisted.gate_max_high,
    gate_block_secrets: gateDrafted ? draft.gate_block_secrets : persisted.gate_block_secrets,
    gate_apply_to_existing: draft.gate_apply_to_existing,
  };
  if (target === 'advisor') {
    return {
      ...reconciled,
      ai_mode: persisted.ai_mode,
      ollama_base_url: persisted.ollama_base_url,
      ollama_model: persisted.ollama_model,
      ollama_thinking: persisted.ollama_thinking,
      auto_triage_limit: persisted.auto_triage_limit,
    };
  }
  if (target === 'gate') {
    return {
      ...reconciled,
      gate_preset: persisted.gate_preset,
      gate_active: persisted.gate_active,
      gate_max_critical: persisted.gate_max_critical,
      gate_max_high: persisted.gate_max_high,
      gate_block_secrets: persisted.gate_block_secrets,
      gate_apply_to_existing: false,
    };
  }
  return target === 'components' ? {
    ...reconciled,
    component_monitoring_enabled: persisted.component_monitoring_enabled,
    component_git_proxy_enabled: persisted.component_git_proxy_enabled,
    component_db_admin_enabled: persisted.component_db_admin_enabled,
  } : reconciled;
}

export function settingsFormFromConfig(next: RuntimeConfig): SettingsFormState {
  return {
    ai_mode: next.ai_mode,
    ollama_base_url: next.ollama_base_url,
    ollama_model: next.ollama_model,
    ollama_thinking: next.ollama_thinking,
    auto_triage_limit: next.auto_triage_limit,
    component_monitoring_enabled: next.component_monitoring_enabled,
    component_git_proxy_enabled: next.component_git_proxy_enabled,
    component_db_admin_enabled: next.component_db_admin_enabled,
    gate_preset: next.gate_preset,
    gate_active: next.gate_active,
    gate_max_critical: next.gate_max_critical,
    gate_max_high: next.gate_max_high,
    gate_block_secrets: next.gate_block_secrets,
    gate_apply_to_existing: false,
  };
}
