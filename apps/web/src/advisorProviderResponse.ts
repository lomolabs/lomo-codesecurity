import type { AdvisorProviderCollection } from './api';

export const invalidAdvisorProviderReadMessage = 'Advisor provider state could not be verified. Use Reload Settings to try again.';
export const unconfirmedAdvisorProviderWriteMessage = 'The provider change could not be confirmed. Use Reload Settings to check its current state before trying again.';

const object = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const nullableString = (value: unknown) => value === null || typeof value === 'string';
const oneOf = (value: unknown, choices: readonly string[]) => typeof value === 'string' && choices.includes(value);
const integer = (value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER) =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum;

/** Validate the existing response contract before rendering or routing Advisor
 * work. This does not establish provider readiness or grant source disclosure. */
export function requireAdvisorProviderCollection(
  value: unknown,
  message = invalidAdvisorProviderReadMessage,
): AdvisorProviderCollection {
  const valid = object(value) && integer(value.revision, 1) && nullableString(value.active_provider_id)
    && Array.isArray(value.providers) && value.providers.length <= 8
    && value.providers.every(provider => object(provider)
      && ['id', 'name', 'model', 'model_digest', 'config_digest'].every(key => typeof provider[key] === 'string')
      && ['base_url', 'ssh_host', 'ssh_user', 'reason', 'reason_code'].every(key => nullableString(provider[key]))
      && (provider.last_activity_at === null || typeof provider.last_activity_at === 'string' && Number.isFinite(Date.parse(provider.last_activity_at)))
      && ['enabled', 'content_disclosure_approved', 'eligible'].every(key => typeof provider[key] === 'boolean')
      && integer(provider.priority, 0, 7) && integer(provider.config_revision, 1)
      && (provider.ssh_port === null || provider.ssh_port === 22)
      && oneOf(provider.transport, ['local', 'direct', 'ssh'])
      && oneOf(provider.authorization, ['not_required', 'required', 'authorized'])
      && oneOf(provider.status, ['idle', 'testing', 'available', 'unavailable', 'active', 'disconnected'])
      && oneOf(provider.remediation, ['none', 'authorize', 'test', 'activate', 'retry', 'refresh']))
    && object(value.resolution) && nullableString(value.resolution.provider_id) && nullableString(value.resolution.reason)
    && oneOf(value.resolution.transport, ['local', 'direct', 'ssh', 'unavailable'])
    && Array.isArray(value.resolution.eligible_provider_ids) && value.resolution.eligible_provider_ids.length <= 8
    && value.resolution.eligible_provider_ids.every(id => typeof id === 'string');
  if (!valid) throw new Error(message);
  return value as AdvisorProviderCollection;
}
