import type { AdvisorProvider } from './api';

const advisorReasonCopy: Readonly<Record<string, string>> = {
  advisor_connector_unavailable: 'The local Advisor connector is unavailable.',
  advisor_provider_route_misconfigured: 'The configured Advisor route needs attention.',
  database_unavailable: 'The database is unavailable, so Advisor readiness cannot be verified.',
  no_configured_provider: 'No local Advisor provider is configured yet.',
  no_executable_provider: 'No tested and active local Advisor provider is available.',
  no_provider_configured: 'No local Advisor provider is configured yet.',
  provider_configuration_missing: 'The local Advisor provider configuration is incomplete.',
  provider_unreachable: 'The configured Advisor provider could not be reached.',
  remote_single_finding_confirmation_required: 'Remote Advisor requires confirmation for one exact finding.',
  work_processing_unavailable: 'Background work processing is unavailable.',
};

export function advisorReasonText(value: unknown, fallback: string): string {
  const normalized = typeof value === 'string' ? value.trim() : '';
  if (!normalized) return fallback;
  return advisorReasonCopy[normalized]
    || (/^[a-z0-9]+(?:[_-][a-z0-9]+)+$/u.test(normalized)
      ? `${normalized.replace(/[_-]+/gu, ' ').replace(/^./u, (letter) => letter.toUpperCase())}.`
      : normalized);
}


export function advisorProviderRemediation(
  provider: AdvisorProvider,
  operationStatus: string | null,
): string {
  const localSetup = 'Choose a detected model above and use it locally. CodeSecurity verifies and activates the exact model in one step without sending finding content.';
  if (provider.transport === 'local') {
    if (operationStatus === 'failed') {
      return 'Retry original snapshot repeats the unchanged failed local setup. After an edit, choose the detected model above and use it locally to verify and activate the new revision.';
    }
    if (provider.status === 'active') return 'This provider is active. Advisor jobs remain pinned to its configuration revision.';
    return localSetup;
  }
  if (provider.authorization === 'required') {
    return 'Authorize this exact host with the owner-reviewed host workflow, then test the connection again.';
  }
  if (operationStatus === 'failed') {
    return 'Retry original snapshot repeats the unchanged failed command. If you edit this profile, save it and choose Test connection to create a new command for the new revision.';
  }
  if (!provider.enabled) return 'Enable this profile before testing or activating it.';
  if (provider.remediation === 'authorize') return 'Authorize this exact host, then test this configuration.';
  if (provider.remediation === 'retry') return 'Retry repeats the original command snapshot. After any profile edit, choose Test connection to test the new revision.';
  if (provider.remediation === 'refresh') return 'Refresh provider state before taking another action.';
  if (provider.remediation === 'test') return 'Test this exact target, model, and digest.';
  if (provider.remediation === 'activate') return 'Activate this tested configuration before remote Advisor use.';
  if (provider.status === 'unavailable') return 'Verify the exact target, model, and digest, then test again.';
  if (provider.status === 'disconnected') return 'Test this profile, then activate it when it is ready.';
  if (provider.status === 'available') return 'Connection and model identity are ready. Activate to select this provider.';
  if (provider.status === 'active') return 'This remote provider is active for explicitly confirmed one-finding reviews. Automatic, scan-wide, and bulk remote routing remain unavailable.';
  return 'Test the connection before activation. No prompt content is sent during readiness fallback.';
}
