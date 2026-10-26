import type {
  AdvisorAiMode,
  AdvisorProvider,
  AdvisorProviderCollection,
  AdvisorTriageProviderPin,
  Health,
  Scan,
} from './api';
import { advisorReasonText } from './advisorProviderGuidance.ts';

export type ResolvedAdvisorRoute =
  | {
    kind: 'local';
    provider: AdvisorProvider;
    pin: AdvisorTriageProviderPin;
  }
  | {
    kind: 'remote-confirmation';
    provider: AdvisorProvider;
  };

export type ScanAdvisorAvailability = Readonly<{
  enabled: boolean;
  reason: string;
}>;

export type AdvisorAiModeAvailability =
  | Readonly<{
    enabled: true;
    reason: null;
    aiMode: Exclude<AdvisorAiMode, 'off'>;
  }>
  | Readonly<{ enabled: false; reason: string }>;

export type AdvisorProviderReadiness =
  | Readonly<{ status: 'loading' }>
  | Readonly<{ status: 'ready'; collection: AdvisorProviderCollection }>
  | Readonly<{ status: 'error'; reason: string }>;

export type AdvisorStatusPresentation = Readonly<{
  detail: string;
  label: 'Checking' | 'Checking provider' | 'Disabled' | 'Needs attention' | 'Ready' | 'Setup required';
  model: string | null;
  pill: 'ai-off' | 'ai-on' | 'pending' | 'unavailable';
}>;

export type AdvisorRoutingContext = Readonly<{
  aiMode: AdvisorAiMode;
  collection: AdvisorProviderCollection;
}>;

export const advisorAiModeOffMessage = 'Advisor is disabled because AI mode is off. Enable AI in Settings and activate a tested local Advisor provider before requesting Advisor review.';
export const advisorAiModeLoadingMessage = 'AI Advisor is disabled while AI readiness is loading. Wait for the workbench to finish loading, then review AI in Settings if it remains unavailable.';

export function advisorAiModeAvailability(aiMode: AdvisorAiMode | null): AdvisorAiModeAvailability {
  if (aiMode === null) return { enabled: false, reason: advisorAiModeLoadingMessage };
  if (aiMode === 'off') return { enabled: false, reason: advisorAiModeOffMessage };
  return { enabled: true, reason: null, aiMode };
}

export function failedAdvisorProviderReadiness(): AdvisorProviderReadiness {
  return {
    status: 'error',
    reason: 'Scan Advisor is disabled because Advisor provider readiness could not be loaded. Refresh the workbench or review Advisor Providers in Settings before retrying.',
  };
}

export function advisorStatusPresentation({
  health,
  providerReadiness,
}: {
  health: Health | null;
  providerReadiness: AdvisorProviderReadiness;
}): AdvisorStatusPresentation {
  if (health?.ai.mode === 'off') {
    return {
      label: 'Disabled',
      detail: 'Advisor is disabled by policy. Enable it in Settings when local review is wanted.',
      model: health.ai.model || null,
      pill: 'ai-off',
    };
  }
  if (!health || providerReadiness.status === 'loading') {
    return {
      label: 'Checking',
      detail: 'Checking the local Advisor provider and transport.',
      model: health?.ai.model || null,
      pill: 'pending',
    };
  }
  if (providerReadiness.status === 'error') {
    return {
      label: 'Needs attention',
      detail: providerReadiness.reason,
      model: health.ai.model || null,
      pill: 'unavailable',
    };
  }
  const provider = providerReadiness.collection.providers.find((candidate) => (
    candidate.id === providerReadiness.collection.resolution.provider_id
    && candidate.transport === 'local'
    && candidate.eligible
    && providerReadiness.collection.resolution.eligible_provider_ids.includes(candidate.id)
  )) || null;
  if (provider && health.ai.available) {
    return {
      label: 'Ready',
      detail: `${provider.name} is verified and available for local review.`,
      model: provider.model,
      pill: 'ai-on',
    };
  }
  if (provider && ['no_provider_configured', 'provider_configuration_missing'].includes(health.ai.reason || '')) {
    return {
      label: 'Checking provider',
      detail: `${provider.name} is activated. Refresh to reconcile the latest local transport check.`,
      model: provider.model,
      pill: 'pending',
    };
  }
  if (provider) {
    return {
      label: 'Needs attention',
      detail: `${provider.name} is configured but the local transport is not ready. Test it again in Settings.`,
      model: provider.model,
      pill: 'unavailable',
    };
  }
  return {
    label: 'Setup required',
    detail: 'No local Advisor provider is active. Open Settings, choose one installed Ollama model, and use it locally once.',
    model: health.ai.model || null,
    pill: 'unavailable',
  };
}

export function advisorRouteUnavailableMessage(collection: AdvisorProviderCollection): string {
  const active = collection.providers.find((provider) => provider.id === collection.active_provider_id) || null;
  const reason = advisorReasonText(active?.reason || collection.resolution.reason, '');
  return [
    'No executable local Advisor provider is available.',
    reason ? `${reason.replace(/[.!?]+$/u, '')}.` : '',
    'Review Advisor Providers in Settings, authorize the exact host when required, test the profile, and activate it before retrying.',
  ].filter(Boolean).join(' ');
}

function resolveAdvisorProviderRoute(collection: AdvisorProviderCollection): ResolvedAdvisorRoute {
  const providerId = collection.resolution.provider_id;
  if (providerId && collection.resolution.transport !== 'unavailable') {
    const provider = collection.providers.find((candidate) => candidate.id === providerId);
    if (
      !provider
      || provider.transport !== collection.resolution.transport
      || !provider.eligible
      || !collection.resolution.eligible_provider_ids.includes(provider.id)
    ) {
      throw new Error('The authoritative Advisor provider resolution is inconsistent; refresh Settings before retrying.');
    }
    if (provider.transport !== 'local') {
      throw new Error('Automatic Advisor routing must resolve a local provider. Refresh Settings before retrying.');
    }
    return {
      kind: 'local',
      provider,
      pin: {
        provider_collection_revision: collection.revision,
        provider_id: provider.id,
        transport: provider.transport,
        provider_config_revision: provider.config_revision,
        provider_config_digest: provider.config_digest,
        model: provider.model,
        model_digest: provider.model_digest,
      },
    };
  }
  const active = collection.providers.find((provider) => provider.id === collection.active_provider_id) || null;
  if (
    active
    && (active.transport === 'direct' || active.transport === 'ssh')
    && active.enabled
    && active.status === 'active'
    && active.authorization === 'authorized'
    && active.content_disclosure_approved
    && !active.eligible
    && !collection.resolution.eligible_provider_ids.includes(active.id)
  ) return { kind: 'remote-confirmation', provider: active };
  throw new Error(advisorRouteUnavailableMessage(collection));
}

export function resolveAdvisorRoute({ aiMode, collection }: AdvisorRoutingContext): ResolvedAdvisorRoute {
  if (aiMode === 'off') throw new Error(advisorAiModeOffMessage);
  return resolveAdvisorProviderRoute(collection);
}

type AdvisorRouteAvailability =
  | Readonly<{ available: true; route: ResolvedAdvisorRoute }>
  | Readonly<{ available: false; reason: string }>;

function advisorRouteAvailability({
  aiMode,
  loadingReason,
  providerReadiness,
}: {
  aiMode: AdvisorAiMode | null;
  loadingReason: string;
  providerReadiness: AdvisorProviderReadiness;
}): AdvisorRouteAvailability {
  const aiAvailability = advisorAiModeAvailability(aiMode);
  if (!aiAvailability.enabled) return { available: false, reason: aiAvailability.reason };
  if (providerReadiness.status === 'loading') return { available: false, reason: loadingReason };
  if (providerReadiness.status === 'error') {
    return { available: false, reason: providerReadiness.reason };
  }
  try {
    return {
      available: true,
      route: resolveAdvisorRoute({
        aiMode: aiAvailability.aiMode,
        collection: providerReadiness.collection,
      }),
    };
  } catch (error) {
    return {
      available: false,
      reason: error instanceof Error ? error.message : String(error),
    };
  }
}

export function newScanAdvisorAvailability({
  aiMode,
  providerReadiness,
}: {
  aiMode: AdvisorAiMode | null;
  providerReadiness: AdvisorProviderReadiness;
}): ScanAdvisorAvailability {
  const availability = advisorRouteAvailability({
    aiMode,
    providerReadiness,
    loadingReason: 'AI Advisor is disabled while Advisor provider readiness is loading. Refresh the workbench or review Advisor Providers in Settings before starting a scan with Advisor.',
  });
  if (!availability.available) return { enabled: false, reason: availability.reason };
  const { route } = availability;
  if (route.kind === 'remote-confirmation') {
    return {
      enabled: false,
      reason: `Scan-wide Advisor is disabled because ${route.provider.name} is a remote provider. Remote Advisor use remains limited to one selected finding after its exact disclosure preview is confirmed.`,
    };
  }
  return {
    enabled: true,
    reason: `Run ${route.provider.name} locally after this scan completes.`,
  };
}

export function scanAdvisorAvailability({
  advisorCandidateCount,
  aiMode,
  providerReadiness,
  scan,
}: {
  advisorCandidateCount: number;
  aiMode: AdvisorAiMode | null;
  providerReadiness: AdvisorProviderReadiness;
  scan?: Scan;
}): ScanAdvisorAvailability {
  const availability = advisorRouteAvailability({
    aiMode,
    providerReadiness,
    loadingReason: 'Scan Advisor is disabled while Advisor provider readiness is loading. Refresh the workbench or review Advisor Providers in Settings before retrying.',
  });
  if (!availability.available) return { enabled: false, reason: availability.reason };
  const { route } = availability;
  if (route.kind === 'remote-confirmation') {
    return {
      enabled: false,
      reason: `Scan-wide Advisor review is disabled because ${route.provider.name} is a remote provider. Remote Advisor use remains limited to one selected finding after its exact disclosure preview is confirmed.`,
    };
  }
  if (!scan || !['completed', 'partial', 'failed'].includes(scan.status)) {
    return {
      enabled: false,
      reason: 'Advisor review requires a terminal scan with at least one unreviewed active finding.',
    };
  }
  if (advisorCandidateCount <= 0) {
    return {
      enabled: false,
      reason: 'Advisor review requires a terminal scan with at least one unreviewed active finding.',
    };
  }
  return {
    enabled: true,
    reason: `Run ${route.provider.name} locally for active findings in this terminal scan that do not already have Advisor output.`,
  };
}
