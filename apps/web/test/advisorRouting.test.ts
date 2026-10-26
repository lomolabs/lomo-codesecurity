import assert from 'node:assert/strict';
import test from 'node:test';

import type { AdvisorProvider, AdvisorProviderCollection, Health, Scan } from '../src/api.ts';
import {
  advisorAiModeAvailability,
  advisorAiModeLoadingMessage,
  advisorAiModeOffMessage,
  advisorStatusPresentation,
  failedAdvisorProviderReadiness,
  newScanAdvisorAvailability,
  resolveAdvisorRoute,
  scanAdvisorAvailability,
} from '../src/advisorRouting.ts';

const provider = (overrides: Partial<AdvisorProvider> = {}): AdvisorProvider => ({
  id: 'local-ollama',
  name: 'Local Ollama',
  transport: 'local',
  priority: 1,
  enabled: true,
  base_url: 'http://host.docker.internal:11434',
  model: 'fixture-model',
  model_digest: 'a'.repeat(64),
  ssh_host: null,
  ssh_port: null,
  ssh_user: null,
  authorization: 'not_required',
  status: 'active',
  reason: null,
  reason_code: null,
  remediation: 'none',
  last_activity_at: '2026-08-27T00:00:00Z',
  content_disclosure_approved: false,
  config_revision: 3,
  config_digest: 'b'.repeat(64),
  eligible: true,
  ...overrides,
});

const collection = (
  providers: AdvisorProvider[],
  activeProviderId: string | null,
  eligibleProviderIds: string[],
): AdvisorProviderCollection => ({
  revision: 7,
  active_provider_id: activeProviderId,
  providers,
  resolution: {
    provider_id: eligibleProviderIds[0] ?? null,
    transport: eligibleProviderIds.length ? 'local' : 'unavailable',
    reason: eligibleProviderIds.length ? null : 'No provider is active, tested, and authorized.',
    eligible_provider_ids: eligibleProviderIds,
  },
});

const terminalScan = { id: 1, status: 'completed' } as Scan;

const health = (overrides: Partial<Health['ai']> = {}): Health => ({
  ok: true,
  version: 'test',
  db: true,
  scanner: true,
  worker: true,
  ai: {
    mode: 'auto',
    available: false,
    base_url: 'http://host.docker.internal:11434',
    model: '',
    thinking: false,
    models: [],
    reason: 'no_provider_configured',
    ...overrides,
  },
});

test('Advisor status has one shared truthful presentation across workbench surfaces', () => {
  const local = provider();
  const ready = { status: 'ready', collection: collection([local], local.id, [local.id]) } as const;
  assert.deepEqual(advisorStatusPresentation({ health: null, providerReadiness: { status: 'loading' } }), {
    label: 'Checking',
    detail: 'Checking the local Advisor provider and transport.',
    model: null,
    pill: 'pending',
  });
  assert.equal(advisorStatusPresentation({ health: health({ mode: 'off' }), providerReadiness: ready }).label, 'Disabled');
  assert.equal(advisorStatusPresentation({ health: health({ available: true, model: local.model }), providerReadiness: ready }).label, 'Ready');
  assert.equal(advisorStatusPresentation({ health: health(), providerReadiness: ready }).label, 'Checking provider');
  assert.equal(advisorStatusPresentation({
    health: health({ reason: 'provider_unreachable' }),
    providerReadiness: ready,
  }).label, 'Needs attention');
  assert.deepEqual(advisorStatusPresentation({
    health: health(),
    providerReadiness: { status: 'ready', collection: collection([], null, []) },
  }), {
    label: 'Setup required',
    detail: 'No local Advisor provider is active. Open Settings, choose one installed Ollama model, and use it locally once.',
    model: null,
    pill: 'unavailable',
  });
  assert.equal(advisorStatusPresentation({
    health: health(),
    providerReadiness: failedAdvisorProviderReadiness(),
  }).label, 'Needs attention');
});

test('Scan Advisor is disabled for AI-off and non-executable providers without widening remote disclosure', () => {
  const local = provider();
  assert.deepEqual(advisorAiModeAvailability(null), {
    enabled: false,
    reason: advisorAiModeLoadingMessage,
  });
  assert.deepEqual(advisorAiModeAvailability('off'), {
    enabled: false,
    reason: advisorAiModeOffMessage,
  });
  assert.deepEqual(advisorAiModeAvailability('auto'), {
    enabled: true,
    reason: null,
    aiMode: 'auto',
  });
  assert.deepEqual(advisorAiModeAvailability('on'), {
    enabled: true,
    reason: null,
    aiMode: 'on',
  });

  assert.deepEqual(scanAdvisorAvailability({
    advisorCandidateCount: 54,
    aiMode: 'off',
    providerReadiness: { status: 'ready', collection: collection([local], local.id, [local.id]) },
    scan: terminalScan,
  }), {
    enabled: false,
    reason: advisorAiModeOffMessage,
  });

  assert.equal(resolveAdvisorRoute({
    aiMode: 'on',
    collection: collection([local], local.id, [local.id]),
  }).kind, 'local');
  assert.throws(() => resolveAdvisorRoute({
    aiMode: 'off',
    collection: collection([local], local.id, [local.id]),
  }), new Error(advisorAiModeOffMessage));

  assert.deepEqual(scanAdvisorAvailability({
    advisorCandidateCount: 54,
    aiMode: null,
    providerReadiness: { status: 'loading' },
    scan: terminalScan,
  }), {
    enabled: false,
    reason: advisorAiModeLoadingMessage,
  });

  assert.deepEqual(scanAdvisorAvailability({
    advisorCandidateCount: 54,
    aiMode: 'on',
    providerReadiness: { status: 'loading' },
    scan: terminalScan,
  }), {
    enabled: false,
    reason: 'Scan Advisor is disabled while Advisor provider readiness is loading. Refresh the workbench or review Advisor Providers in Settings before retrying.',
  });

  assert.deepEqual(scanAdvisorAvailability({
    advisorCandidateCount: 54,
    aiMode: 'on',
    providerReadiness: failedAdvisorProviderReadiness(),
    scan: terminalScan,
  }), {
    enabled: false,
    reason: 'Scan Advisor is disabled because Advisor provider readiness could not be loaded. Refresh the workbench or review Advisor Providers in Settings before retrying.',
  });

  const unavailable = scanAdvisorAvailability({
    advisorCandidateCount: 54,
    aiMode: 'on',
    providerReadiness: { status: 'ready', collection: collection([], null, []) },
    scan: terminalScan,
  });
  assert.equal(unavailable.enabled, false);
  assert.match(unavailable.reason, /^No executable local Advisor provider is available\./u);
  assert.match(unavailable.reason, /authorize the exact host when required, test the profile, and activate it/u);

  const remote = provider({
    id: 'remote-approved',
    name: 'Approved Remote',
    transport: 'direct',
    authorization: 'authorized',
    content_disclosure_approved: true,
    eligible: false,
  });
  const remoteOnly = scanAdvisorAvailability({
    advisorCandidateCount: 54,
    aiMode: 'on',
    providerReadiness: { status: 'ready', collection: collection([remote], remote.id, []) },
    scan: terminalScan,
  });
  assert.equal(remoteOnly.enabled, false);
  assert.match(remoteOnly.reason, /Remote Advisor use remains limited to one selected finding after its exact disclosure preview is confirmed\./u);

  assert.deepEqual(scanAdvisorAvailability({
    advisorCandidateCount: 54,
    aiMode: 'on',
    providerReadiness: { status: 'ready', collection: collection([local], local.id, [local.id]) },
    scan: terminalScan,
  }), {
    enabled: true,
    reason: 'Run Local Ollama locally for active findings in this terminal scan that do not already have Advisor output.',
  });
});

test('new-scan Advisor control requires authoritative executable local-provider readiness', () => {
  const local = provider();
  assert.deepEqual(newScanAdvisorAvailability({
    aiMode: 'on',
    providerReadiness: { status: 'loading' },
  }), {
    enabled: false,
    reason: 'AI Advisor is disabled while Advisor provider readiness is loading. Refresh the workbench or review Advisor Providers in Settings before starting a scan with Advisor.',
  });

  const failed = newScanAdvisorAvailability({
    aiMode: 'on',
    providerReadiness: failedAdvisorProviderReadiness(),
  });
  assert.equal(failed.enabled, false);
  assert.match(failed.reason, /provider readiness could not be loaded/u);

  const unavailable = newScanAdvisorAvailability({
    aiMode: 'on',
    providerReadiness: { status: 'ready', collection: collection([], null, []) },
  });
  assert.equal(unavailable.enabled, false);
  assert.match(unavailable.reason, /^No executable local Advisor provider is available\./u);

  const remote = provider({
    id: 'remote-approved',
    name: 'Approved Remote',
    transport: 'direct',
    authorization: 'authorized',
    content_disclosure_approved: true,
    eligible: false,
  });
  const remoteOnly = newScanAdvisorAvailability({
    aiMode: 'on',
    providerReadiness: { status: 'ready', collection: collection([remote], remote.id, []) },
  });
  assert.equal(remoteOnly.enabled, false);
  assert.match(remoteOnly.reason, /Remote Advisor use remains limited to one selected finding/u);

  assert.deepEqual(newScanAdvisorAvailability({
    aiMode: 'auto',
    providerReadiness: { status: 'ready', collection: collection([local], local.id, [local.id]) },
  }), {
    enabled: true,
    reason: 'Run Local Ollama locally after this scan completes.',
  });
});
