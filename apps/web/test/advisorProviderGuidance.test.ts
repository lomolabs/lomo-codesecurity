import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

import type { AdvisorProvider } from '../src/api.ts';
import { advisorProviderRemediation, advisorReasonText } from '../src/advisorProviderGuidance.ts';


const provider = {
  id: 'local-fixture',
  name: 'Local fixture',
  transport: 'local',
  priority: 0,
  enabled: true,
  base_url: null,
  model: 'fixture:latest',
  model_digest: 'a'.repeat(64),
  ssh_host: null,
  ssh_port: null,
  ssh_user: null,
  authorization: 'not_required',
  status: 'unavailable',
  reason: 'Fixture failure.',
  reason_code: 'advisor_provider_model_missing',
  remediation: 'test',
  last_activity_at: null,
  content_disclosure_approved: false,
  config_revision: 1,
  config_digest: 'b'.repeat(64),
  eligible: false,
} satisfies AdvisorProvider;


test('failed local provider guidance distinguishes retrying the original snapshot from one-step setup after an edit', () => {
  const guidance = advisorProviderRemediation(provider, 'failed');
  assert.match(guidance, /Retry original snapshot repeats the unchanged failed local setup/u);
  assert.match(guidance, /After an edit.*use it locally.*new revision/u);
});


test('local provider state without an operation directs the one-step local setup action', () => {
  assert.equal(
    advisorProviderRemediation(provider, null),
    'Choose a detected model above and use it locally. CodeSecurity verifies and activates the exact model in one step without sending finding content.',
  );
});


test('remote provider state retains separate test and activation guidance', () => {
  const remote = {
    ...provider,
    id: 'direct-fixture',
    name: 'Direct fixture',
    transport: 'direct',
    base_url: 'http://ollama.example.test:11434',
    authorization: 'authorized',
  } satisfies AdvisorProvider;
  assert.equal(
    advisorProviderRemediation(remote, null),
    'Test this exact target, model, and digest.',
  );
  assert.match(
    advisorProviderRemediation(remote, 'failed'),
    /edit this profile.*Test connection.*new revision/u,
  );
});


test('Advisor reasons present shared human copy and never expose machine codes', () => {
  assert.equal(advisorReasonText('no_provider_configured', 'fallback'), 'No local Advisor provider is configured yet.');
  assert.equal(advisorReasonText('new_internal_reason', 'fallback'), 'New internal reason.');
  assert.equal(advisorReasonText(null, 'No readiness result is available.'), 'No readiness result is available.');
  assert.equal(
    advisorReasonText(null, 'No additional provider readiness detail is available.'),
    'No additional provider readiness detail is available.',
  );
});


test('untested and rejected local provider cards describe enforced policy, not an unverified privacy claim', async (context) => {
  const vite = await createServer({
    root: fileURLToPath(new URL('..', import.meta.url)),
    configFile: false,
    appType: 'custom',
    logLevel: 'silent',
    server: { middlewareMode: true },
  });
  context.after(async () => {
    await vite.close();
  });
  const module = await vite.ssrLoadModule('/src/AdvisorProviders.tsx') as typeof import('../src/AdvisorProviders.tsx');
  const unchanged = async () => undefined;
  for (const status of ['idle', 'unavailable'] as const) {
    const markup = renderToStaticMarkup(createElement(module.SettingsAdvisorProvidersPanel, {
      collection: {
        revision: 1,
        active_provider_id: null,
        providers: [{ ...provider, model: 'fixture:cloud', status }],
        resolution: {
          provider_id: null,
          transport: 'unavailable',
          reason: 'no_executable_provider',
          eligible_provider_ids: [],
        },
      },
      deepLinkReady: true,
      error: null,
      localCatalog: null,
      localDetectionError: null,
      localDetectionLoading: false,
      loadState: 'success',
      mutationsEnabled: true,
      operation: null,
      saving: false,
      status: null,
      onCancelOperation: unchanged,
      onUseDetectedLocal: unchanged,
      onCommand: unchanged,
      onDetectLocal: unchanged,
      onRemove: unchanged,
      onRetryOperation: unchanged,
      onSave: unchanged,
      onToggle: unchanged,
    }));
    assert.match(markup, /<dt>Evidence sharing<\/dt><dd>Local weights only; verified before each run\.<\/dd>/u);
    assert.doesNotMatch(markup, /stays on this device/u);
  }
});
