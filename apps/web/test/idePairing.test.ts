import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import type { IdeInvalidCapability, IdeValidCapability } from '../src/api.ts';
import {
  compareIdeCapabilities,
  ideCapabilityRevocationRequest,
  ideCapabilityMutationRequiresAuthoritativeRefresh,
  ideClientDisplayName,
  ideClientStatus,
  ideClientTargetLabel,
  idePendingCancellationRequest,
  idePendingClientDisplayName,
  ideSourceOpenAuthorityRecovery,
  ideSourceOpenTarget,
  invalidIdeCapabilityRecoveryRequest,
  requireIdePendingCancellationResponse,
  requireIdeRevocationResponse,
  requireInvalidIdeRecoveryResponse,
  sourceOpenIdeCapabilities,
} from '../src/idePairing.ts';
import { ideEnrollmentPresentation } from '../src/pairingKeyState.ts';


test('IDE recovery guidance names the exact visible Settings control', async () => {
  const appSource = await readFile(fileURLToPath(new URL('../src/App.tsx', import.meta.url)), 'utf8');
  assert.match(appSource, /Refresh IDE access and choose the current generation/u);
  assert.match(appSource, /use Refresh IDE access before retrying/u);
  assert.match(appSource, /`IDE access refreshed\. \$\{nextEnrollments\.length\} pending approval\./u);
  assert.doesNotMatch(appSource, /Refresh IDE clients/u);
});


test('expired IDE enrollment decisions fail closed while the authoritative list refreshes', () => {
  const enrollment = { activation_expires_at: '2026-08-31T18:10:00.000Z' };
  assert.deepEqual(ideEnrollmentPresentation(enrollment, Date.parse('2026-08-31T18:09:59.999Z')), {
    expired: false,
    label: 'Approval required',
    tone: 'pending',
    decisionDisabledReason: null,
  });
  assert.deepEqual(ideEnrollmentPresentation(enrollment, Date.parse(enrollment.activation_expires_at)), {
    expired: true,
    label: 'Expired',
    tone: 'unavailable',
    decisionDisabledReason: 'This request expired. CodeSecurity is refreshing the authoritative pending list.',
  });
  assert.equal(ideEnrollmentPresentation({ activation_expires_at: 'invalid' }).expired, true);
});


const activeClient: IdeValidCapability = {
  state: 'valid',
  id: 'ks1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  client_name: 'Fedora QA profile',
  scopes: ['scan:run'],
  created_at: '2026-08-29T10:00:00Z',
  expires_at: '2027-02-25T10:00:00Z',
  revoked: false,
  active: true,
  connected: true,
  active_generation: 1,
  latest_generation: 2,
  pending_activation: true,
  pending_generation: 2,
  pending_client_name: 'Fedora QA profile replacement',
  pending_activation_expires_at: '2026-08-29T10:10:00Z',
  source_open_available: true,
  source_open_disabled_reason: null,
  invalid_recovery_token: null,
};

const invalidClient: IdeInvalidCapability = {
  state: 'invalid',
  id: 'ks1_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
  client_name: 'Invalid IDE client record',
  scopes: [],
  created_at: null,
  revoked: false,
  active: false,
  connected: false,
  active_generation: null,
  latest_generation: null,
  pending_activation: false,
  pending_generation: null,
  pending_client_name: null,
  pending_activation_expires_at: null,
  source_open_available: false,
  source_open_disabled_reason: 'This IDE client record is invalid or not active.',
  invalid_recovery_token: `kir1_${'b'.repeat(64)}`,
};


test('IDE client status keeps the live authority truthful during pending replacement', () => {
  assert.deepEqual(ideClientStatus(activeClient), {
    label: 'Active · connected',
    tone: 'ready',
  });
  assert.equal(ideClientDisplayName(activeClient), 'Fedora QA profile');
  assert.equal(idePendingClientDisplayName(activeClient), 'Fedora QA profile replacement');
});


test('identically named IDE clients receive stable, non-secret profile labels', () => {
  const second = {
    ...activeClient,
    id: 'ks1_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
  };
  assert.equal(ideClientTargetLabel(activeClient, [activeClient]), 'Fedora QA profile');
  assert.equal(
    ideClientTargetLabel(activeClient, [activeClient, second]),
    'Fedora QA profile · profile …AAAAAAAA',
  );
  assert.equal(
    ideClientTargetLabel(second, [activeClient, second]),
    'Fedora QA profile · profile …CCCCCCCC',
  );
});


test('pending setup cancellation is bound to the exact rendered generation', () => {
  const cancellation = idePendingCancellationRequest(activeClient.id, 7);

  assert.deepEqual(cancellation, {
    path: `/v1/auth/ide/capabilities/${activeClient.id}/pending`,
    init: {
      method: 'DELETE',
      body: '{"expected_pending_generation":7}',
    },
  });
  assert.throws(() => idePendingCancellationRequest('not-a-profile-slot', 7), /one exact profile slot/u);
  assert.throws(() => idePendingCancellationRequest(activeClient.id, 0), /between 1 and 2147483647/u);
  assert.throws(() => idePendingCancellationRequest(activeClient.id, 1.5), /between 1 and 2147483647/u);
});


test('IDE revocation, pending cancellation, and invalid recovery require exact literal-true confirmations', () => {
  assert.deepEqual(requireIdeRevocationResponse({ revoked: true }), { revoked: true });
  assert.deepEqual(requireIdePendingCancellationResponse({ cancelled: true }), { cancelled: true });
  assert.deepEqual(requireInvalidIdeRecoveryResponse({ recovered: true }), { recovered: true });
  for (const invalid of [{ revoked: false }, { revoked: 1 }, { revoked: true, extra: true }, undefined]) {
    assert.throws(() => requireIdeRevocationResponse(invalid), /invalid IDE revocation confirmation/u);
  }
  for (const invalid of [{ cancelled: false }, { cancelled: 1 }, { cancelled: true, extra: true }, null]) {
    assert.throws(() => requireIdePendingCancellationResponse(invalid), /invalid pending IDE cancellation confirmation/u);
  }
  for (const invalid of [{ recovered: false }, { recovered: 'true' }, { recovered: true, extra: true }, []]) {
    assert.throws(() => requireInvalidIdeRecoveryResponse(invalid), /invalid IDE record recovery confirmation/u);
  }
});


test('invalid IDE recovery is bound to the redacted slot and exact server-state token', () => {
  assert.deepEqual(invalidIdeCapabilityRecoveryRequest(invalidClient), {
    path: `/v1/auth/ide/capabilities/${invalidClient.id}/invalid`,
    init: {
      method: 'DELETE',
      body: JSON.stringify({ recovery_token: invalidClient.invalid_recovery_token }),
    },
  });
  assert.throws(
    () => invalidIdeCapabilityRecoveryRequest({ ...invalidClient, invalid_recovery_token: 'not-a-token' }),
    /one exact reviewed server-state token/u,
  );
});


test('full IDE revocation is bound to the exact active, pending, and latest tuple', () => {
  assert.deepEqual(ideCapabilityRevocationRequest(activeClient), {
    path: `/v1/auth/ide/capabilities/${activeClient.id}`,
    init: {
      method: 'DELETE',
      body: '{"expected_latest_generation":2,"expected_active_generation":1,"expected_pending_generation":2}',
    },
  });
  assert.throws(
    () => ideCapabilityRevocationRequest({ ...activeClient, latest_generation: 0 }),
    /Latest IDE generation must be an integer between 1 and 2147483647/u,
  );
});


test('pending-only and expired setup never render as an active authority', () => {
  const pendingOnly: IdeValidCapability = {
    ...activeClient,
    client_name: 'Fedora QA pending-only profile',
    scopes: [],
    created_at: '2026-08-29T10:01:00Z',
    active: false,
    connected: false,
    active_generation: null,
    latest_generation: 1,
    pending_generation: 1,
    source_open_available: false,
  };

  assert.deepEqual(ideClientStatus(pendingOnly), {
    label: 'Activation pending',
    tone: 'pending',
  });
  assert.equal(ideClientDisplayName(pendingOnly), 'Fedora QA pending-only profile');
  assert.deepEqual(ideClientStatus({ ...pendingOnly, pending_activation: false }), {
    label: 'Activation expired',
    tone: 'unavailable',
  });
  assert.deepEqual(ideClientStatus({
    ...pendingOnly,
    pending_activation: false,
    pending_generation: null,
    pending_client_name: null,
    pending_activation_expires_at: null,
  }), {
    label: 'No active authority · ready to pair',
    tone: 'idle',
  });
  assert.deepEqual(ideClientStatus({
    ...pendingOnly,
    pending_activation: false,
    pending_generation: null,
    active_generation: 1,
  }), {
    label: 'No active authority · ready to pair',
    tone: 'idle',
  });
});


test('invalid clients sort first, then usable connected clients, and never become source-open targets', () => {
  const unavailableValid: IdeValidCapability = {
    ...activeClient,
    id: 'ks1_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
    connected: false,
    source_open_available: false,
    source_open_disabled_reason: 'This IDE client is not currently connected to the CodeSecurity event stream.',
  };
  const sorted = [unavailableValid, activeClient, invalidClient].sort(compareIdeCapabilities);
  assert.deepEqual(sorted.map((client) => client.id), [invalidClient.id, activeClient.id, unavailableValid.id]);
  assert.deepEqual(sourceOpenIdeCapabilities(sorted).map((client) => client.id), [activeClient.id]);
});


test('source navigation carries the exact rendered active authority generation', () => {
  assert.deepEqual(ideSourceOpenTarget(activeClient), {
    target_capability_id: activeClient.id,
    expected_target_generation: 1,
  });
  assert.equal(ideSourceOpenTarget({ ...activeClient, active: false }), null);
  assert.equal(ideSourceOpenTarget({ ...activeClient, connected: false }), null);
  assert.equal(ideSourceOpenTarget({ ...activeClient, active_generation: null }), null);
  assert.equal(ideSourceOpenTarget({ ...activeClient, active_generation: 1.5 }), null);
});


test('source navigation typed authority failures produce exact recovery guidance', () => {
  const targetContext = {
    target_capability_id: activeClient.id,
    expected_target_generation: 1,
  };
  assert.deepEqual(ideSourceOpenAuthorityRecovery({
    code: 'ide_source_target_generation_conflict',
    action: 'refresh_ide_clients',
    context: { ...targetContext, current_target_generation: 2 },
  }), {
    title: 'IDE authority changed',
    detail: 'The selected IDE authority changed from generation 1 to generation 2 before source navigation was queued. Select the current connected client and try again.',
  });
  assert.deepEqual(ideSourceOpenAuthorityRecovery({
    code: 'ide_source_target_inactive',
    action: 'refresh_ide_clients',
    context: targetContext,
  }), {
    title: 'IDE client is no longer active',
    detail: 'Generation 1 of the selected IDE client is no longer authorized. Pair or reconnect the current client, then try again.',
  });
  assert.deepEqual(ideSourceOpenAuthorityRecovery({
    code: 'ide_source_target_ambiguous',
    action: 'reconnect_ide',
    context: { ...targetContext, connection_count: 2 },
  }), {
    title: 'Choose one connected IDE window',
    detail: 'Generation 1 has 2 event-stream connections. Keep exactly one VS Code window connected to this profile, then try again.',
  });
  assert.equal(ideSourceOpenAuthorityRecovery({
    code: 'ide_source_target_generation_conflict',
    action: 'reconnect_ide',
    context: { ...targetContext, current_target_generation: 2 },
  }), null);
  assert.equal(ideSourceOpenAuthorityRecovery({
    code: 'ide_source_target_ambiguous',
    action: 'reconnect_ide',
    context: { ...targetContext, connection_count: -1 },
  }), null);
});


test('all authoritative IDE mutation races share one exact reconciliation rule', () => {
  for (const code of [
    'ide_pairing_pending_generation_conflict',
    'ide_pairing_reset_generation_conflict',
    'ide_pairing_slot_state_invalid',
    'ide_pairing_invalid_recovery_conflict',
    'ide_pairing_invalid_recovery_not_required',
  ]) {
    assert.equal(ideCapabilityMutationRequiresAuthoritativeRefresh(code), true, code);
  }
  assert.equal(ideCapabilityMutationRequiresAuthoritativeRefresh('http_500'), false);
});
