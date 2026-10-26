import type {
  ApiProblem,
  IdeCapability,
  IdeInvalidCapability,
  IdeValidCapability,
} from './api.ts';


const IDE_CLIENT_SLOT_PATTERN = /^ks1_[A-Za-z0-9_-]{43}$/u;
const IDE_INVALID_RECOVERY_TOKEN_PATTERN = /^kir1_[0-9a-f]{64}$/u;
const IDE_AUTHORITATIVE_REFRESH_CODES = new Set([
  'ide_pairing_pending_generation_conflict',
  'ide_pairing_reset_generation_conflict',
  'ide_pairing_slot_state_invalid',
  'ide_pairing_invalid_recovery_conflict',
  'ide_pairing_invalid_recovery_not_required',
]);


function requireIdeClientSlot(value: string, operation: string): void {
  if (!IDE_CLIENT_SLOT_PATTERN.test(value)) {
    throw new Error(`${operation} requires one exact profile slot.`);
  }
}


function requireIdeGeneration(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2_147_483_647) {
    throw new Error(`${label} must be an integer between 1 and 2147483647.`);
  }
}


function requireNullableIdeGeneration(value: number | null, label: string): void {
  if (value !== null) requireIdeGeneration(value, label);
}


function hasOnlyLiteralTrue(value: unknown, field: 'cancelled' | 'recovered' | 'revoked'): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 1) {
    return false;
  }
  if (field === 'cancelled') return 'cancelled' in value && value.cancelled === true;
  if (field === 'recovered') return 'recovered' in value && value.recovered === true;
  return 'revoked' in value && value.revoked === true;
}


export function requireIdePendingCancellationResponse(value: unknown): { cancelled: true } {
  if (!hasOnlyLiteralTrue(value, 'cancelled')) {
    throw new Error('CodeSecurity returned an invalid pending IDE cancellation confirmation.');
  }
  return { cancelled: true };
}


export function requireInvalidIdeRecoveryResponse(value: unknown): { recovered: true } {
  if (!hasOnlyLiteralTrue(value, 'recovered')) {
    throw new Error('CodeSecurity returned an invalid IDE record recovery confirmation.');
  }
  return { recovered: true };
}


export function requireIdeRevocationResponse(value: unknown): { revoked: true } {
  if (!hasOnlyLiteralTrue(value, 'revoked')) {
    throw new Error('CodeSecurity returned an invalid IDE revocation confirmation.');
  }
  return { revoked: true };
}


export function isValidIdeCapability(capability: IdeCapability): capability is IdeValidCapability {
  return capability.state === 'valid';
}


export function validIdeCapabilities(capabilities: readonly IdeCapability[]): IdeValidCapability[] {
  return capabilities.filter(isValidIdeCapability);
}


export function sourceOpenIdeCapabilities(capabilities: readonly IdeCapability[]): IdeValidCapability[] {
  return validIdeCapabilities(capabilities).filter((capability) => capability.source_open_available);
}


export function ideSourceOpenTarget(
  capability: IdeValidCapability,
): { target_capability_id: string; expected_target_generation: number } | null {
  if (
    !IDE_CLIENT_SLOT_PATTERN.test(capability.id)
    || !capability.active
    || !capability.connected
    || capability.active_generation === null
    || !Number.isSafeInteger(capability.active_generation)
    || capability.active_generation < 1
    || capability.active_generation > 2_147_483_647
  ) return null;
  return {
    target_capability_id: capability.id,
    expected_target_generation: capability.active_generation,
  };
}


export type IdeSourceOpenAuthorityRecovery = {
  title: string;
  detail: string;
};


function exactProblemGeneration(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= 2_147_483_647
    ? value
    : null;
}


export function ideSourceOpenAuthorityRecovery(
  problem: Pick<ApiProblem, 'code' | 'action' | 'context'>,
): IdeSourceOpenAuthorityRecovery | null {
  const capabilityId = problem.context.target_capability_id;
  const expectedGeneration = exactProblemGeneration(problem.context.expected_target_generation);
  if (
    typeof capabilityId !== 'string'
    || !IDE_CLIENT_SLOT_PATTERN.test(capabilityId)
    || expectedGeneration === null
  ) return null;

  if (
    problem.code === 'ide_source_target_generation_conflict'
    && problem.action === 'refresh_ide_clients'
  ) {
    const currentGeneration = exactProblemGeneration(problem.context.current_target_generation);
    if (currentGeneration === null) return null;
    return {
      title: 'IDE authority changed',
      detail: `The selected IDE authority changed from generation ${expectedGeneration} to generation ${currentGeneration} before source navigation was queued. Select the current connected client and try again.`,
    };
  }
  if (
    problem.code === 'ide_source_target_inactive'
    && problem.action === 'refresh_ide_clients'
  ) {
    return {
      title: 'IDE client is no longer active',
      detail: `Generation ${expectedGeneration} of the selected IDE client is no longer authorized. Pair or reconnect the current client, then try again.`,
    };
  }
  if (
    problem.code === 'ide_source_target_ambiguous'
    && problem.action === 'reconnect_ide'
  ) {
    const connectionCount = problem.context.connection_count;
    if (typeof connectionCount !== 'number' || !Number.isSafeInteger(connectionCount) || connectionCount < 0) return null;
    return {
      title: 'Choose one connected IDE window',
      detail: `Generation ${expectedGeneration} has ${connectionCount} event-stream connections. Keep exactly one VS Code window connected to this profile, then try again.`,
    };
  }
  return null;
}


export function compareIdeCapabilities(left: IdeCapability, right: IdeCapability): number {
  if (left.state !== right.state) return left.state === 'invalid' ? -1 : 1;
  if (left.state === 'invalid' && right.state === 'invalid') return left.id.localeCompare(right.id);
  if (left.state !== 'valid' || right.state !== 'valid') return 0;
  if (left.active !== right.active) return left.active ? -1 : 1;
  if (left.connected !== right.connected) return left.connected ? -1 : 1;
  if (left.pending_activation !== right.pending_activation) return left.pending_activation ? -1 : 1;
  return (right.created_at || '').localeCompare(left.created_at || '');
}


export function ideCapabilityMutationRequiresAuthoritativeRefresh(code: string): boolean {
  return IDE_AUTHORITATIVE_REFRESH_CODES.has(code);
}


export function ideCapabilityRevocationRequest(
  capability: Pick<IdeValidCapability, 'id' | 'latest_generation' | 'active_generation' | 'pending_generation'>,
): { path: string; init: RequestInit } {
  requireIdeClientSlot(capability.id, 'IDE revocation');
  requireIdeGeneration(capability.latest_generation, 'Latest IDE generation');
  requireNullableIdeGeneration(capability.active_generation, 'Active IDE generation');
  requireNullableIdeGeneration(capability.pending_generation, 'Pending IDE generation');
  return {
    path: `/v1/auth/ide/capabilities/${encodeURIComponent(capability.id)}`,
    init: {
      method: 'DELETE',
      body: JSON.stringify({
        expected_latest_generation: capability.latest_generation,
        expected_active_generation: capability.active_generation,
        expected_pending_generation: capability.pending_generation,
      }),
    },
  };
}


export function idePendingCancellationRequest(
  capabilityId: string,
  expectedPendingGeneration: number,
): { path: string; init: RequestInit } {
  requireIdeClientSlot(capabilityId, 'Pending IDE cancellation');
  requireIdeGeneration(expectedPendingGeneration, 'Pending IDE generation');
  return {
    path: `/v1/auth/ide/capabilities/${encodeURIComponent(capabilityId)}/pending`,
    init: {
      method: 'DELETE',
      body: JSON.stringify({ expected_pending_generation: expectedPendingGeneration }),
    },
  };
}


export function invalidIdeCapabilityRecoveryRequest(
  capability: Pick<IdeInvalidCapability, 'id' | 'invalid_recovery_token'>,
): { path: string; init: RequestInit } {
  requireIdeClientSlot(capability.id, 'Invalid IDE record recovery');
  if (!IDE_INVALID_RECOVERY_TOKEN_PATTERN.test(capability.invalid_recovery_token)) {
    throw new Error('Invalid IDE record recovery requires one exact reviewed server-state token.');
  }
  return {
    path: `/v1/auth/ide/capabilities/${encodeURIComponent(capability.id)}/invalid`,
    init: {
      method: 'DELETE',
      body: JSON.stringify({ recovery_token: capability.invalid_recovery_token }),
    },
  };
}


export type IdeClientStatus = {
  label: string;
  tone: 'disabled' | 'unavailable' | 'ready' | 'idle' | 'pending';
};


export function ideClientStatus(client: IdeValidCapability): IdeClientStatus {
  if (client.active && client.connected) return { label: 'Active · connected', tone: 'ready' };
  if (client.active) return { label: 'Active · disconnected', tone: 'idle' };
  if (client.pending_activation) return { label: 'Activation pending', tone: 'pending' };
  if (client.pending_generation !== null) return { label: 'Activation expired', tone: 'unavailable' };
  if (client.revoked) return { label: 'Revoked · ready to re-pair', tone: 'disabled' };
  return { label: 'No active authority · ready to pair', tone: 'idle' };
}


export function ideClientDisplayName(client: IdeValidCapability): string {
  return client.client_name.trim()
    || client.pending_client_name?.trim()
    || 'Unnamed VS Code client';
}


export function ideClientTargetLabel(
  client: IdeValidCapability,
  capabilities: readonly IdeCapability[],
): string {
  const name = ideClientDisplayName(client);
  const duplicateCount = validIdeCapabilities(capabilities)
    .filter((candidate) => ideClientDisplayName(candidate) === name)
    .length;
  if (duplicateCount < 2) return name;
  return `${name} · profile …${client.id.slice(-8)}`;
}


export function idePendingClientDisplayName(client: IdeValidCapability): string {
  return client.pending_client_name?.trim()
    || client.client_name.trim()
    || 'Unnamed VS Code client';
}
