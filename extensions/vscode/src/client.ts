import { canonicalLoopbackOrigin } from './authority';
import { CodeSecurityRequestError } from './request-error';
export { CodeSecurityRequestError } from './request-error';
import {
  ProfileActiveAuthority,
  ProfileAuthorityIdentity,
  ProfileCredentialStoreError,
  ProfileCredentialStoreLike,
  ProfilePendingAuthority,
  ProfileRejectionReason,
  validateProfileAuthorityIdentity,
  validateProfileActiveAuthority,
  validateProfilePendingAuthority,
} from './credentials';

const REST_REQUEST_TIMEOUT_MS = 15_000;
const MAX_REST_REQUEST_TIMEOUT_MS = 10 * 60_000;
// The API holds an invitation-membership lookup for at most 20 seconds. The
// remaining five seconds cover local request and response work without polling.
const BROWSER_MEMBERSHIP_WAIT_DEADLINE_MS = 25_000;

export const IDE_CAPABILITY_SCOPES = Object.freeze([
  'browser:invite',
  'event:read',
  'finding:advisor',
  'finding:delete',
  'finding:lifecycle',
  'finding:read',
  'job:cancel',
  'job:read',
  'project:create',
  'project:resolve',
  'scan:create',
  'scan:read',
  'source:open-ack',
  'source:open-context',
  'source:snapshot',
] as const);

export type AuthorityInvalidation = Readonly<{
  endpoint: string;
  reason: 'endpoint_changed' | 'unauthorized' | 'missing_or_invalid';
}>;

export type IdeConnectionOutcome = Readonly<{
  finishFirstOwnerSetup: boolean;
  authority: 'activated_now' | 'retained';
}>;

type EnrollmentResponse = {
  request_id?: unknown;
  state?: unknown;
  revision?: unknown;
  verification_code?: unknown;
  capability?: unknown;
  scopes?: unknown;
  client_slot?: unknown;
  generation?: unknown;
  requested_at?: unknown;
  activation_expires_at?: unknown;
};

type EnrollmentStatusResponse = {
  request_id?: unknown;
  state?: unknown;
  revision?: unknown;
  decision_at?: unknown;
  activation_expires_at?: unknown;
};

type ActivationResponse = {
  client_slot?: unknown;
  generation?: unknown;
  scopes?: unknown;
};

export type BrowserInvitation = Readonly<{
  bootstrapToken: string;
  invitationId: string;
  purpose: BrowserInvitationPurpose;
  issuedAt: string;
  expiresAt: string;
}>;

export type BrowserInvitationPurpose = 'integrated_dashboard' | 'extra_browser';

export type BrowserInvitationMembership = Readonly<{
  invitationId: string;
  status: 'pending';
  purpose: BrowserInvitationPurpose;
  expiresAt: string;
}> | Readonly<{
  invitationId: string;
  status: 'active';
  purpose: BrowserInvitationPurpose;
  memberId: string;
  createdAt: string;
}> | Readonly<{
  invitationId: string;
  status: 'missing_or_revoked';
}>;

export type IdeEnrollmentReview = Readonly<{
  requestId: string;
  verificationCode: string;
  state: 'awaiting_approval' | 'approved' | ProfileRejectionReason;
  revision: number;
  activationExpiresAt: string;
}>;

const BROWSER_INVITATION_TOKEN = /^kbi1\.[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{43}$/u;
const BROWSER_INVITATION_ID = /^[A-Za-z0-9_-]{24}$/u;
const BROWSER_MEMBER_ID = /^kbm1_[A-Za-z0-9_-]{32}$/u;
const IDE_ENROLLMENT_REQUEST_ID = /^ker1_[A-Za-z0-9_-]{24}$/u;
const IDE_ENROLLMENT_VERIFICATION_CODE = /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/u;

function strictInstant(value: unknown): value is string {
  return typeof value === 'string'
    && value.length >= 20
    && value.length <= 64
    && /(?:Z|[+-][0-9]{2}:[0-9]{2})$/u.test(value)
    && !/[\p{Cc}\p{Cf}]/u.test(value)
    && Number.isFinite(Date.parse(value));
}

type CodeSecurityClientOptions = Readonly<{
  requestTimeoutMs?: number;
}>;

export type CodeSecurityRequestOptions = Readonly<{
  deadlineMs?: number;
}>;

function hasExactIdeScopes(value: unknown): boolean {
  if (!Array.isArray(value) || value.length !== IDE_CAPABILITY_SCOPES.length) return false;
  if (!value.every((scope) => typeof scope === 'string')) return false;
  const scopes = new Set(value);
  return scopes.size === IDE_CAPABILITY_SCOPES.length
    && IDE_CAPABILITY_SCOPES.every((scope) => scopes.has(scope));
}

export class PairingRequiredError extends Error {
  constructor(message = 'Connect this VS Code profile to Lomo CodeSecurity before using API commands.') {
    super(message);
    this.name = 'PairingRequiredError';
  }
}

export class IdeEnrollmentApprovalRequiredError extends PairingRequiredError {
  constructor(readonly review: IdeEnrollmentReview) {
    super(`Approve CodeSecurity IDE access ${review.verificationCode} in Settings to connect this VS Code profile.`);
    this.name = 'IdeEnrollmentApprovalRequiredError';
  }
}

const MAX_PROBLEM_BYTES = 16_384;
const MAX_PROBLEM_MESSAGE_CHARACTERS = 1_000;
const SAFE_PROBLEM_CODE = /^[a-z][a-z0-9_.-]{0,79}$/;
const SAFE_CORRELATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
const UNSAFE_PROBLEM_CHARACTER = /[\p{Cc}\p{Cf}]/u;

type SafeApiProblem = Readonly<{
  code?: string;
  message?: string;
  action?: string;
  correlationId?: string;
  sourceBoundary?: Readonly<{
    selectedTarget?: string;
    authorizedRoots: readonly string[];
  }>;
}>;

const MAX_BOUNDARY_PATH_CHARACTERS = 512;
const MAX_AUTHORIZED_ROOTS = 32;

function safeProblemText(value: unknown, limit: number): string | undefined {
  if (typeof value !== 'string' || value.length > limit || UNSAFE_PROBLEM_CHARACTER.test(value)) return undefined;
  const normalized = value.trim();
  return normalized || undefined;
}

function safeSourceBoundaryContext(
  value: unknown,
  safeDetailsValue: unknown,
): SafeApiProblem['sourceBoundary'] {
  const context = value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
  const safeDetails = safeDetailsValue && typeof safeDetailsValue === 'object'
    && !Array.isArray(safeDetailsValue)
    ? safeDetailsValue as Record<string, unknown>
    : undefined;
  const sourceTarget = context.source_target && typeof context.source_target === 'object'
    && !Array.isArray(context.source_target)
    ? context.source_target as Record<string, unknown>
    : undefined;
  const boundary = context.authorization_boundary && typeof context.authorization_boundary === 'object'
    && !Array.isArray(context.authorization_boundary)
    ? context.authorization_boundary as Record<string, unknown>
    : undefined;
  const selectedTarget = safeProblemText(
    safeDetails?.selected_source ?? sourceTarget?.display_path ?? context.selected_path,
    MAX_BOUNDARY_PATH_CHARACTERS,
  );
  const rootsValue = boundary?.display_paths ?? context.allowed_roots;
  const configuredBoundary = safeProblemText(
    safeDetails?.configured_source_boundary,
    MAX_BOUNDARY_PATH_CHARACTERS,
  );
  const authorizedRoots = Array.isArray(rootsValue)
    ? [...new Set(rootsValue
      .slice(0, MAX_AUTHORIZED_ROOTS)
      .map((root) => safeProblemText(root, MAX_BOUNDARY_PATH_CHARACTERS))
      .filter((root): root is string => root !== undefined))]
    : configuredBoundary
      ? [configuredBoundary]
      : [];
  return selectedTarget || authorizedRoots.length > 0
    ? { selectedTarget, authorizedRoots }
    : undefined;
}

function safeApiProblem(value: unknown): SafeApiProblem | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length === 1 && Array.isArray(record.detail) && record.detail.length > 0 && record.detail.length <= 8) {
    const messages: string[] = [];
    for (const value of record.detail) {
      // Accept only the API's sanitized validation projection, never FastAPI's
      // raw input/ctx/url fields or arbitrary object/string error bodies.
      if (!value || typeof value !== 'object' || Array.isArray(value)
        || Object.keys(value).sort().join(',') !== 'loc,msg,type') return undefined;
      const item = value as Record<string, unknown>;
      const message = safeProblemText(item.msg, 240);
      if (!message || typeof item.type !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/u.test(item.type)
        || !Array.isArray(item.loc) || item.loc.length > 6
        || item.loc.some((part) => typeof part === 'string' ? !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u.test(part)
          : !Number.isSafeInteger(part) || part < 0 || part > 5000)) return undefined;
      const field = item.loc.length ? item.loc.join('.') : 'request';
      messages.push(`${field}: ${message}`);
    }
    const message = `Check the request: ${messages.slice(0, 3).join('; ')}`;
    if (message.length > MAX_PROBLEM_MESSAGE_CHARACTERS) return undefined;
    return { code: 'request_validation_failed', message };
  }
  const detail = record.detail && typeof record.detail === 'object' && !Array.isArray(record.detail)
    ? record.detail as Record<string, unknown>
    : undefined;
  const candidate = detail || record;
  const message = safeProblemText(candidate.message, MAX_PROBLEM_MESSAGE_CHARACTERS);
  const action = typeof candidate.action === 'string' && SAFE_PROBLEM_CODE.test(candidate.action)
    ? candidate.action
    : undefined;
  const code = typeof candidate.code === 'string' && SAFE_PROBLEM_CODE.test(candidate.code)
    ? candidate.code
    : undefined;
  const correlationId = typeof candidate.correlation_id === 'string'
    && SAFE_CORRELATION_ID.test(candidate.correlation_id)
    ? candidate.correlation_id
    : undefined;
  const sourceBoundary = code === 'source_outside_allowed_root'
    ? safeSourceBoundaryContext(candidate.context, candidate.safe_details)
    : undefined;
  return code || message || action || correlationId
    ? { code, message, action, correlationId, sourceBoundary }
    : undefined;
}

async function readBoundedProblem(response: Response): Promise<SafeApiProblem | undefined> {
  const declaredLength = Number(response.headers.get('Content-Length'));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_PROBLEM_BYTES) {
    await response.body?.cancel().catch(() => undefined);
    return undefined;
  }
  if (!response.body) return undefined;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_PROBLEM_BYTES) {
        await reader.cancel().catch(() => undefined);
        return undefined;
      }
      chunks.push(value);
    }
  } catch {
    return undefined;
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return safeApiProblem(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)));
  } catch {
    return undefined;
  }
}

async function readBoundedJson(response: Response, label: 'authentication' | 'public health' = 'authentication'): Promise<unknown> {
  const declaredLength = Number(response.headers.get('Content-Length'));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_PROBLEM_BYTES) {
    await response.body?.cancel().catch(() => undefined);
    throw new CodeSecurityRequestError(`CodeSecurity returned an oversized ${label} response.`);
  }
  if (!response.body) throw new CodeSecurityRequestError(`CodeSecurity returned an empty ${label} response.`);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_PROBLEM_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new CodeSecurityRequestError(`CodeSecurity returned an oversized ${label} response.`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    throw new CodeSecurityRequestError(`CodeSecurity returned an invalid ${label} response.`);
  }
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

export function profileCredentialStorageFailure(error: ProfileCredentialStoreError): CodeSecurityRequestError {
  return new CodeSecurityRequestError(
    error.message,
    undefined,
    false,
    { code: error.code, action: error.action },
  );
}

function throwIfPairingStopped(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw new DOMException('CodeSecurity IDE connection was stopped.', 'AbortError');
  }
}

export function durableCommandHeaders(): Record<string, string> {
  const key = globalThis.crypto?.randomUUID?.();
  if (!key) {
    throw new CodeSecurityRequestError('VS Code could not create a durable command identity.');
  }
  return { 'Idempotency-Key': `vscode-${key}` };
}

export function workspaceScanCommand(
  projectId: number,
  targetPath?: string,
  targetKind?: 'file' | 'directory',
  sourceSnapshotDigest?: string,
): { path: string; init: RequestInit } {
  if (!Number.isSafeInteger(projectId) || projectId < 1) {
    throw new CodeSecurityRequestError('CodeSecurity requires a valid workspace project before scanning.');
  }
  if (
    targetPath !== undefined
    && (
      !targetPath
      || targetPath.startsWith('/')
      || targetPath.includes('\\')
      || /[\p{Cc}\p{Cf}]/u.test(targetPath)
      || targetPath.split('/').some((part) => !part || part === '.' || part === '..')
    )
  ) {
    throw new CodeSecurityRequestError('CodeSecurity requires a canonical project-relative selected source target.');
  }
  if (
    (targetPath === undefined) !== (targetKind === undefined)
    || targetKind !== undefined && targetKind !== 'file' && targetKind !== 'directory'
  ) {
    throw new CodeSecurityRequestError(
      'CodeSecurity requires one explicit file or directory kind for the selected source target.',
    );
  }
  if (
    sourceSnapshotDigest !== undefined
    && !/^[0-9a-f]{64}$/u.test(sourceSnapshotDigest)
  ) {
    throw new CodeSecurityRequestError('CodeSecurity requires an exact native source snapshot digest.');
  }
  return {
    path: '/v1/scans',
    init: {
      method: 'POST',
      headers: durableCommandHeaders(),
      // Workspace scans are evidence collection. Advisor work is a
      // separate, explicit user command and never rides along implicitly.
      body: JSON.stringify({
        project_id: projectId,
        mode: 'full',
        use_ai: false,
        ...(targetPath === undefined ? {} : { target_path: targetPath }),
        ...(targetKind === undefined ? {} : { target_kind: targetKind }),
        ...(sourceSnapshotDigest === undefined ? {} : { source_snapshot_digest: sourceSnapshotDigest }),
      }),
    },
  };
}

export function normalizeEndpoint(value: string): string {
  const endpoint = canonicalLoopbackOrigin(value);
  if (!endpoint) {
    throw new CodeSecurityRequestError(
      'The CodeSecurity API URL must be an exact HTTP loopback origin with an explicit port.',
    );
  }
  return endpoint;
}

export class CodeSecurityClient {
  private authorityQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly credentials: ProfileCredentialStoreLike,
    private readonly endpointProvider: () => string,
    private readonly fetchImplementation: typeof fetch = globalThis.fetch,
    private readonly onAuthorityInvalidated?: (invalidation: AuthorityInvalidation) => void,
    private readonly options: CodeSecurityClientOptions = {},
  ) {}

  /** Fixed public endpoint; never reads profile authority or sends credentials. */
  async publicHealth(signal?: AbortSignal): Promise<unknown> {
    const endpoint = this.currentEndpoint();
    return this.withRestDeadline(signal, 'request', async requestSignal => {
      this.requireSelectedEndpoint(endpoint, 'The CodeSecurity endpoint changed before public health was requested.');
      let response: Response;
      try {
        response = await this.fetchImplementation(`${endpoint}/healthz`, { method: 'GET',
          headers: { Accept: 'application/json' }, credentials: 'omit', redirect: 'error', signal: requestSignal });
      } catch (error) {
        if (isAbortError(error)) throw error;
        throw new CodeSecurityRequestError('Could not read the selected local CodeSecurity public health endpoint.', undefined, true);
      }
      try {
        this.requireSelectedEndpoint(endpoint, 'The CodeSecurity endpoint changed while public health was requested.');
      } catch (error) { await response.body?.cancel().catch(() => undefined); throw error; }
      if (!response.ok || response.redirected || response.url && response.url !== `${endpoint}/healthz`) {
        await response.body?.cancel().catch(() => undefined);
        throw new CodeSecurityRequestError('CodeSecurity public health refused a redirect or unsuccessful response.', response.status, false);
      }
      const health = await readBoundedJson(response, 'public health');
      this.requireSelectedEndpoint(endpoint, 'The CodeSecurity endpoint changed while public health was read.');
      return health;
    });
  }

  async connectIde(
    clientName: string,
    onReview: (review: IdeEnrollmentReview) => void = () => undefined,
    signal?: AbortSignal,
    firstOwnerBootstrapToken?: string,
  ): Promise<IdeConnectionOutcome> {
    const name = clientName.trim();
    if (!name) throw new CodeSecurityRequestError('A recognizable IDE client name is required.');

    const endpoint = this.currentEndpoint();
    return this.withAuthorityLock(async () => {
      throwIfPairingStopped(signal);
      const pending = await this.readPendingRecord(endpoint);
      if (pending) {
        const current = firstOwnerBootstrapToken
          ? await this.readEnrollmentStatus(endpoint, pending, 0, signal)
          : undefined;
        const claimed = firstOwnerBootstrapToken && current?.state === 'awaiting_approval'
          ? await this.claimFirstOwner(endpoint, pending, firstOwnerBootstrapToken, signal)
          : Boolean(firstOwnerBootstrapToken && current?.state === 'approved');
        await this.waitForEnrollmentAndActivate(
          endpoint,
          pending,
          onReview,
          signal,
          current?.state === 'awaiting_approval' ? undefined : current,
        );
        return Object.freeze({
          finishFirstOwnerSetup: claimed,
          authority: 'activated_now',
        });
      }
      const retained = await this.readAuthorityRecord(endpoint);
      const retainedRejected = retained
        ? await this.authorityIsRejected(endpoint, retained)
        : false;
      if (retained && !retainedRejected) {
        // A first-owner process may have committed local promotion and then
        // stopped before issuing its browser invitation and deleting the
        // owner-only installer artifact. Preserve that cleanup provenance
        // without sending the bootstrap or granting any new IDE authority.
        return Object.freeze({
          finishFirstOwnerSetup: firstOwnerBootstrapToken !== undefined,
          authority: 'retained',
        });
      }
      const expectedGeneration = retainedRejected ? 0 : retained?.generation ?? 0;
      let issuedPayload: unknown;
      let receivedIssuedPayload = false;
      let receivedSuccessfulEnrollmentResponse = false;
      let payload: unknown;
      try {
        payload = await this.withRestDeadline(signal, 'pairing', async (requestSignal) => {
          let response: Response;
          try {
            response = await this.fetchImplementation(`${endpoint}/v1/auth/ide/enrollments`, {
              method: 'POST',
              headers: {
                Accept: 'application/json',
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                client_name: name,
                client_slot: this.credentials.clientSlot,
                expected_active_generation: expectedGeneration,
              }),
              signal: requestSignal,
            });
          } catch (error) {
            if (isAbortError(error)) throw error;
            throw new CodeSecurityRequestError(
              'Could not reach the local CodeSecurity IDE enrollment endpoint.',
              undefined,
              true,
            );
          }

          if (!response.ok) {
            const problem = await readBoundedProblem(response);
            throw new CodeSecurityRequestError(
              problem?.message || `CodeSecurity IDE enrollment failed with status ${response.status}.`,
              response.status,
              response.status >= 500,
              problem,
            );
          }
          receivedSuccessfulEnrollmentResponse = true;
          issuedPayload = await readBoundedJson(response);
          receivedIssuedPayload = true;
          return issuedPayload;
        });
      } catch (error) {
        if (receivedIssuedPayload) {
          const identity = this.enrollmentIdentity(issuedPayload, endpoint);
          await this.confirmPendingCleanup(endpoint, identity);
        } else if (receivedSuccessfulEnrollmentResponse) {
          const boundedReason = error instanceof CodeSecurityRequestError
            ? ` ${error.message}`
            : '';
          throw new CodeSecurityRequestError(
            `CodeSecurity issued a pending authority but returned an unusable enrollment body.${boundedReason} No returned bearer was used; review IDE access in CodeSecurity Settings.`,
            undefined,
            false,
            { code: 'ide_enrollment_response_identity_untrusted', action: 'review_paired_ide_clients' },
          );
        }
        throw error;
      }
      const identity = this.enrollmentIdentity(payload, endpoint);
      if (!this.validEnrollmentEnvelope(payload)) {
        await this.confirmPendingCleanup(endpoint, identity);
        throw new CodeSecurityRequestError(
          'CodeSecurity returned an invalid IDE enrollment response. Its exact pending authority was cancelled and was not retained locally.',
        );
      }
      let record: ProfilePendingAuthority;
      try {
        record = this.enrollmentCandidate(payload, endpoint);
      } catch (error) {
        if (!(error instanceof ProfileCredentialStoreError)) throw error;
        await this.confirmPendingCleanup(endpoint, identity);
        throw new CodeSecurityRequestError(
          'CodeSecurity returned a malformed or mismatched pending enrollment authority. Its exact server pending authority was cancelled.',
        );
      }
      if (this.currentEndpoint() !== endpoint) {
        // The endpoint changed before this candidate was written locally.
        // Cancel only the exact server pending authority; there is no local
        // pending record to discard.
        await this.confirmPendingCleanup(endpoint, identity);
        throw new CodeSecurityRequestError(
          'The CodeSecurity API endpoint changed while IDE enrollment was created. The pending authority was cancelled; connect again with the selected endpoint.',
        );
      }
      try {
        await this.credentials.writePending(endpoint, record);
      } catch (error) {
        await this.confirmPendingCleanup(endpoint, identity, record);
        if (
          error instanceof ProfileCredentialStoreError
          && error.code === 'profile_credential_store_write_unconfirmed'
          && retainedRejected
          && retained
          && record.generation <= retained.generation
        ) {
          throw new CodeSecurityRequestError(
            'This VS Code profile retains a rejected connection from a previous CodeSecurity installation at this address. Reset only this profile connection, then request IDE access again.',
            undefined,
            false,
            {
              code: 'rejected_profile_authority_generation_conflict',
              action: 'reset_rejected_profile_authority',
            },
          );
        }
        if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
        throw error;
      }
      throwIfPairingStopped(signal);
      const claimed = firstOwnerBootstrapToken
        ? await this.claimFirstOwner(endpoint, record, firstOwnerBootstrapToken, signal)
        : false;
      await this.waitForEnrollmentAndActivate(endpoint, record, onReview, signal);
      return Object.freeze({
        finishFirstOwnerSetup: claimed,
        authority: 'activated_now',
      });
    });
  }

  private async claimFirstOwner(
    endpoint: string,
    pending: ProfilePendingAuthority,
    bootstrapToken: string,
    signal?: AbortSignal,
  ): Promise<boolean> {
    if (!/^[A-Za-z0-9_-]{43}$/u.test(bootstrapToken)) {
      throw new CodeSecurityRequestError(
        'CodeSecurity refused malformed first-owner installer bootstrap material.',
        undefined,
        false,
        { code: 'first_owner_bootstrap_invalid', action: 'restore_first_owner_bootstrap' },
      );
    }
    return this.withRestDeadline(signal, 'pairing', async (requestSignal) => {
      let response: Response;
      try {
        response = await this.fetchImplementation(
          `${endpoint}/v1/auth/ide/enrollments/current/claim-first-owner`,
          {
            method: 'POST',
            headers: {
              Accept: 'application/json',
              Authorization: `Bearer ${pending.capability}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              bootstrap_token: bootstrapToken,
              expected_request_id: pending.enrollment_request_id,
              expected_revision: pending.enrollment_revision,
              expected_generation: pending.generation,
            }),
            signal: requestSignal,
          },
        );
      } catch (error) {
        if (isAbortError(error)) throw error;
        throw new CodeSecurityRequestError(
          'Could not reach the local CodeSecurity first-owner claim endpoint.',
          undefined,
          true,
        );
      }
      if (!response.ok) {
        const problem = await readBoundedProblem(response);
        if (
          response.status === 409
          && [
            'first_owner_bootstrap_consumed',
            'first_owner_claim_not_pristine',
            'first_owner_claim_not_winner',
          ].includes(problem?.code || '')
        ) return false;
        throw new CodeSecurityRequestError(
          problem?.message || `CodeSecurity first-owner setup failed with status ${response.status}.`,
          response.status,
          response.status >= 500,
          problem,
        );
      }
      const review = this.validEnrollmentStatus(await readBoundedJson(response), pending);
      if (
        !review
        || review.state !== 'approved'
        || review.revision !== pending.enrollment_revision + 1
      ) {
        throw new CodeSecurityRequestError(
          'CodeSecurity returned an invalid first-owner claim response.',
          undefined,
          false,
          { code: 'first_owner_claim_response_invalid', action: 'review_paired_ide_clients' },
        );
      }
      return true;
    });
  }

  private async confirmPendingCleanup(
    endpoint: string,
    identity: ProfileAuthorityIdentity,
    localPending?: ProfilePendingAuthority,
  ): Promise<void> {
    try {
      await this.cancelServerPending(endpoint, identity);
      if (localPending) await this.credentials.discardPending(endpoint, localPending);
    } catch (error) {
      if (!(error instanceof CodeSecurityRequestError) && !(error instanceof ProfileCredentialStoreError)) {
        throw error;
      }
      throw new CodeSecurityRequestError(
        'CodeSecurity could not confirm exact pending-authority cleanup. Review IDE access in CodeSecurity Settings before connecting again.',
        undefined,
        false,
        { code: 'ide_enrollment_pending_cleanup_unconfirmed', action: 'review_paired_ide_clients' },
      );
    }
  }

  private async cancelServerPending(
    endpoint: string,
    identity: ProfileAuthorityIdentity,
  ): Promise<void> {
    await this.withRestDeadline(undefined, 'pairing', async (requestSignal) => {
      let response: Response;
      try {
        response = await this.fetchImplementation(`${endpoint}/v1/auth/ide/pending`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${identity.capability}` },
          signal: requestSignal,
        });
      } catch (error) {
        if (isAbortError(error)) throw error;
        throw new CodeSecurityRequestError(
          'Could not reach the local CodeSecurity pending-authority cancellation endpoint.',
          undefined,
          true,
        );
      }
      if (!response.ok) {
        const problem = await readBoundedProblem(response);
        throw new CodeSecurityRequestError(
          problem?.message || `CodeSecurity pending-authority cancellation failed with status ${response.status}.`,
          response.status,
          response.status >= 500,
          problem,
        );
      }
      const body = await readBoundedJson(response);
      if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).join('\0') !== 'cancelled' || (body as { cancelled?: unknown }).cancelled !== true) {
        throw new CodeSecurityRequestError('CodeSecurity returned an invalid pending-authority cancellation response.');
      }
    });
  }

  private enrollmentIdentity(payload: unknown, endpoint: string): ProfileAuthorityIdentity {
    const record = payload !== null && typeof payload === 'object' && !Array.isArray(payload)
      ? payload as Record<string, unknown>
      : {};
    try {
      return validateProfileAuthorityIdentity({
        v: 1,
        endpoint,
        client_slot: record.client_slot,
        generation: record.generation,
        capability: record.capability,
      }, endpoint, this.credentials.clientSlot);
    } catch (error) {
      if (!(error instanceof ProfileCredentialStoreError)) throw error;
      throw new CodeSecurityRequestError(
        'CodeSecurity returned an untrusted enrollment identity. No returned bearer was used; IDE access may require review in CodeSecurity Settings.',
        undefined,
        false,
        { code: 'ide_enrollment_response_identity_untrusted', action: 'review_paired_ide_clients' },
      );
    }
  }

  private enrollmentCandidate(payload: EnrollmentResponse, endpoint: string): ProfilePendingAuthority {
    return validateProfilePendingAuthority({
      v: 1,
      endpoint,
      client_slot: payload.client_slot,
      generation: payload.generation,
      capability: payload.capability,
      activation_expires_at: payload.activation_expires_at,
      enrollment_request_id: payload.request_id,
      enrollment_revision: payload.revision,
      enrollment_verification_code: payload.verification_code,
    }, endpoint, this.credentials.clientSlot);
  }

  private validEnrollmentEnvelope(payload: unknown): payload is EnrollmentResponse {
    return payload !== null
      && typeof payload === 'object'
      && !Array.isArray(payload)
      && Object.keys(payload).sort().join('\0')
      === 'activation_expires_at\0capability\0client_slot\0generation\0request_id\0requested_at\0revision\0scopes\0state\0verification_code'
      && (payload as EnrollmentResponse).state === 'awaiting_approval'
      && (payload as EnrollmentResponse).revision === 1
      && typeof (payload as EnrollmentResponse).request_id === 'string'
      && IDE_ENROLLMENT_REQUEST_ID.test((payload as EnrollmentResponse).request_id as string)
      && typeof (payload as EnrollmentResponse).verification_code === 'string'
      && IDE_ENROLLMENT_VERIFICATION_CODE.test((payload as EnrollmentResponse).verification_code as string)
      && strictInstant((payload as EnrollmentResponse).requested_at)
      && strictInstant((payload as EnrollmentResponse).activation_expires_at)
      && Date.parse((payload as EnrollmentResponse).activation_expires_at as string)
        > Date.parse((payload as EnrollmentResponse).requested_at as string)
      && hasExactIdeScopes((payload as EnrollmentResponse).scopes);
  }

  private reviewFromPending(
    pending: ProfilePendingAuthority,
    state: IdeEnrollmentReview['state'] = 'awaiting_approval',
    revision = pending.enrollment_revision,
  ): IdeEnrollmentReview {
    return Object.freeze({
      requestId: pending.enrollment_request_id,
      verificationCode: pending.enrollment_verification_code,
      state,
      revision,
      activationExpiresAt: pending.activation_expires_at,
    });
  }

  private validEnrollmentStatus(
    payload: unknown,
    pending: ProfilePendingAuthority,
  ): IdeEnrollmentReview | undefined {
    if (
      payload === null
      || typeof payload !== 'object'
      || Array.isArray(payload)
      || Object.keys(payload).sort().join('\0')
        !== 'activation_expires_at\0decision_at\0request_id\0revision\0state'
    ) return undefined;
    const value = payload as EnrollmentStatusResponse;
    if (
      value.request_id !== pending.enrollment_request_id
      || !Number.isSafeInteger(value.revision)
      || (value.revision as number) < pending.enrollment_revision
      || (value.revision as number) > 2_147_483_647
      || !['awaiting_approval', 'approved', 'rejected', 'expired'].includes(String(value.state))
      || value.activation_expires_at !== pending.activation_expires_at
      || value.decision_at !== null && !strictInstant(value.decision_at)
      || value.state === 'awaiting_approval' && value.decision_at !== null
      || ['approved', 'rejected'].includes(String(value.state)) && value.decision_at === null
    ) return undefined;
    return this.reviewFromPending(
      pending,
      value.state as IdeEnrollmentReview['state'],
      value.revision as number,
    );
  }

  private async readEnrollmentStatus(
    endpoint: string,
    pending: ProfilePendingAuthority,
    afterRevision: number,
    signal?: AbortSignal,
  ): Promise<IdeEnrollmentReview> {
    return this.withRestDeadline(signal, 'pairing', async (requestSignal) => {
      let response: Response;
      try {
        const url = new URL(`${endpoint}/v1/auth/ide/enrollments/current/wait`);
        url.searchParams.set('after_revision', String(afterRevision));
        response = await this.fetchImplementation(url.toString(), {
          method: 'GET',
          headers: {
            Accept: 'application/json',
            Authorization: `Bearer ${pending.capability}`,
            'Cache-Control': 'no-cache',
          },
          signal: requestSignal,
        });
      } catch (error) {
        if (isAbortError(error)) throw error;
        throw new CodeSecurityRequestError(
          'Could not reach the local CodeSecurity IDE enrollment review endpoint.',
          undefined,
          true,
        );
      }
      if (!response.ok) {
        const problem = await readBoundedProblem(response);
        throw new CodeSecurityRequestError(
          problem?.message || `CodeSecurity IDE enrollment review failed with status ${response.status}.`,
          response.status,
          response.status >= 500,
          problem,
        );
      }
      const review = this.validEnrollmentStatus(await readBoundedJson(response), pending);
      if (!review) throw new CodeSecurityRequestError('CodeSecurity returned an invalid IDE enrollment review response.');
      return review;
    }, 30_000);
  }

  private async waitForEnrollmentAndActivate(
    endpoint: string,
    pending: ProfilePendingAuthority,
    onReview: (review: IdeEnrollmentReview) => void,
    signal?: AbortSignal,
    initialReview?: IdeEnrollmentReview,
  ): Promise<void> {
    const terminalReason = await this.authorityRejectionReason(endpoint, pending);
    if (terminalReason) {
      onReview(this.reviewFromPending(pending, terminalReason));
      throw new CodeSecurityRequestError(
        `This IDE enrollment is ${terminalReason}. Cancel it or review IDE access in CodeSecurity Settings before connecting again.`,
        terminalReason === 'expired' ? 410 : 403,
        false,
        { code: `ide_enrollment_${terminalReason}`, action: 'review_paired_ide_clients' },
      );
    }
    let review = initialReview || this.reviewFromPending(pending);
    onReview(review);
    while (review.state === 'awaiting_approval') {
      throwIfPairingStopped(signal);
      review = await this.readEnrollmentStatus(endpoint, pending, review.revision, signal);
      onReview(review);
    }
    if (review.state !== 'approved') {
      try {
        await this.credentials.markRejected(endpoint, pending, review.state === 'expired' ? 'expired' : 'rejected');
      } catch (error) {
        if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
        throw error;
      }
      throw new CodeSecurityRequestError(
        review.state === 'rejected'
          ? 'This IDE enrollment was rejected in CodeSecurity Settings.'
          : 'This IDE enrollment expired before it was approved.',
        review.state === 'rejected' ? 403 : 410,
        false,
        {
          code: review.state === 'rejected' ? 'ide_enrollment_rejected' : 'ide_enrollment_expired',
          action: review.state === 'rejected' ? 'review_paired_ide_clients' : 'start_new_enrollment',
        },
      );
    }
    const active = await this.activatePending(endpoint, pending, signal);
    try {
      await this.credentials.promotePending(endpoint, pending, active);
    } catch (error) {
      if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
      throw error;
    }
  }

  private async activatePending(
    endpoint: string,
    pending: ProfilePendingAuthority,
    signal?: AbortSignal,
  ): Promise<ProfileActiveAuthority> {
    return this.withRestDeadline(signal, 'pairing', async (requestSignal) => {
      let response: Response;
      try {
        response = await this.fetchImplementation(`${endpoint}/v1/auth/ide/activate`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${pending.capability}` },
          signal: requestSignal,
        });
      } catch (error) {
        if (isAbortError(error)) throw error;
        throw new CodeSecurityRequestError(
          'Could not reach the local CodeSecurity authority-activation endpoint.',
          undefined,
          true,
        );
      }
      if (!response.ok) {
        const problem = await readBoundedProblem(response);
        this.requireSelectedEndpoint(
          endpoint,
          'The CodeSecurity API endpoint changed while pending authority activation was in flight. The pending record was preserved; retry against the selected endpoint.',
        );
        if (response.status === 401 || response.status === 410) {
          try {
            await this.credentials.markRejected(endpoint, pending, response.status === 410 ? 'expired' : 'unavailable');
          } catch (error) {
            if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
            throw error;
          }
        }
        throw new CodeSecurityRequestError(
          problem?.message || `CodeSecurity authority activation failed with status ${response.status}.`,
          response.status,
          response.status >= 500,
          problem,
        );
      }
      const body = await readBoundedJson(response) as ActivationResponse;
      if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).sort().join('\0') !== 'client_slot\0generation\0scopes'
        || !hasExactIdeScopes(body.scopes)) {
        throw new CodeSecurityRequestError('CodeSecurity returned an invalid authority-activation response.');
      }
      try {
        return validateProfileActiveAuthority({
          v: 1,
          endpoint,
          client_slot: body.client_slot,
          generation: body.generation,
          capability: pending.capability,
        }, endpoint, pending.client_slot);
      } catch (error) {
        if (!(error instanceof ProfileCredentialStoreError)) throw error;
        throw new CodeSecurityRequestError('CodeSecurity returned an invalid authority-activation response.');
      }
    });
  }

  private async recoverPendingUnlocked(endpoint: string, signal?: AbortSignal): Promise<boolean> {
    const pending = await this.readPendingRecord(endpoint);
    if (!pending) return false;
    const terminalReason = await this.authorityRejectionReason(endpoint, pending);
    if (terminalReason) {
      throw new IdeEnrollmentApprovalRequiredError(this.reviewFromPending(pending, terminalReason));
    }
    try {
      this.requireSelectedEndpoint(
        endpoint,
        'The CodeSecurity API endpoint changed before pending enrollment recovery. No authority was changed and no request was sent; retry against the selected endpoint.',
      );
      const review = await this.readEnrollmentStatus(endpoint, pending, 0, signal);
      if (review.state === 'awaiting_approval') {
        throw new IdeEnrollmentApprovalRequiredError(review);
      }
      if (review.state !== 'approved') {
        await this.credentials.markRejected(endpoint, pending, review.state === 'expired' ? 'expired' : 'rejected');
        throw new IdeEnrollmentApprovalRequiredError(review);
      }
      const active = await this.activatePending(endpoint, pending, signal);
      this.requireSelectedEndpoint(
        endpoint,
        'The CodeSecurity API endpoint changed while pending authority activation was completing. The pending record was preserved; retry against the selected endpoint.',
      );
      await this.credentials.promotePending(endpoint, pending, active);
    } catch (error) {
      if (error instanceof IdeEnrollmentApprovalRequiredError) throw error;
      if (error instanceof CodeSecurityRequestError && (error.status === 401 || error.status === 403 || error.status === 410)) {
        this.requireSelectedEndpoint(
          endpoint,
          'The CodeSecurity API endpoint changed while pending authority recovery was completing. The pending record was preserved; retry against the selected endpoint.',
        );
        try {
          await this.credentials.markRejected(endpoint, pending, error.status === 410 ? 'expired' : error.status === 403 ? 'rejected' : 'unavailable');
        } catch (storageError) {
          if (storageError instanceof ProfileCredentialStoreError) {
            throw profileCredentialStorageFailure(storageError);
          }
          throw storageError;
        }
        throw new IdeEnrollmentApprovalRequiredError(this.reviewFromPending(
          pending,
          error.status === 410 ? 'expired' : error.status === 403 ? 'rejected' : 'unavailable',
        ));
      }
      if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
      throw error;
    }
    return true;
  }

  private async readAuthorityRecord(endpoint: string): Promise<ProfileActiveAuthority | undefined> {
    try {
      return await this.credentials.readAuthority(endpoint);
    } catch (error) {
      if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
      throw error;
    }
  }

  private async readPendingRecord(endpoint: string): Promise<ProfilePendingAuthority | undefined> {
    try {
      return await this.credentials.readPending(endpoint);
    } catch (error) {
      if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
      throw error;
    }
  }

  private async authorityIsRejected(endpoint: string, record: ProfileAuthorityIdentity): Promise<boolean> {
    try {
      return await this.credentials.isRejected(endpoint, record);
    } catch (error) {
      if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
      throw error;
    }
  }

  private async authorityRejectionReason(endpoint: string, record: ProfileAuthorityIdentity): Promise<ProfileRejectionReason | undefined> {
    try {
      return await this.credentials.rejectionReason(endpoint, record);
    } catch (error) {
      if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
      throw error;
    }
  }

  async pendingIdeEnrollment(): Promise<IdeEnrollmentReview | undefined> {
    const endpoint = this.currentEndpoint();
    return this.withAuthorityLock(async () => {
      const pending = await this.readPendingRecord(endpoint);
      if (!pending) return undefined;
      return this.reviewFromPending(
        pending,
        await this.authorityRejectionReason(endpoint, pending) ?? 'awaiting_approval',
      );
    });
  }

  async cancelIdeEnrollment(signal?: AbortSignal): Promise<void> {
    const endpoint = this.currentEndpoint();
    await this.withAuthorityLock(async () => {
      throwIfPairingStopped(signal);
      const pending = await this.readPendingRecord(endpoint);
      if (!pending) return;
      try {
        await this.cancelServerPending(endpoint, pending);
      } catch (error) {
        if (
          !(error instanceof CodeSecurityRequestError)
          || error.status === undefined
          || ![401, 403, 410].includes(error.status)
        ) throw error;
        this.requireSelectedEndpoint(
          endpoint,
          'The CodeSecurity API endpoint changed while the exact IDE enrollment cancellation was reconciled. The local pending record was preserved.',
        );
      }
      try {
        await this.credentials.discardPending(endpoint, pending);
      } catch (error) {
        if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
        throw error;
      }
    });
  }

  async resetRejectedIdeAuthority(): Promise<void> {
    const endpoint = this.currentEndpoint();
    await this.withAuthorityLock(async () => {
      const pending = await this.readPendingRecord(endpoint);
      if (pending) {
        throw new CodeSecurityRequestError(
          'Cancel this profile\'s pending IDE access request before resetting its rejected connection.',
          undefined,
          false,
          { code: 'ide_enrollment_already_pending', action: 'resume_pending_enrollment' },
        );
      }
      const retained = await this.readAuthorityRecord(endpoint);
      if (!retained) return;
      if (!await this.authorityIsRejected(endpoint, retained)) {
        throw new CodeSecurityRequestError(
          'CodeSecurity refused to reset an IDE authority that is not proven rejected for this exact profile and endpoint.',
          undefined,
          false,
          { code: 'profile_authority_not_rejected', action: 'review_paired_ide_clients' },
        );
      }
      try {
        await this.credentials.discardRejectedAuthority(endpoint, retained);
      } catch (error) {
        if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
        throw error;
      }
    });
  }

  async request<T>(
    path: string,
    init?: RequestInit,
    requestOptions: CodeSecurityRequestOptions = {},
  ): Promise<T> {
    if (!path.startsWith('/')) {
      throw new CodeSecurityRequestError('CodeSecurity API paths must be absolute.');
    }

    const endpoint = this.currentEndpoint();
    const record = await this.readCapability(endpoint);
    if (!record) {
      throw new PairingRequiredError();
    }
    if (record.endpoint !== endpoint) {
      throw new CodeSecurityRequestError(
        'CodeSecurity refused a profile authority from a different local endpoint namespace.',
      );
    }

    const headers = new Headers(init?.headers);
    headers.set('Authorization', `Bearer ${record.capability}`);
    if (init?.body !== undefined && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    const result = await this.withRestDeadline(
      init?.signal,
      'request',
      async (requestSignal) => {
        this.requireSelectedEndpoint(
          endpoint,
          'The CodeSecurity API endpoint changed before this request was sent. No authority was rejected; retry the command against the selected endpoint.',
        );
        let response: Response;
        try {
          response = await this.fetchImplementation(`${endpoint}${path}`, {
            ...init,
            headers,
            signal: requestSignal,
          });
        } catch (error) {
          if (isAbortError(error)) throw error;
          throw new CodeSecurityRequestError('Could not reach the local CodeSecurity API.', undefined, true);
        }
        if (response.status === 401) return { unauthorized: true as const };
        if (!response.ok) {
          const problem = await readBoundedProblem(response);
          throw new CodeSecurityRequestError(
            problem?.message || `CodeSecurity request failed with status ${response.status}.`,
            response.status,
            response.status >= 500,
            problem,
          );
        }

        try {
          return { unauthorized: false as const, value: (await response.json()) as T };
        } catch (error) {
          if (isAbortError(error)) throw error;
          throw new CodeSecurityRequestError('CodeSecurity returned an invalid JSON response.');
        }
      },
      requestOptions.deadlineMs,
    );
    if (result.unauthorized) {
      const invalidated = await this.invalidateIfCurrent(record, 'unauthorized');
      if (!invalidated) {
        throw new CodeSecurityRequestError(
          'CodeSecurity authority changed while this request was in flight. Retry the command.',
        );
      }
      throw new PairingRequiredError(
        'The CodeSecurity capability is missing or revoked. Request IDE access again.',
      );
    }
    return result.value;
  }

  async issueBrowserInvitation(purpose: BrowserInvitationPurpose): Promise<BrowserInvitation> {
    const value = await this.request<unknown>('/v1/auth/ide/browser-invitations', {
      method: 'POST',
      body: JSON.stringify({ purpose }),
    });
    if (
      !value
      || typeof value !== 'object'
      || Array.isArray(value)
      || Object.keys(value).sort().join('\0')
        !== 'bootstrap_token\0expires_at\0expires_in\0invitation_id\0issued_at\0purpose'
    ) {
      throw new CodeSecurityRequestError('CodeSecurity returned an invalid browser invitation.');
    }
    const record = value as Record<string, unknown>;
    if (
      typeof record.bootstrap_token !== 'string'
      || !BROWSER_INVITATION_TOKEN.test(record.bootstrap_token)
      || typeof record.invitation_id !== 'string'
      || !BROWSER_INVITATION_ID.test(record.invitation_id)
      || !record.bootstrap_token.startsWith(`kbi1.${record.invitation_id}.`)
      || record.purpose !== purpose
      || !strictInstant(record.issued_at)
      || !strictInstant(record.expires_at)
      || record.expires_in !== 600
      || Date.parse(record.expires_at) - Date.parse(record.issued_at) !== 600_000
    ) {
      throw new CodeSecurityRequestError('CodeSecurity returned an invalid browser invitation.');
    }
    return Object.freeze({
      bootstrapToken: record.bootstrap_token,
      invitationId: record.invitation_id,
      purpose,
      issuedAt: record.issued_at,
      expiresAt: record.expires_at,
    });
  }

  async waitForBrowserInvitationMembership(
    invitationId: string,
  ): Promise<BrowserInvitationMembership> {
    if (!BROWSER_INVITATION_ID.test(invitationId)) {
      throw new CodeSecurityRequestError('CodeSecurity requires a valid browser invitation identity.');
    }
    const value = await this.request<unknown>(
      `/v1/auth/ide/browser-invitations/${invitationId}/membership`,
      undefined,
      { deadlineMs: BROWSER_MEMBERSHIP_WAIT_DEADLINE_MS },
    );
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new CodeSecurityRequestError('CodeSecurity returned an invalid browser membership acknowledgement.');
    }
    const record = value as Record<string, unknown>;
    if (record.invitation_id !== invitationId || typeof record.status !== 'string') {
      throw new CodeSecurityRequestError('CodeSecurity returned an invalid browser membership acknowledgement.');
    }
    if (record.status === 'missing_or_revoked') {
      if (Object.keys(record).sort().join('\0') !== 'invitation_id\0status') {
        throw new CodeSecurityRequestError('CodeSecurity returned an invalid missing browser membership acknowledgement.');
      }
      return Object.freeze({ invitationId, status: 'missing_or_revoked' });
    }
    if (record.status === 'pending') {
      if (
        Object.keys(record).sort().join('\0') !== 'expires_at\0invitation_id\0purpose\0status'
        || record.purpose !== 'integrated_dashboard' && record.purpose !== 'extra_browser'
        || !strictInstant(record.expires_at)
      ) {
        throw new CodeSecurityRequestError('CodeSecurity returned an invalid pending browser membership acknowledgement.');
      }
      return Object.freeze({
        invitationId,
        status: 'pending',
        purpose: record.purpose,
        expiresAt: record.expires_at,
      });
    }
    if (
      record.status !== 'active'
      || Object.keys(record).sort().join('\0')
        !== 'created_at\0invitation_id\0member_id\0purpose\0status'
      || record.purpose !== 'integrated_dashboard' && record.purpose !== 'extra_browser'
      || typeof record.member_id !== 'string'
      || !BROWSER_MEMBER_ID.test(record.member_id)
      || !strictInstant(record.created_at)
    ) {
      throw new CodeSecurityRequestError('CodeSecurity returned an invalid active browser membership acknowledgement.');
    }
    return Object.freeze({
      invitationId,
      status: 'active',
      purpose: record.purpose,
      memberId: record.member_id,
      createdAt: record.created_at,
    });
  }

  endpointIdentity(): string {
    return this.currentEndpoint();
  }

  /** Non-secret identity for an explicit repository-member consent request. */
  async activeIdeIdentity(): Promise<Readonly<{ endpoint: string; clientSlot: string; generation: number }>> {
    const endpoint = this.currentEndpoint();
    const record = await this.readCapability(endpoint);
    this.requireSelectedEndpoint(endpoint, 'The local endpoint changed while reading this IDE identity. Review the repository again.');
    if (!record) throw new PairingRequiredError();
    return Object.freeze({ endpoint, clientSlot: record.client_slot, generation: record.generation });
  }

  async openEventStream(lastEventId: number, signal: AbortSignal): Promise<Response> {
    if (!Number.isSafeInteger(lastEventId) || lastEventId < 0) {
      throw new CodeSecurityRequestError('CodeSecurity event cursors must be non-negative safe integers.');
    }
    const endpoint = this.currentEndpoint();
    const record = await this.readCapability(endpoint);
    if (!record) throw new PairingRequiredError();
    if (record.endpoint !== endpoint) {
      throw new CodeSecurityRequestError(
        'CodeSecurity refused a profile authority from a different local endpoint namespace.',
      );
    }

    let response: Response;
    try {
      this.requireSelectedEndpoint(
        endpoint,
        'The CodeSecurity API endpoint changed before the event stream was opened. No authority was rejected; reconnect to the selected endpoint.',
      );
      response = await this.fetchImplementation(`${endpoint}/v1/events`, {
        method: 'GET',
        headers: {
          Accept: 'text/event-stream',
          Authorization: `Bearer ${record.capability}`,
          'Cache-Control': 'no-cache',
          'Last-Event-ID': String(lastEventId),
        },
        signal,
      });
    } catch (error) {
      if (error instanceof CodeSecurityRequestError) throw error;
      if (isAbortError(error)) throw error;
      throw new CodeSecurityRequestError('Could not reach the local CodeSecurity event stream.', undefined, true);
    }
    if (response.status === 401) {
      const invalidated = await this.invalidateIfCurrent(record, 'unauthorized');
      if (!invalidated) {
        throw new CodeSecurityRequestError(
          'CodeSecurity authority changed while the event stream was opening. Reconnect to the selected endpoint.',
          undefined,
          true,
        );
      }
      throw new PairingRequiredError(
        'The CodeSecurity capability is missing or revoked. Request IDE access again.',
      );
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new CodeSecurityRequestError(
        `CodeSecurity event stream failed with status ${response.status}.`,
        response.status,
        response.status >= 500,
      );
    }
    const contentType = response.headers.get('Content-Type')?.toLowerCase() || '';
    if (!contentType.startsWith('text/event-stream')) {
      await response.body?.cancel().catch(() => undefined);
      throw new CodeSecurityRequestError('CodeSecurity returned an invalid event-stream response.');
    }
    if (!response.body) {
      throw new CodeSecurityRequestError('CodeSecurity returned an event stream without a body.');
    }
    return response;
  }

  private currentEndpoint(): string {
    return normalizeEndpoint(this.endpointProvider());
  }

  private requireSelectedEndpoint(endpoint: string, message: string): void {
    if (this.currentEndpoint() === endpoint) return;
    throw new CodeSecurityRequestError(
      message,
      undefined,
      true,
      { code: 'ide_endpoint_changed', action: 'retry_against_selected_endpoint' },
    );
  }

  private async withRestDeadline<T>(
    parentSignal: AbortSignal | null | undefined,
    operationName: 'pairing' | 'request',
    operation: (signal: AbortSignal) => Promise<T>,
    requestDeadlineMs?: number,
  ): Promise<T> {
    if (parentSignal?.aborted) {
      throw new DOMException('The CodeSecurity request was stopped.', 'AbortError');
    }
    if (
      requestDeadlineMs !== undefined
      && (
        !Number.isSafeInteger(requestDeadlineMs)
        || requestDeadlineMs < 1
        || requestDeadlineMs > MAX_REST_REQUEST_TIMEOUT_MS
      )
    ) {
      throw new CodeSecurityRequestError(
        `CodeSecurity request deadlines must be integers from 1 to ${MAX_REST_REQUEST_TIMEOUT_MS} milliseconds.`,
      );
    }
    const controller = new AbortController();
    let timedOut = false;
    const stop = () => controller.abort();
    parentSignal?.addEventListener('abort', stop, { once: true });
    const configuredTimeout = requestDeadlineMs ?? this.options.requestTimeoutMs;
    const timeoutMilliseconds = Number.isSafeInteger(configuredTimeout)
      && (configuredTimeout as number) > 0
      && (configuredTimeout as number) <= MAX_REST_REQUEST_TIMEOUT_MS
      ? configuredTimeout as number
      : REST_REQUEST_TIMEOUT_MS;
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMilliseconds);
    try {
      // Fetch and native Response-body consumption honor AbortSignal. Awaiting
      // the physical operation (instead of racing an abort promise) is also a
      // memory invariant for exact-file hydration: an advisory-abort-ignoring
      // adapter retains its scheduler slot/reservation until it truly settles.
      const value = await operation(controller.signal);
      if (controller.signal.aborted) {
        throw new DOMException('The CodeSecurity request was stopped.', 'AbortError');
      }
      return value;
    } catch (error) {
      if (timedOut && !parentSignal?.aborted) {
        throw new CodeSecurityRequestError(
          `The local CodeSecurity ${operationName} timed out.`,
          408,
          true,
        );
      }
      throw error;
    } finally {
      clearTimeout(timeout);
      parentSignal?.removeEventListener('abort', stop);
    }
  }

  private readCapability(endpoint: string): Promise<ProfileActiveAuthority | undefined> {
    return this.withAuthorityLock(() => this.readCapabilityUnlocked(endpoint, true));
  }

  private async readCapabilityUnlocked(
    endpoint: string,
    notifyMissing: boolean,
  ): Promise<ProfileActiveAuthority | undefined> {
    await this.recoverPendingUnlocked(endpoint);
    let record: ProfileActiveAuthority | undefined;
    try {
      record = await this.credentials.readAuthority(endpoint);
    } catch (error) {
      if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
      throw error;
    }
    if (!record) {
      if (notifyMissing) {
        this.onAuthorityInvalidated?.({ endpoint, reason: 'missing_or_invalid' });
      }
      return undefined;
    }
    try {
      if (await this.credentials.isRejected(endpoint, record)) {
        if (notifyMissing) this.onAuthorityInvalidated?.({ endpoint, reason: 'missing_or_invalid' });
        return undefined;
      }
    } catch (error) {
      if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
      throw error;
    }
    return record;
  }

  private invalidateIfCurrent(
    expected: ProfileActiveAuthority,
    reason: AuthorityInvalidation['reason'],
  ): Promise<boolean> {
    return this.withAuthorityLock(async () => {
      const current = await this.readAuthorityRecord(expected.endpoint);
      if (!current || !this.sameAuthority(current, expected)) return false;
      try {
        await this.credentials.markRejected(expected.endpoint, expected);
      } catch (error) {
        if (error instanceof ProfileCredentialStoreError) throw profileCredentialStorageFailure(error);
        throw error;
      }
      this.onAuthorityInvalidated?.({ endpoint: expected.endpoint, reason });
      return true;
    });
  }

  private sameAuthority(left: ProfileActiveAuthority, right: ProfileActiveAuthority): boolean {
    return left.v === right.v
      && left.endpoint === right.endpoint
      && left.client_slot === right.client_slot
      && left.generation === right.generation
      && left.capability === right.capability;
  }

  private withAuthorityLock<T>(operation: () => PromiseLike<T>): Promise<T> {
    const result = this.authorityQueue.then(operation, operation);
    this.authorityQueue = result.then(() => undefined, () => undefined);
    return result;
  }
}
