import { createHash, randomUUID } from 'node:crypto';
import { constants as fileConstants, type Stats } from 'node:fs';
import { lstat, mkdir, open, readdir, rename, unlink } from 'node:fs/promises';
import * as path from 'node:path';

import { canonicalLoopbackOrigin, MAX_IDE_AUTHORITY_GENERATION } from './authority';
import { verifyWindowsPrivatePath, WindowsPrivatePathError } from './windows-private-path';

export const PROFILE_CREDENTIAL_DIRECTORY_NAME = 'credentials-v1';
export const PROFILE_AUTHORITY_FILE_NAME = 'authority.json';
export const PROFILE_PENDING_AUTHORITY_FILE_NAME = 'pending.json';
export const PROFILE_AUTHORITY_LOCK_FILE_NAME = '.authority.lock';

const AUTHORITY_VERSION = 1;
const MAX_RECORD_BYTES = 16 * 1024;
const MAX_REJECTION_DIRECTORY_ENTRIES = 32;
const ABANDONED_TEMPORARY_AGE_MS = 15 * 60 * 1_000;
const CLIENT_SLOT = /^ks1_[A-Za-z0-9_-]{43}$/u;
const CAPABILITY = /^kc1\.(ks1_[A-Za-z0-9_-]{43})\.([1-9][0-9]{0,9})\.([A-Za-z0-9_-]{43})$/u;
const ENROLLMENT_REQUEST_ID = /^ker1_[A-Za-z0-9_-]{24}$/u;
const ENROLLMENT_VERIFICATION_CODE = /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/u;
const REJECTION_FILE = /^rejected-([1-9][0-9]{0,9})-([0-9a-f]{64})\.json$/u;
const TEMPORARY_FILE = /^\.pending\.write-[1-9][0-9]*-[0-9a-f-]{36}$/u;
const LOCK_NONCE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EXACT_PENDING_KEYS = Object.freeze([
  'activation_expires_at',
  'capability',
  'client_slot',
  'endpoint',
  'enrollment_request_id',
  'enrollment_revision',
  'enrollment_verification_code',
  'generation',
  'v',
]);
const EXACT_ACTIVE_KEYS = Object.freeze([
  'capability',
  'client_slot',
  'endpoint',
  'generation',
  'v',
]);
const EXACT_REJECTION_KEYS = Object.freeze(['client_slot', 'endpoint_hash', 'generation', 'raw_sha256', 'v']);
const EXACT_TERMINAL_KEYS = Object.freeze(['client_slot', 'endpoint_hash', 'generation', 'raw_sha256', 'reason', 'v']);
const EXACT_LOCK_KEYS = Object.freeze(['client_slot', 'created_at', 'endpoint_hash', 'nonce', 'pid', 'v']);

export type ProfileAuthorityIdentity = Readonly<{
  v: typeof AUTHORITY_VERSION;
  endpoint: string;
  client_slot: string;
  generation: number;
  capability: string;
}>;

export type ProfilePendingAuthority = ProfileAuthorityIdentity & Readonly<{
  activation_expires_at: string;
  enrollment_request_id: string;
  enrollment_revision: number;
  enrollment_verification_code: string;
}>;

export type ProfileActiveAuthority = ProfileAuthorityIdentity;

export type ProfileAuthority = ProfilePendingAuthority | ProfileActiveAuthority;

export type ProfileRejectionReason = 'rejected' | 'expired' | 'unavailable';

export interface ProfileCredentialStoreLike {
  readonly clientSlot: string;
  readAuthority(endpoint: string): Promise<ProfileActiveAuthority | undefined>;
  readPending(endpoint: string): Promise<ProfilePendingAuthority | undefined>;
  writePending(endpoint: string, record: ProfilePendingAuthority): Promise<void>;
  promotePending(
    endpoint: string,
    expected: ProfilePendingAuthority,
    active: ProfileActiveAuthority,
  ): Promise<void>;
  discardPending(endpoint: string, expected: ProfilePendingAuthority): Promise<void>;
  discardRejectedAuthority(endpoint: string, expected: ProfileActiveAuthority): Promise<void>;
  markRejected(endpoint: string, record: ProfileAuthority, reason?: ProfileRejectionReason): Promise<void>;
  rejectionReason(endpoint: string, record: ProfileAuthority): Promise<ProfileRejectionReason | undefined>;
  isRejected(endpoint: string, record: ProfileAuthority): Promise<boolean>;
}

export type ProfileRepairResult = Readonly<{ removed: readonly string[] }>;

type ProfileRepairCandidate = Readonly<{
  name: string;
  target: string;
  before: Stats;
  kind: 'corrupt_record' | 'abandoned_temporary';
  validate?: () => Promise<unknown>;
}>;

type ProfileMutationLock = Readonly<{
  target: string;
  raw: string;
  before: Stats;
}>;

export type ProfileCredentialStoreFailureCode =
  | 'profile_credential_store_corrupt'
  | 'profile_credential_store_insecure'
  | 'profile_credential_store_busy'
  | 'profile_credential_store_unavailable'
  | 'profile_credential_store_write_unconfirmed';

export class ProfileCredentialStoreError extends Error {
  readonly action: 'repair_profile_credential_store'
    | 'review_profile_storage_security'
    | 'restore_profile_storage_access'
    | 'review_paired_ide_clients';

  constructor(readonly code: ProfileCredentialStoreFailureCode, message: string) {
    super(message);
    this.name = 'ProfileCredentialStoreError';
    this.action = code === 'profile_credential_store_corrupt'
      ? 'repair_profile_credential_store'
      : code === 'profile_credential_store_insecure'
        ? 'review_profile_storage_security'
        : code === 'profile_credential_store_busy'
          ? 'review_paired_ide_clients'
          : code === 'profile_credential_store_unavailable'
            ? 'restore_profile_storage_access'
            : 'review_paired_ide_clients';
  }
}

function isFileSystemError(error: unknown, code: string): boolean {
  return error instanceof Error && 'code' in error && error.code === code;
}

function digestHex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function digestUrl(value: string): string {
  return createHash('sha256')
    .update(value, 'utf8')
    .digest('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
}

function canonicalPending(record: ProfilePendingAuthority): string {
  return JSON.stringify({
    activation_expires_at: record.activation_expires_at,
    capability: record.capability,
    client_slot: record.client_slot,
    endpoint: record.endpoint,
    enrollment_request_id: record.enrollment_request_id,
    enrollment_revision: record.enrollment_revision,
    enrollment_verification_code: record.enrollment_verification_code,
    generation: record.generation,
    v: AUTHORITY_VERSION,
  });
}

function canonicalActive(record: ProfileActiveAuthority): string {
  return JSON.stringify({
    capability: record.capability,
    client_slot: record.client_slot,
    endpoint: record.endpoint,
    generation: record.generation,
    v: AUTHORITY_VERSION,
  });
}

function validInstant(value: unknown): value is string {
  return typeof value === 'string'
    && value.length >= 20
    && value.length <= 64
    && !/[\p{Cc}\p{Cf}]/u.test(value)
    && /(?:Z|[+-][0-9]{2}:[0-9]{2})$/u.test(value)
    && Number.isFinite(Date.parse(value));
}

function canonicalMutationLock(value: Readonly<{
  client_slot: string;
  created_at: string;
  endpoint_hash: string;
  nonce: string;
  pid: number;
}>): string {
  return JSON.stringify({
    client_slot: value.client_slot,
    created_at: value.created_at,
    endpoint_hash: value.endpoint_hash,
    nonce: value.nonce,
    pid: value.pid,
    v: 1,
  });
}

function validateMutationLock(opened: OpenedRecord): Readonly<{
  client_slot: string;
  created_at: string;
  endpoint_hash: string;
  nonce: string;
  pid: number;
}> {
  const value = opened.parsed;
  if (
    !value
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.keys(value).sort().join('\0') !== EXACT_LOCK_KEYS.join('\0')
  ) throw corruptAuthority();
  const record = value as Record<string, unknown>;
  if (
    record.v !== 1
    || typeof record.client_slot !== 'string'
    || !CLIENT_SLOT.test(record.client_slot)
    || !validInstant(record.created_at)
    || typeof record.endpoint_hash !== 'string'
    || !/^[0-9a-f]{64}$/u.test(record.endpoint_hash)
    || typeof record.nonce !== 'string'
    || !LOCK_NONCE.test(record.nonce)
    || !Number.isSafeInteger(record.pid)
    || (record.pid as number) < 1
    || canonicalMutationLock({
      client_slot: record.client_slot,
      created_at: record.created_at,
      endpoint_hash: record.endpoint_hash,
      nonce: record.nonce,
      pid: record.pid as number,
    }) !== opened.decoded
  ) throw corruptAuthority();
  return Object.freeze({
    client_slot: record.client_slot,
    created_at: record.created_at,
    endpoint_hash: record.endpoint_hash,
    nonce: record.nonce,
    pid: record.pid as number,
  });
}

function corruptAuthority(): ProfileCredentialStoreError {
  return new ProfileCredentialStoreError(
    'profile_credential_store_corrupt',
    'CodeSecurity refused a malformed or mismatched profile authority record.',
  );
}

function changedRepairPlan(): ProfileCredentialStoreError {
  return new ProfileCredentialStoreError(
    'profile_credential_store_write_unconfirmed',
    'CodeSecurity refused a profile authority repair plan changed by another window.',
  );
}

async function readRepairDirectory(directory: string) {
  try {
    return await readdir(directory, { withFileTypes: true });
  } catch (error) {
    throw storageFailure('read', error);
  }
}

async function lstatRepairPath(target: string): Promise<Stats> {
  try {
    return await lstat(target, { bigint: false });
  } catch (error) {
    if (isFileSystemError(error, 'ENOENT')) throw changedRepairPlan();
    throw storageFailure('read', error);
  }
}

export function validateProfileAuthorityIdentity(
  value: unknown,
  expectedEndpoint?: string,
  expectedSlot?: string,
): ProfileAuthorityIdentity {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw corruptAuthority();
  const record = value as Partial<ProfileAuthority>;
  const endpoint = typeof record.endpoint === 'string' ? canonicalLoopbackOrigin(record.endpoint) : undefined;
  const capability = typeof record.capability === 'string' ? CAPABILITY.exec(record.capability) : null;
  if (
    record.v !== AUTHORITY_VERSION
    || endpoint === undefined
    || endpoint !== record.endpoint
    || typeof record.client_slot !== 'string'
    || !CLIENT_SLOT.test(record.client_slot)
    || !Number.isSafeInteger(record.generation)
    || (record.generation as number) < 1
    || (record.generation as number) > MAX_IDE_AUTHORITY_GENERATION
    || !capability
    || capability[1] !== record.client_slot
    || Number(capability[2]) !== record.generation
    || expectedEndpoint !== undefined && endpoint !== expectedEndpoint
    || expectedSlot !== undefined && record.client_slot !== expectedSlot
  ) throw corruptAuthority();
  return Object.freeze({
    v: AUTHORITY_VERSION,
    endpoint,
    client_slot: record.client_slot,
    generation: record.generation as number,
    capability: record.capability as string,
  });
}

export function validateProfilePendingAuthority(
  value: unknown,
  expectedEndpoint?: string,
  expectedSlot?: string,
): ProfilePendingAuthority {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw corruptAuthority();
  const record = value as Partial<ProfilePendingAuthority>;
  if (
    Object.keys(record).sort().join('\0') !== EXACT_PENDING_KEYS.join('\0')
    || !validInstant(record.activation_expires_at)
    || typeof record.enrollment_request_id !== 'string'
    || !ENROLLMENT_REQUEST_ID.test(record.enrollment_request_id)
    || !Number.isSafeInteger(record.enrollment_revision)
    || (record.enrollment_revision as number) < 1
    || (record.enrollment_revision as number) > MAX_IDE_AUTHORITY_GENERATION
    || typeof record.enrollment_verification_code !== 'string'
    || !ENROLLMENT_VERIFICATION_CODE.test(record.enrollment_verification_code)
  ) throw corruptAuthority();
  return Object.freeze({
    ...validateProfileAuthorityIdentity(record, expectedEndpoint, expectedSlot),
    activation_expires_at: record.activation_expires_at,
    enrollment_request_id: record.enrollment_request_id,
    enrollment_revision: record.enrollment_revision as number,
    enrollment_verification_code: record.enrollment_verification_code,
  });
}

export function validateProfileActiveAuthority(
  value: unknown,
  expectedEndpoint?: string,
  expectedSlot?: string,
): ProfileActiveAuthority {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw corruptAuthority();
  const record = value as Partial<ProfileActiveAuthority>;
  if (
    Object.keys(record).sort().join('\0') !== EXACT_ACTIVE_KEYS.join('\0')
  ) throw corruptAuthority();
  return validateProfileAuthorityIdentity(record, expectedEndpoint, expectedSlot);
}

function validateProfileAuthority(
  value: unknown,
  expectedEndpoint?: string,
  expectedSlot?: string,
): ProfileAuthority {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw corruptAuthority();
  const keys = Object.keys(value).sort().join('\0');
  if (keys === EXACT_PENDING_KEYS.join('\0')) {
    return validateProfilePendingAuthority(value, expectedEndpoint, expectedSlot);
  }
  if (keys === EXACT_ACTIVE_KEYS.join('\0')) {
    return validateProfileActiveAuthority(value, expectedEndpoint, expectedSlot);
  }
  throw corruptAuthority();
}

function storageFailure(operation: 'read' | 'write', error: unknown): ProfileCredentialStoreError {
  if (error instanceof ProfileCredentialStoreError) return error;
  const fileSystemCode = error instanceof Error
    && 'code' in error
    && typeof error.code === 'string'
    && /^[A-Z0-9_]{1,32}$/u.test(error.code)
    ? error.code
    : undefined;
  if (!fileSystemCode) throw error;
  return new ProfileCredentialStoreError(
    operation === 'read' ? 'profile_credential_store_unavailable' : 'profile_credential_store_write_unconfirmed',
    operation === 'read'
      ? 'CodeSecurity could not read its dedicated profile authority store. Restore access to this exact VS Code profile storage directory before reconnecting.'
      : 'CodeSecurity could not durably commit and verify its profile authority. Review IDE access before requesting access again.',
  );
}

function samePending(left: ProfilePendingAuthority, right: ProfilePendingAuthority): boolean {
  return canonicalPending(left) === canonicalPending(right);
}

function sameActive(left: ProfileActiveAuthority, right: ProfileActiveAuthority): boolean {
  return canonicalActive(left) === canonicalActive(right);
}

function sameIdentity(left: ProfileAuthority, right: ProfileAuthority): boolean {
  return left.v === right.v
    && left.endpoint === right.endpoint
    && left.client_slot === right.client_slot
    && left.generation === right.generation
    && left.capability === right.capability;
}

async function assertPath(
  stats: Stats, kind: 'parent' | 'directory' | 'file', target: string, protectNew = false,
): Promise<void> {
  const directory = kind !== 'file';
  if (stats.isSymbolicLink() || (directory ? !stats.isDirectory() : !stats.isFile())) {
    throw new ProfileCredentialStoreError(
      'profile_credential_store_insecure',
      `CodeSecurity refused a symbolic-link or non-regular profile authority ${directory ? 'directory' : 'file'}.`,
    );
  }
  if (!directory && stats.nlink !== 1) {
    throw new ProfileCredentialStoreError(
      'profile_credential_store_insecure',
      'CodeSecurity refused a hard-linked profile authority file.',
    );
  }
  if (process.platform === 'win32') {
    try { await verifyWindowsPrivatePath(target, directory ? 'directory' : 'file', protectNew); }
    catch (error) {
      if (!(error instanceof WindowsPrivatePathError)) throw error;
      throw new ProfileCredentialStoreError(error.code === 'windows_private_path_insecure'
        ? 'profile_credential_store_insecure' : 'profile_credential_store_unavailable', error.message);
    }
    const after = await lstat(target);
    if (after.dev !== stats.dev || after.ino !== stats.ino || after.size !== stats.size || after.nlink !== stats.nlink) {
      throw new ProfileCredentialStoreError('profile_credential_store_insecure',
        'CodeSecurity refused a profile authority path changed during permission verification.');
    }
    return;
  }
  const currentUser = process.getuid?.();
  if (currentUser === undefined || stats.uid !== currentUser) {
    throw new ProfileCredentialStoreError(
      'profile_credential_store_insecure',
      'CodeSecurity requires profile authority storage to belong to the current user.',
    );
  }
  const mode = stats.mode & 0o777;
  const validMode = kind === 'file'
    ? mode === 0o600
    : kind === 'directory'
      ? mode === 0o700
      : (mode & 0o022) === 0;
  if (!validMode) {
    throw new ProfileCredentialStoreError(
      'profile_credential_store_insecure',
      kind === 'file'
        ? 'CodeSecurity requires profile authority files to use mode 600.'
        : kind === 'directory'
          ? 'CodeSecurity requires its private authority directories to use mode 700.'
          : 'CodeSecurity refuses a profile storage parent that is writable by another user.',
    );
  }
}

async function closeHandle(handle: Awaited<ReturnType<typeof open>>): Promise<void> {
  await handle.close();
}

type OpenedRecord = Readonly<{
  decoded: string;
  parsed: unknown;
  stats: Stats;
}>;

async function readBoundedRegularFile(filePath: string): Promise<OpenedRecord | undefined> {
  let pathStats: Awaited<ReturnType<typeof lstat>>;
  try {
    pathStats = await lstat(filePath);
  } catch (error) {
    if (isFileSystemError(error, 'ENOENT')) return undefined;
    throw error;
  }
  await assertPath(pathStats, 'file', filePath);
  const noFollow = process.platform === 'win32' ? 0 : fileConstants.O_NOFOLLOW;
  const handle = await open(filePath, fileConstants.O_RDONLY | noFollow);
  try {
    const openedStats = await handle.stat();
    await assertPath(openedStats, 'file', filePath);
    if (pathStats.dev !== openedStats.dev || pathStats.ino !== openedStats.ino || openedStats.size > MAX_RECORD_BYTES) {
      throw openedStats.size > MAX_RECORD_BYTES
        ? corruptAuthority()
        : new ProfileCredentialStoreError(
          'profile_credential_store_insecure',
          'CodeSecurity refused a profile authority file that changed while it was opened.',
        );
    }
    const bytes = Buffer.alloc(openedStats.size + 1);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.byteLength - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset !== openedStats.size) {
      throw new ProfileCredentialStoreError(
        'profile_credential_store_insecure',
        'CodeSecurity refused a profile authority file that changed while it was read.',
      );
    }
    let decoded: string;
    try {
      decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, offset));
    } catch {
      throw corruptAuthority();
    }
    try {
      return { decoded, parsed: JSON.parse(decoded), stats: openedStats };
    } catch {
      throw corruptAuthority();
    }
  } finally {
    await closeHandle(handle);
  }
}

export class ProfileCredentialStore implements ProfileCredentialStoreLike {
  readonly clientSlot: string;
  private readonly credentialRoot: string;

  constructor(private readonly globalStoragePath: string, globalStorageIdentity: string) {
    if (
      !path.isAbsolute(globalStoragePath)
      || !globalStorageIdentity
      || globalStorageIdentity.length > 4096
      || /[\p{Cc}\p{Cf}]/u.test(globalStorageIdentity)
    ) {
      throw new ProfileCredentialStoreError(
        'profile_credential_store_insecure',
        'CodeSecurity requires one canonical absolute VS Code profile storage identity.',
      );
    }
    this.credentialRoot = path.join(globalStoragePath, PROFILE_CREDENTIAL_DIRECTORY_NAME);
    // globalStorageUri is stable for one extension in one named VS Code
    // profile. Its canonical URI differs across native and remote hosts.
    this.clientSlot = `ks1_${digestUrl(`lomo-kodesec-profile-slot-v1\0${globalStorageIdentity}`)}`;
  }

  async readAuthority(endpoint: string): Promise<ProfileActiveAuthority | undefined> {
    return this.readActive(endpoint);
  }

  async readPending(endpoint: string): Promise<ProfilePendingAuthority | undefined> {
    return this.readPendingRecord(endpoint);
  }

  async writePending(endpoint: string, record: ProfilePendingAuthority): Promise<void> {
    const normalized = validateProfilePendingAuthority(record, endpoint, this.clientSlot);
    await this.withMutationLock(endpoint, async (namespace) => {
      const active = await this.readActiveFileIfPresent(
        path.join(namespace, PROFILE_AUTHORITY_FILE_NAME),
        endpoint,
      );
      if (active && normalized.generation <= active.generation) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_write_unconfirmed',
          'CodeSecurity refused to stage a profile authority generation that does not advance the retained active authority.',
        );
      }
      const target = path.join(namespace, PROFILE_PENDING_AUTHORITY_FILE_NAME);
      const existing = await this.readPendingFileIfPresent(target, endpoint);
      if (existing) {
        if (samePending(existing, normalized)) return;
        throw new ProfileCredentialStoreError(
          'profile_credential_store_write_unconfirmed',
          'Another CodeSecurity window already retained a different pending authority for this profile and endpoint.',
        );
      }
      await this.atomicWriteRecord(
        namespace,
        target,
        canonicalPending(normalized),
        async () => {
          const committed = await this.readPendingFileIfPresent(target, endpoint);
          return committed !== undefined && samePending(committed, normalized);
        },
      );
    });
  }

  async promotePending(
    endpoint: string,
    expected: ProfilePendingAuthority,
    active: ProfileActiveAuthority,
  ): Promise<void> {
    const normalizedPending = validateProfilePendingAuthority(expected, endpoint, this.clientSlot);
    const normalizedActive = validateProfileActiveAuthority(active, endpoint, this.clientSlot);
    if (!sameIdentity(normalizedPending, normalizedActive)) throw corruptAuthority();
    await this.withMutationLock(endpoint, async (namespace) => {
      const pendingPath = path.join(namespace, PROFILE_PENDING_AUTHORITY_FILE_NAME);
      const authorityPath = path.join(namespace, PROFILE_AUTHORITY_FILE_NAME);
      const authority = await this.readActiveFileIfPresent(authorityPath, endpoint);
      if (authority) {
        if (authority.generation > normalizedActive.generation) {
          throw new ProfileCredentialStoreError(
            'profile_credential_store_write_unconfirmed',
            'CodeSecurity refused to replace a newer active profile authority with an older generation.',
          );
        }
        if (authority.generation === normalizedActive.generation) {
          if (!sameActive(authority, normalizedActive)) {
            throw new ProfileCredentialStoreError(
              'profile_credential_store_write_unconfirmed',
              'CodeSecurity refused a different authority for the retained active generation.',
            );
          }
          const pending = await this.readPendingFileIfPresent(pendingPath, endpoint);
          if (pending) {
            if (!samePending(pending, normalizedPending)) {
              throw new ProfileCredentialStoreError(
                'profile_credential_store_write_unconfirmed',
                'CodeSecurity refused to discard a different pending profile authority.',
              );
            }
            await unlink(pendingPath);
            await this.syncDirectory(namespace);
          }
          return;
        }
      }
      const pending = await this.readPendingFileIfPresent(pendingPath, endpoint);
      if (!pending) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_write_unconfirmed',
          'CodeSecurity could not find the exact activated profile authority candidate.',
        );
      }
      if (!samePending(pending, normalizedPending)) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_write_unconfirmed',
          'CodeSecurity refused to promote a different pending profile authority.',
        );
      }
      await this.atomicWriteRecord(
        namespace,
        authorityPath,
        canonicalActive(normalizedActive),
        async () => {
          const committed = await this.readActiveFileIfPresent(authorityPath, endpoint);
          return committed !== undefined && sameActive(committed, normalizedActive);
        },
      );
      try {
        await unlink(pendingPath);
      } catch (error) {
        throw storageFailure('write', error);
      }
      await this.syncDirectory(namespace);
      const committed = await this.readActiveFileIfPresent(authorityPath, endpoint);
      if (!committed || !sameActive(committed, normalizedActive)) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_write_unconfirmed',
          'CodeSecurity could not verify the exact activated profile authority after commit.',
        );
      }
      await this.cleanRejectionMarkers(namespace, normalizedActive);
    });
  }

  async discardPending(endpoint: string, expected: ProfilePendingAuthority): Promise<void> {
    const normalized = validateProfilePendingAuthority(expected, endpoint, this.clientSlot);
    await this.withMutationLock(endpoint, async (namespace) => {
      const pendingPath = path.join(namespace, PROFILE_PENDING_AUTHORITY_FILE_NAME);
      const pending = await this.readPendingFileIfPresent(pendingPath, endpoint);
      if (!pending) return;
      if (!samePending(pending, normalized)) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_write_unconfirmed',
          'CodeSecurity refused to discard a different pending profile authority.',
        );
      }
      try {
        await unlink(pendingPath);
      } catch (error) {
        if (!isFileSystemError(error, 'ENOENT')) throw storageFailure('write', error);
      }
      await this.syncDirectory(namespace);
    });
  }

  async discardRejectedAuthority(endpoint: string, expected: ProfileActiveAuthority): Promise<void> {
    const normalized = validateProfileActiveAuthority(expected, endpoint, this.clientSlot);
    await this.withMutationLock(endpoint, async (namespace) => {
      const authorityPath = path.join(namespace, PROFILE_AUTHORITY_FILE_NAME);
      const pendingPath = path.join(namespace, PROFILE_PENDING_AUTHORITY_FILE_NAME);
      const retained = await this.readActiveFileIfPresent(authorityPath, endpoint);
      if (!retained) return;
      if (!sameActive(retained, normalized)) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_write_unconfirmed',
          'CodeSecurity refused to reset a different retained profile authority.',
        );
      }
      if (await this.readPendingFileIfPresent(pendingPath, endpoint)) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_write_unconfirmed',
          'CodeSecurity refused to reset a retained authority while this profile has a pending IDE access request.',
        );
      }
      const rawHash = digestHex(normalized.capability);
      const markerPath = path.join(namespace, `rejected-${normalized.generation}-${rawHash}.json`);
      const marker = this.rejectionRecord(endpoint, normalized, rawHash);
      if (!await this.rejectionMatches(markerPath, marker)) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_write_unconfirmed',
          'CodeSecurity refused to reset an authority that is not proven rejected for this exact profile and endpoint.',
        );
      }
      try {
        await unlink(authorityPath);
        await this.syncDirectory(namespace);
      } catch (error) {
        if (!isFileSystemError(error, 'ENOENT')) throw storageFailure('write', error);
      }
      if (await this.readActiveFileIfPresent(authorityPath, endpoint)) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_write_unconfirmed',
          'CodeSecurity could not verify removal of the exact rejected profile authority.',
        );
      }
      try {
        await unlink(markerPath);
      } catch (error) {
        if (!isFileSystemError(error, 'ENOENT')) throw storageFailure('write', error);
      }
      await this.syncDirectory(namespace);
    });
  }

  async markRejected(endpoint: string, record: ProfileAuthority, reason: ProfileRejectionReason = 'rejected'): Promise<void> {
    const normalized = validateProfileAuthority(record, endpoint, this.clientSlot);
    if (!['rejected', 'expired', 'unavailable'].includes(reason) || reason === 'expired' && !('activation_expires_at' in normalized)) {
      throw corruptAuthority();
    }
    await this.withMutationLock(endpoint, async (namespace) => {
      const rawHash = digestHex(normalized.capability);
      const marker = this.rejectionRecord(endpoint, normalized, rawHash, reason);
      const markerPath = path.join(namespace, `rejected-${normalized.generation}-${rawHash}.json`);
      let handle: Awaited<ReturnType<typeof open>> | undefined;
      try {
        const noFollow = process.platform === 'win32' ? 0 : fileConstants.O_NOFOLLOW;
        handle = await open(markerPath, fileConstants.O_CREAT | fileConstants.O_EXCL | fileConstants.O_WRONLY | noFollow, 0o600);
        await assertPath(await handle.stat(), 'file', markerPath, true);
        await handle.writeFile(marker, { encoding: 'utf8' });
        await handle.sync();
        await closeHandle(handle);
        handle = undefined;
        await this.syncDirectory(namespace);
      } catch (error) {
        if (handle) await closeHandle(handle);
        if (!isFileSystemError(error, 'EEXIST')) throw storageFailure('write', error);
      }
      if ((await this.readRejectionRecord(markerPath, endpoint))?.decoded !== marker) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_write_unconfirmed',
          'CodeSecurity could not verify the exact rejected authority marker.',
        );
      }
      await this.cleanRejectionMarkers(namespace, normalized);
    });
  }

  async isRejected(endpoint: string, record: ProfileAuthority): Promise<boolean> {
    return await this.rejectionReason(endpoint, record) !== undefined;
  }

  async rejectionReason(endpoint: string, record: ProfileAuthority): Promise<ProfileRejectionReason | undefined> {
    const normalized = validateProfileAuthority(record, endpoint, this.clientSlot);
    const namespace = await this.namespaceIfPresent(endpoint);
    if (!namespace) return undefined;
    const rawHash = digestHex(normalized.capability);
    const markerPath = path.join(namespace, `rejected-${normalized.generation}-${rawHash}.json`);
    const opened = await this.readRejectionRecord(markerPath, endpoint);
    if (!opened) return undefined;
    const reason = (opened.parsed as { reason?: ProfileRejectionReason }).reason ?? 'unavailable';
    if (reason === 'expired' && !('activation_expires_at' in normalized)) throw corruptAuthority();
    const expected = JSON.parse(this.rejectionRecord(endpoint, normalized, rawHash, reason));
    const actual = opened.parsed as Record<string, unknown>;
    if (!['client_slot', 'endpoint_hash', 'generation', 'raw_sha256'].every(key => actual[key] === expected[key])) {
      throw corruptAuthority();
    }
    return reason;
  }

  async repairCorruptRecords(endpoint: string): Promise<ProfileRepairResult> {
    const namespace = await this.namespaceIfPresent(endpoint);
    if (!namespace) return Object.freeze({ removed: Object.freeze([]) });
    let removedAbandonedLock = false;
    let mutationLock = await this.tryCreateMutationLock(namespace, endpoint);
    if (!mutationLock) {
      await this.removeRepairableMutationLock(namespace, endpoint);
      removedAbandonedLock = true;
      mutationLock = await this.tryCreateMutationLock(namespace, endpoint);
      if (!mutationLock) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_busy',
          'Another CodeSecurity window acquired the profile authority mutation lock. No authority records were repaired.',
        );
      }
    }
    try {
      const result = await this.repairCorruptRecordsUnderLock(endpoint, namespace, mutationLock);
      return removedAbandonedLock
        ? Object.freeze({
          removed: Object.freeze([...result.removed, PROFILE_AUTHORITY_LOCK_FILE_NAME].sort()),
        })
        : result;
    } finally {
      await this.releaseMutationLock(namespace, mutationLock);
    }
  }

  private async repairCorruptRecordsUnderLock(
    endpoint: string,
    namespace: string,
    mutationLock: ProfileMutationLock,
  ): Promise<ProfileRepairResult> {
    const entries = await readRepairDirectory(namespace);
    if (entries.length > MAX_REJECTION_DIRECTORY_ENTRIES) {
      throw new ProfileCredentialStoreError(
        'profile_credential_store_insecure',
        'CodeSecurity refused to repair an unexpectedly large profile authority directory.',
      );
    }
    const initialNames = entries.map(({ name }) => name).sort();
    const observedEntries = new Map<string, Stats>();
    const candidates: ProfileRepairCandidate[] = [];
    for (const entry of entries) {
      const target = path.join(namespace, entry.name);
      if (!entry.isFile()) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_insecure',
          'CodeSecurity refused a non-regular entry in its profile authority namespace.',
        );
      }
      const before = await lstatRepairPath(target);
      await assertPath(before, 'file', target);
      observedEntries.set(entry.name, before);
      if (entry.name === PROFILE_AUTHORITY_LOCK_FILE_NAME) {
        const opened = await readBoundedRegularFile(target);
        if (
          !opened
          || opened.decoded !== mutationLock.raw
          || before.dev !== mutationLock.before.dev
          || before.ino !== mutationLock.before.ino
        ) throw changedRepairPlan();
        validateMutationLock(opened);
        continue;
      }
      if (entry.name === PROFILE_AUTHORITY_FILE_NAME) {
        const validate = () => this.readActiveFileIfPresent(target, endpoint);
        if (await this.isCorruptRecord(validate)) {
          candidates.push({ name: entry.name, target, before, kind: 'corrupt_record', validate });
        }
        continue;
      }
      if (entry.name === PROFILE_PENDING_AUTHORITY_FILE_NAME) {
        const validate = () => this.readPendingFileIfPresent(target, endpoint);
        if (await this.isCorruptRecord(validate)) {
          candidates.push({ name: entry.name, target, before, kind: 'corrupt_record', validate });
        }
        continue;
      }
      if (REJECTION_FILE.test(entry.name)) {
        const validate = () => this.readRejectionRecord(target, endpoint);
        if (await this.isCorruptRecord(validate)) {
          candidates.push({ name: entry.name, target, before, kind: 'corrupt_record', validate });
        }
        continue;
      }
      if (TEMPORARY_FILE.test(entry.name)) {
        if (Date.now() - before.mtimeMs < ABANDONED_TEMPORARY_AGE_MS) {
          throw new ProfileCredentialStoreError(
            'profile_credential_store_write_unconfirmed',
            'CodeSecurity found a recent profile authority write owned by another window. Close the other IDE access flow and retry.',
          );
        }
        candidates.push({
          name: entry.name,
          target,
          before,
          kind: 'abandoned_temporary',
        });
        continue;
      }
      throw new ProfileCredentialStoreError(
        'profile_credential_store_insecure',
        'CodeSecurity refused an unexpected file in its profile authority namespace.',
      );
    }

    const currentEntries = await readRepairDirectory(namespace);
    const currentNames = currentEntries.map(({ name }) => name).sort();
    if (currentNames.join('\0') !== initialNames.join('\0')) throw changedRepairPlan();
    for (const entry of currentEntries) {
      const before = observedEntries.get(entry.name);
      if (!entry.isFile() || !before) throw changedRepairPlan();
      const current = await lstatRepairPath(path.join(namespace, entry.name));
      await assertPath(current, 'file', path.join(namespace, entry.name));
      if (current.dev !== before.dev || current.ino !== before.ino) throw changedRepairPlan();
    }
    for (const candidate of candidates) await this.assertRepairCandidate(candidate);

    const removed: string[] = [];
    for (const candidate of candidates) {
      await this.unlinkUnchangedRegularFile(candidate.target, candidate.before);
      removed.push(candidate.name);
    }
    if (removed.length > 0) await this.syncDirectory(namespace);
    return Object.freeze({ removed: Object.freeze([...removed].sort()) });
  }

  private rejectionRecord(endpoint: string, record: ProfileAuthority, rawHash: string, reason: ProfileRejectionReason = 'rejected'): string {
    return JSON.stringify({
      client_slot: record.client_slot,
      endpoint_hash: digestHex(endpoint),
      generation: record.generation,
      raw_sha256: rawHash,
      reason,
      v: 2,
    });
  }

  private async isCorruptRecord(validate: () => Promise<unknown>): Promise<boolean> {
    try {
      if (await validate() === undefined) throw changedRepairPlan();
      return false;
    } catch (error) {
      if (!(error instanceof ProfileCredentialStoreError) || error.code !== 'profile_credential_store_corrupt') {
        throw error;
      }
      return true;
    }
  }

  private async assertRepairCandidate(candidate: ProfileRepairCandidate): Promise<void> {
    const current = await lstatRepairPath(candidate.target);
    await assertPath(current, 'file', candidate.target);
    if (current.dev !== candidate.before.dev || current.ino !== candidate.before.ino) {
      throw changedRepairPlan();
    }
    if (candidate.kind === 'abandoned_temporary') {
      if (Date.now() - current.mtimeMs < ABANDONED_TEMPORARY_AGE_MS) throw changedRepairPlan();
      return;
    }
    if (!candidate.validate || !await this.isCorruptRecord(candidate.validate)) throw changedRepairPlan();
  }

  private async unlinkUnchangedRegularFile(
    target: string,
    before: Stats,
  ): Promise<void> {
    const current = await lstatRepairPath(target);
    await assertPath(current, 'file', target);
    if (current.dev !== before.dev || current.ino !== before.ino) {
      throw new ProfileCredentialStoreError(
        'profile_credential_store_write_unconfirmed',
        'CodeSecurity refused to repair a profile authority file changed by another window.',
      );
    }
    try {
      await unlink(target);
    } catch (error) {
      throw storageFailure('write', error);
    }
  }

  private async readPendingRecord(endpoint: string): Promise<ProfilePendingAuthority | undefined> {
    try {
      const namespace = await this.namespaceIfPresent(endpoint);
      if (!namespace) return undefined;
      return this.readPendingFileIfPresent(
        path.join(namespace, PROFILE_PENDING_AUTHORITY_FILE_NAME),
        endpoint,
      );
    } catch (error) {
      throw storageFailure('read', error);
    }
  }

  private async readActive(endpoint: string): Promise<ProfileActiveAuthority | undefined> {
    try {
      const namespace = await this.namespaceIfPresent(endpoint);
      if (!namespace) return undefined;
      return this.readActiveFileIfPresent(path.join(namespace, PROFILE_AUTHORITY_FILE_NAME), endpoint);
    } catch (error) {
      throw storageFailure('read', error);
    }
  }

  private async readPendingFileIfPresent(
    filePath: string,
    endpoint: string,
  ): Promise<ProfilePendingAuthority | undefined> {
    const opened = await readBoundedRegularFile(filePath);
    if (!opened) return undefined;
    const record = validateProfilePendingAuthority(opened.parsed, endpoint, this.clientSlot);
    if (opened.decoded !== canonicalPending(record)) throw corruptAuthority();
    return record;
  }

  private async readActiveFileIfPresent(
    filePath: string,
    endpoint: string,
  ): Promise<ProfileActiveAuthority | undefined> {
    const opened = await readBoundedRegularFile(filePath);
    if (!opened) return undefined;
    const record = validateProfileActiveAuthority(opened.parsed, endpoint, this.clientSlot);
    if (opened.decoded !== canonicalActive(record)) throw corruptAuthority();
    return record;
  }

  private async withMutationLock<T>(
    endpoint: string,
    operation: (namespace: string) => Promise<T>,
  ): Promise<T> {
    const namespace = await this.ensureNamespace(endpoint);
    const mutationLock = await this.acquireMutationLock(namespace, endpoint);
    try {
      return await operation(namespace);
    } finally {
      await this.releaseMutationLock(namespace, mutationLock);
    }
  }

  private async acquireMutationLock(namespace: string, endpoint: string): Promise<ProfileMutationLock> {
    const mutationLock = await this.tryCreateMutationLock(namespace, endpoint);
    if (mutationLock) return mutationLock;
    const target = path.join(namespace, PROFILE_AUTHORITY_LOCK_FILE_NAME);
    let opened: OpenedRecord | undefined;
    try {
      const pathStats = await lstatRepairPath(target);
      await assertPath(pathStats, 'file', target);
      if (Date.now() - pathStats.mtimeMs < ABANDONED_TEMPORARY_AGE_MS) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_busy',
          'Another CodeSecurity window is changing this exact profile authority. Review current IDE access before retrying.',
        );
      }
      opened = await readBoundedRegularFile(target);
      if (!opened) throw changedRepairPlan();
      const record = validateMutationLock(opened);
      if (record.client_slot !== this.clientSlot || record.endpoint_hash !== digestHex(endpoint)) {
        throw corruptAuthority();
      }
      throw new ProfileCredentialStoreError(
        'profile_credential_store_corrupt',
        'CodeSecurity found an explicitly stale profile authority mutation lock. Use the confirmed exact-profile repair before requesting IDE access again.',
      );
    } catch (error) {
      if (error instanceof ProfileCredentialStoreError) throw error;
      throw storageFailure('read', error);
    }
    throw new ProfileCredentialStoreError(
      'profile_credential_store_busy',
      'Another CodeSecurity window is changing this exact profile authority. Review current IDE access before retrying.',
    );
  }

  private async tryCreateMutationLock(
    namespace: string,
    endpoint: string,
  ): Promise<ProfileMutationLock | undefined> {
    const target = path.join(namespace, PROFILE_AUTHORITY_LOCK_FILE_NAME);
    const record = Object.freeze({
      client_slot: this.clientSlot,
      created_at: new Date().toISOString(),
      endpoint_hash: digestHex(endpoint),
      nonce: randomUUID(),
      pid: process.pid,
    });
    const raw = canonicalMutationLock(record);
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      const noFollow = process.platform === 'win32' ? 0 : fileConstants.O_NOFOLLOW;
      handle = await open(
        target,
        fileConstants.O_CREAT | fileConstants.O_EXCL | fileConstants.O_WRONLY | noFollow,
        0o600,
      );
      await assertPath(await handle.stat(), 'file', target, true);
      await handle.writeFile(raw, { encoding: 'utf8' });
      await handle.sync();
      await closeHandle(handle);
      handle = undefined;
      await this.syncDirectory(namespace);
      const opened = await readBoundedRegularFile(target);
      if (!opened || opened.decoded !== raw) {
        throw new ProfileCredentialStoreError(
          'profile_credential_store_write_unconfirmed',
          'CodeSecurity could not verify its exact profile authority mutation lock.',
        );
      }
      const validated = validateMutationLock(opened);
      if (
        validated.client_slot !== record.client_slot
        || validated.endpoint_hash !== record.endpoint_hash
        || validated.nonce !== record.nonce
        || validated.pid !== record.pid
      ) throw changedRepairPlan();
      return Object.freeze({
        target,
        raw,
        before: opened.stats,
      });
    } catch (error) {
      if (handle) await closeHandle(handle);
      if (isFileSystemError(error, 'EEXIST')) return undefined;
      throw storageFailure('write', error);
    }
  }

  private async removeRepairableMutationLock(namespace: string, endpoint: string): Promise<void> {
    const target = path.join(namespace, PROFILE_AUTHORITY_LOCK_FILE_NAME);
    const before = await lstatRepairPath(target);
    await assertPath(before, 'file', target);
    if (Date.now() - before.mtimeMs < ABANDONED_TEMPORARY_AGE_MS) {
      throw new ProfileCredentialStoreError(
        'profile_credential_store_busy',
        'Another CodeSecurity window is changing this exact profile authority. No repair was attempted.',
      );
    }

    let exactRaw: string | undefined;
    try {
      const opened = await readBoundedRegularFile(target);
      if (!opened) throw changedRepairPlan();
      const record = validateMutationLock(opened);
      if (
        record.client_slot !== this.clientSlot
        || record.endpoint_hash !== digestHex(endpoint)
      ) {
        throw corruptAuthority();
      }
      exactRaw = opened.decoded;
    } catch (error) {
      if (!(error instanceof ProfileCredentialStoreError)) throw error;
      if (error.code !== 'profile_credential_store_corrupt') throw error;
    }

    try {
      const opened = await readBoundedRegularFile(target);
      if (!opened) throw changedRepairPlan();
      if (exactRaw !== undefined) {
        if (opened.decoded !== exactRaw) throw changedRepairPlan();
      } else {
        const record = validateMutationLock(opened);
        if (
          record.client_slot !== this.clientSlot
          || record.endpoint_hash !== digestHex(endpoint)
        ) throw corruptAuthority();
        throw changedRepairPlan();
      }
    } catch (error) {
      if (exactRaw !== undefined) throw error;
      if (!(error instanceof ProfileCredentialStoreError) || error.code !== 'profile_credential_store_corrupt') {
        throw error;
      }
    }
    await this.unlinkUnchangedRegularFile(target, before);
    await this.syncDirectory(namespace);
  }

  private async releaseMutationLock(
    namespace: string,
    mutationLock: ProfileMutationLock,
  ): Promise<void> {
    try {
      const opened = await readBoundedRegularFile(mutationLock.target);
      if (
        !opened
        || opened.decoded !== mutationLock.raw
        || opened.stats.dev !== mutationLock.before.dev
        || opened.stats.ino !== mutationLock.before.ino
      ) throw changedRepairPlan();
      validateMutationLock(opened);
      await unlink(mutationLock.target);
      await this.syncDirectory(namespace);
    } catch (error) {
      const fileSystemFailure = error instanceof Error
        && 'code' in error
        && typeof error.code === 'string'
        && /^[A-Z0-9_]{1,32}$/u.test(error.code);
      if (!(error instanceof ProfileCredentialStoreError) && !fileSystemFailure) throw error;
      throw new ProfileCredentialStoreError(
        'profile_credential_store_write_unconfirmed',
        'CodeSecurity could not confirm release of its exact profile authority mutation lock. Review current IDE access before retrying.',
      );
    }
  }

  private async atomicWriteRecord(
    namespace: string,
    target: string,
    raw: string,
    verify: () => Promise<boolean>,
  ): Promise<void> {
    if (Buffer.byteLength(raw, 'utf8') > MAX_RECORD_BYTES) throw corruptAuthority();
    // The endpoint mutation lock serializes authority commits. This unique
    // temporary remains owner-specific so an interrupted write can be
    // distinguished and repaired without touching another process's file.
    const temporaryPath = path.join(namespace, `.pending.write-${process.pid}-${randomUUID()}`);
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    let renamed = false;
    try {
      const noFollow = process.platform === 'win32' ? 0 : fileConstants.O_NOFOLLOW;
      handle = await open(temporaryPath, fileConstants.O_CREAT | fileConstants.O_EXCL | fileConstants.O_WRONLY | noFollow, 0o600);
      await assertPath(await handle.stat(), 'file', temporaryPath, true);
      await handle.writeFile(raw, { encoding: 'utf8' });
      await handle.sync();
      await closeHandle(handle);
      handle = undefined;
      await rename(temporaryPath, target);
      renamed = true;
      await this.syncDirectory(namespace);
    } catch (error) {
      if (handle) await closeHandle(handle);
      throw storageFailure('write', error);
    } finally {
      if (!renamed) {
        try {
          await unlink(temporaryPath);
        } catch (error) {
          if (!isFileSystemError(error, 'ENOENT')) throw storageFailure('write', error);
        }
      }
    }
    if (!await verify()) {
      throw new ProfileCredentialStoreError(
        'profile_credential_store_write_unconfirmed',
        'CodeSecurity could not verify the exact profile authority record after commit.',
      );
    }
  }

  private async namespaceIfPresent(endpoint: string): Promise<string | undefined> {
    const namespace = this.namespacePath(endpoint);
    try {
      await assertPath(await lstat(this.globalStoragePath), 'parent', this.globalStoragePath);
      await assertPath(await lstat(this.credentialRoot), 'directory', this.credentialRoot);
      await assertPath(await lstat(namespace), 'directory', namespace);
      return namespace;
    } catch (error) {
      if (isFileSystemError(error, 'ENOENT')) return undefined;
      throw error;
    }
  }

  private async ensureNamespace(endpoint: string): Promise<string> {
    const namespace = this.namespacePath(endpoint);
    let newCredentialRoot = false;
    try {
      await mkdir(this.globalStoragePath, { recursive: true, mode: 0o700 });
      await assertPath(await lstat(this.globalStoragePath), 'parent', this.globalStoragePath);
      await mkdir(this.credentialRoot, { mode: 0o700 });
      newCredentialRoot = true;
    } catch (error) {
      if (!isFileSystemError(error, 'EEXIST')) throw storageFailure('write', error);
    }
    await assertPath(await lstat(this.credentialRoot), 'directory', this.credentialRoot, newCredentialRoot);
    let newNamespace = false;
    try {
      await mkdir(namespace, { mode: 0o700 });
      newNamespace = true;
    } catch (error) {
      if (!isFileSystemError(error, 'EEXIST')) throw storageFailure('write', error);
    }
    await assertPath(await lstat(namespace), 'directory', namespace, newNamespace);
    return namespace;
  }

  private namespacePath(endpoint: string): string {
    if (canonicalLoopbackOrigin(endpoint) !== endpoint) throw corruptAuthority();
    return path.join(this.credentialRoot, digestHex(endpoint));
  }

  private async rejectionMatches(filePath: string, expected: string): Promise<boolean> {
    const opened = await this.readRejectionRecord(filePath);
    if (!opened) return false;
    const actual = opened.parsed as Record<string, unknown>;
    const identity = JSON.parse(expected) as Record<string, unknown>;
    return ['client_slot', 'endpoint_hash', 'generation', 'raw_sha256'].every(key => actual[key] === identity[key]);
  }

  private async readRejectionRecord(
    filePath: string,
    endpoint?: string,
  ): Promise<OpenedRecord | undefined> {
    let opened: OpenedRecord | undefined;
    try {
      opened = await readBoundedRegularFile(filePath);
    } catch (error) {
      throw storageFailure('read', error);
    }
    if (!opened) return undefined;
    const value = opened.parsed;
    if (
      !value
      || typeof value !== 'object'
      || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== ((value as { v?: unknown }).v === 2
        ? EXACT_TERMINAL_KEYS : EXACT_REJECTION_KEYS).join('\0')
      || JSON.stringify(value) !== opened.decoded
      || !((value as { v?: unknown }).v === 1
        || (value as { v?: unknown }).v === 2
          && typeof (value as { reason?: unknown }).reason === 'string'
          && ['rejected', 'expired', 'unavailable'].includes((value as { reason: string }).reason))
      || (value as { client_slot?: unknown }).client_slot !== this.clientSlot
      || !Number.isSafeInteger((value as { generation?: unknown }).generation)
      || ((value as { generation: number }).generation < 1)
      || ((value as { generation: number }).generation > MAX_IDE_AUTHORITY_GENERATION)
      || typeof (value as { endpoint_hash?: unknown }).endpoint_hash !== 'string'
      || !/^[0-9a-f]{64}$/u.test((value as { endpoint_hash: string }).endpoint_hash)
      || typeof (value as { raw_sha256?: unknown }).raw_sha256 !== 'string'
      || !/^[0-9a-f]{64}$/u.test((value as { raw_sha256: string }).raw_sha256)
      || endpoint !== undefined
        && (value as { endpoint_hash?: unknown }).endpoint_hash !== digestHex(endpoint)
    ) throw corruptAuthority();
    const fields = value as Record<string, unknown>;
    const canonical = JSON.stringify({
      client_slot: fields.client_slot,
      endpoint_hash: fields.endpoint_hash,
      generation: fields.generation,
      raw_sha256: fields.raw_sha256,
      ...(fields.v === 2 ? { reason: fields.reason } : {}),
      v: fields.v,
    });
    if (opened.decoded !== canonical) throw corruptAuthority();
    return opened;
  }

  private async cleanRejectionMarkers(namespace: string, keep: ProfileAuthority): Promise<void> {
    const entries = await readdir(namespace, { withFileTypes: true });
    if (entries.length > MAX_REJECTION_DIRECTORY_ENTRIES) {
      throw new ProfileCredentialStoreError(
        'profile_credential_store_insecure',
        'CodeSecurity refused an unexpectedly large profile authority directory.',
      );
    }
    const active = await this.readActiveFileIfPresent(
      path.join(namespace, PROFILE_AUTHORITY_FILE_NAME),
      keep.endpoint,
    );
    const pending = await this.readPendingFileIfPresent(
      path.join(namespace, PROFILE_PENDING_AUTHORITY_FILE_NAME),
      keep.endpoint,
    );
    const keepNames = new Set([keep, active, pending].filter((value): value is ProfileAuthority => value !== undefined).map((candidate) => {
      const hash = digestHex(candidate.capability);
      return `rejected-${candidate.generation}-${hash}.json`;
    }));
    for (const entry of entries) {
      if (keepNames.has(entry.name) || !REJECTION_FILE.test(entry.name)) continue;
      const target = path.join(namespace, entry.name);
      await assertPath(await lstat(target), 'file', target);
      try {
        await unlink(target);
      } catch (error) {
        if (!isFileSystemError(error, 'ENOENT')) throw storageFailure('write', error);
      }
    }
    await this.syncDirectory(namespace);
  }

  private async syncDirectory(directory: string): Promise<void> {
    // Windows guarantees same-volume rename ordering, but Node exposes no
    // supported directory fsync primitive. ACLs are independently verified
    // above; native reboot persistence still requires foreground acceptance.
    if (process.platform === 'win32') return;
    const handle = await open(directory, fileConstants.O_RDONLY | fileConstants.O_DIRECTORY);
    try {
      await handle.sync();
    } finally {
      await closeHandle(handle);
    }
  }
}
