import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, mkdir, open, realpath, rename, rmdir, unlink } from 'node:fs/promises';
import * as path from 'node:path';

import { canonicalLoopbackOrigin } from './authority';
import { CodeSecurityClient, CodeSecurityRequestError } from './client';
import { ProfileCredentialStore, ProfileCredentialStoreLike } from './credentials';
import { GitPushBoundaryError, inspectGitRepository } from './git-push-objects';
import { gitHookScript, installGitHook, observeGitHook, previewGitHook, removeGitHook } from './git-push-hook';
import { GitPushHostStatus, GitPushPolicy, GitPushRepository, validateGitPushPolicy } from './git-push-ui';
import { verifyWindowsPrivatePath } from './windows-private-path';
import { sameCanonicalLocalPath } from './canonical-local-path';

export type GitPushHostContext = Readonly<{
  endpoint: string;
  globalStoragePath: string;
  globalStorageIdentity: string;
  extensionPath: string;
  nodePath: string;
}>;
export type GitPushHostConfiguration = Readonly<{
  schema: 'lomo-git-push-host/v1';
  repository: GitPushRepository;
  context: GitPushHostContext;
  enabled: boolean;
  revision: number;
  hookDigest: string;
  helperDigest: string;
}>;
const CONFIG_LIMIT = 32 * 1024;
const SHA = /^[0-9a-f]{64}$/u;
const missing = (error: unknown) => error instanceof Error && 'code' in error && error.code === 'ENOENT';
function fail(message: string): never { throw new GitPushBoundaryError('git_push_host_unverified', message); }
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
const location = (repository: GitPushRepository, context: GitPushHostContext) => path.join(context.globalStoragePath, 'git-push-v1', `${repository.repositoryId}.json`);
const helperPath = (context: GitPushHostContext) => path.join(context.extensionPath, 'dist', 'git-push-cli.js');
const removalPath = (repository: GitPushRepository, context: GitPushHostContext) => path.join(context.globalStoragePath, 'git-push-v1', `${repository.repositoryId}.removal.json`);
const keys = (value: object, expected: string) => Object.keys(value).sort().join(',') === expected;

async function privatePath(target: string, kind: 'parent' | 'directory' | 'file', protectNew = false): Promise<void> {
  const before = await lstat(target);
  if (before.isSymbolicLink() || (kind === 'file' ? !before.isFile() || before.nlink !== 1 : !before.isDirectory())
    || !sameCanonicalLocalPath(await realpath(target), path.resolve(target))) fail('Push protection storage must have one canonical, unlinked owner-private path.');
  if (process.platform === 'win32') {
    await verifyWindowsPrivatePath(target, kind === 'file' ? 'file' : 'directory', protectNew);
  } else if (before.uid !== process.getuid?.() || (kind === 'file' ? (before.mode & 0o777) !== 0o600
    : kind === 'directory' ? (before.mode & 0o777) !== 0o700 : (before.mode & 0o022) !== 0)) {
    fail('Push protection storage requires the current owner and private file/directory permissions. No existing permissions were changed.');
  }
  const after = await lstat(target);
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size) fail('Push protection storage changed during permission verification.');
}

async function bytes(target: string, maximum: number, ownerPrivate: boolean): Promise<Buffer> {
  if (ownerPrivate) await privatePath(target, 'file');
  const lexical = await lstat(target);
  if (!lexical.isFile() || lexical.isSymbolicLink() || lexical.nlink !== 1 || lexical.size > maximum) fail('Push protection requires a bounded regular configuration or helper file.');
  const handle = await open(target, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
  try {
    const before = await handle.stat();
    if (before.dev !== lexical.dev || before.ino !== lexical.ino || before.size !== lexical.size) fail('Push protection file changed before it was read.');
    const buffer = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const read = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (!read.bytesRead) break;
      offset += read.bytesRead;
    }
    const after = await handle.stat();
    if (offset !== before.size || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) fail('Push protection file changed during its bounded read.');
    return buffer.subarray(0, offset);
  } finally { await handle.close(); }
}

function validateConfiguration(value: unknown): GitPushHostConfiguration {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || !keys(value, 'context,enabled,helperDigest,hookDigest,repository,revision,schema')) fail('Push protection configuration is invalid. Review it in VS Code.');
  const item = value as GitPushHostConfiguration;
  const { repository, context } = item;
  if (item.schema !== 'lomo-git-push-host/v1' || typeof item.enabled !== 'boolean'
    || !Number.isSafeInteger(item.revision) || item.revision < 1 || item.revision > 2_147_483_647
    || !SHA.test(item.hookDigest) || !SHA.test(item.helperDigest)
    || !repository || !keys(repository, 'clientSlot,generation,gitDirectory,name,projectId,repositoryId,root')
    || !SHA.test(repository.repositoryId) || !Number.isSafeInteger(repository.projectId) || repository.projectId! < 1
    || !Number.isSafeInteger(repository.generation) || repository.generation < 1 || repository.generation > 2_147_483_647
    || !/^ks1_[A-Za-z0-9_-]{43}$/u.test(repository.clientSlot)
    || typeof repository.name !== 'string' || !repository.name || repository.name.length > 120 || /[\p{Cc}\p{Cf}]/u.test(repository.name)
    || !context || !keys(context, 'endpoint,extensionPath,globalStorageIdentity,globalStoragePath,nodePath')
    || canonicalLoopbackOrigin(context.endpoint) !== context.endpoint
    || typeof context.globalStorageIdentity !== 'string' || !context.globalStorageIdentity || context.globalStorageIdentity.length > 4096
    || /[\p{Cc}\p{Cf}]/u.test(context.globalStorageIdentity)) fail('Push protection configuration identity is invalid.');
  for (const target of [repository.root, repository.gitDirectory, context.extensionPath, context.globalStoragePath, context.nodePath]) {
    if (typeof target !== 'string' || target.length > 4096 || !path.isAbsolute(target) || path.resolve(target) !== target || /[\p{Cc}\p{Cf}]/u.test(target)) fail('Push protection configuration paths must be exact absolute identities.');
  }
  if (hash(`lomo-git-repository/v1\0${repository.root}\0${repository.gitDirectory}`) !== repository.repositoryId) fail('Push protection repository identity does not match its root.');
  const relative = path.relative(repository.root, context.globalStoragePath);
  if (!relative || !relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative)) fail('Push protection profile state cannot live inside the protected source repository.');
  return Object.freeze(item);
}

export async function readGitPushConfiguration(target: string): Promise<GitPushHostConfiguration> {
  await privatePath(path.dirname(target), 'directory');
  const raw = await bytes(target, CONFIG_LIMIT, true);
  let parsed: unknown;
  try { parsed = JSON.parse(raw.toString('utf8')); }
  catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    return fail('Push protection configuration is not valid JSON.');
  }
  const value = validateConfiguration(parsed);
  if (target !== location(value.repository, value.context) || raw.toString('utf8') !== JSON.stringify(value) + '\n') fail('Push protection configuration is not its exact canonical record.');
  await privatePath(value.context.globalStoragePath, 'parent');
  return value;
}

function sameProfile(configuration: GitPushHostConfiguration, repository: GitPushRepository, context: GitPushHostContext): boolean {
  return configuration.repository.repositoryId === repository.repositoryId
    && configuration.repository.root === repository.root && configuration.repository.gitDirectory === repository.gitDirectory
    && (repository.projectId === null || configuration.repository.projectId === repository.projectId)
    && (['endpoint', 'extensionPath', 'globalStorageIdentity', 'globalStoragePath', 'nodePath'] as const)
      .every((key) => configuration.context[key] === context[key])
    && configuration.repository.clientSlot === repository.clientSlot;
}

function sameOwner(configuration: GitPushHostConfiguration, repository: GitPushRepository, context: GitPushHostContext): boolean {
  return sameProfile(configuration, repository, context) && configuration.repository.generation === repository.generation;
}

async function unchangedHook(configuration: GitPushHostConfiguration): Promise<boolean> {
  const repository = await inspectGitRepository(configuration.repository.root);
  return repository.repositoryId === configuration.repository.repositoryId
    && await observeGitHook(repository, {
      repositoryId: repository.repositoryId, hookPath: path.join(repository.gitDirectory, 'hooks', 'pre-push'), hookDigest: configuration.hookDigest,
    }) === 'installed';
}

async function observed(configuration: GitPushHostConfiguration): Promise<GitPushHostStatus> {
  const helper = await bytes(helperPath(configuration.context), 4 * 1024 * 1024, false);
  const installed = hash(helper) === configuration.helperDigest && await unchangedHook(configuration);
  return Object.freeze({ state: installed ? 'installed' : 'needs_repair', enabled: configuration.enabled,
    revision: configuration.revision, hookDigest: configuration.hookDigest });
}

export async function inspectGitPushPolicy(repository: GitPushRepository, _policy: GitPushPolicy | null, context: GitPushHostContext): Promise<GitPushHostStatus> {
  const pendingRemoval = await readRemoval(repository, context);
  if (pendingRemoval) return Object.freeze({ state: 'needs_repair', enabled: null,
    revision: pendingRemoval.expectedRevision, hookDigest: pendingRemoval.hookDigest });
  let configuration: GitPushHostConfiguration;
  try { configuration = await readGitPushConfiguration(location(repository, context)); }
  catch (error) {
    if (!missing(error)) throw error;
    try { await previewGitHook(repository.root); }
    catch (failure) {
      if (!(failure instanceof GitPushBoundaryError)) throw failure;
      return Object.freeze({ state: 'needs_repair', enabled: null, revision: null, hookDigest: null });
    }
    return Object.freeze({ state: 'not_installed', enabled: null, revision: null, hookDigest: null });
  }
  if (!sameOwner(configuration, repository, context)) {
    return Object.freeze({ state: 'needs_repair', enabled: null, revision: null, hookDigest: null });
  }
  return observed(configuration);
}

/** CLI requests may read/reject an existing authority, never enroll, activate or repair one. */
export function gitPushClient(configuration: Pick<GitPushHostConfiguration, 'repository' | 'context'>): CodeSecurityClient {
  const store = new ProfileCredentialStore(configuration.context.globalStoragePath, configuration.context.globalStorageIdentity);
  if (store.clientSlot !== configuration.repository.clientSlot) fail('The hook belongs to a different IDE profile. Apply protection again in its owner profile.');
  const refuse = async (): Promise<never> => fail('Open the owning VS Code profile to finish IDE access before pushing.');
  const readonlyStore: ProfileCredentialStoreLike = {
    clientSlot: store.clientSlot,
    readAuthority: async (endpoint) => {
      const record = await store.readAuthority(endpoint);
      if (record && record.generation !== configuration.repository.generation) return refuse();
      return record;
    },
    readPending: async (endpoint) => { if (await store.readPending(endpoint)) return refuse(); return undefined; },
    rejectionReason: store.rejectionReason.bind(store),
    isRejected: store.isRejected.bind(store), markRejected: store.markRejected.bind(store),
    writePending: refuse, promotePending: refuse, discardPending: refuse, discardRejectedAuthority: refuse,
  };
  return new CodeSecurityClient(readonlyStore, () => configuration.context.endpoint);
}

export async function applyGitPushPolicy(repository: GitPushRepository, policy: GitPushPolicy, context: GitPushHostContext): Promise<GitPushHostStatus> {
  const bound = Object.freeze({ ...repository, projectId: policy.project_id });
  const api = gitPushClient({ repository: bound, context });
  const latest = validateGitPushPolicy(await api.request(`/v1/git/push-protection/${repository.repositoryId}`), bound);
  if (latest.revision !== policy.revision || latest.enabled !== policy.enabled
    || !latest.members.some((member) => member.client_slot === bound.clientSlot && member.generation === bound.generation && member.state === 'approved')) fail('The repository setting or exact IDE approval changed. Review it before applying.');
  await privatePath(context.globalStoragePath, 'parent');
  const directory = path.join(context.globalStoragePath, 'git-push-v1');
  try {
    await mkdir(directory, { mode: 0o700 });
    await privatePath(directory, 'directory', true);
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
    await privatePath(directory, 'directory');
  }
  const lock = path.join(directory, `${bound.repositoryId}.lock`);
  try { await mkdir(lock, { mode: 0o700 }); }
  catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'EEXIST') fail('Another hook setup is active or needs recovery. No configuration was replaced.');
    throw error;
  }
  try {
    try { await lstat(removalPath(bound, context)); fail('Removal is pending for this exact hook. Finish Remove push protection before installing it again.'); }
    catch (error) { if (!missing(error)) throw error; }
    const target = location(bound, context);
    let prior: GitPushHostConfiguration | undefined;
    try { prior = await readGitPushConfiguration(target); } catch (error) { if (!missing(error)) throw error; }
    // Explicit Apply may accept an installed helper update or a newer, active
    // generation of this exact profile after fresh repository approval above.
    // Ordinary pushes/inspection stay generation-bound. Never downgrade,
    // transfer a profile, replace a changed hook or rewrite credentials.
    if (prior && (!sameProfile(prior, bound, context)
      || prior.repository.generation > bound.generation || !await unchangedHook(prior))) {
      fail('The installed hook or profile binding changed. Preserve it and review host setup.');
    }
    const preview = prior ? undefined : await previewGitHook(bound.root);
    const script = gitHookScript(context.nodePath, helperPath(context), target);
    const configuration = validateConfiguration({ schema: 'lomo-git-push-host/v1', repository: bound, context,
      enabled: latest.enabled, revision: latest.revision, hookDigest: hash(script),
      helperDigest: hash(await bytes(helperPath(context), 4 * 1024 * 1024, false)) });
    if (prior && prior.hookDigest !== configuration.hookDigest) fail('This hook was installed by a different runtime. Review its existing binding before replacement.');
    const temporary = path.join(directory, `${bound.repositoryId}.${randomUUID()}.tmp`);
    const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
    try {
      await privatePath(temporary, 'file', true);
      await handle.writeFile(JSON.stringify(configuration) + '\n', 'utf8'); await handle.sync();
    } finally { await handle.close(); }
    let current: GitPushHostConfiguration | undefined;
    try { current = await readGitPushConfiguration(target); } catch (error) { if (!missing(error)) throw error; }
    if (JSON.stringify(current) !== JSON.stringify(prior)) { await unlink(temporary); fail('The local setting changed during confirmation. No configuration was replaced.'); }
    await rename(temporary, target);
    if (process.platform !== 'win32') {
      const parent = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY);
      try { await parent.sync(); } finally { await parent.close(); }
    }
    if (preview) await installGitHook(preview, script);
    const verified = await readGitPushConfiguration(target);
    if (JSON.stringify(verified) !== JSON.stringify(configuration)) fail('The applied hook configuration could not be confirmed.');
    return observed(verified);
  } finally { await rmdir(lock); }
}

export type GitPushRemovalResult = Readonly<{
  localRemoved: true; registrationRemoved: boolean; cleanup: 'complete' | 'retryable' | 'review_required'; reasonCode: string | null;
}>;
type GitPushRemoval = Readonly<{
  schema: 'lomo-git-push-removal/v1'; repository: GitPushRepository; context: GitPushHostContext;
  expectedRevision: number; hookDigest: string | null; configurationDigest: string | null;
  hookRemoved: boolean;
}>;

function sameRemovalOwner(retained: GitPushRemoval | GitPushHostConfiguration, repository: GitPushRepository, context: GitPushHostContext): boolean {
  return retained.repository.repositoryId === repository.repositoryId
    && retained.repository.root === repository.root && retained.repository.gitDirectory === repository.gitDirectory
    && retained.repository.clientSlot === repository.clientSlot && retained.repository.generation === repository.generation
    && (['endpoint', 'globalStorageIdentity', 'globalStoragePath'] as const).every((key) => retained.context[key] === context[key]);
}

function validateRemoval(value: unknown): GitPushRemoval {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || !keys(value, 'configurationDigest,context,expectedRevision,hookDigest,hookRemoved,repository,schema')) fail('The retained hook-removal receipt is invalid.');
  const item = value as GitPushRemoval;
  if (item.schema !== 'lomo-git-push-removal/v1' || typeof item.hookRemoved !== 'boolean' || (item.configurationDigest === null) !== (item.hookDigest === null)
    || item.configurationDigest !== null && (typeof item.configurationDigest !== 'string' || !SHA.test(item.configurationDigest))
    || item.hookDigest !== null && (typeof item.hookDigest !== 'string' || !SHA.test(item.hookDigest))) fail('The retained hook-removal identity is invalid.');
  validateConfiguration({ schema: 'lomo-git-push-host/v1', repository: item.repository, context: item.context,
    enabled: false, revision: item.expectedRevision, hookDigest: item.hookDigest ?? '0'.repeat(64), helperDigest: '0'.repeat(64) });
  return Object.freeze(item);
}

async function readRemoval(repository: GitPushRepository, context: GitPushHostContext): Promise<GitPushRemoval | undefined> {
  const target = removalPath(repository, context);
  let raw: Buffer;
  try { raw = await bytes(target, CONFIG_LIMIT, true); } catch (error) { if (missing(error)) return undefined; throw error; }
  await privatePath(path.dirname(target), 'directory'); await privatePath(context.globalStoragePath, 'parent');
  let value: unknown;
  try { value = JSON.parse(raw.toString('utf8')); }
  catch (error) { if (!(error instanceof SyntaxError)) throw error; return fail('The retained hook-removal receipt is not valid JSON.'); }
  const receipt = validateRemoval(value);
  if (target !== removalPath(receipt.repository, receipt.context) || raw.toString('utf8') !== JSON.stringify(receipt) + '\n'
    || !sameRemovalOwner(receipt, repository, context)) fail('Hook removal belongs to a different private profile, generation or repository.');
  return receipt;
}

async function removeUnchangedPrivateFile(target: string, expected: string): Promise<void> {
  const captured = await bytes(target, CONFIG_LIMIT, true);
  if (hash(captured) !== expected) fail('Private hook state changed during removal. It was left unchanged.');
  const parked = `${target}.${randomUUID()}.removing`;
  await rename(target, parked);
  const restore = async () => {
    try { await link(parked, target); }
    catch (error) {
      if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
      fail('Changed hook state was preserved in its private removal recovery file. Review it before further cleanup.');
    }
    await unlink(parked);
  };
  let unchanged: boolean;
  try { unchanged = hash(await bytes(parked, CONFIG_LIMIT, true)) === expected; }
  catch (error) { await restore(); throw error; }
  if (!unchanged) { await restore(); fail('Private hook state changed during removal and was restored without replacement.'); }
  await unlink(parked);
}

async function syncRemovalDirectory(directory: string): Promise<void> {
  if (process.platform === 'win32') return;
  const parent = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY);
  try { await parent.sync(); } finally { await parent.close(); }
}

async function confirmHookRemoved(receipt: GitPushRemoval): Promise<GitPushRemoval> {
  const next = validateRemoval({ ...receipt, hookRemoved: true });
  const target = removalPath(receipt.repository, receipt.context);
  const temporary = `${target}.${randomUUID()}.tmp`;
  const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
  try { await privatePath(temporary, 'file', true); await handle.writeFile(JSON.stringify(next) + '\n'); await handle.sync(); }
  finally { await handle.close(); }
  if (JSON.stringify(await readRemoval(receipt.repository, receipt.context)) !== JSON.stringify(receipt)) {
    await unlink(temporary); fail('The removal receipt changed while confirming local cleanup. It was preserved.');
  }
  await rename(temporary, target); await syncRemovalDirectory(path.dirname(target));
  return next;
}

/** Explicit host-owner removal; API outage retains an exact, retryable receipt. */
export async function removeGitPushPolicy(repository: GitPushRepository, policy: GitPushPolicy | null,
  context: GitPushHostContext): Promise<GitPushRemovalResult> {
  await privatePath(context.globalStoragePath, 'parent');
  const directory = path.join(context.globalStoragePath, 'git-push-v1');
  try { await mkdir(directory, { mode: 0o700 }); await privatePath(directory, 'directory', true); }
  catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error; await privatePath(directory, 'directory'); }
  const lock = path.join(directory, `${repository.repositoryId}.lock`);
  try { await mkdir(lock, { mode: 0o700 }); }
  catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'EEXIST') fail('Another exact hook operation is active or needs recovery. No hook was removed.');
    throw error;
  }
  try {
    let receipt = await readRemoval(repository, context);
    const resuming = receipt !== undefined;
    let configuration: GitPushHostConfiguration | undefined;
    const target = location(repository, context);
    try { configuration = await readGitPushConfiguration(target); } catch (error) { if (!missing(error)) throw error; }
    if (configuration && !sameRemovalOwner(configuration, repository, context)) fail('The local hook belongs to another profile or generation. It was left unchanged.');
    if (!receipt) {
      if (policy) {
        validateGitPushPolicy(policy, { ...repository, projectId: null });
        const latest = validateGitPushPolicy(await gitPushClient({ repository, context }).request(
          `/v1/git/push-protection/${repository.repositoryId}`), { ...repository, projectId: policy.project_id });
        if (latest.revision !== policy.revision || latest.enabled !== policy.enabled
          || !latest.members.some((member) => member.client_slot === repository.clientSlot && member.generation === repository.generation && member.state === 'approved')) {
          fail('Repository policy or exact IDE approval changed after removal confirmation. No hook was removed.');
        }
      }
      if (configuration && policy && configuration.repository.projectId !== policy.project_id) fail('The server registration is different from this retained hook binding. Review the exact old registration before removal.');
      if (!configuration && !policy) fail('No retained local hook or registered policy identifies this removal.');
      if (configuration) {
        if (!await unchangedHook(configuration)) fail('The installed hook changed. It was left unchanged.');
      } else await previewGitHook(repository.root);
      receipt = validateRemoval({ schema: 'lomo-git-push-removal/v1',
        repository: configuration?.repository ?? { ...repository, projectId: policy!.project_id }, context: configuration?.context ?? context,
        expectedRevision: policy?.revision ?? configuration!.revision, hookDigest: configuration?.hookDigest ?? null,
        configurationDigest: configuration ? hash(JSON.stringify(configuration) + '\n') : null, hookRemoved: false });
      const handle = await open(removalPath(repository, context), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
      try { await privatePath(removalPath(repository, context), 'file', true); await handle.writeFile(JSON.stringify(receipt) + '\n'); await handle.sync(); }
      finally { await handle.close(); }
      await syncRemovalDirectory(directory);
    }
    if (configuration && hash(JSON.stringify(configuration) + '\n') !== receipt.configurationDigest) fail('The retained configuration changed after removal began. No hook was changed.');
    const git = await inspectGitRepository(repository.root);
    const hookPath = path.join(git.gitDirectory, 'hooks', 'pre-push');
    let hookPresent = true;
    try { await lstat(hookPath); } catch (error) { if (!missing(error)) throw error; hookPresent = false; }
    if (hookPresent) {
      if (resuming || receipt.hookRemoved) fail('A hook is present while resuming removal. It was left unchanged; owner review is required before any further host cleanup.');
      if (!configuration || !receipt.hookDigest) fail('A new or unrelated hook appeared during removal. It was left unchanged.');
      await removeGitHook(git, { repositoryId: receipt.repository.repositoryId, hookPath, hookDigest: receipt.hookDigest });
    }
    // Absence is checked through the existing default-hook/standalone boundary,
    // including retries. A newly installed hook never gets silently removed.
    await previewGitHook(repository.root);
    if (!receipt.hookRemoved) receipt = await confirmHookRemoved(receipt);
    const client = gitPushClient(receipt);
    let response: unknown;
    try {
      response = await client.request(`/v1/git/push-protection/${repository.repositoryId}/remove`, {
        method: 'POST', body: JSON.stringify({ expected_revision: receipt.expectedRevision, confirm_removal: true, hook_digest: receipt.hookDigest }),
      });
    } catch (error) {
      if (!(error instanceof CodeSecurityRequestError)) throw error;
      return Object.freeze({ localRemoved: true, registrationRemoved: false,
        cleanup: error.retryable || error.status !== undefined && error.status >= 500 ? 'retryable' : 'review_required',
        reasonCode: error.code && /^[a-z][a-z0-9_]{0,79}$/u.test(error.code) ? error.code : null });
    }
    const result = response as Record<string, unknown>;
    if (!result || typeof result !== 'object' || Array.isArray(result)
      || !keys(result, 'already_removed,removed,repository_id,revision,tree_bindings_deleted')
      || result.repository_id !== receipt.repository.repositoryId || result.revision !== receipt.expectedRevision
      || result.removed !== true || typeof result.already_removed !== 'boolean'
      || !Number.isSafeInteger(result.tree_bindings_deleted) || (result.tree_bindings_deleted as number) < 0) {
      return Object.freeze({ localRemoved: true, registrationRemoved: false, cleanup: 'review_required', reasonCode: 'push_removal_response_invalid' });
    }
    await previewGitHook(repository.root);
    try {
      await lstat(target);
      if (!receipt.configurationDigest) fail('New local hook configuration appeared during cleanup. It was preserved.');
      await removeUnchangedPrivateFile(target, receipt.configurationDigest);
    } catch (error) { if (!missing(error)) throw error; }
    await removeUnchangedPrivateFile(removalPath(repository, context), hash(JSON.stringify(receipt) + '\n'));
    await syncRemovalDirectory(directory);
    return Object.freeze({ localRemoved: true, registrationRemoved: true, cleanup: 'complete', reasonCode: null });
  } finally { await rmdir(lock); }
}

export async function verifyGitPushConfiguration(configuration: GitPushHostConfiguration): Promise<void> {
  if ((await observed(configuration)).state !== 'installed') fail('The hook or its installed helper changed. No push was approved.');
}

export async function verifyGitPushHelper(configuration: GitPushHostConfiguration): Promise<void> {
  if (hash(await bytes(helperPath(configuration.context), 4 * 1024 * 1024, false)) !== configuration.helperDigest) {
    fail('The installed push helper changed. Review its owner profile before pushing.');
  }
}
