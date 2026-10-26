/** Read-only filesystem witnesses shared by public unit tests and private UI
 * journeys. Windows DACL collection belongs to the caller; without an explicit
 * native reader, Windows observation fails before filesystem access. */
import { isAbsolute, join, resolve, win32 } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';

const SHA = /^[a-f0-9]{64}$/u;
const positive = (value) => Number.isSafeInteger(value) && value > 0;
const require = (condition, message) => { if (!condition) throw new Error(message); };

// Preserve the existing foreground origin contract without its UI dependencies.
export function validateGitPushHostControlOrigin(value) {
  let origin;
  try { origin = new URL(value); } catch {
    throw new Error('Foreground Web actions require one credential-free loopback HTTP origin.');
  }
  if (
    origin.protocol !== 'http:'
    || !['127.0.0.1', '[::1]', 'localhost'].includes(origin.hostname)
    || origin.username
    || origin.password
    || origin.pathname !== '/'
    || origin.search
    || origin.hash
  ) throw new Error('Foreground Web actions require one credential-free loopback HTTP origin.');
  return origin.origin;
}

/** VS Code URI labels lowercase drive letters; realpath retains the native
 * spelling. Compare only that drive character, preserving every other byte.
 */
export function gitPickerDescriptionMatches(actual, expected, platform) {
  if (actual === expected) return true;
  return platform === 'win32' && [actual,expected].every(value => typeof value === 'string'
    && /^[A-Za-z]:\\/u.test(value) && win32.normalize(value) === value
    && !/[\p{Cc}\p{Cf}\p{Cs}]/u.test(value))
    && actual[0].toLowerCase() === expected[0].toLowerCase() && actual.slice(1) === expected.slice(1);
}

/** Host records retain VS Code's drive spelling; filesystem and ACL evidence
 * are checked separately against the canonical paths supplied by the runner. */
export function gitPushHostContextPathsMatch(context, expected, platform) {
  return Boolean(context) && gitPickerDescriptionMatches(context.globalStoragePath, expected.globalStoragePath, platform)
    && gitPickerDescriptionMatches(context.extensionPath, expected.extensionPath, platform);
}

async function scmFile(path, maximum, readAcl) {
  const lexical = await lstat(path);
  require(lexical.isFile() && !lexical.isSymbolicLink() && lexical.nlink === 1
    && lexical.size <= maximum && await realpath(path) === path, 'SCM host proof requires one bounded canonical regular file.');
  const acl = readAcl?.(path);
  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
  try {
    const before = await handle.stat();
    require(before.isFile() && before.nlink === 1 && before.dev === lexical.dev && before.ino === lexical.ino
      && before.size === lexical.size && before.size <= maximum, 'SCM host file changed before observation.');
    const bytes = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!read.bytesRead) break;
      offset += read.bytesRead;
    }
    const after = await handle.stat();
    const finalAcl = readAcl?.(path);
    const finalPath = await lstat(path);
    require(offset === before.size && after.size === before.size && after.mtimeMs === before.mtimeMs
      && after.ctimeMs === before.ctimeMs && finalPath.isFile() && !finalPath.isSymbolicLink()
      && finalPath.dev === before.dev && finalPath.ino === before.ino
      && finalPath.size === before.size && finalPath.mtimeMs === before.mtimeMs
      && finalPath.ctimeMs === before.ctimeMs && await realpath(path) === path,
    'SCM host file or pathname changed during observation.');
    require(!readAcl || isDeepStrictEqual(acl, finalAcl), 'SCM Windows DACL changed during observation.');
    return { bytes: bytes.subarray(0, offset), mode: before.mode & 0o777, uid: before.uid,
      ...(readAcl ? { acl_sha256: createHash('sha256').update(JSON.stringify(acl)).digest('hex') } : {}) };
  } finally { await handle.close(); }
}

/** Read only exact admitted config/hook/helper paths; never credential files. */
export async function inspectGitPushScmFiles({ globalStoragePath, globalStorageIdentity, extensionPath, controlOrigin, expected_helper_sha256, repositories }, { createWindowsAclReader } = {}) {
  require(Array.isArray(repositories) && repositories.length >= 2,
    'SCM proof requires selected and neighboring clones.');
  return inspectGitPushHostFiles({ globalStoragePath, globalStorageIdentity, extensionPath, controlOrigin, expected_helper_sha256, repositories }, { createWindowsAclReader });
}

/** Exact host effect reader, also used by single-clone protection journeys. */
export async function inspectGitPushHostFiles({ globalStoragePath, globalStorageIdentity, extensionPath, controlOrigin, expected_helper_sha256, repositories }, { createWindowsAclReader } = {}) {
  const windows = process.platform === 'win32';
  require(windows || process.platform === 'darwin' || process.platform === 'linux',
    'SCM filesystem acceptance requires a supported owned platform.');
  const endpoint = validateGitPushHostControlOrigin(controlOrigin);
  require([globalStoragePath, extensionPath].every(path => isAbsolute(path) && resolve(path) === path)
    && typeof globalStorageIdentity === 'string' && globalStorageIdentity.length > 0
    && globalStorageIdentity.length <= 4096 && !/[\p{Cc}\p{Cf}]/u.test(globalStorageIdentity)
    && SHA.test(expected_helper_sha256) && Array.isArray(repositories) && repositories.length >= 1 && repositories.length <= 32,
  'SCM filesystem proof requires an owned profile and selected plus neighboring clones.');
  if (windows) require([globalStoragePath, extensionPath, ...repositories.flatMap(row => [row.root, row.git_directory])]
    .every(path => typeof path === 'string' && /^[A-Za-z]:\\/u.test(path) && win32.normalize(path) === path
      && !/[\p{Cc}\p{Cf}]/u.test(path)), 'SCM Windows proof requires exact native local-drive paths.');
  require(!windows || typeof createWindowsAclReader === 'function',
    'SCM Windows filesystem proof requires an injected native DACL reader.');
  const readAcl = windows ? createWindowsAclReader(globalStoragePath) : undefined;
  require(!windows || typeof readAcl === 'function',
    'SCM Windows filesystem proof requires an injected native DACL reader.');
  for (const [directory, privateMode] of [[globalStoragePath, false], [join(globalStoragePath, 'git-push-v1'), true]]) {
    const metadata = await lstat(directory);
    require(metadata.isDirectory() && !metadata.isSymbolicLink() && await realpath(directory) === directory
      && (windows || metadata.uid === process.getuid() && (privateMode ? (metadata.mode & 0o777) === 0o700 : !(metadata.mode & 0o022))),
    'SCM host storage is not the exact canonical owner-private namespace.');
  }
  const result = [];
  const helper = await scmFile(join(extensionPath, 'dist', 'git-push-cli.js'), 4 * 1024 * 1024);
  const helperDigest = createHash('sha256').update(helper.bytes).digest('hex');
  require(helperDigest === expected_helper_sha256, 'SCM shipped helper differs from the owner-sealed candidate.');
  for (const repository of repositories) {
    const { repository_id, root, git_directory } = repository;
    require(SHA.test(repository_id) && isAbsolute(root) && resolve(root) === root
      && git_directory === join(root, '.git') && await realpath(root) === root
      && await realpath(git_directory) === git_directory
      && createHash('sha256').update(`lomo-git-repository/v1\0${root}\0${git_directory}`).digest('hex') === repository_id,
    'SCM filesystem repository identity is not exact.');
    const config = await scmFile(join(globalStoragePath, 'git-push-v1', `${repository_id}.json`), 32 * 1024, readAcl);
    let record;
    try { record = JSON.parse(config.bytes.toString('utf8')); }
    catch { throw new Error('SCM host configuration is not valid JSON.'); }
    const hook = await scmFile(join(git_directory, 'hooks', 'pre-push'), 64 * 1024);
    const hookDigest = createHash('sha256').update(hook.bytes).digest('hex');
    require(record.schema === 'lomo-git-push-host/v1' && record.repository?.repositoryId === repository_id
      && record.repository.root === root && record.repository.gitDirectory === git_directory
      && gitPushHostContextPathsMatch(record.context, {globalStoragePath, extensionPath}, process.platform)
      && record.context.endpoint === endpoint
      && record.context.globalStorageIdentity === globalStorageIdentity
      && typeof record.enabled === 'boolean' && positive(record.revision) && positive(record.repository.projectId)
      && /^ks1_[A-Za-z0-9_-]{43}$/u.test(record.repository.clientSlot) && positive(record.repository.generation)
      && (windows ? SHA.test(config.acl_sha256) : config.uid === process.getuid() && config.mode === 0o600 && Boolean(hook.mode & 0o111))
      && record.hookDigest === hookDigest && record.helperDigest === helperDigest,
    'SCM filesystem hook/helper/config do not prove the exact current applied state.');
    result.push({ repository_id, root, git_directory, project_id: record.repository.projectId,
      client_slot: record.repository.clientSlot, generation: record.repository.generation,
      enabled: record.enabled, revision: record.revision, hook_digest: hookDigest, helper_digest: helperDigest,
      config_sha256: createHash('sha256').update(config.bytes).digest('hex'), hook_mode: windows ? null : hook.mode,
      ...(windows ? { config_acl_sha256: config.acl_sha256, permission_evidence: 'windows-dacl' } : {}) });
  }
  require(new Set(result.map(row => row.repository_id)).size === result.length, 'SCM filesystem contains duplicate clone identities.');
  return result.sort((a, b) => a.repository_id.localeCompare(b.repository_id));
}

