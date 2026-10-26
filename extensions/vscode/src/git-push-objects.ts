import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, realpath } from 'node:fs/promises';
import * as path from 'node:path';
import { sameCanonicalLocalPath } from './canonical-local-path';

export type GitPushErrorCode =
  | 'push_input_invalid' | 'push_ref_limit' | 'push_apply_required' | 'push_check_required'
  | 'git_objects_unavailable' | 'git_metadata_invalid' | 'git_root_invalid' | 'git_root_incomplete'
  | 'git_directory_invalid' | 'git_format_unsupported' | 'git_history_incomplete' | 'git_history_indirect'
  | 'git_remote_unsupported' | 'git_remote_unavailable' | 'git_remote_limit' | 'git_remote_invalid' | 'git_remote_changed'
  | 'git_repository_changed' | 'git_tip_unsupported' | 'git_history_invalid' | 'git_history_limit'
  | 'git_tree_invalid' | 'git_tree_limit' | 'git_tree_unsupported' | 'git_blob_invalid' | 'git_blob_limit'
  | 'git_push_host_unverified' | 'git_hook_conflict' | 'git_hook_changed' | 'git_hook_config_unavailable'
  | 'git_hook_path_conflict' | 'git_shared_hook_conflict' | 'git_hook_already_installed' | 'git_hook_path_invalid'
  | 'git_hook_script_invalid' | 'git_hook_directory_invalid' | 'git_hook_install_unconfirmed' | 'git_hook_recovery_required';

export class GitPushBoundaryError extends Error {
  constructor(readonly code: GitPushErrorCode, message: string) {
    super(message);
    this.name = 'GitPushBoundaryError';
  }
}

export type GitObjectFormat = 'sha1' | 'sha256';
export type GitPushRef = Readonly<{
  local_ref: string;
  local_oid: string;
  remote_ref: string;
  remote_oid: string;
}>;
export type GitTreeFile = Readonly<{
  path: string;
  mode: '100644' | '100755';
  oid: string;
  sha256: string;
  size_bytes: number;
  content_base64: string;
}>;
export type GitCommitTree = Readonly<{
  commit_oid: string;
  tree_oid: string;
}>;
export type GitPushPlan = Readonly<{
  schema: 'lomo-git-push-plan/v1';
  repository_id: string;
  object_format: GitObjectFormat;
  destination_digest: string | null;
  advertised_bases: readonly string[];
  refs: readonly GitPushRef[];
  commits: readonly GitCommitTree[];
  trees: readonly string[];
  digest: string;
}>;

export const GIT_PUSH_LIMITS = Object.freeze({
  refs: 64,
  commits: 256,
  files: 5_000,
  fileBytes: 8 * 1024 * 1024,
  treeBytes: 64 * 1024 * 1024,
  inputBytes: 32 * 1024,
  metadataBytes: 4 * 1024 * 1024,
  pathDepth: 64,
});
const ZERO = /^0+$/u;
const OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;

function boundary(code: GitPushErrorCode, message: string): never {
  throw new GitPushBoundaryError(code, message);
}

function safeRef(value: string, deleted = false): boolean {
  return (deleted && value === '(delete)') || (
    value.startsWith('refs/') && value.length <= 1024 &&
    !/[\s\x00-\x1f\x7f~^:?*\[\\]/u.test(value) &&
    !value.includes('..') && !value.includes('@{') && !value.includes('//') &&
    !value.endsWith('/') && !value.endsWith('.') &&
    value.split('/').every(part => part.length > 0 && !part.startsWith('.') && !part.endsWith('.lock'))
  );
}

function safeLocalToken(value: string): boolean {
  return value.length > 0 && value.length <= 1024 && !/[\s\p{Cc}\p{Cf}]/u.test(value);
}

export function parseGitPushInput(input: string, format: GitObjectFormat): readonly GitPushRef[] {
  if (Buffer.byteLength(input) > GIT_PUSH_LIMITS.inputBytes || /[\x00-\x09\x0b-\x1f\x7f\p{Cf}]/u.test(input)) {
    return boundary('push_input_invalid', 'Git supplied an invalid or oversized outgoing reference list.');
  }
  const lines = input.endsWith('\n') ? input.slice(0, -1).split('\n') : input.split('\n');
  if (input === '') return [];
  if (lines.length > GIT_PUSH_LIMITS.refs) return boundary('push_ref_limit', 'This push exceeds the supported reference limit.');
  const seen = new Set<string>();
  const length = format === 'sha1' ? 40 : 64;
  const refs = lines.map(line => {
    const fields = line.split(' ');
    if (fields.length !== 4) return boundary('push_input_invalid', 'Git supplied an invalid outgoing reference.');
    const [local_ref, local_oid, remote_ref, remote_oid] = fields;
    if (!safeLocalToken(local_ref) || !safeRef(remote_ref) ||
        !OID.test(local_oid) || !OID.test(remote_oid) || local_oid.length !== length || remote_oid.length !== length ||
        seen.has(remote_ref) || (ZERO.test(local_oid) && ZERO.test(remote_oid))) {
      return boundary('push_input_invalid', 'Git supplied an ambiguous or unsupported outgoing reference.');
    }
    seen.add(remote_ref);
    return Object.freeze({ local_ref, local_oid, remote_ref, remote_oid });
  });
  return Object.freeze(refs.sort((a, b) => a.remote_ref.localeCompare(b.remote_ref, 'en')));
}

function gitEnvironment(): NodeJS.ProcessEnv {
  // Read-only object commands must not lazy-fetch source, use replace objects,
  // execute a pager, or inherit an alternate object/index/worktree selection.
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith('GIT_')) delete env[key];
  }
  return {
    ...env,
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_NO_LAZY_FETCH: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    LC_ALL: 'C',
  };
}

export type GitRemoteAdvertisement = Readonly<{
  destinationDigest: string;
  commitBases: readonly string[];
  refs: Readonly<Record<string, string>>;
}>;

async function gitBytes(root: string, args: readonly string[], maximum: number, input?: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = execFile('git', ['--no-pager', '--no-replace-objects', '-C', root, ...args], {
      encoding: 'buffer', maxBuffer: maximum, windowsHide: true,
      timeout: 30_000, env: gitEnvironment(),
    }, (error, stdout) => {
      if (error) {
        reject(new GitPushBoundaryError('git_objects_unavailable', 'Git could not provide bounded local object evidence. Check Git availability and complete local history; no push was approved.'));
      } else resolve(stdout);
    });
    if (input !== undefined) {
      child.stdin?.on('error', () => reject(new GitPushBoundaryError('git_objects_unavailable', 'Git object input was interrupted; no push was approved.')));
      child.stdin?.end(input);
    }
  });
}

async function gitText(root: string, args: readonly string[], maximum = GIT_PUSH_LIMITS.metadataBytes): Promise<string> {
  const raw = await gitBytes(root, args, maximum);
  const value = raw.toString('utf8');
  if (!Buffer.from(value, 'utf8').equals(raw)) return boundary('git_metadata_invalid', 'Git returned metadata that is not valid UTF-8.');
  return value.trimEnd();
}

export type GitRepository = Readonly<{
  root: string;
  gitDirectory: string;
  commonDirectory: string;
  repositoryId: string;
  format: GitObjectFormat;
}>;

export async function inspectGitRepository(requestedRoot: string): Promise<GitRepository> {
  if (!path.isAbsolute(requestedRoot) || /[\p{Cc}\p{Cf}]/u.test(requestedRoot)) {
    return boundary('git_root_invalid', 'Choose one exact, trusted local Git repository root.');
  }
  const root = await realpath(requestedRoot);
  if (!sameCanonicalLocalPath(root, path.resolve(requestedRoot)) || !(await lstat(root)).isDirectory()) {
    return boundary('git_root_invalid', 'Push protection does not follow a linked repository root.');
  }
  const observed = path.resolve(await gitText(root, ['rev-parse', '--show-toplevel']));
  if (!sameCanonicalLocalPath(root, observed)) return boundary('git_root_incomplete', 'Protect the exact repository root, not a selected subfolder.');
  const requestedGitDirectory = path.resolve(await gitText(root, ['rev-parse', '--absolute-git-dir']));
  const gitDirectory = await realpath(requestedGitDirectory);
  if (!path.isAbsolute(requestedGitDirectory) || !sameCanonicalLocalPath(gitDirectory, requestedGitDirectory)) {
    return boundary('git_directory_invalid', 'The Git directory must have one canonical local identity.');
  }
  const commonPath = await gitText(root, ['rev-parse', '--git-common-dir']);
  const requestedCommonDirectory = path.resolve(root, commonPath);
  const commonDirectory = await realpath(requestedCommonDirectory);
  if (!sameCanonicalLocalPath(commonDirectory, requestedCommonDirectory)) {
    return boundary('git_directory_invalid', 'The common Git object store must have one canonical local identity.');
  }
  const format = await gitText(root, ['rev-parse', '--show-object-format']);
  if (format !== 'sha1' && format !== 'sha256') return boundary('git_format_unsupported', 'This Git object format is not supported.');
  if (await gitText(root, ['rev-parse', '--is-shallow-repository']) !== 'false') {
    return boundary('git_history_incomplete', 'A shallow clone cannot prove outgoing history. Fetch complete history before enabling push protection.');
  }
  const config = (await gitBytes(root, ['config', '--local', '--list', '--null'], GIT_PUSH_LIMITS.metadataBytes)).toString('utf8');
  if (config.split('\0').some(entry => {
    const split = entry.indexOf('\n');
    const key = entry.slice(0, split < 0 ? undefined : split).toLowerCase();
    const value = split < 0 ? '' : entry.slice(split + 1).toLowerCase();
    return key === 'extensions.partialclone' || (/^remote\..+\.promisor$/u.test(key) && !['false', 'no', 'off', '0'].includes(value));
  })) return boundary('git_history_incomplete', 'Partial clones cannot prove complete local history. Use a complete clone; push checks never fetch source objects implicitly.');
  // Grafts can hide historical commits even with replace objects disabled.
  for (const relative of ['info/grafts', 'objects/info/alternates']) {
    try {
      await lstat(path.join(commonDirectory, relative));
      return boundary('git_history_indirect', 'Grafts and alternate object stores are not supported for protected pushes.');
    } catch (error) {
      if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error;
    }
  }
  return Object.freeze({
    root, gitDirectory, commonDirectory, format,
    repositoryId: createHash('sha256').update(`lomo-git-repository/v1\0${root}\0${gitDirectory}`).digest('hex'),
  });
}

function validateGitPushDestination(destination: string): void {
  const local = path.isAbsolute(destination);
  const sshLike = /^[A-Za-z0-9._-]+@(?:[A-Za-z0-9.-]+):[^\s]+$/u.test(destination);
  let network = false;
  try {
    const url = new URL(destination);
    network = ['https:', 'http:', 'ssh:'].includes(url.protocol) && !url.password && !url.search && !url.hash &&
      (url.protocol === 'ssh:' || !url.username);
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
  }
  if ((!local && !sshLike && !network) || destination.length > 4096 || /[\p{Cc}\p{Cf}]/u.test(destination)) {
    return boundary('git_remote_unsupported', 'Protected pushes support ordinary local, HTTP(S), and SSH remotes, not custom remote-helper commands.');
  }
}

/** Ref metadata only. Git's hook does not expose the other advertised heads. */
export async function readGitRemoteAdvertisement(repository: GitRepository, destination: string): Promise<GitRemoteAdvertisement> {
  validateGitPushDestination(destination);
  const raw = await new Promise<Buffer>((resolve, reject) => {
    execFile('git', ['-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
      '-c', 'protocol.http.allow=always', '-c', 'protocol.ssh.allow=always',
      '-c', 'protocol.file.allow=always', '-c', 'protocol.ext.allow=never',
      '-C', repository.root, 'ls-remote', '--refs', '--', destination], {
      encoding: 'buffer', maxBuffer: GIT_PUSH_LIMITS.metadataBytes, windowsHide: true, timeout: 30_000,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ALLOW_PROTOCOL: 'https:http:ssh:file' },
    }, (error, output) => {
      if (error) reject(new GitPushBoundaryError('git_remote_unavailable', 'Remote reference metadata could not be verified. No source was approved for this push.'));
      else resolve(output);
    });
  });
  if (!Buffer.from(raw.toString('utf8')).equals(raw)) return boundary('git_remote_invalid', 'Remote reference names must be valid UTF-8.');
  const lines = raw.length ? raw.toString('utf8').trimEnd().split('\n') : [];
  if (lines.length > 1024) return boundary('git_remote_limit', 'The remote reference inventory exceeds the bounded protection limit.');
  const ids = new Set<string>();
  const remoteRefs: Record<string, string> = {};
  for (const line of lines) {
    const pair = line.split('\t');
    if (pair.length !== 2 || !OID.test(pair[0]) || !safeRef(pair[1]) || remoteRefs[pair[1]] !== undefined) {
      return boundary('git_remote_invalid', 'The remote returned an invalid reference inventory.');
    }
    remoteRefs[pair[1]] = pair[0];
    if (pair[1].startsWith('refs/heads/')) ids.add(pair[0]);
  }
  const ordered = [...ids].sort();
  const bases: string[] = [];
  if (ordered.length) {
    const check = (await gitBytes(repository.root, ['cat-file', '--batch-check=%(objectname) %(objecttype)'], GIT_PUSH_LIMITS.metadataBytes, ordered.join('\n') + '\n')).toString('ascii').trimEnd().split('\n');
    if (check.length !== ordered.length) return boundary('git_remote_invalid', 'The local remote-base inventory is incomplete.');
    check.forEach((line, index) => {
      if (line === ordered[index] + ' commit') bases.push(ordered[index]);
      else if (line !== ordered[index] + ' missing') boundary('git_remote_invalid', 'A remote branch does not name a locally verifiable commit.');
    });
  }
  return Object.freeze({ destinationDigest: createHash('sha256').update(destination).digest('hex'), commitBases: Object.freeze(bases), refs: Object.freeze(remoteRefs) });
}

export async function planGitPush(repository: GitRepository, input: string, advertisement?: GitRemoteAdvertisement): Promise<GitPushPlan> {
  const current = await inspectGitRepository(repository.root);
  if (current.repositoryId !== repository.repositoryId || current.format !== repository.format) {
    return boundary('git_repository_changed', 'The repository identity changed before push verification.');
  }
  const refs = parseGitPushInput(input, repository.format);
  const outgoing = new Set<string>();
  for (const ref of refs) {
    if (advertisement && (advertisement.refs[ref.remote_ref] ?? '0'.repeat(ref.remote_oid.length)) !== ref.remote_oid) {
      return boundary('git_remote_changed', 'The target remote reference changed during verification. Retry the push against its current reference state.');
    }
    if (ZERO.test(ref.local_oid)) continue;
    // Commit-pointing annotated/lightweight tags are supported. Blob/tree tags
    // are refused rather than silently treating unscanned objects as a pass.
    const tip = await gitText(repository.root, ['rev-parse', '--verify', `${ref.local_oid}^{commit}`]);
    if (!OID.test(tip)) return boundary('git_tip_unsupported', 'Only commit-pointing references can be checked.');
    // Even a rewind or commit already on a different remote branch must check
    // the exact new tip. Metadata advertisement is not a transport attestation.
    outgoing.add(tip);
    const bases: string[] = [];
    if (!ZERO.test(ref.remote_oid)) {
      // A missing remote old object fails closed; no network fetch is implicit.
      const old = await gitText(repository.root, ['rev-parse', '--verify', `${ref.remote_oid}^{commit}`]);
      if (!OID.test(old)) return boundary('git_history_incomplete', 'The remote base commit is not available locally.');
      bases.push(old);
    }
    const args = ['rev-list', '--max-count=' + (GIT_PUSH_LIMITS.commits + 1), tip];
    if (bases.length) args.push('--not', ...new Set(bases));
    const commits = await gitText(repository.root, args);
    for (const oid of commits ? commits.split('\n') : []) {
      if (!OID.test(oid)) return boundary('git_history_invalid', 'Git returned an invalid outgoing commit identity.');
      outgoing.add(oid);
      if (outgoing.size > GIT_PUSH_LIMITS.commits) return boundary('git_history_limit', 'New outgoing history exceeds the bounded check limit. Review initial repository import separately; no push was approved.');
    }
  }
  const commits: GitCommitTree[] = [];
  if (outgoing.size) {
    const ordered = [...outgoing].sort();
    const raw = await gitBytes(repository.root, ['show', '--no-patch', '--no-show-signature', '--no-notes', '--format=%H %T', '--stdin'],
      GIT_PUSH_LIMITS.metadataBytes, ordered.join('\n') + '\n');
    const rows = raw.toString('ascii').trimEnd().split('\n');
    const seen = new Set<string>();
    for (const row of rows) {
      const [commit_oid, tree_oid, extra] = row.split(' ');
      if (extra !== undefined || !outgoing.has(commit_oid) || seen.has(commit_oid) || !OID.test(tree_oid)) {
        return boundary('git_tree_invalid', 'Git returned invalid commit-to-tree metadata.');
      }
      seen.add(commit_oid);
      commits.push(Object.freeze({ commit_oid, tree_oid }));
    }
    if (seen.size !== outgoing.size) return boundary('git_tree_invalid', 'Git returned incomplete commit-to-tree metadata.');
    commits.sort((a, b) => a.commit_oid.localeCompare(b.commit_oid));
  }
  const value = {
    schema: 'lomo-git-push-plan/v1' as const,
    repository_id: repository.repositoryId,
    object_format: repository.format,
    destination_digest: advertisement?.destinationDigest ?? null,
    advertised_bases: advertisement?.commitBases ?? [],
    refs,
    commits: Object.freeze(commits),
    trees: Object.freeze([...new Set(commits.map(item => item.tree_oid))].sort()),
  };
  return Object.freeze({ ...value, digest: createHash('sha256').update(JSON.stringify(value)).digest('hex') });
}

function safeTreePath(value: string): boolean {
  return value.length > 0 && value.length <= 4096 && !/[\p{Cc}\p{Cf}\\]/u.test(value) &&
    !value.startsWith('/') && value.split('/').length <= GIT_PUSH_LIMITS.pathDepth && value.split('/').every(part =>
      part.length > 0 && part !== '.' && part !== '..' && part.toLowerCase() !== '.git');
}

/** Read raw immutable blobs; never checkout, archive export filters, or execute source. */
export async function exportGitTree(repository: GitRepository, treeOid: string): Promise<readonly GitTreeFile[]> {
  if (!OID.test(treeOid)) return boundary('git_tree_invalid', 'A verified immutable Git tree is required.');
  const raw = await gitBytes(repository.root, ['ls-tree', '-r', '-z', '--full-tree', treeOid], GIT_PUSH_LIMITS.metadataBytes);
  const text = raw.toString('utf8');
  if (!Buffer.from(text).equals(raw) || (raw.length > 0 && raw[raw.length - 1] !== 0)) {
    return boundary('git_tree_invalid', 'The Git tree contains unsupported path bytes.');
  }
  const entries = text ? text.slice(0, -1).split('\0') : [];
  if (entries.length > GIT_PUSH_LIMITS.files) return boundary('git_tree_limit', 'The Git tree exceeds the supported file limit.');
  const metadata = entries.map(entry => {
    const match = /^(100644|100755) blob ([0-9a-f]+)\t(.+)$/u.exec(entry);
    if (!match || !OID.test(match[2]) || !safeTreePath(match[3])) {
      return boundary('git_tree_unsupported', 'Protected pushes require regular tracked files; links, submodules and unsafe paths need explicit review.');
    }
    return { mode: match[1] as '100644' | '100755', oid: match[2], path: match[3] };
  });
  if (!metadata.length) return [];
  // Query size before fetching bytes; a single huge blob cannot defeat bounds.
  const ids = metadata.map(item => item.oid).join('\n') + '\n';
  const sizes = (await gitBytes(repository.root, ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'], GIT_PUSH_LIMITS.metadataBytes, ids)).toString('ascii').trimEnd().split('\n');
  if (sizes.length !== metadata.length) return boundary('git_blob_invalid', 'Git object size inventory is incomplete.');
  let total = 0;
  const lengths = sizes.map((row, index) => {
    const fields = row.split(' ');
    const size = Number(fields[2]);
    if (fields.length !== 3 || fields[0] !== metadata[index].oid || fields[1] !== 'blob' || !/^(0|[1-9][0-9]*)$/u.test(fields[2]) || !Number.isSafeInteger(size) || size > GIT_PUSH_LIMITS.fileBytes) {
      return boundary('git_blob_limit', 'A tracked file exceeds the supported immutable-snapshot limit.');
    }
    total += size;
    if (total > GIT_PUSH_LIMITS.treeBytes) return boundary('git_tree_limit', 'The immutable tree exceeds the supported snapshot byte limit.');
    return size;
  });
  const content = await gitBytes(repository.root, ['cat-file', '--batch'], total + metadata.length * 100, ids);
  let offset = 0;
  const files = metadata.map((item, index) => {
    const end = content.indexOf(10, offset);
    const expected = `${item.oid} blob ${lengths[index]}`;
    if (end < 0 || content.subarray(offset, end).toString('ascii') !== expected) return boundary('git_blob_invalid', 'Git object bytes do not match their inventory.');
    offset = end + 1;
    const bytes = content.subarray(offset, offset + lengths[index]);
    offset += lengths[index];
    if (bytes.length !== lengths[index] || content[offset++] !== 10) return boundary('git_blob_invalid', 'Git object content is incomplete.');
    return Object.freeze({ ...item, sha256: createHash('sha256').update(bytes).digest('hex'), size_bytes: bytes.length, content_base64: bytes.toString('base64') });
  });
  if (offset !== content.length) return boundary('git_blob_invalid', 'Git returned trailing object content.');
  return Object.freeze(files.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))));
}

/** Exact read-only choices for the owner's outgoing-check preview. */
export async function readGitLocalRefs(repository: GitRepository): Promise<readonly Readonly<{ ref: string; oid: string }>[]> {
  const output = await gitText(repository.root, ['for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads', 'refs/tags']);
  const rows = output ? output.split('\n') : [];
  if (rows.length > 1024) return boundary('push_ref_limit', 'The local reference inventory exceeds the supported selection limit.');
  const seen = new Set<string>();
  return Object.freeze(rows.map((row) => {
    const [ref, oid, extra] = row.split(' ');
    if (extra !== undefined || !safeRef(ref) || !OID.test(oid) || oid.length !== (repository.format === 'sha1' ? 40 : 64) || seen.has(ref)) {
      return boundary('git_metadata_invalid', 'Git returned an invalid or ambiguous local reference inventory.');
    }
    seen.add(ref); return Object.freeze({ ref, oid });
  }));
}

export async function readGitPushDestinations(repository: GitRepository): Promise<readonly Readonly<{ name: string; destination: string }>[]> {
  const output = await gitText(repository.root, ['remote', '-v']);
  const rows = output ? output.split('\n') : [];
  if (rows.length > 256) return boundary('git_remote_limit', 'The configured remote inventory exceeds the supported selection limit.');
  const seen = new Set<string>();
  const choices: { name: string; destination: string }[] = [];
  for (const row of rows) {
    const match = /^([^\s\p{Cc}\p{Cf}]+)\t(.+) \((fetch|push)\)$/u.exec(row);
    if (!match || match[1].length > 120) return boundary('git_remote_invalid', 'Git returned an invalid configured remote inventory.');
    if (match[3] !== 'push') continue;
    const destination = match[2];
    // Use the same destination admission before showing any URL in a picker.
    validateGitPushDestination(destination);
    const identity = `${match[1]}\0${destination}`;
    if (seen.has(identity)) return boundary('git_remote_invalid', 'Git returned a duplicate configured push destination.');
    seen.add(identity); choices.push(Object.freeze({ name: match[1], destination }));
  }
  return Object.freeze(choices);
}
