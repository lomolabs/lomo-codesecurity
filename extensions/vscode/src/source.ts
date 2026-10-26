import { win32 } from 'node:path';

import { CodeSecurityRequestError } from './client';
import {
  isNativeWindowsWorkspace,
  nativeWindowsWorkspaceSourceId,
  workspaceSourceAuthorizationMode,
  workspaceSourcePath,
} from './workspace';

export type SourceUri = Readonly<{
  scheme: string;
  authority: string;
  path: string;
  fsPath: string;
  toString(): string;
}>;

export type SourceWorkspaceFolder = Readonly<{
  name: string;
  index?: number;
  uri: SourceUri;
}>;

export type SourceTarget = Readonly<{
  kind: 'workspace' | 'directory' | 'file';
  key: string;
  label: string;
  uri: SourceUri;
  owner: SourceWorkspaceFolder;
  /** A selected child keeps the physical editor parent open without authorizing it. */
  workspaceOwner?: SourceWorkspaceFolder;
  contextGeneration?: number;
  folder: SourceWorkspaceFolder;
  repoPath: string;
  targetPath?: string;
  authorizationMode: 'mounted' | 'snapshot';
  sourceId?: string;
}>;

export const MAX_WORKSPACE_SCAN_ROOTS = 32;

export type MountedSourcePreview = Readonly<{
  installation_id: string;
  repo_path: string;
  authorization_mode: 'mounted';
  authorized: boolean;
  configured_roots: readonly string[];
  reason_code: null | 'source_outside_allowed_root';
}>;

function canonicalMountedPath(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 4096
    && value.startsWith('/') && !/[\\\p{Cc}\p{Cf}]/u.test(value)
    && (value === '/' || value.slice(1).split('/').every((part) => part && part !== '.' && part !== '..'));
}

/** Current configured-boundary information, not a source-read or admission proof. */
export function validateMountedSourcePreview(value: unknown, repoPath: string): MountedSourcePreview {
  const invalid = () => new CodeSecurityRequestError('CodeSecurity returned an invalid source-boundary preview. No scan was started.');
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
  const item = value as Record<string, unknown>;
  const keys = ['installation_id', 'repo_path', 'authorization_mode', 'authorized', 'configured_roots', 'reason_code'];
  if (Object.keys(item).length !== keys.length || keys.some((key) => !(key in item))
    || typeof item.installation_id !== 'string' || !/^[a-f0-9]{12}$/u.test(item.installation_id)
    || item.repo_path !== repoPath || !canonicalMountedPath(item.repo_path)
    || item.authorization_mode !== 'mounted' || typeof item.authorized !== 'boolean'
    || !Array.isArray(item.configured_roots) || item.configured_roots.length < 1
    || item.configured_roots.length > MAX_WORKSPACE_SCAN_ROOTS
    || !item.configured_roots.every(canonicalMountedPath)
    || new Set(item.configured_roots).size !== item.configured_roots.length
    || item.reason_code !== (item.authorized ? null : 'source_outside_allowed_root')) throw invalid();
  return Object.freeze({
    installation_id: item.installation_id,
    repo_path: item.repo_path,
    authorization_mode: 'mounted',
    authorized: item.authorized,
    configured_roots: Object.freeze([...item.configured_roots]),
    reason_code: item.reason_code,
  }) as MountedSourcePreview;
}

/** Freeze only explicit open roots; never merge overlapping roots or deduplicate silently. */
export function workspaceScanTargets(
  selected: readonly SourceWorkspaceFolder[],
  open: readonly SourceWorkspaceFolder[],
  platform = '',
): readonly SourceTarget[] {
  if (selected.length < 1 || selected.length > MAX_WORKSPACE_SCAN_ROOTS) {
    throw new CodeSecurityRequestError(`Choose between 1 and ${MAX_WORKSPACE_SCAN_ROOTS} workspace folders per scan batch.`);
  }
  const targets = selected.map((folder) => {
    if (!open.some((candidate) => candidate.uri.toString() === folder.uri.toString())) {
      throw new CodeSecurityRequestError('A selected workspace folder is no longer open. Review the folder selection again.');
    }
    const target = workspaceSourceTarget(folder, open, platform);
    if (target.kind !== 'workspace') throw new CodeSecurityRequestError('Select an exact open workspace root for this scan batch.');
    return target;
  });
  if (new Set(targets.map((target) => target.key)).size !== targets.length) {
    throw new CodeSecurityRequestError('A workspace folder appears more than once in this scan batch.');
  }
  return Object.freeze(targets);
}

const SUPPORTED_FILE_EXTENSIONS = new Set([
  '.py', '.js', '.jsx', '.ts', '.tsx', '.go', '.rs', '.java', '.rb', '.php',
  '.cs', '.sh', '.bash', '.zsh', '.yaml', '.yml', '.json', '.toml', '.tf',
  '.ini', '.cfg',
]);

export function supportedSourceFileName(value: string): boolean {
  const name = value.toLowerCase();
  if (name === '.env' || name === '.env.local' || name === '.env.production') return true;
  if (name.startsWith('dockerfile') || name.endsWith('.dockerfile')) return true;
  const separator = name.lastIndexOf('.');
  return separator >= 0 && SUPPORTED_FILE_EXTENSIONS.has(name.slice(separator));
}

function normalizedUriPath(uri: SourceUri): string {
  if (!uri.path.startsWith('/') || /[\p{Cc}\p{Cf}]/u.test(uri.path)) {
    throw new CodeSecurityRequestError('The selected folder does not expose a safe absolute source URI.');
  }
  return uri.path === '/' ? '/' : uri.path.replace(/\/+$/, '');
}

function containsUri(root: SourceUri, candidate: SourceUri): boolean {
  if (root.scheme !== candidate.scheme || root.authority !== candidate.authority) return false;
  if (isNativeWindowsWorkspace({ name: 'root', uri: root })) {
    const relative = win32.relative(root.fsPath, candidate.fsPath);
    return relative === '' || (
      !relative.startsWith('..\\')
      && relative !== '..'
      && !win32.isAbsolute(relative)
    );
  }
  const rootPath = normalizedUriPath(root);
  const candidatePath = normalizedUriPath(candidate);
  return rootPath === '/' || candidatePath === rootPath || candidatePath.startsWith(`${rootPath}/`);
}

function projectRelativeTargetPath(
  uri: SourceUri,
  owner: SourceWorkspaceFolder,
  snapshot: boolean,
): string {
  const targetPath = snapshot
    ? win32.relative(owner.uri.fsPath, uri.fsPath).split('\\').join('/')
    : (() => {
      const ownerPath = normalizedUriPath(owner.uri);
      const candidatePath = normalizedUriPath(uri);
      return candidatePath.slice(ownerPath === '/' ? 1 : ownerPath.length + 1);
    })();
  if (
    !targetPath
    || targetPath.startsWith('/')
    || targetPath.includes('\\')
    || /[\p{Cc}\p{Cf}]/u.test(targetPath)
    || targetPath.split('/').some((part) => !part || part === '.' || part === '..')
  ) {
    throw new CodeSecurityRequestError(
      'The selected source does not expose a canonical path below its open workspace.',
    );
  }
  return targetPath;
}

/** Resolve one supported file to its deepest unambiguous workspace owner. */
export function workspaceOwnerForFileUri(
  uri: SourceUri,
  workspaceFolders: readonly SourceWorkspaceFolder[],
): SourceWorkspaceFolder {
  const owners = workspaceFolders.filter((folder) => containsUri(folder.uri, uri));
  if (owners.length === 0) {
    throw new CodeSecurityRequestError(
      'The selected file is not inside an open workspace. Add its folder to the workspace before scanning.',
    );
  }
  const maximumSpecificity = Math.max(...owners.map((folder) => normalizedUriPath(folder.uri).length));
  const mostSpecific = owners.filter(
    (folder) => normalizedUriPath(folder.uri).length === maximumSpecificity,
  );
  if (mostSpecific.length !== 1) {
    throw new CodeSecurityRequestError(
      'The selected file belongs to more than one equally specific workspace root. Remove the duplicate root before scanning.',
    );
  }
  return mostSpecific[0];
}

export function sourceTargetForFileUri(
  uri: SourceUri,
  workspaceFolders: readonly SourceWorkspaceFolder[],
  platform = '',
): SourceTarget {
  const owner = workspaceOwnerForFileUri(uri, workspaceFolders);
  const snapshot = workspaceSourceAuthorizationMode(owner, platform) === 'snapshot';
  const targetPath = projectRelativeTargetPath(uri, owner, snapshot);
  const label = sourceLabel(uri, owner);
  if (!supportedSourceFileName(label)) {
    throw new CodeSecurityRequestError(
      'This file type is not supported for an exact CodeSecurity file scan. Choose a source, Dockerfile, Terraform, Kubernetes, or supported text configuration file.',
    );
  }
  return Object.freeze({
    kind: 'file',
    key: owner.uri.toString(),
    label,
    uri,
    owner,
    folder: owner,
    repoPath: workspaceSourcePath(owner, platform),
    targetPath,
    authorizationMode: snapshot ? 'snapshot' : 'mounted',
    ...(snapshot ? { sourceId: nativeWindowsWorkspaceSourceId(owner) } : {}),
  });
}

function sourceLabel(uri: SourceUri, owner: SourceWorkspaceFolder): string {
  if (uri.toString() === owner.uri.toString()) return owner.name;
  const segment = normalizedUriPath(uri).split('/').filter(Boolean).at(-1);
  if (!segment) return owner.name;
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

export function sourceTargetForUri(
  uri: SourceUri,
  workspaceFolders: readonly SourceWorkspaceFolder[],
  platform = '',
): SourceTarget {
  const owners = workspaceFolders.filter((folder) => containsUri(folder.uri, uri));
  if (owners.length === 0) {
    throw new CodeSecurityRequestError(
      'The selected folder is not inside an open workspace. Add it to the workspace before scanning.',
    );
  }
  const maximumSpecificity = Math.max(...owners.map((folder) => normalizedUriPath(folder.uri).length));
  const mostSpecific = owners.filter(
    (folder) => normalizedUriPath(folder.uri).length === maximumSpecificity,
  );
  if (mostSpecific.length !== 1) {
    throw new CodeSecurityRequestError(
      'The selected folder belongs to more than one equally specific workspace root. Remove the duplicate root before scanning.',
    );
  }
  const owner = mostSpecific[0];
  const label = sourceLabel(uri, owner);
  const isWorkspace = uri.toString() === owner.uri.toString();
  const authorizationMode = workspaceSourceAuthorizationMode(owner, platform);
  const targetPath = isWorkspace
    ? undefined
    : projectRelativeTargetPath(uri, owner, authorizationMode === 'snapshot');
  return Object.freeze({
    kind: isWorkspace ? 'workspace' : 'directory',
    key: owner.uri.toString(),
    label,
    uri,
    owner,
    folder: owner,
    repoPath: workspaceSourcePath(owner, platform),
    ...(targetPath === undefined ? {} : { targetPath }),
    authorizationMode,
    ...(authorizationMode === 'snapshot'
      ? { sourceId: nativeWindowsWorkspaceSourceId(owner) }
      : {}),
  });
}

export function workspaceSourceTarget(
  folder: SourceWorkspaceFolder,
  workspaceFolders: readonly SourceWorkspaceFolder[],
  platform = '',
): SourceTarget {
  return sourceTargetForUri(folder.uri, workspaceFolders, platform);
}

/** An explicitly selected descendant is an independent source root. */
export function repositorySourceTarget(
  folder: SourceWorkspaceFolder,
  workspaceOwner: SourceWorkspaceFolder,
  open: readonly SourceWorkspaceFolder[],
  platform = '',
): SourceTarget {
  if (!open.some(candidate => candidate.uri.toString() === workspaceOwner.uri.toString())
    || folder.uri.toString() === workspaceOwner.uri.toString() || !containsUri(workspaceOwner.uri, folder.uri)) {
    throw new CodeSecurityRequestError('Select an exact repository below a currently open workspace parent.');
  }
  return Object.freeze({ ...workspaceSourceTarget(folder, [folder], platform), workspaceOwner });
}

/** SCM repository menus pass one SourceControl; palette invocations pass none.
 * Resolve only a currently managed exact root, before any filesystem inspection.
 */
export function sourceControlRepositoryRoot<T extends SourceWorkspaceFolder>(
  arguments_: readonly unknown[], roots: readonly T[],
): T | undefined {
  if (arguments_.length === 0 || arguments_.length === 1 && arguments_[0] === undefined) return undefined;
  const invalid = () => new CodeSecurityRequestError('Choose one current Git repository in Source Control before using this action.', 409);
  if (arguments_.length !== 1 || !arguments_[0] || typeof arguments_[0] !== 'object' || Array.isArray(arguments_[0])) throw invalid();
  const control = arguments_[0] as { id?: unknown; rootUri?: unknown };
  if (control.id !== 'git' || !control.rootUri || typeof control.rootUri !== 'object' || Array.isArray(control.rootUri)) throw invalid();
  const uri = control.rootUri as SourceUri & { query?: unknown; fragment?: unknown };
  if (typeof uri.scheme !== 'string' || typeof uri.authority !== 'string' || typeof uri.path !== 'string'
    || typeof uri.fsPath !== 'string' || typeof uri.toString !== 'function'
    || uri.query !== undefined && uri.query !== '' || uri.fragment !== undefined && uri.fragment !== ''
    || [uri.authority, uri.path, uri.fsPath].some(value => value.length > 4096 || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value))) throw invalid();
  if (roots.length < 1 || roots.length > MAX_WORKSPACE_SCAN_ROOTS) throw invalid();
  const matches = roots.filter(root => root.uri.toString() === uri.toString()
    && root.uri.scheme === uri.scheme && root.uri.authority === uri.authority
    && root.uri.path === uri.path && root.uri.fsPath === uri.fsPath);
  if (matches.length !== 1) throw invalid();
  workspaceSourcePath(matches[0]); // Existing native/Remote-WSL/UNC classification, no filesystem read.
  return matches[0];
}
