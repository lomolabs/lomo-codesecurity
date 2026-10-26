import { lstatSync, realpathSync } from 'node:fs';
import { opendir } from 'node:fs/promises';
import * as path from 'node:path';
import { CodeSecurityRequestError } from './client';
import { sameCanonicalLocalPath } from './canonical-local-path';

export const REPOSITORY_CONTEXT_STATE_KEY = 'lomoCodeSecurity.repositoryContexts.v1';
export const MAX_REPOSITORY_CONTEXTS = 32;
export type RepositoryContextRecord = Readonly<{
  parent_uri: string;
  relative_path: string;
  root_identity: string;
  git_identity: string;
  project_id: number | null;
}>;

function fail(): never {
  throw new CodeSecurityRequestError('The selected repository context changed or is invalid. Choose its exact canonical root again; no source authority was granted.', 409);
}

export function canonicalRepositoryRelativePath(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 4096 && value.length > 0
    && !value.includes('\\') && !/[\p{Cc}\p{Cf}\p{Cs}]/u.test(value)
    && value.split('/').every(part => part.length > 0 && part !== '.' && part !== '..');
}

/** Workspace state is a selection hint, never source or IDE authorization. */
export function readRepositoryContexts(value: unknown): readonly RepositoryContextRecord[] {
  if (value === undefined) return Object.freeze([]);
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  const envelope = value as Record<string, unknown>;
  if (!['managed_parents,roots,schema_version', 'roots,schema_version'].includes(Object.keys(envelope).sort().join(',')) || envelope.schema_version !== 1
    || !Array.isArray(envelope.roots) || envelope.roots.length > MAX_REPOSITORY_CONTEXTS) fail();
  if (envelope.managed_parents !== undefined && (!Array.isArray(envelope.managed_parents)
    || envelope.managed_parents.length > MAX_REPOSITORY_CONTEXTS
    || !envelope.managed_parents.every(parent => typeof parent === 'string' && parent.length <= 4096 && !/[\p{Cc}\p{Cf}\p{Cs}]/u.test(parent))
    || new Set(envelope.managed_parents).size !== envelope.managed_parents.length)) fail();
  const records = envelope.roots.map(value => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
    const item = value as Record<string, unknown>;
    if (Object.keys(item).sort().join(',') !== 'git_identity,parent_uri,project_id,relative_path,root_identity'
      || typeof item.parent_uri !== 'string' || item.parent_uri.length > 4096 || /[\p{Cc}\p{Cf}]/u.test(item.parent_uri)
      || !canonicalRepositoryRelativePath(item.relative_path)
      || ![item.root_identity, item.git_identity].every(identity => typeof identity === 'string' && /^[0-9]{1,30}:[0-9]{1,30}$/u.test(identity))
      || item.project_id !== null && (!Number.isSafeInteger(item.project_id) || (item.project_id as number) < 1)) fail();
    return Object.freeze({ ...item }) as RepositoryContextRecord;
  });
  if (new Set(records.map(record => `${record.parent_uri}\0${record.relative_path}`)).size !== records.length) fail();
  if (envelope.managed_parents !== undefined && records.some(record => !(envelope.managed_parents as string[]).includes(record.parent_uri))) fail();
  return Object.freeze(records);
}

/** Retain an opted-in parent even with zero selected children; never fall back to scanning it. */
export function managedRepositoryParents(value: unknown): readonly string[] {
  const roots = readRepositoryContexts(value);
  const explicit = value && typeof value === 'object' ? (value as Record<string, unknown>).managed_parents : undefined;
  return Object.freeze(explicit === undefined ? [...new Set(roots.map(record => record.parent_uri))] : [...explicit as string[]]);
}

function identity(target: string, directory: boolean): string {
  const stat = lstatSync(target, { bigint: true });
  if (stat.isSymbolicLink() || directory && !stat.isDirectory()
    || !directory && !stat.isDirectory() && !stat.isFile()
    || stat.isFile() && stat.nlink !== 1n) fail();
  return `${stat.dev}:${stat.ino}`;
}

function repositoryIdentity(parentPath: string, relativePath: string): Readonly<{ root: string; rootIdentity: string; gitIdentity: string }> {
  if (!canonicalRepositoryRelativePath(relativePath) || !path.isAbsolute(parentPath)) fail();
  const parent = path.resolve(parentPath);
  const root = path.join(parent, ...relativePath.split('/'));
  try {
    if (!sameCanonicalLocalPath(realpathSync(parent), parent) || !sameCanonicalLocalPath(realpathSync(root), root)) fail();
    const rootIdentity = identity(root, true);
    const gitPath = path.join(root, '.git');
    if (!sameCanonicalLocalPath(realpathSync(gitPath), gitPath)) fail();
    return Object.freeze({ root, rootIdentity, gitIdentity: identity(gitPath, false) });
  } catch { return fail(); }
}

export function newRepositoryContext(parentUri: string, parentPath: string, relativePath: string): RepositoryContextRecord {
  const observed = repositoryIdentity(parentPath, relativePath);
  return Object.freeze({ parent_uri: parentUri, relative_path: relativePath,
    root_identity: observed.rootIdentity, git_identity: observed.gitIdentity, project_id: null });
}

/** Recheck before every source use; a replaced clone cannot inherit a binding. */
export function verifyRepositoryContext(record: RepositoryContextRecord, parentPath: string): string {
  const observed = repositoryIdentity(parentPath, record.relative_path);
  if (observed.rootIdentity !== record.root_identity || observed.gitIdentity !== record.git_identity) fail();
  return observed.root;
}

export function bindRepositoryProject(record: RepositoryContextRecord, projectId: number): RepositoryContextRecord {
  // The caller supplies a fresh, exact-root API receipt. This changes a local
  // association only; retained Git protection policies keep their own fences.
  if (!Number.isSafeInteger(projectId) || projectId < 1) fail();
  return Object.freeze({ ...record, project_id: projectId });
}

/** Only immediate entry names and .git metadata, never recursive source reads. */
export async function discoverImmediateRepositories(parentUri: string, parentPath: string): Promise<Readonly<{
  roots: readonly RepositoryContextRecord[]; truncated: boolean; examined: number;
}>> {
  if (!path.isAbsolute(parentPath) || !sameCanonicalLocalPath(realpathSync(parentPath), path.resolve(parentPath))) fail();
  const directory = await opendir(parentPath);
  const roots: RepositoryContextRecord[] = [];
  let examined = 0;
  let truncated = false;
  try {
    for (;;) {
      const entry = await directory.read();
      if (!entry) break;
      if (examined === MAX_REPOSITORY_CONTEXTS) { truncated = true; break; }
      examined += 1;
      if (!entry.isDirectory() || entry.isSymbolicLink() || !canonicalRepositoryRelativePath(entry.name)) continue;
      try { roots.push(newRepositoryContext(parentUri, parentPath, entry.name)); }
      catch { /* Missing, linked, or changed repository metadata is not selected. */ }
    }
  } finally { await directory.close(); }
  return Object.freeze({ roots: Object.freeze(roots.sort((a, b) => a.relative_path.localeCompare(b.relative_path))), truncated, examined });
}
