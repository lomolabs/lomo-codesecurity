import { createHash } from 'node:crypto';
import { lstatSync, realpathSync } from 'node:fs';
import * as path from 'node:path';
import { CodeSecurityRequestError } from './client';
import { sameCanonicalLocalPath } from './canonical-local-path';
import { REPOSITORY_CONTEXT_STATE_KEY, readRepositoryContexts, managedRepositoryParents,
  verifyRepositoryContext } from './repository-context';

type State = Readonly<{
  get<T>(key: string): T | undefined;
  update(key: string, value: unknown): PromiseLike<void>;
}>;
type Scope = Readonly<{
  session: string | undefined;
  workspace_uri: string | null;
  untitled: boolean;
  folders: readonly Readonly<{ uri: string; path: string }>[];
}>;
type Entry = Readonly<{
  parent_uri: string;
  parent_identity: string;
  session_sha256: string | null;
  updated_at: number;
  metadata: unknown;
  revision?: string;
}>;
const digest = (value: string) => createHash('sha256').update(value).digest('hex');

function sessionDigest(value: string | undefined): string | null {
  // VS Code's null telemetry service has a fixed placeholder. It must never
  // establish window lineage. Telemetry level Off still has a normal session.
  return typeof value === 'string'
    && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?:[.:-]?\d{10,16})?$/iu.test(value)
    ? digest(value) : null;
}

function parentIdentity(path: string): string {
  const stat = lstatSync(path, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink() || !sameCanonicalLocalPath(realpathSync(path), path))
    throw new CodeSecurityRequestError('The open repository parent changed. Choose its exact canonical root again.', 409);
  return `${stat.dev}:${stat.ino}`;
}

function entry(value: unknown): Entry {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid repository recovery record.');
  const item = value as Record<string, unknown>;
  if (Object.keys(item).sort().join(',') !== 'metadata,parent_identity,parent_uri,revision,session_sha256,updated_at'
    || typeof item.revision !== 'string' || !/^[a-f0-9-]{36}$/u.test(item.revision)
    || typeof item.parent_uri !== 'string' || item.parent_uri.length > 4096
    || typeof item.parent_identity !== 'string' || !/^\d{1,30}:\d{1,30}$/u.test(item.parent_identity)
    || item.session_sha256 !== null && (typeof item.session_sha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(item.session_sha256))
    || !Number.isSafeInteger(item.updated_at) || (item.updated_at as number) < 0) throw new Error('Invalid repository recovery record.');
  readRepositoryContexts(item.metadata);
  if (!managedRepositoryParents(item.metadata).includes(item.parent_uri)) throw new Error('Invalid repository recovery parent.');
  return item as Entry;
}

export type RepositoryRecoveryFailurePhase = 'startup-seed' | 'seed-write' | 'startup-restore' | 'restore' | 'selection-update' | 'selection-backup';
export type RepositoryRecoveryFailure = Readonly<{
  schema: 'lomo-repository-recovery-failure/v1';
  phase: RepositoryRecoveryFailurePhase;
  category: string;
  errno: string;
  workspace_kind: 'folder' | 'saved' | 'untitled' | 'unavailable';
  folder_count: number;
}>;

/** Closed scalar diagnostics only: never serialize exception text, paths,
 * repository contents, renderer/session identifiers, or credential material. */
export function repositoryRecoveryFailure(error: unknown, phase: RepositoryRecoveryFailurePhase,
  scope?: Scope): RepositoryRecoveryFailure {
  let category = 'unknown', errno = 'none';
  try {
    const message = error instanceof Error ? error.message : '';
    const categories: Readonly<Record<string, string>> = {
      'Repository selection recovery changed. Choose repositories in the current workspace again.': 'scope-changed',
      'The open repository parent changed. Choose its exact canonical root again.': 'parent-identity',
      'Repository recovery parent changed.': 'parent-identity',
      'The selected repository context changed or is invalid. Choose its exact canonical root again; no source authority was granted.': 'repository-identity',
      'Invalid repository recovery record.': 'metadata-invalid',
      'Invalid repository recovery parent.': 'metadata-invalid',
      'A repository selection change needs explicit confirmation.': 'checkpoint-pending',
      'Repository selections changed in another window.': 'checkpoint-conflict',
      'Repository selections changed in another window. Refresh before choosing again.': 'checkpoint-conflict',
      'Repository recovery selection changed. Choose repositories again.': 'checkpoint-conflict',
      'Authoritative repository selections changed during recovery backup.': 'checkpoint-conflict',
      'Authoritative repository selections changed before persistence.': 'checkpoint-conflict',
      'Authoritative repository selections changed before backup publication.': 'checkpoint-conflict',
      'Repository recovery record is busy.': 'record-busy',
      'Repository recovery storage is full; existing workspace selections remain available.': 'capacity',
      'Repository recovery storage needs review.': 'capacity',
      'Repository recovery has too many active windows.': 'capacity',
      'Repository recovery record is too large.': 'capacity',
      'Repository recovery storage changed.': 'storage-shape',
      'Invalid repository recovery file.': 'storage-shape',
      'Repository recovery file changed while reading.': 'storage-shape',
    };
    category = Object.hasOwn(categories, message) ? categories[message] : 'unknown';
    const code = error && typeof error === 'object' ? (error as {code?: unknown}).code : undefined;
    if (typeof code === 'string' && ['EACCES','EPERM','ENOSPC','EIO','EBUSY','EMFILE','ENFILE','EROFS','ENOENT','EEXIST','EXDEV'].includes(code)) {
      errno = code; if (category === 'unknown') category = 'filesystem';
    }
  } catch { category = 'unknown'; errno = 'none'; }
  return Object.freeze({schema:'lomo-repository-recovery-failure/v1', phase, category, errno,
    workspace_kind: !scope ? 'unavailable' : scope.workspace_uri === null ? 'folder' : scope.untitled ? 'untitled' : 'saved',
    folder_count: scope ? Math.min(33, scope.folders.length) : 0});
}

/** WorkspaceState stays authoritative. Only the same window's ordinary
 * single-folder → untitled conversion can recover automatically. This bounded
 * profile store contains selection hints, never credentials or source grants. */
export function createRepositoryRecoveryState(options: Readonly<{
  workspace: State;
  recovery: Readonly<{
    candidates(parent: string, session: string | null): Promise<unknown[]>;
    write(parent: string, session: string | null, entry: unknown, beforePublish: () => void): Promise<void>;
    change(parent: string, session: string | null, entry: unknown, beforePublish: () => void,
      update: () => Promise<void>, backupFailure: (error?: unknown) => void, expectedMetadata: unknown): Promise<void>;
    restore(parent: string, session: string | null, entry: unknown, beforePublish: () => void,
      update: () => Promise<void>): Promise<void>;
  }>;
  scope: () => Scope | undefined; // undefined in Restricted Mode; no source stats
  active: () => boolean;
  offer: (count: number, restore: () => Promise<void>) => void;
  failure: (failure: RepositoryRecoveryFailure) => void;
}>): Readonly<{ state: State; readonly ready: Promise<void> }> {
  let value = options.workspace.get<unknown>(REPOSITORY_CONTEXT_STATE_KEY);
  let started = false;
  let queue: Promise<void> = Promise.resolve();
  const report = (error: unknown, phase: RepositoryRecoveryFailurePhase, scope?: Scope) => { try { options.failure(repositoryRecoveryFailure(error, phase, scope)); } catch { /* Reporting must not create an unhandled task. */ } };
  const current = (scope: Scope) => {
    const now = options.scope();
    if (!options.active() || !now || JSON.stringify(now) !== JSON.stringify(scope))
      throw new CodeSecurityRequestError('Repository selection recovery changed. Choose repositories in the current workspace again.', 409);
  };
  const verify = (entry: Entry, scope: Scope) => {
    current(scope);
    const parent = scope.folders.find(folder => folder.uri === entry.parent_uri);
    if (!parent || parentIdentity(parent.path) !== entry.parent_identity) throw new Error('Repository recovery parent changed.');
    for (const record of readRepositoryContexts(entry.metadata)) {
      const openParent = scope.folders.find(folder => folder.uri === record.parent_uri);
      if (openParent) verifyRepositoryContext(record, openParent.path);
    }
  };
  const schedule = (action: () => Promise<void>, phase: RepositoryRecoveryFailurePhase, scope?: Scope) => {
    const operation = queue.then(action);
    queue = operation.catch(error => { report(error, phase, scope); });
    return operation;
  };
  const backupEntry = (scope: Scope, metadata: unknown): Entry | undefined => {
    if (scope.workspace_uri !== null || scope.folders.length !== 1) return;
    const parent = scope.folders[0];
    readRepositoryContexts(metadata);
    if (!managedRepositoryParents(metadata).includes(parent.uri)) return;
    const entry: Entry = { parent_uri: parent.uri, parent_identity: parentIdentity(parent.path),
      session_sha256: sessionDigest(scope.session), updated_at: Date.now(), metadata };
    verify(entry, scope); return entry;
  };
  const seed = async (scope: Scope, metadata: unknown) => {
    const entry = backupEntry(scope, metadata);
    if (!entry) return;
    try {
      await options.recovery.write(entry.parent_uri, entry.session_sha256, entry, () => {
        verify(entry, scope);
        if (JSON.stringify(options.workspace.get(REPOSITORY_CONTEXT_STATE_KEY)) !== JSON.stringify(entry.metadata))
          throw new Error('Authoritative repository selections changed during recovery backup.');
      });
      current(scope);
    } catch (error) { report(error, 'seed-write', scope); } // The current workspace's authoritative selection still works.
  };
  const begin = () => {
    const scope = options.scope();
    if (started || !scope) return;
    started = true;
    if (value !== undefined) { void schedule(async () => {
      current(scope);
      const authoritative = options.workspace.get(REPOSITORY_CONTEXT_STATE_KEY);
      if (authoritative !== undefined) await seed(scope, authoritative);
    }, 'startup-seed', scope).catch(() => {}); return; }
    if (!scope.untitled || scope.folders.length < 2 || scope.folders.length > 32) return;
    // Fence a nested container parent while asynchronous recovery is pending.
    // A failed optional cache must still allow explicit repository selection.
    value = { schema_version: 1, managed_parents: [scope.folders[0].uri], roots: [] };
    void schedule(async () => {
      current(scope);
      const candidates = (await options.recovery.candidates(scope.folders[0].uri, sessionDigest(scope.session)))
        .map(entry).filter(row => row.parent_uri === scope.folders[0].uri);
      current(scope);
      if (options.workspace.get(REPOSITORY_CONTEXT_STATE_KEY) !== undefined) return;
      if (!candidates.length) {
        const parent = scope.folders[0].path;
        const nested = scope.folders.slice(1).some(folder => {
          const relative = path.relative(parent, folder.path);
          return relative.length > 0 && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
        });
        if (!nested) value = undefined;
        return;
      }
      const session = sessionDigest(scope.session);
      const matched = session && candidates.filter(row => row.session_sha256 === session);
      const exact = matched && matched.length === 1 ? matched[0] : undefined;
      const selected = exact || candidates[0]; verify(selected, scope);
      let restoration: Promise<void> | undefined;
      const persist = async () => {
        current(scope); verify(selected, scope);
        if (options.workspace.get(REPOSITORY_CONTEXT_STATE_KEY) !== undefined) return;
        await options.recovery.restore(selected.parent_uri, selected.session_sha256, selected,
          () => verify(selected, scope), async () => {
            if (options.workspace.get(REPOSITORY_CONTEXT_STATE_KEY) !== undefined) return;
            await options.workspace.update(REPOSITORY_CONTEXT_STATE_KEY, selected.metadata);
            current(scope); verify(selected, scope); value = selected.metadata;
          });
      };
      const restore = () => restoration ??= schedule(persist, 'restore', scope);
      if (exact) await persist();
      else options.offer(readRepositoryContexts(selected.metadata).length, restore);
    }, 'startup-restore', scope).catch(() => { /* queue retains the reported failure; callers of restore reject. */ });
  };

  const state: State = {
    get<T>(key: string): T | undefined {
      if (key !== REPOSITORY_CONTEXT_STATE_KEY) return options.workspace.get<T>(key);
      begin();
      if (!options.active()) throw new CodeSecurityRequestError('This repository selection belongs to a closed editor activation.', 409);
      // Preserve the managed-parent fence after a cache failure. Explicit
      // selection must remain usable instead of being blocked by this hint.
      const authoritative = options.workspace.get<T>(key);
      return authoritative === undefined ? value as T | undefined : authoritative;
    },
    async update(key: string, next: unknown): Promise<void> {
      if (key !== REPOSITORY_CONTEXT_STATE_KEY) throw new Error('Only repository metadata is writable through recovery.');
      begin(); const scope = options.scope();
      if (!scope) throw new CodeSecurityRequestError('Trust this workspace before changing repository selections.');
      await schedule(async () => {
        current(scope); readRepositoryContexts(next);
        for (const record of readRepositoryContexts(next)) {
          const parent = scope.folders.find(folder => folder.uri === record.parent_uri);
          if (parent) verifyRepositoryContext(record, parent.path);
        }
        const previous = options.workspace.get(key);
        if (scope.workspace_uri === null && scope.folders.length === 1
          && managedRepositoryParents(previous).includes(scope.folders[0].uri)
          && !managedRepositoryParents(next).includes(scope.folders[0].uri))
          throw new Error('Keep the managed parent excluded when removing its selected repositories.');
        let committed = false;
        const update = async () => {
          current(scope);
          if (JSON.stringify(options.workspace.get(key)) !== JSON.stringify(previous))
            throw new Error('Authoritative repository selections changed before persistence.');
          await options.workspace.update(key, next); current(scope); value = next; committed = true;
        };
        const entry = backupEntry(scope, next);
        if (entry) await options.recovery.change(entry.parent_uri, entry.session_sha256, entry,
          () => {
            verify(entry, scope);
            if (committed && JSON.stringify(options.workspace.get(key)) !== JSON.stringify(next))
              throw new Error('Authoritative repository selections changed before backup publication.');
          }, update, error => report(error, 'selection-backup', scope), previous);
        else await update();
      }, 'selection-update', scope);
    },
  };
  return { state, get ready() { begin(); return queue; } };
}
