import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, opendir, realpath, rename, rmdir, unlink } from 'node:fs/promises';
import * as path from 'node:path';
import { sameCanonicalLocalPath } from './canonical-local-path';

const MAX_RECORDS = 128;
const MAX_BYTES = 256 * 1024;
const MIN_RETENTION_MS = 24 * 60 * 60 * 1000;
const NAME = /^[a-f0-9]{64}\.json$/u;
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const missing = (error: unknown) => (error as NodeJS.ErrnoException)?.code === 'ENOENT';
type Window = Readonly<{ id: string; pid: number }>;
type Record = Readonly<{ schema_version: 1; revision: string; pending: boolean;
  updated_at: number; windows: readonly Window[]; entry: unknown }>;
const metadata = (entry: unknown) => JSON.stringify((entry as { metadata: unknown }).metadata);

/** One atomic selection checkpoint per original folder workspace. Separate
 * parents have separate files; windows of the same folder share its metadata,
 * just as they share workspaceState. No global-memento index is involved. */
export class RepositoryRecoveryStore {
  private readonly directory: string;
  private readonly anonymousWindow = hash(randomUUID());
  constructor(profilePath: string) { this.directory = path.join(profilePath, 'repository-recovery-v1'); }

  private async directoryReady(): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const stat = await lstat(this.directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || !sameCanonicalLocalPath(await realpath(this.directory), path.resolve(this.directory))
      || typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new Error('Repository recovery storage changed.');
  }

  private async names(): Promise<string[]> {
    const directory = await opendir(this.directory), names: string[] = [];
    try {
      for (;;) {
        const entry = await directory.read();
        if (!entry) return names;
        if (names.length >= MAX_RECORDS * 3) throw new Error('Repository recovery storage needs review.');
        names.push(entry.name);
      }
    } finally { await directory.close(); }
  }

  private async read(name: string): Promise<Record | undefined> {
    const target = path.join(this.directory, name);
    let handle;
    try {
      const expected = await lstat(target);
      if (!expected.isFile() || expected.isSymbolicLink()) throw new Error('Invalid repository recovery file.');
      handle = await open(target, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
      const before = await handle.stat();
      if (!before.isFile() || before.nlink !== 1 || before.size > MAX_BYTES || before.dev !== expected.dev || before.ino !== expected.ino
        || typeof process.getuid === 'function' && before.uid !== process.getuid()) throw new Error('Invalid repository recovery file.');
      const buffer = Buffer.alloc(MAX_BYTES + 1); let length = 0;
      while (length < buffer.length) {
        const read = await handle.read(buffer, length, buffer.length - length, length);
        if (!read.bytesRead) break; length += read.bytesRead;
      }
      const after = await handle.stat();
      if (length > MAX_BYTES || length !== before.size || before.size !== after.size
        || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new Error('Repository recovery file changed while reading.');
      const value = JSON.parse(buffer.subarray(0, length).toString('utf8'));
      if (!value || Object.keys(value).sort().join(',') !== 'entry,pending,revision,schema_version,updated_at,windows'
        || value.schema_version !== 1 || typeof value.revision !== 'string' || !/^[a-f0-9-]{36}$/u.test(value.revision)
        || typeof value.pending !== 'boolean' || !Number.isSafeInteger(value.updated_at) || value.updated_at < 0
        || !Array.isArray(value.windows) || value.windows.length < 1 || value.windows.length > 32
        || value.windows.some((window: Window) => !window || Object.keys(window).sort().join(',') !== 'id,pid'
          || !/^[a-f0-9]{64}$/u.test(window.id) || !Number.isSafeInteger(window.pid) || window.pid < 1)
        || new Set(value.windows.map((window: Window) => window.id)).size !== value.windows.length
        || value.pending !== (value.entry === null)) throw new Error('Invalid repository recovery file.');
      return value;
    } catch (error) { if (missing(error)) return undefined; throw error; }
    finally { await handle?.close(); }
  }

  private async lock(name: string, wait: boolean): Promise<(() => Promise<void>) | undefined> {
    const target = path.join(this.directory, `${name}.lock`), deadline = performance.now() + 1000;
    for (;;) {
      try { await mkdir(target, { mode: 0o700 }); return () => rmdir(target); }
      catch (error) {
        if ((error as NodeJS.ErrnoException)?.code !== 'EEXIST') throw error;
        if (!wait) return undefined;
        if (performance.now() >= deadline) throw new Error('Repository recovery record is busy.');
        await new Promise(resolve => setTimeout(resolve, 20));
      }
    }
  }

  private ended(pid: number): boolean {
    try { process.kill(pid, 0); return false; }
    catch (error) { return (error as NodeJS.ErrnoException)?.code === 'ESRCH'; }
  }

  private windows(previous: Record | undefined, session: string | null): readonly Window[] {
    const id = session ?? this.anonymousWindow;
    const retained = (previous?.windows ?? []).filter(window => window.id !== id);
    while (retained.length >= 32) {
      const inactive = retained.findIndex(window => this.ended(window.pid));
      if (inactive < 0) throw new Error('Repository recovery has too many active windows.');
      retained.splice(inactive, 1);
    }
    return [...retained, { id, pid: process.pid }];
  }

  private async admit(name: string): Promise<void> {
    const records = (await this.names()).filter(candidate => NAME.test(candidate));
    if (records.includes(name) || records.length < MAX_RECORDS) return;
    for (const candidate of records) {
      const release = await this.lock(candidate, false); if (!release) continue;
      try {
        const record = await this.read(candidate);
        if (record && !record.pending && Date.now() - record.updated_at >= MIN_RETENTION_MS
          && record.windows.every(window => this.ended(window.pid))) {
          await unlink(path.join(this.directory, candidate)); return;
        }
      } finally { await release(); }
    }
    throw new Error('Repository recovery storage is full; existing workspace selections remain available.');
  }

  private async withRecord(parent: string, action: (name: string) => Promise<void>): Promise<void> {
    await this.directoryReady();
    const name = `${hash(parent)}.json`, release = await this.lock(name, true);
    try { await action(name); } finally { await release?.(); }
  }

  async candidates(parent: string, session: string | null): Promise<unknown[]> {
    await this.directoryReady();
    const record = await this.read(`${hash(parent)}.json`);
    if (!record || record.pending) return [];
    return [{ ...(record.entry as object), revision: record.revision,
      session_sha256: session && record.windows.some(window => window.id === session) ? session : null }];
  }

  async write(parent: string, session: string | null, entry: unknown, fence: () => void): Promise<void> {
    await this.withRecord(parent, async name => {
      const previous = await this.read(name);
      if (previous?.pending) throw new Error('A repository selection change needs explicit confirmation.');
      if (previous && metadata(previous.entry) !== metadata(entry)) throw new Error('Repository selections changed in another window.');
      await this.publish(name, { schema_version: 1, revision: previous?.revision ?? randomUUID(), pending: false,
        updated_at: Date.now(), windows: this.windows(previous, session), entry }, fence);
    });
  }

  /** Invalidation, authoritative workspace mutation and final checkpoint share
   * one parent lock. Startup cannot overwrite an unresolved mutation. */
  async change(parent: string, session: string | null, entry: unknown, fence: () => void,
    update: () => Promise<void>, backupFailure: (error?: unknown) => void, expectedMetadata: unknown): Promise<void> {
    await this.withRecord(parent, async name => {
      const previous = await this.read(name);
      if (previous && !previous.pending && metadata(previous.entry) !== JSON.stringify(expectedMetadata))
        throw new Error('Repository selections changed in another window. Refresh before choosing again.');
      const pending: Record = { schema_version: 1, revision: randomUUID(), pending: true,
        updated_at: Date.now(), windows: this.windows(previous, session), entry: null };
      await this.publish(name, pending, fence);
      await update();
      try { await this.publish(name, { ...pending, pending: false, updated_at: Date.now(), entry }, fence); }
      catch (error) { backupFailure(error); } // The workspace mutation is already committed.
    });
  }

  async restore(parent: string, _session: string | null, expected: unknown, fence: () => void,
    update: () => Promise<void>): Promise<void> {
    await this.withRecord(parent, async name => {
      const record = await this.read(name), selected = expected as { revision: string };
      if (!record || record.pending || record.revision !== selected.revision || metadata(record.entry) !== metadata(expected))
        throw new Error('Repository recovery selection changed. Choose repositories again.');
      fence(); await update(); fence();
    });
  }

  private async publish(name: string, value: Record, beforePublish: () => void): Promise<void> {
    const capacity = await this.lock('capacity', true);
    const temporary = path.join(this.directory, `.${name}.${randomUUID()}.tmp`); let created = false;
    try {
      await this.admit(name);
      const raw = JSON.stringify(value);
      if (Buffer.byteLength(raw) > MAX_BYTES) throw new Error('Repository recovery record is too large.');
      const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600); created = true;
      try { await handle.writeFile(raw); await handle.sync(); } finally { await handle.close(); }
      await this.directoryReady(); beforePublish();
      await rename(temporary, path.join(this.directory, name)); created = false;
      if (process.platform !== 'win32') {
        const directory = await open(this.directory, constants.O_RDONLY);
        try { await directory.sync(); } finally { await directory.close(); }
      }
      beforePublish();
    } finally { try { if (created) await unlink(temporary); } finally { await capacity?.(); } }
  }
}
