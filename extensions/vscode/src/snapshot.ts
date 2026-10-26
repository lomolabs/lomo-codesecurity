import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';

import { CodeSecurityRequestError } from './client';
import { SourceTarget } from './source';
import { nativeWindowsWorkspaceSourceId } from './workspace';

const MAX_SNAPSHOT_FILES = 5_000;
const MAX_SNAPSHOT_FILE_BYTES = 8 * 1024 * 1024;
const MAX_SNAPSHOT_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_HELPER_OUTPUT_BYTES = 112 * 1024 * 1024;
const SNAPSHOT_HELPER_DEADLINE_MS = 60_000;
const SNAPSHOT_HELPER_STOP_GRACE_MS = 1_000;

export const SOURCE_SNAPSHOT_LIMITS = Object.freeze({
  schema_version: 1,
  max_file_bytes: MAX_SNAPSHOT_FILE_BYTES,
  max_total_bytes: MAX_SNAPSHOT_TOTAL_BYTES,
  max_files: MAX_SNAPSHOT_FILES,
  max_encoded_request_bytes: MAX_HELPER_OUTPUT_BYTES,
  eligible_source_max_file_bytes: 1_048_576,
});

export function admittedSourceSnapshotLimits(value: unknown): typeof SOURCE_SNAPSHOT_LIMITS {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== Object.keys(SOURCE_SNAPSHOT_LIMITS).sort().join(',')
    || Object.entries(SOURCE_SNAPSHOT_LIMITS).some(([key, expected]) => (value as Record<string, unknown>)[key] !== expected)) {
    throw new CodeSecurityRequestError('The local backend does not advertise the supported bounded source-transfer contract. Update the backend source before transferring this repository.');
  }
  return SOURCE_SNAPSHOT_LIMITS;
}

export type SourceSnapshotEntry = Readonly<{
  path: string;
  content_base64: string;
  sha256: string;
  size_bytes: number;
}>;

export type SourceSnapshotUpload = Readonly<{
  source_id: string;
  name: string;
  directory_scope: string | null;
  files: readonly SourceSnapshotEntry[];
}>;

export type AdmittedSourceSnapshot = Readonly<{
  project: Readonly<{ id: number; name: string; repo_path: string; revision?: number }>;
  snapshotDigest: string;
}>;

/**
 * Executed by `wsl.exe --exec python3 -I -c` for a native Windows workspace.
 * Every path component is opened relative to a pinned directory descriptor
 * with O_NOFOLLOW. `/proc/self/fd` must continue to name the exact lexical
 * entry before enumeration and before/after each read, so a junction, rename,
 * or same-name replacement is terminal instead of disclosing outside bytes.
 */
export const NATIVE_WINDOWS_SNAPSHOT_HELPER = String.raw`
import base64
import hashlib
import json
import os
import signal
import stat
import sys
import threading

MAX_FILES = 5000
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
# Transfer the complete bounded source/control view. Analysis exclusions belong
# to scanners; applying lite exclusions here would permanently remove bytes
# before the API seals the snapshot and could falsely report complete coverage.
DIRECTORY_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW


class SnapshotBoundaryError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _safe_name(value):
    if (
        not value or value in {'.', '..'} or '/' in value or '\\' in value
        or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)
    ):
        raise SnapshotBoundaryError('unsafe_path')
    return value


def _fd_path(descriptor):
    try:
        value = os.readlink('/proc/self/fd/' + str(descriptor))
    except OSError as exc:
        if sys.platform != 'darwin':
            raise SnapshotBoundaryError('handle_identity_unavailable') from exc
        try:
            import fcntl
            value = fcntl.fcntl(descriptor, 50, b'\x00' * 1024).split(b'\x00', 1)[0].decode('utf-8')
        except (OSError, UnicodeError, ValueError) as fallback_exc:
            raise SnapshotBoundaryError('handle_identity_unavailable') from fallback_exc
    if value.endswith(' (deleted)'):
        raise SnapshotBoundaryError('source_changed')
    return os.path.normpath(value)


def _assert_fd_path(descriptor, expected):
    if _fd_path(descriptor) != os.path.normpath(expected):
        raise SnapshotBoundaryError('source_changed')


def _open_directory_path(root_path):
    if not root_path.startswith('/') or '\x00' in root_path:
        raise SnapshotBoundaryError('unsafe_root')
    parts = [_safe_name(part) for part in root_path.split('/') if part]
    descriptor = os.open('/', DIRECTORY_FLAGS)
    expected = '/'
    try:
        _assert_fd_path(descriptor, expected)
        for part in parts:
            _assert_fd_path(descriptor, expected)
            try:
                child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as exc:
                raise SnapshotBoundaryError('linked_or_changed_directory') from exc
            os.close(descriptor)
            descriptor = child
            expected = os.path.join(expected, part)
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise SnapshotBoundaryError('non_directory_root')
            _assert_fd_path(descriptor, expected)
        return descriptor, expected
    except (OSError, SnapshotBoundaryError):
        os.close(descriptor)
        raise


def _open_child_directory(parent_fd, parent_path, name):
    _assert_fd_path(parent_fd, parent_path)
    try:
        descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise SnapshotBoundaryError('linked_or_changed_directory') from exc
    expected = os.path.join(parent_path, name)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise SnapshotBoundaryError('non_directory_entry')
        _assert_fd_path(descriptor, expected)
        return descriptor, expected
    except (OSError, SnapshotBoundaryError):
        os.close(descriptor)
        raise


def _read_file(parent_fd, parent_path, name, relative_path):
    _assert_fd_path(parent_fd, parent_path)
    try:
        descriptor = os.open(name, FILE_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise SnapshotBoundaryError('linked_or_changed_file') from exc
    expected = os.path.join(parent_path, name)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SnapshotBoundaryError('non_regular_entry')
        if before.st_size > MAX_FILE_BYTES:
            raise SnapshotBoundaryError('file_too_large')
        _assert_fd_path(descriptor, expected)
        chunks = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b''.join(chunks)
        after = os.fstat(descriptor)
        _assert_fd_path(descriptor, expected)
        identity_before = (
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        )
        if len(content) > MAX_FILE_BYTES or len(content) != after.st_size or identity_before != identity_after:
            raise SnapshotBoundaryError('source_changed')
        return {
            'path': relative_path,
            'content_base64': base64.b64encode(content).decode('ascii'),
            'sha256': hashlib.sha256(content).hexdigest(),
            'size_bytes': len(content),
        }
    finally:
        os.close(descriptor)


def _target_parts(target_path):
    if target_path is None:
        return None
    parts = [_safe_name(part) for part in target_path.split('/')]
    if not parts or '/'.join(parts) != target_path:
        raise SnapshotBoundaryError('unsafe_target')
    return parts


def collect_snapshot(root_path, target_path=None, target_kind=None):
    if (target_path is None) != (target_kind is None) or target_kind not in {None, 'file', 'directory'}:
        raise SnapshotBoundaryError('invalid_target')
    root_fd, root_identity = _open_directory_path(root_path)
    files = []
    total_bytes = 0

    def append(parent_fd, parent_path, name, relative_path):
        nonlocal total_bytes
        if len(files) >= MAX_FILES:
            raise SnapshotBoundaryError('too_many_files')
        entry = _read_file(parent_fd, parent_path, name, relative_path)
        total_bytes += entry['size_bytes']
        if total_bytes > MAX_TOTAL_BYTES:
            raise SnapshotBoundaryError('snapshot_too_large')
        files.append(entry)

    def walk(directory_fd, directory_path, relative_parts):
        _assert_fd_path(directory_fd, directory_path)
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError as exc:
            raise SnapshotBoundaryError('enumeration_failed') from exc
        for raw_name in names:
            name = _safe_name(raw_name)
            _assert_fd_path(directory_fd, directory_path)
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise SnapshotBoundaryError('source_changed') from exc
            relative = '/'.join(relative_parts + [name])
            if stat.S_ISLNK(metadata.st_mode):
                raise SnapshotBoundaryError('linked_entry')
            if stat.S_ISDIR(metadata.st_mode):
                if name != '.git':
                    child_fd, child_path = _open_child_directory(directory_fd, directory_path, name)
                    try:
                        walk(child_fd, child_path, relative_parts + [name])
                    finally:
                        os.close(child_fd)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise SnapshotBoundaryError('non_regular_entry')
            append(directory_fd, directory_path, name, relative)

    try:
        target_parts = _target_parts(target_path)
        if target_parts is None:
            walk(root_fd, root_identity, [])
        elif target_kind == 'file':
            parent_fd = root_fd
            parent_path = root_identity
            owned = []
            try:
                for part in target_parts[:-1]:
                    parent_fd, parent_path = _open_child_directory(parent_fd, parent_path, part)
                    owned.append(parent_fd)
                append(parent_fd, parent_path, target_parts[-1], target_path)
            finally:
                for descriptor in reversed(owned):
                    os.close(descriptor)
        else:
            directory_fd = root_fd
            directory_path = root_identity
            owned = []
            try:
                for part in target_parts:
                    directory_fd, directory_path = _open_child_directory(
                        directory_fd, directory_path, part
                    )
                    owned.append(directory_fd)
                walk(directory_fd, directory_path, target_parts)
            finally:
                for descriptor in reversed(owned):
                    os.close(descriptor)
    finally:
        os.close(root_fd)
    files.sort(key=lambda item: item['path'])
    return {
        'directory_scope': target_path if target_kind == 'directory' else None,
        'files': files,
    }


def _main():
    owned_input = sys.argv[-1:] == ['--owned-input']
    if owned_input:
        sys.argv.pop()
    def stop(_signal, _frame):
        raise SnapshotBoundaryError('helper_cancelled' if _signal == signal.SIGTERM else 'helper_deadline')
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGALRM, stop)
    signal.setitimer(signal.ITIMER_REAL, 60)
    if owned_input:
        # EOF belongs to this exact bridge; never signal a guessed process/distro.
        def watch_owner():
            os.read(sys.stdin.fileno(), 1)
            os.kill(os.getpid(), signal.SIGTERM)
        threading.Thread(target=watch_owner, daemon=True).start()
    if len(sys.argv) not in {3, 5} or sys.argv[1] != '--root-posix':
        raise SnapshotBoundaryError('invalid_invocation')
    target = None
    target_kind = None
    if len(sys.argv) == 5:
        if sys.argv[3] == '--target-file':
            target_kind = 'file'
        elif sys.argv[3] == '--target-directory':
            target_kind = 'directory'
        else:
            raise SnapshotBoundaryError('invalid_invocation')
        target = sys.argv[4]
    result = collect_snapshot(sys.argv[2], target, target_kind)
    sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(',', ':'), sort_keys=True))


if __name__ == '__main__':
    try:
        _main()
    except SnapshotBoundaryError as exc:
        sys.stderr.write(json.dumps({'code': exc.code}, separators=(',', ':')))
        raise SystemExit(23)
`;

function safeRelativePath(value: unknown): value is string {
  return typeof value === 'string'
    && value.length >= 1
    && new TextEncoder().encode(value).byteLength <= 4_096
    && !value.startsWith('/')
    && !value.includes('\\')
    && !/[\p{Cc}\p{Cf}]/u.test(value)
    && value.split('/').every((part) => part && part !== '.' && part !== '..');
}

function decodeCanonicalBase64(value: unknown): Uint8Array {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(MAX_SNAPSHOT_FILE_BYTES / 3)) {
    throw new CodeSecurityRequestError('Secure native snapshot helper returned invalid base64 source data.');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) {
    throw new CodeSecurityRequestError('Secure native snapshot helper returned invalid base64 source data.');
  }
  return bytes;
}

function validateHelperOutput(value: unknown, target: SourceTarget): readonly SourceSnapshotEntry[] {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new CodeSecurityRequestError('Secure native snapshot helper returned an invalid receipt.');
  }
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).length !== 2
    || !Object.hasOwn(record, 'directory_scope')
    || !Array.isArray(record.files)
    || record.files.length > MAX_SNAPSHOT_FILES
  ) {
    throw new CodeSecurityRequestError('Secure native snapshot helper exceeded its file manifest boundary.');
  }
  const expectedDirectoryScope = target.kind === 'directory' ? target.targetPath : null;
  if (record.directory_scope !== expectedDirectoryScope) {
    throw new CodeSecurityRequestError(
      'Secure native snapshot helper returned the wrong exact selected directory scope.',
    );
  }
  const files: SourceSnapshotEntry[] = [];
  let totalBytes = 0;
  for (const raw of record.files) {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new CodeSecurityRequestError('Secure native snapshot helper returned an invalid file receipt.');
    }
    const item = raw as Record<string, unknown>;
    const content = decodeCanonicalBase64(item.content_base64);
    if (
      Object.keys(item).length !== 4
      || !safeRelativePath(item.path)
      || typeof item.sha256 !== 'string'
      || !/^[0-9a-f]{64}$/u.test(item.sha256)
      || !Number.isSafeInteger(item.size_bytes)
      || (item.size_bytes as number) < 0
      || (item.size_bytes as number) > MAX_SNAPSHOT_FILE_BYTES
      || content.byteLength !== item.size_bytes
      || createHash('sha256').update(content).digest('hex') !== item.sha256
    ) {
      throw new CodeSecurityRequestError('Secure native snapshot helper returned a file with the wrong immutable binding.');
    }
    totalBytes += content.byteLength;
    if (totalBytes > MAX_SNAPSHOT_TOTAL_BYTES) {
      throw new CodeSecurityRequestError('Secure native snapshot helper exceeded the 64 MiB source boundary.');
    }
    files.push(Object.freeze({
      path: item.path,
      content_base64: item.content_base64 as string,
      sha256: item.sha256,
      size_bytes: item.size_bytes as number,
    }));
  }
  if (
    files.some((item, index) => index > 0 && files[index - 1].path >= item.path)
    || target.kind === 'file'
    && (files.length !== 1 || files[0].path !== target.targetPath)
    || target.kind === 'directory'
    && files.some((item) => !item.path.startsWith(`${target.targetPath as string}/`))
  ) {
    throw new CodeSecurityRequestError('Secure native snapshot helper returned files outside the exact selected scope.');
  }
  return Object.freeze(files);
}

function windowsPathToWsl(value: string): string {
  const match = /^([A-Za-z]):\\(.+)$/u.exec(value);
  if (!match) {
    throw new CodeSecurityRequestError('Secure native snapshot collection requires a non-root local Windows drive folder.');
  }
  const parts = match[2].split('\\');
  if (parts.some((part) => !part || part === '.' || part === '..' || /[\p{Cc}\p{Cf}]/u.test(part))) {
    throw new CodeSecurityRequestError('The selected Windows source path is not canonical.');
  }
  return `/mnt/${match[1].toLowerCase()}/${parts.join('/')}`;
}

async function runSecureWslSnapshot(
  target: SourceTarget,
  signal?: AbortSignal,
): Promise<unknown> {
  const rootPath = target.owner.uri.fsPath;
  const args = [
    '--exec', 'python3', '-I', '-c', NATIVE_WINDOWS_SNAPSHOT_HELPER,
    '--root-posix', windowsPathToWsl(rootPath),
    ...(target.kind === 'file'
      ? ['--target-file', target.targetPath as string]
      : target.kind === 'directory'
        ? ['--target-directory', target.targetPath as string]
        : []),
  ];
  return runBoundedSnapshotHelper('wsl.exe', [...args, '--owned-input'], signal);
}

/** Await the owned child close; cancellation never claims cleanup from kill alone. */
export async function runBoundedSnapshotHelper(
  executable: string,
  args: readonly string[],
  signal?: AbortSignal,
  deadlineMs = SNAPSHOT_HELPER_DEADLINE_MS,
): Promise<unknown> {
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > SNAPSHOT_HELPER_DEADLINE_MS) {
    throw new CodeSecurityRequestError('The native source collector deadline is invalid.');
  }
  if (signal?.aborted) throw new DOMException('Native source snapshot collection was cancelled.', 'AbortError');
  return new Promise((resolve, reject) => {
    let stopping: 'cancelled' | 'deadline' | undefined;
    let forced = false;
    let stopTimer: ReturnType<typeof setTimeout> | undefined;
    const child = execFile(
      executable,
      [...args],
      { encoding: 'utf8', maxBuffer: MAX_HELPER_OUTPUT_BYTES, windowsHide: true },
      (error, stdout, stderr) => {
        clearTimeout(deadline);
        clearTimeout(stopTimer);
        signal?.removeEventListener('abort', abort);
        child.stdin?.destroy();
        let code = 'helper_unavailable';
        try {
          const failure = JSON.parse(stderr) as unknown;
          if (failure && typeof failure === 'object' && !Array.isArray(failure)
            && Object.keys(failure).length === 1
            && typeof (failure as Record<string, unknown>).code === 'string'
            && /^[a-z][a-z0-9_]{0,79}$/u.test((failure as Record<string, string>).code)) {
            code = (failure as Record<string, string>).code;
          }
        } catch { /* Unknown bridge stderr is never displayed. */ }
        if (stopping) {
          if (forced || error && code !== 'helper_cancelled' && code !== 'helper_deadline') {
            reject(new CodeSecurityRequestError('Native source collection stopped, but the WSL helper terminal cleanup could not be confirmed. Retry only after reviewing the exact local collector.', undefined, false, { code: 'native_snapshot_cleanup_unconfirmed' }));
          } else if (stopping === 'cancelled') {
            reject(new DOMException('Native source snapshot collection was cancelled.', 'AbortError'));
          } else {
            reject(new CodeSecurityRequestError('Native source collection reached its bounded deadline.', undefined, false, { code: 'native_snapshot_deadline' }));
          }
          return;
        }
        if (error) {
          if (code === 'helper_deadline') {
            reject(new CodeSecurityRequestError('Native source collection reached its bounded deadline.', undefined, false, { code: 'native_snapshot_deadline' }));
            return;
          }
          if (child.killed && code === 'helper_unavailable') {
            reject(new CodeSecurityRequestError('Native source collection exceeded its bridge boundary, and WSL helper cleanup could not be confirmed.', undefined, false, { code: 'native_snapshot_cleanup_unconfirmed' }));
            return;
          }
          reject(new CodeSecurityRequestError(
            `Secure native Windows source collection stopped (${code}). `
            + 'Confirm WSL and Python 3 are available, then retry the exact selected source.',
          ));
          return;
        }
        try {
          resolve(JSON.parse(stdout));
        } catch (parseError) {
          reject(parseError instanceof SyntaxError
            ? new CodeSecurityRequestError('Secure native snapshot helper returned malformed JSON.')
            : parseError);
        }
      },
    );
    const stop = (reason: 'cancelled' | 'deadline') => {
      if (stopping) return;
      stopping = reason;
      child.stdin?.end();
      stopTimer = setTimeout(() => {
        forced = true;
        child.kill('SIGKILL');
      }, SNAPSHOT_HELPER_STOP_GRACE_MS);
    };
    const abort = () => stop('cancelled');
    child.stdin?.on('error', () => { /* Child close/terminal proof owns the result. */ });
    const deadline = setTimeout(() => stop('deadline'), deadlineMs);
    if (signal?.aborted) abort();
    else signal?.addEventListener('abort', abort, { once: true });
  });
}

export async function collectNativeWindowsSourceSnapshot(
  target: SourceTarget,
  signal?: AbortSignal,
  runHelper: (target: SourceTarget, signal?: AbortSignal) => Promise<unknown> = runSecureWslSnapshot,
): Promise<SourceSnapshotUpload> {
  if (target.authorizationMode !== 'snapshot' || !target.sourceId) {
    throw new CodeSecurityRequestError('A mounted workspace cannot cross the native Windows snapshot boundary.');
  }
  // Validate the clicked URI independently from its durable owner identity so
  // a forged/mutated UNC target cannot inherit permission from a local root.
  nativeWindowsWorkspaceSourceId({ name: target.label, uri: target.uri });
  const sourceFolder = {
    name: target.owner.name,
    uri: target.owner.uri,
  };
  if (nativeWindowsWorkspaceSourceId(sourceFolder) !== target.sourceId) {
    throw new CodeSecurityRequestError(
      'The native Windows snapshot target does not match its exact local-drive source identity.',
    );
  }
  const files = validateHelperOutput(await runHelper(target, signal), target);
  return Object.freeze({
    source_id: target.sourceId,
    name: (target.owner.name.trim() || 'workspace').replace(/[^a-zA-Z0-9_.-]+/gu, '-').slice(0, 120),
    directory_scope: target.kind === 'directory' ? target.targetPath as string : null,
    files,
  });
}

export function admittedNativeWindowsSourceSnapshot(
  value: unknown,
  target: SourceTarget,
  upload: SourceSnapshotUpload,
): AdmittedSourceSnapshot {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid native source snapshot receipt.');
  }
  const record = value as Record<string, unknown>;
  const project = record.project;
  if (project === null || typeof project !== 'object' || Array.isArray(project)) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid native source project binding.');
  }
  const projectRecord = project as Record<string, unknown>;
  const snapshotDigest = record.snapshot_digest;
  const expectedBytes = upload.files.reduce((total, item) => total + item.size_bytes, 0);
  if (
    !Number.isSafeInteger(projectRecord.id) || (projectRecord.id as number) < 1
    || typeof projectRecord.name !== 'string' || !projectRecord.name
    || projectRecord.repo_path !== target.repoPath
    || typeof snapshotDigest !== 'string' || !/^[0-9a-f]{64}$/u.test(snapshotDigest)
    || record.directory_scope !== upload.directory_scope
    || record.file_count !== upload.files.length
    || record.total_bytes !== expectedBytes
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned a native source snapshot receipt with the wrong immutable binding.');
  }
  return Object.freeze({
    project: Object.freeze({
      id: projectRecord.id as number,
      name: projectRecord.name,
      repo_path: projectRecord.repo_path,
      ...(Number.isSafeInteger(projectRecord.revision)
        ? { revision: projectRecord.revision as number }
        : {}),
    }),
    snapshotDigest,
  });
}
