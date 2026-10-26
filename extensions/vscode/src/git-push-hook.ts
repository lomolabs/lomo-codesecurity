import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, mkdir, mkdtemp, open, realpath, rename, rmdir, unlink } from 'node:fs/promises';
import * as path from 'node:path';
import { execFile } from 'node:child_process';

import { GitPushBoundaryError, GitRepository, inspectGitRepository } from './git-push-objects';

const MARKER = '# Lomo CodeSecurity repository push protection v1\n';
const MAX_HOOK_BYTES = 64 * 1024;

export type GitHookPreview = Readonly<{
  repository: GitRepository;
  hookPath: string;
  observedHookDigest: string | null;
}>;
export type GitHookInstallation = Readonly<{
  repositoryId: string;
  hookPath: string;
  hookDigest: string;
}>;

function hash(bytes: string | Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

async function regularBytes(target: string): Promise<{ bytes: Buffer; mode: number } | null> {
  let handle;
  try {
    const lexical = await lstat(target);
    if (!lexical.isFile() || lexical.nlink !== 1 || lexical.size > MAX_HOOK_BYTES) {
      throw new GitPushBoundaryError('git_hook_conflict', 'An existing hook is linked, oversized or not a regular file. It was left unchanged.');
    }
    handle = await open(target, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
    const before = await handle.stat();
    if (before.dev !== lexical.dev || before.ino !== lexical.ino || before.size !== lexical.size) {
      throw new GitPushBoundaryError('git_hook_changed', 'The hook changed while being inspected. Review it again.');
    }
    const buffer = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const read = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (!read.bytesRead) break;
      offset += read.bytesRead;
    }
    const bytes = buffer.subarray(0, offset);
    const after = await handle.stat();
    if (before.size !== bytes.length || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
      throw new GitPushBoundaryError('git_hook_changed', 'The hook changed while being inspected. Review it again.');
    }
    return { bytes, mode: before.mode & 0o777 };
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return null;
    throw error;
  } finally {
    await handle?.close();
  }
}

async function assertDefaultHookPath(repository: GitRepository): Promise<void> {
  // Unlike object reads, this observation deliberately includes the user's
  // effective Git configuration: a global hooksPath changes which hook runs.
  await new Promise<void>((resolve, reject) => {
    execFile('git', ['-C', repository.root, 'config', '--get', 'core.hooksPath'], {
      encoding: 'utf8', maxBuffer: 8192, windowsHide: true, timeout: 15_000,
    }, (error, stdout) => {
      if (error && error.code === 1 && stdout === '') resolve();
      else if (error) reject(new GitPushBoundaryError('git_hook_config_unavailable', 'Git hook configuration could not be verified. No hook was changed.'));
      else reject(new GitPushBoundaryError('git_hook_path_conflict', 'This clone uses a custom hooksPath. Keep it unchanged and integrate Lomo through that hook manager before claiming protection.'));
    });
  });
}

async function inspectHookDirectory(repository: GitRepository): Promise<boolean> {
  const directory = path.join(repository.gitDirectory, 'hooks');
  try {
    const metadata = await lstat(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || await realpath(directory) !== directory) {
      throw new GitPushBoundaryError('git_hook_directory_invalid', 'The Git hooks directory must have one canonical, unlinked identity. No hook was changed.');
    }
    return true;
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return false;
    throw error;
  }
}

export async function previewGitHook(root: string): Promise<GitHookPreview> {
  const repository = await inspectGitRepository(root);
  await assertDefaultHookPath(repository);
  if (repository.gitDirectory !== repository.commonDirectory) {
    throw new GitPushBoundaryError('git_shared_hook_conflict', 'Linked worktrees share their Git hook with other roots. Set up push protection in a standalone clone; this shared hook was left unchanged.');
  }
  const hookPath = path.join(repository.gitDirectory, 'hooks', 'pre-push');
  await inspectHookDirectory(repository);
  const hook = await regularBytes(hookPath);
  if (hook?.bytes.toString('utf8').includes(MARKER)) {
    throw new GitPushBoundaryError('git_hook_already_installed', 'Lomo already owns this hook. Verify its existing installation instead of replacing it.');
  }
  if (hook) {
    throw new GitPushBoundaryError('git_hook_conflict', 'This repository already has a pre-push hook. It was left unchanged; integrate Lomo through the existing hook manager before claiming protection.');
  }
  return Object.freeze({ repository, hookPath, observedHookDigest: null });
}

function quote(value: string): string {
  if (!path.isAbsolute(value) || /[\p{Cc}\p{Cf}]/u.test(value)) throw new GitPushBoundaryError('git_hook_path_invalid', 'The installed runtime and helper paths must be exact absolute paths.');
  return "'" + value.replaceAll('\\', '/').replaceAll("'", "'\\''") + "'";
}

/** Paths only: credentials are read by the shared private profile store at run time. */
export function gitHookScript(nodePath: string, helperPath: string, configurationPath: string): string {
  return '#!/bin/sh\n' + MARKER +
    `exec env ELECTRON_RUN_AS_NODE=1 ${quote(nodePath)} ${quote(helperPath)} --hook ${quote(configurationPath)} "$@"\n`;
}

async function writeNew(target: string, bytes: string, mode: number): Promise<void> {
  const handle = await open(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), mode);
  try {
    await handle.writeFile(bytes, 'utf8');
    await handle.sync();
  } finally { await handle.close(); }
}

/** Must be invoked only after explicit owner confirmation of this exact preview. */
export async function installGitHook(preview: GitHookPreview, script: string): Promise<GitHookInstallation> {
  if (!script.startsWith('#!/bin/sh\n' + MARKER) || Buffer.byteLength(script) > MAX_HOOK_BYTES) {
    throw new GitPushBoundaryError('git_hook_script_invalid', 'The Lomo hook script is invalid.');
  }
  const current = await previewGitHook(preview.repository.root);
  if (current.repository.repositoryId !== preview.repository.repositoryId ||
      current.observedHookDigest !== preview.observedHookDigest) {
    throw new GitPushBoundaryError('git_hook_changed', 'The repository hook changed after confirmation. No hook was replaced.');
  }
  const directory = path.dirname(current.hookPath);
  await mkdir(directory, { recursive: false }).catch(error => {
    if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
  });
  if (!await inspectHookDirectory(current.repository)) {
    throw new GitPushBoundaryError('git_hook_directory_invalid', 'The Git hooks directory must not be linked.');
  }
  // Hard-link publication is exclusive on every supported filesystem. Unlike
  // rename(), it cannot overwrite another tool's concurrently created hook.
  const staging = current.hookPath + '.lomo-installing';
  await writeNew(staging, script, 0o700);
  const before = await regularBytes(current.hookPath);
  if ((before ? hash(before.bytes) : null) !== current.observedHookDigest) {
    await unlink(staging);
    throw new GitPushBoundaryError('git_hook_changed', 'The hook changed during installation. No existing hook was replaced.');
  }
  try {
    await link(staging, current.hookPath);
  } catch (error) {
    await unlink(staging);
    if (error instanceof Error && 'code' in error && error.code === 'EEXIST') {
      throw new GitPushBoundaryError('git_hook_changed', 'Another tool installed a hook during confirmation. It was left unchanged.');
    }
    throw error;
  }
  await unlink(staging);
  const installed = await regularBytes(current.hookPath);
  if (!installed || hash(installed.bytes) !== hash(script)
    || process.platform !== 'win32' && !(installed.mode & 0o111)) {
    throw new GitPushBoundaryError('git_hook_install_unconfirmed', 'Push protection installation needs recovery; protection is not confirmed.');
  }
  return Object.freeze({ repositoryId: current.repository.repositoryId, hookPath: current.hookPath,
    hookDigest: hash(script) });
}

export async function observeGitHook(repository: GitRepository, installed: GitHookInstallation): Promise<'installed' | 'needs_repair'> {
  await assertDefaultHookPath(repository);
  const current = await inspectGitRepository(repository.root);
  if (current.repositoryId !== installed.repositoryId || current.gitDirectory !== current.commonDirectory ||
      installed.hookPath !== path.join(current.gitDirectory, 'hooks', 'pre-push') || !await inspectHookDirectory(current)) return 'needs_repair';
  const hook = await regularBytes(installed.hookPath);
  // Windows does not expose POSIX executable bits. Git for Windows invokes
  // the shebang hook; its actual execution is covered by the native push test.
  return hook && hash(hook.bytes) === installed.hookDigest
    && (process.platform === 'win32' || Boolean(hook.mode & 0o111)) ? 'installed' : 'needs_repair';
}

/** Removing Lomo never deletes a concurrently installed check from another tool. */
export async function removeGitHook(repository: GitRepository, installed: GitHookInstallation): Promise<void> {
  if (await observeGitHook(repository, installed) !== 'installed') {
    throw new GitPushBoundaryError('git_hook_changed', 'The installed hook changed. Review it before removing protection.');
  }
  // Move into an exclusively created recovery directory before inspecting the
  // entry we would delete. A changed hook is restored without overwrite; when
  // another writer owns the original name it stays preserved for owner review.
  const recovery = await mkdtemp(path.join(path.dirname(installed.hookPath), '.lomo-remove-'));
  const parked = path.join(recovery, 'pre-push');
  await rename(installed.hookPath, parked);
  const captured = await regularBytes(parked);
  if (!captured || hash(captured.bytes) !== installed.hookDigest) {
    try { await link(parked, installed.hookPath); }
    catch (error) {
      if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
      throw new GitPushBoundaryError('git_hook_recovery_required', 'A concurrently changed hook was preserved in the repository’s Lomo recovery directory. Review it before changing hooks.');
    }
    await unlink(parked);
    await rmdir(recovery);
    throw new GitPushBoundaryError('git_hook_changed', 'Another tool changed the hook during removal. Its hook was restored unchanged.');
  }
  await unlink(parked);
  await rmdir(recovery);
}
