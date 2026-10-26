import { createHash } from 'node:crypto';
import { constants as fileConstants, type Stats } from 'node:fs';
import { lstat, open, unlink } from 'node:fs/promises';
import * as path from 'node:path';

import { canonicalLoopbackOrigin } from './authority';
import { canonicalWindowsLocalPath, verifyWindowsPrivatePath, WindowsPrivatePathError } from './windows-private-path';

export const FIRST_OWNER_BOOTSTRAP_FILE_NAME = 'first-owner-browser-v1.json';

const MAX_BOOTSTRAP_FILE_BYTES = 2 * 1024;
const BOOTSTRAP_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const INSTALLATION_ID = /^[a-f0-9]{12}$/u;
const EXACT_BOOTSTRAP_KEYS = 'bootstrap_token\0control_origin\0installation_id\0v';

export type FirstOwnerBrowserBootstrap = Readonly<{
  artifactPath: string;
  bootstrapToken: string;
  controlOrigin: string;
  installationId: string;
  identity: Readonly<{
    dev: number;
    ino: number;
    size: number;
    sha256: string;
  }>;
}>;

export class FirstOwnerBootstrapError extends Error {
  readonly code = 'first_owner_bootstrap_insecure';

  constructor(message: string) {
    super(message);
    this.name = 'FirstOwnerBootstrapError';
  }
}

function missing(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}

async function assertPrivatePath(stats: Stats, kind: 'directory' | 'file', target: string): Promise<void> {
  if (
    stats.isSymbolicLink()
    || (kind === 'directory' ? !stats.isDirectory() : !stats.isFile())
    || kind === 'file' && stats.nlink !== 1
  ) {
    throw new FirstOwnerBootstrapError(
      `CodeSecurity refused a symbolic-link, hard-linked, or non-${kind} first-owner bootstrap path.`,
    );
  }
  if (process.platform === 'win32') {
    try { await verifyWindowsPrivatePath(target, kind); }
    catch (error) {
      if (!(error instanceof WindowsPrivatePathError)) throw error;
      throw new FirstOwnerBootstrapError(error.message);
    }
    const after = await lstat(target);
    if (after.dev !== stats.dev || after.ino !== stats.ino || after.size !== stats.size || after.nlink !== stats.nlink) {
      throw new FirstOwnerBootstrapError('CodeSecurity refused a first-owner bootstrap path changed during permission verification.');
    }
    return;
  }
  const currentUser = process.getuid?.();
  const expectedMode = kind === 'directory' ? 0o700 : 0o600;
  if (currentUser === undefined || stats.uid !== currentUser || (stats.mode & 0o777) !== expectedMode) {
    throw new FirstOwnerBootstrapError(
      `CodeSecurity requires its first-owner bootstrap ${kind} to belong to the current user with mode ${expectedMode.toString(8)}.`,
    );
  }
}

function defaultStateDirectory(environment: NodeJS.ProcessEnv, platform: NodeJS.Platform): string | undefined {
  const explicit = environment.KODESEC_STATE_DIR;
  if (platform === 'win32') {
    if (explicit !== undefined) return canonicalWindowsLocalPath(explicit) ? explicit : undefined;
    if (environment.LOCALAPPDATA !== undefined) {
      return canonicalWindowsLocalPath(environment.LOCALAPPDATA)
        ? path.win32.join(environment.LOCALAPPDATA, 'lomo-kodesec') : undefined;
    }
    return canonicalWindowsLocalPath(environment.USERPROFILE)
      ? path.win32.join(environment.USERPROFILE, 'AppData', 'Local', 'lomo-kodesec') : undefined;
  }
  if (explicit !== undefined) return path.isAbsolute(explicit) ? path.normalize(explicit) : undefined;
  const xdg = environment.XDG_STATE_HOME;
  if (xdg !== undefined) {
    return path.isAbsolute(xdg) ? path.join(path.normalize(xdg), 'lomo-kodesec') : undefined;
  }
  const home = environment.HOME;
  return home && path.isAbsolute(home)
    ? path.join(path.normalize(home), '.local', 'state', 'lomo-kodesec')
    : undefined;
}

export function firstOwnerBootstrapPath(
  environment: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string | undefined {
  const stateDirectory = defaultStateDirectory(environment, platform);
  return stateDirectory ? (platform === 'win32' ? path.win32 : path).join(stateDirectory, FIRST_OWNER_BOOTSTRAP_FILE_NAME) : undefined;
}

async function closeHandle(handle: Awaited<ReturnType<typeof open>>): Promise<void> {
  await handle.close();
}

export async function readFirstOwnerBrowserBootstrap(
  expectedEndpoint: string,
  artifactPath = firstOwnerBootstrapPath(),
): Promise<FirstOwnerBrowserBootstrap | undefined> {
  const endpoint = canonicalLoopbackOrigin(expectedEndpoint);
  if (!endpoint || endpoint !== expectedEndpoint || !artifactPath || !path.isAbsolute(artifactPath)) return undefined;
  const stateDirectory = path.dirname(artifactPath);
  if (path.basename(artifactPath) !== FIRST_OWNER_BOOTSTRAP_FILE_NAME) return undefined;

  let directoryStats: Stats;
  let pathStats: Stats;
  try {
    directoryStats = await lstat(stateDirectory);
    pathStats = await lstat(artifactPath);
  } catch (error) {
    if (missing(error)) return undefined;
    throw error;
  }
  await assertPrivatePath(directoryStats, 'directory', stateDirectory);
  await assertPrivatePath(pathStats, 'file', artifactPath);
  if (pathStats.size < 2 || pathStats.size > MAX_BOOTSTRAP_FILE_BYTES) {
    throw new FirstOwnerBootstrapError('CodeSecurity refused an oversized or empty first-owner bootstrap file.');
  }

  const noFollow = process.platform === 'win32' ? 0 : fileConstants.O_NOFOLLOW;
  const handle = await open(artifactPath, fileConstants.O_RDONLY | noFollow);
  try {
    const openedStats = await handle.stat();
    await assertPrivatePath(openedStats, 'file', artifactPath);
    if (
      openedStats.dev !== pathStats.dev
      || openedStats.ino !== pathStats.ino
      || openedStats.size !== pathStats.size
    ) {
      throw new FirstOwnerBootstrapError('CodeSecurity refused a first-owner bootstrap file that changed while opened.');
    }
    const bytes = Buffer.alloc(openedStats.size + 1);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.byteLength - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset !== openedStats.size) {
      throw new FirstOwnerBootstrapError('CodeSecurity refused a first-owner bootstrap file that changed while read.');
    }
    let decoded: string;
    let parsed: unknown;
    try {
      decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, offset));
      parsed = JSON.parse(decoded);
    } catch {
      throw new FirstOwnerBootstrapError('CodeSecurity refused malformed first-owner bootstrap material.');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new FirstOwnerBootstrapError('CodeSecurity refused malformed first-owner bootstrap material.');
    }
    const value = parsed as Record<string, unknown>;
    if (
      Object.keys(value).sort().join('\0') !== EXACT_BOOTSTRAP_KEYS
      || value.v !== 1
      || value.control_origin !== endpoint
      || typeof value.bootstrap_token !== 'string'
      || !BOOTSTRAP_TOKEN.test(value.bootstrap_token)
      || typeof value.installation_id !== 'string'
      || !INSTALLATION_ID.test(value.installation_id)
    ) {
      throw new FirstOwnerBootstrapError('CodeSecurity refused mismatched first-owner bootstrap material.');
    }
    return Object.freeze({
      artifactPath,
      bootstrapToken: value.bootstrap_token,
      controlOrigin: endpoint,
      installationId: value.installation_id,
      identity: Object.freeze({
        dev: openedStats.dev,
        ino: openedStats.ino,
        size: openedStats.size,
        sha256: createHash('sha256').update(bytes.subarray(0, offset)).digest('hex'),
      }),
    });
  } finally {
    await closeHandle(handle);
  }
}

export async function consumeFirstOwnerBrowserBootstrap(
  expected: FirstOwnerBrowserBootstrap,
): Promise<void> {
  const current = await readFirstOwnerBrowserBootstrap(expected.controlOrigin, expected.artifactPath);
  if (!current) return;
  if (
    current.identity.dev !== expected.identity.dev
    || current.identity.ino !== expected.identity.ino
    || current.identity.size !== expected.identity.size
    || current.identity.sha256 !== expected.identity.sha256
    || current.bootstrapToken !== expected.bootstrapToken
  ) {
    throw new FirstOwnerBootstrapError(
      'CodeSecurity refused to consume first-owner bootstrap material changed by another local process.',
    );
  }
  await unlink(expected.artifactPath);
}
