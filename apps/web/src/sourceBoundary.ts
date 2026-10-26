export type RegisteredSource = Readonly<{
  repo_path: string;
}>;

export type ProjectSourceAdapter = 'mounted_directory' | 'native_windows_snapshot' | 'git_commit_snapshot';

export type SourceBoundaryLoadState =
  | Readonly<{ status: 'loading' }>
  | Readonly<{ status: 'ready'; roots: readonly string[]; installationId?: string }>
  | Readonly<{ status: 'error'; reason: string }>;

export type SourceRegistrationSummary = Readonly<{
  insideCount: number;
  outsideCount: number;
  snapshotCount: number;
  message: string;
}>;

const nativeWindowsSnapshotPath = /^\/source-snapshots\/native-windows\/[0-9a-f]{64}$/u;
const gitCommitSnapshotPath = /^\/source-snapshots\/git-commit\/[0-9a-f]{64}$/u;
const reservedSnapshotNamespace = (value: string) => {
  const canonical = normalizedSourcePath(value);
  return canonical === '/source-snapshots' || canonical.startsWith('/source-snapshots/');
};
const baseBroadSourceRoots = [
  '/',
  '/Users',
  '/home',
  '/Volumes',
  '/private',
  '/private/tmp',
  '/private/var/tmp',
  '/tmp',
  '/var',
  '/var/tmp',
  '/usr',
  '/etc',
  '/opt',
  '/mnt',
  '/media',
  '/root',
] as const;
const macDataVolumeRoot = '/System/Volumes/Data';
const broadSourceRoots = new Set([
  ...baseBroadSourceRoots,
  macDataVolumeRoot,
  ...baseBroadSourceRoots
    .filter((root) => root !== '/')
    .map((root) => `${macDataVolumeRoot}${root}`),
]);
const unsafeSourceRootCharacters = /[,$'"#\\\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u;

function normalizedSourcePath(sourceRoot: string): string {
  const segments: string[] = [];
  for (const segment of sourceRoot.split('/')) {
    if (!segment || segment === '.') continue;
    if (segment === '..') {
      segments.pop();
    } else {
      segments.push(segment);
    }
  }
  return `/${segments.join('/')}`;
}

function isBroadSourceRoot(sourceRoot: string): boolean {
  return broadSourceRoots.has(normalizedSourcePath(sourceRoot));
}

export function sourceAuthorizationCommand(sourceRoot: string, installationId: unknown, operation: 'add' | 'remove' = 'add'): string | null {
  if (
    typeof installationId !== 'string' || !/^[a-f0-9]{12}$/u.test(installationId)
    || sourceRoot !== sourceRoot.trim()
    || !sourceRoot.startsWith('/')
    || isBroadSourceRoot(sourceRoot)
    || reservedSnapshotNamespace(sourceRoot)
    || unsafeSourceRootCharacters.test(sourceRoot)
  ) return null;
  const bytes = new TextEncoder().encode(sourceRoot);
  if (bytes.length === 0 || bytes.length > 4096) return null;
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
  return `KODESEC_EXPECT_INSTALLATION_ID=${installationId} ${operation === 'remove' ? 'KODESEC_SOURCE_OPERATION=remove ' : ''}KODESEC_SOURCE_ROOT_B64=${encoded} make apply-source`;
}

export function safeAllowedSourceRoots(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  const roots = values.filter((value): value is string => {
    if (typeof value !== 'string' || value !== value.trim() || !value.startsWith('/')) return false;
    if (isBroadSourceRoot(value) || reservedSnapshotNamespace(value) || unsafeSourceRootCharacters.test(value)) return false;
    const length = new TextEncoder().encode(value).length;
    return length > 0 && length <= 4096;
  });
  return [...new Set(roots)].slice(0, 32);
}

export function projectSourceAdapter(repoPath: string): ProjectSourceAdapter {
  return nativeWindowsSnapshotPath.test(repoPath) ? 'native_windows_snapshot'
    : gitCommitSnapshotPath.test(repoPath) ? 'git_commit_snapshot' : 'mounted_directory';
}

export function snapshotProjectScanGuidance(adapter: ProjectSourceAdapter | null): string | null {
  if (adapter === 'git_commit_snapshot') return 'This project contains immutable Git snapshots, not a mounted checkout. In the exact repository’s VS Code window, use CodeSecurity: Check Outgoing Commits… to check the intended outgoing history. Do not authorize this reserved identity as a source mount.';
  if (adapter === 'native_windows_snapshot') return 'Native Windows snapshot projects must be refreshed and scanned from their exact native VS Code workspace. Start a fresh CodeSecurity scan there; the reserved identity is not a source mount.';
  return null;
}

export function projectSourceNavigationDisabledReason(repoPath: string | undefined): string | null {
  if (!repoPath) return 'Refresh this scan and its project before opening source in VS Code.';
  const canonical = normalizedSourcePath(repoPath);
  if (canonical === '/source-snapshots/git-commit' || canonical.startsWith('/source-snapshots/git-commit/')) {
    return 'This finding belongs to an immutable Git snapshot, not the current checkout. Opening historical snapshot source in VS Code is not supported yet; a matching filename could contain different code. Review the retained finding details and snippet below.';
  }
  return null;
}

export function authoritativeSourceRoots(state: SourceBoundaryLoadState): readonly string[] {
  return state.status === 'ready' ? state.roots : [];
}

export async function resolveSourceBoundaryLoad(
  loadConfig: () => Promise<{ allowed_roots: unknown; installation_id: unknown }>,
): Promise<SourceBoundaryLoadState> {
  try {
    const config = await loadConfig();
    if (typeof config.installation_id !== 'string' || !/^[a-f0-9]{12}$/u.test(config.installation_id)) {
      throw new Error('Runtime installation identity is unavailable.');
    }
    return { status: 'ready', roots: safeAllowedSourceRoots(config.allowed_roots), installationId: config.installation_id };
  } catch {
    return {
      status: 'error',
      reason: 'The current read-only source boundary could not be loaded. Reload it before scanning; no retained registration response is authoritative.',
    };
  }
}

export function commitCurrentSourceBoundaryLoad(
  loadGeneration: number,
  currentGeneration: number,
  state: SourceBoundaryLoadState,
  commit: (state: SourceBoundaryLoadState) => void,
): boolean {
  if (loadGeneration !== currentGeneration) return false;
  commit(state);
  return true;
}

export function mountedProjectIsAuthorized(repoPath: string, state: SourceBoundaryLoadState): boolean {
  return projectSourceAdapter(repoPath) === 'mounted_directory'
    && sourcePathIsAuthorized(repoPath, authoritativeSourceRoots(state));
}

export function sourcePathIsAuthorized(repoPath: string, roots: readonly string[]): boolean {
  return !reservedSnapshotNamespace(repoPath)
    && roots.some((root) => repoPath === root || repoPath.startsWith(`${root.replace(/\/+$/u, '')}/`));
}

export function summarizeSourceRegistrations(
  projects: readonly RegisteredSource[],
  allowedRoots: readonly string[],
): SourceRegistrationSummary {
  const nativeCount = projects.reduce(
    (count, project) => count + Number(projectSourceAdapter(project.repo_path) === 'native_windows_snapshot'),
    0,
  );
  const gitCount = projects.reduce((count, project) => count + Number(projectSourceAdapter(project.repo_path) === 'git_commit_snapshot'), 0);
  const snapshotCount = nativeCount + gitCount;
  const mountedCount = projects.length - snapshotCount;
  const insideCount = projects.reduce(
    (count, project) => count + Number(mountedProjectIsAuthorized(project.repo_path, {
      status: 'ready',
      roots: allowedRoots,
    })),
    0,
  );
  const outsideCount = mountedCount - insideCount;
  const subject = mountedCount === 1 ? 'project is' : 'projects are';
  const outsideNotice = outsideCount > 0
    ? ` ${outsideCount} registered mounted ${outsideCount === 1 ? 'project remains' : 'projects remain'} outside this boundary; ${outsideCount === 1 ? 'it stays' : 'they stay'} visible, but Web scanning requires re-authorizing that source or deleting the registration.`
    : '';
  const snapshotNotice = nativeCount > 0
    ? ` ${nativeCount} native Windows ${nativeCount === 1 ? 'snapshot remains' : 'snapshots remain'} available only through a fresh scan from the exact native VS Code workspace; ${nativeCount === 1 ? 'it is not a mounted source path' : 'they are not mounted source paths'}.`
    : '';
  const gitNotice = gitCount > 0
    ? ` ${gitCount} immutable Git snapshot ${gitCount === 1 ? 'project requires' : 'projects require'} Check Outgoing Commits in the exact repository’s VS Code window; these are not mounted source paths.` : '';
  return {
    insideCount,
    outsideCount,
    snapshotCount,
    message: `${insideCount} of ${mountedCount} registered mounted ${subject} inside the current read-only source boundary.${outsideNotice}${snapshotNotice}${gitNotice}`,
  };
}
