import type { GitPushPolicy, Project } from './api';

export type ProtectionMatch = { policy: GitPushPolicy | null; ambiguous: boolean };
type MatchOptions = { signal?: AbortSignal; subtle?: Pick<SubtleCrypto, 'digest'> | null };
const SHA256 = /^[0-9a-f]{64}$/;
function checkAborted(signal?: AbortSignal) {
  if (signal?.aborted) throw new DOMException('Source verification aborted', 'AbortError');
}
export async function nativeWindowsSourceId(root: string, options: MatchOptions = {}): Promise<string | null> {
  checkAborted(options.signal);
  if (!/^[A-Za-z]:\\/.test(root)) return null;
  const subtle = options.subtle === undefined ? globalThis.crypto?.subtle : options.subtle;
  if (!subtle) throw new Error('Source identity verification unavailable');
  // Matches register_push_repository: remove trailing backslashes, NFC, lower,
  // then hash UTF-8 bytes with the native source domain separator.
  const normalized = root.replace(/\\+$/, '').normalize('NFC').toLowerCase();
  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(`native-windows\u0000${normalized}`));
  checkAborted(options.signal);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
export async function exactProjectProtection(project: Pick<Project, 'id' | 'repo_path'>,
  policies: GitPushPolicy[], options: MatchOptions = {}): Promise<ProtectionMatch> {
  checkAborted(options.signal);
  const native = /^\/source-snapshots\/native-windows\/([0-9a-f]{64})$/.exec(project.repo_path);
  const git = /^\/source-snapshots\/git-commit\/([0-9a-f]{64})$/.exec(project.repo_path);
  const hashes = new Map<string, Promise<string | null>>();
  const candidates = policies.filter((policy) => policy.project_id === project.id);
  const verified = await Promise.all(candidates.map(async (policy) => {
    if (git) return SHA256.test(policy.repository_id) && git[1] === policy.repository_id;
    if (native) {
      let hash = hashes.get(policy.root_path);
      if (!hash) { hash = nativeWindowsSourceId(policy.root_path, options); hashes.set(policy.root_path, hash); }
      return native[1] === await hash;
    }
    // Canonical snapshot namespace cannot fall through to a mounted root match.
    if (project.repo_path.startsWith('/source-snapshots/')) return false;
    return policy.root_path === project.repo_path;
  }));
  checkAborted(options.signal);
  const matches = candidates.filter((_, index) => verified[index]);
  return { policy: matches.length === 1 ? matches[0] : null, ambiguous: matches.length > 1 };
}

export const protectionSettingsHash = (repositoryId?: string) => repositoryId
  ? `#git-push-protection-${encodeURIComponent(repositoryId)}` : '#git-push-protection';
