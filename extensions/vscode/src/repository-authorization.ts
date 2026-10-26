import { MAX_WORKSPACE_SCAN_ROOTS } from './source';

const broadRoots = new Set(['/', '/Users', '/home', '/Volumes', '/private', '/private/tmp',
  '/private/var/tmp', '/tmp', '/var', '/var/tmp', '/usr', '/etc', '/opt', '/mnt', '/media', '/root']);
const reserved = ['/bin', '/sbin', '/usr', '/lib', '/lib64', '/etc', '/proc', '/sys', '/dev', '/run', '/data', '/app'];

/** Encodes an explicitly reviewed list; only the host helper can authorize it. */
export function reviewedRepositoryAuthorizationCommand(roots: readonly string[], installationId: unknown): string | null {
  if (typeof installationId !== 'string' || !/^[0-9a-f]{12}$/u.test(installationId)
    || !Array.isArray(roots) || roots.length < 1 || roots.length > MAX_WORKSPACE_SCAN_ROOTS
    || new Set(roots).size !== roots.length) return null;
  for (const root of roots) {
    if (typeof root !== 'string' || !root.startsWith('/') || root !== root.trim()
      || /[\p{Cc}\p{Cf}\p{Cs}$'"#\\,]/u.test(root)
      || root.slice(1).split('/').some((part) => !part || part === '.' || part === '..')
      || new TextEncoder().encode(root).length > 4096) return null;
    const physical = root.replace(/^\/System\/Volumes\/Data(?=\/|$)/u, '') || '/';
    if (broadRoots.has(physical) || reserved.some((prefix) => physical === prefix || physical.startsWith(`${prefix}/`))) return null;
    if (roots.some((other) => root !== other && root.startsWith(`${other}/`))) return null;
  }
  const bytes = new TextEncoder().encode(JSON.stringify(roots));
  if (bytes.length > 64 * 1024) return null;
  // Encode the complete vector as data; no path is interpolated into shell code.
  const encoded = Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
  return `KODESEC_EXPECT_INSTALLATION_ID=${installationId} KODESEC_SOURCE_ROOTS_B64=${encoded} make apply-source`;
}
