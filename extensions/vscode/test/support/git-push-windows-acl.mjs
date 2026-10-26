import { win32 } from 'node:path';
import { spawnSync } from 'node:child_process';
import { readWindowsHandoffAclProof } from './windows-handoff-acl.mjs';

const require = (condition, message) => { if (!condition) throw new Error(message); };

/** Validate effective DACL metadata using the trustee/rights contract from
 * production windows-private-path.ts. No permission changes or credential reads.
 * The maintained collector traverses the exact profile → namespace → config.
 */
export function validateScmWindowsAclProof(proof, relativePath) {
  const parts = relativePath.split('/');
  const paths = ['', ...parts.map((_, i) => parts.slice(0, i + 1).join('/'))];
  require(parts.length === 2 && parts[0] === 'git-push-v1' && /^[a-f0-9]{64}\.json$/u.test(parts[1])
    && proof?.schema === 'lomo-windows-private-handoff-acl/v1'
    && Object.keys(proof).sort().join(',') === 'current_sid,entries,schema'
    && /^S-1-[0-9]{1,15}(?:-[0-9]{1,10}){1,15}$/u.test(proof.current_sid)
    && Array.isArray(proof.entries) && proof.entries.length === paths.length,
  'SCM Windows DACL proof is malformed or does not cover the exact configuration.');
  const trustees = new Set([proof.current_sid, 'S-1-5-18', 'S-1-5-32-544']);
  for (const [i, entry] of proof.entries.entries()) {
    const directory = i < paths.length - 1;
    require(entry && Object.keys(entry).sort().join(',') === 'directory,owner_sid,protected,relative_path,reparse,rules'
      && entry.relative_path === paths[i] && entry.directory === directory && entry.reparse === false
      && entry.owner_sid === proof.current_sid && typeof entry.protected === 'boolean'
      && Array.isArray(entry.rules) && entry.rules.length >= 1 && entry.rules.length <= 16,
    'SCM Windows DACL owner, path or metadata is not exact.');
    let ownerFull = false;
    for (const rule of entry.rules) {
      require(rule && Object.keys(rule).sort().join(',') === 'allow,inheritance,propagation,rights,sid'
        && trustees.has(rule.sid) && rule.allow === true && Number.isSafeInteger(rule.rights)
        && rule.rights > 0 && (rule.rights & 0x1f01ff) === rule.rights
        && Number.isInteger(rule.inheritance) && rule.inheritance >= 0 && rule.inheritance <= 3
        && Number.isInteger(rule.propagation) && rule.propagation >= 0 && rule.propagation <= 3
        && (directory || rule.inheritance === 0 && rule.propagation === 0),
      'SCM Windows DACL contains a denied, broad or malformed effective rule.');
      if (rule.sid === proof.current_sid && rule.rights === 0x1f01ff && !(rule.propagation & 2)) ownerFull = true;
    }
    require(ownerFull, 'SCM Windows DACL does not grant the current owner effective full control.');
  }
}

export function scmWindowsAclReader(root) {
  // The maintained handoff schema projects effective rules without the
  // IsInherited flag; this witness verifies every effective trustee/right, not
  // the production verifier's additional protected/inherited consistency bit.
  const systemRoot = process.env.SystemRoot;
  require(typeof systemRoot === 'string' && /^[A-Za-z]:\\/u.test(systemRoot)
    && win32.normalize(systemRoot) === systemRoot && !/[<>:"/|?*\p{Cc}\p{Cf}]/u.test(systemRoot.slice(3))
    && systemRoot.slice(3).split('\\').every(part => part && part !== '.' && part !== '..' && !/[. ]$/u.test(part)),
  'SCM Windows DACL requires the exact native SystemRoot PowerShell path.');
  const executable = win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const deadline = Date.now() + 60_000;
  return path => {
    const remaining = deadline - Date.now();
    require(remaining > 0, 'SCM Windows DACL observation exceeded its whole 60s deadline.');
    const proof = readWindowsHandoffAclProof(path, root, (_pathExecutable, args, options) =>
      spawnSync(executable, args, { ...options, timeout: Math.min(options.timeout, remaining) }));
    require(Date.now() <= deadline, 'SCM Windows DACL observation exceeded its whole 60s deadline.');
    validateScmWindowsAclProof(proof, win32.relative(root, path).replaceAll('\\', '/'));
    return proof;
  };
}

