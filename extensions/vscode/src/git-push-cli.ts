import { CodeSecurityRequestError } from './request-error';
import { GitPushBoundaryError, GitPushPlan, GIT_PUSH_LIMITS, inspectGitRepository, planGitPush, readGitRemoteAdvertisement } from './git-push-objects';
import { gitPushClient, readGitPushConfiguration, verifyGitPushConfiguration, verifyGitPushHelper } from './git-push-host';
import { validateGitPushPolicy } from './git-push-ui';
import { canonicalWindowsLocalPath } from './windows-private-path';

/** Git's POSIX shell passes the generated config argument with forward
 * separators. Normalize only that exact drive-path spelling at CLI ingress;
 * private storage readers keep their canonical path and ACL checks. */
export function normalizeGitHookConfigurationArgument(value: string,
  platform: NodeJS.Platform = process.platform): string {
  if (platform !== 'win32') return value;
  if (/^[A-Za-z]:\//u.test(value) && !value.includes('\\')) {
    const native = value.replaceAll('/', '\\');
    if (canonicalWindowsLocalPath(native) && native.replaceAll('\\', '/') === value) return native;
  }
  if (canonicalWindowsLocalPath(value)) return value;
  throw new GitPushBoundaryError('git_push_host_unverified', 'The hook configuration argument is not a canonical local Windows path.');
}

const positive = (value: unknown) => Number.isSafeInteger(value) && (value as number) > 0;
const SHA = /^[0-9a-f]{64}$/u;
export function decodeGitPushInput(bytes: Buffer): string {
  const input = bytes.toString('utf8');
  if (!Buffer.from(input, 'utf8').equals(bytes)) {
    throw new GitPushBoundaryError('push_input_invalid', 'Git supplied outgoing references with unsupported text bytes.');
  }
  return input;
}
export type GitPushCheck = Readonly<{
  repository_id: string; policy_revision: number; plan_digest: string;
  decision: 'pass' | 'blocked' | 'off'; reason_code: string | null;
  missing_trees: readonly string[];
  scans: readonly Readonly<{ tree_oid: string; scan_id: number; job_id: number; status: string;
    gate_decision: string | null; revision: number; findings_revision: number }>[];
  preflight_revision?: string; evidence_digest?: string;
}>;
export function readGitPushCheck(value: unknown, plan: GitPushPlan, policyRevision: number): GitPushCheck | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const item = value as Record<string, unknown>;
  const fields = ['repository_id', 'policy_revision', 'plan_digest', 'decision', 'reason_code', 'missing_trees', 'scans', 'preflight_revision', 'evidence_digest'];
  if (Object.keys(item).some((key) => !fields.includes(key))
    || item.repository_id !== plan.repository_id || item.policy_revision !== policyRevision
    || item.plan_digest !== plan.digest || !['pass', 'blocked', 'off'].includes(item.decision as string)
    || item.reason_code !== null && (typeof item.reason_code !== 'string' || !/^[a-z][a-z0-9_]{0,79}$/u.test(item.reason_code))
    || !Array.isArray(item.missing_trees) || item.missing_trees.length > plan.trees.length
    || item.missing_trees.some((tree) => typeof tree !== 'string' || !plan.trees.includes(tree))
    || new Set(item.missing_trees).size !== item.missing_trees.length
    || item.preflight_revision !== undefined && (typeof item.preflight_revision !== 'string' || !SHA.test(item.preflight_revision))
    || item.evidence_digest !== undefined && (typeof item.evidence_digest !== 'string' || !SHA.test(item.evidence_digest))
    || !Array.isArray(item.scans) || item.scans.length > plan.trees.length) return undefined;
  const seen = new Set<string>();
  for (const scan of item.scans) {
    if (!scan || typeof scan !== 'object' || Array.isArray(scan)
      || Object.keys(scan).sort().join(',') !== 'findings_revision,gate_decision,job_id,revision,scan_id,status,tree_oid'
      || typeof scan.tree_oid !== 'string' || !plan.trees.includes(scan.tree_oid) || seen.has(scan.tree_oid) || item.missing_trees.includes(scan.tree_oid)
      || !positive(scan.scan_id) || !positive(scan.job_id) || !positive(scan.revision) || !positive(scan.findings_revision)
      || !['queued', 'running', 'completed', 'partial', 'failed', 'cancelled'].includes(scan.status)
      || ![null, 'pass', 'fail', 'incomplete', 'not_configured'].includes(scan.gate_decision)) return undefined;
    seen.add(scan.tree_oid);
  }
  if (item.decision === 'pass' && (item.reason_code !== null || item.missing_trees.length !== 0
    || seen.size !== plan.trees.length || !item.preflight_revision || !item.evidence_digest
    || item.scans.some((scan) => scan.status !== 'completed' || scan.gate_decision !== 'pass'))) return undefined;
  return Object.freeze({ ...item, missing_trees: Object.freeze([...item.missing_trees]),
    scans: Object.freeze(item.scans.map((scan) => Object.freeze({ ...scan }))) }) as GitPushCheck;
}

export function validateGitPushCheck(value: unknown, plan: GitPushPlan, policyRevision: number): boolean {
  return readGitPushCheck(value, plan, policyRevision)?.decision === 'pass';
}

export async function runGitPushHook(configurationPath: string, input: string, destination: string): Promise<number> {
  const configuration = await readGitPushConfiguration(configurationPath);
  await verifyGitPushHelper(configuration);
  // Applied Off verifies only its private setting and this helper, never Git
  // history/source eligibility or a running service.
  if (!configuration.enabled) return 0;
  await verifyGitPushConfiguration(configuration);
  const client = gitPushClient(configuration);
  const policy = validateGitPushPolicy(await client.request(`/v1/git/push-protection/${configuration.repository.repositoryId}`), configuration.repository);
  if (!policy.enabled || policy.revision !== configuration.revision
    || !policy.members.some((member) => member.client_slot === configuration.repository.clientSlot
      && member.generation === configuration.repository.generation && member.state === 'approved')) {
    throw new GitPushBoundaryError('push_apply_required', 'Review and apply the current repository setting in VS Code before pushing.');
  }
  const repository = await inspectGitRepository(configuration.repository.root);
  const advertisement = await readGitRemoteAdvertisement(repository, destination);
  const plan = await planGitPush(repository, input, advertisement);
  const proof = await client.request(`/v1/git/push-protection/${repository.repositoryId}/check`, {
    method: 'POST', body: JSON.stringify(plan),
  });
  if (!validateGitPushCheck(proof, plan, policy.revision)) {
    throw new GitPushBoundaryError('push_check_required', 'The exact outgoing commits do not have current passing scan evidence. Check outgoing commits in VS Code and retry.');
  }
  const current = await readGitPushConfiguration(configurationPath);
  if (JSON.stringify(current) !== JSON.stringify(configuration)) {
    throw new GitPushBoundaryError('push_apply_required', 'The applied repository setting changed during verification. Retry with its current setting.');
  }
  await verifyGitPushConfiguration(current);
  return 0;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  // Must precede every file, credential, source, or HTTP observation.
  if (args.length !== 4 || args[0] !== '--hook' || !args[1] || !args[2] || !args[3]) {
    process.stderr.write('Usage: git-push-cli --hook <private-config> <remote-name> <destination>\n');
    process.exitCode = 2; return;
  }
  try {
    const configurationPath = normalizeGitHookConfigurationArgument(args[1]);
    const configuration = await readGitPushConfiguration(configurationPath);
    await verifyGitPushHelper(configuration);
    if (!configuration.enabled) {
      // Git still writes its input pipe. Drain without retaining or applying
      // protection's semantic/size limits while the trusted setting is Off.
      for await (const _chunk of process.stdin) { /* no source retained */ }
      process.exitCode = 0; return;
    }
    let length = 0;
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      length += buffer.length;
      if (length > GIT_PUSH_LIMITS.inputBytes) throw new GitPushBoundaryError('push_input_invalid', 'Outgoing references exceed the hook input bound.');
      chunks.push(buffer);
    }
    const input = decodeGitPushInput(Buffer.concat(chunks));
    process.exitCode = await runGitPushHook(configurationPath, input, args[3]);
  } catch (error) {
    const code = error instanceof GitPushBoundaryError || error instanceof CodeSecurityRequestError
      ? error.code : undefined;
    const safeCode = typeof code === 'string' && /^[a-z][a-z0-9_.-]{0,79}$/u.test(code) ? code : 'push_verification_unavailable';
    // Codes only: API messages and source/credential contents never enter hook output.
    process.stderr.write(`Lomo blocked this push (${safeCode}). Review Push Protection in the owning VS Code profile and check the exact outgoing commits before retrying.\n`);
    process.exitCode = 1;
  }
}

if (require.main === module) void main();
