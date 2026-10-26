import { CodeSecurityRequestError } from './request-error';

export type GitPushRepository = Readonly<{
  repositoryId: string;
  projectId: number | null;
  name: string;
  root: string;
  gitDirectory: string;
  clientSlot: string;
  generation: number;
}>;
export type GitPushPolicy = Readonly<{
  repository_id: string;
  name: string;
  project_id: number;
  root_path: string;
  git_directory: string;
  revision: number;
  enabled: boolean;
  observed_state: 'not_installed' | 'installed' | 'needs_repair';
  observed_revision: number | null;
  observed_at: string | null;
  hook_digest: string | null;
  reason_code: 'host_setup_required' | 'hook_missing_or_changed' | 'policy_changed' | null;
  members: readonly Readonly<{
    client_slot: string;
    generation: number;
    name: string;
    state: 'requested' | 'approved' | 'revoked';
    requested_at: string;
    approved_at: string | null;
  }>[];
}>;
export type GitPushHostStatus = Readonly<{
  state: 'not_installed' | 'installed' | 'needs_repair';
  enabled: boolean | null;
  revision: number | null;
  hookDigest: string | null;
}>;
type Choice = Readonly<{ id: 'setup' | 'toggle' | 'apply' | 'refresh' | 'settings' | 'remove'; label: string; detail: string }>;
export type GitPushUiAdapters = Readonly<{
  chooseRepository(): Promise<GitPushRepository | undefined>;
  assertCurrent(repository: GitPushRepository): void;
  request(path: string, init?: RequestInit): Promise<unknown>;
  inspectPolicy(repository: GitPushRepository, policy: GitPushPolicy | null): Promise<GitPushHostStatus>;
  applyPolicy(repository: GitPushRepository, policy: GitPushPolicy): Promise<GitPushHostStatus>;
  removePolicy(repository: GitPushRepository, policy: GitPushPolicy | null): Promise<Readonly<{
    localRemoved: true; registrationRemoved: boolean; cleanup: 'complete' | 'retryable' | 'review_required'; reasonCode: string | null;
  }>>;
  choose(choices: readonly Choice[], title: string, description: string): Promise<Choice['id'] | undefined>;
  confirm(title: string, detail: string, action: string): Promise<boolean>;
  showStatus(message: string): Promise<void>;
  openSettings(): Promise<void>;
}>;

const BASE = '/v1/git/push-protection';
const SHA256 = /^[0-9a-f]{64}$/u;
const POLICY_FIELDS = [
  'repository_id', 'name', 'project_id', 'root_path', 'git_directory', 'revision', 'enabled', 'observed_state',
  'observed_revision', 'observed_at', 'hook_digest', 'reason_code', 'members',
];
const BYPASS_WARNING = 'Local commits remain allowed. This opt-in hook checks pushes only from this clone; '
  + 'Git --no-verify, a changed hook, or another clone can bypass it. No remote enforcement or global Git setting is changed.';

function positiveRevision(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 1 && (value as number) <= 2_147_483_647;
}
function invalidPolicy(): CodeSecurityRequestError {
  return new CodeSecurityRequestError('Push protection returned an invalid or different repository policy. Refresh before changing it.');
}
function instant(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 64
    && /^\d{4}-\d\d-\d\dT[^\p{Cc}\p{Cf}]+(?:Z|[+-]\d\d:\d\d)$/u.test(value)
    && Number.isFinite(Date.parse(value));
}
function members(value: unknown): value is GitPushPolicy['members'] {
  if (!Array.isArray(value) || value.length > 32) return false;
  const identities = new Set<string>();
  return value.every((item) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)
      || Object.keys(item).sort().join(',') !== 'approved_at,client_slot,generation,name,requested_at,state'
      || typeof item.client_slot !== 'string' || !/^ks1_[A-Za-z0-9_-]{43}$/u.test(item.client_slot)
      || !positiveRevision(item.generation) || typeof item.name !== 'string'
      || !item.name || item.name.length > 120 || item.name.trim() !== item.name || /[\p{Cc}\p{Cf}]/u.test(item.name)
      || !['requested', 'approved', 'revoked'].includes(item.state)
      || !instant(item.requested_at) || item.approved_at !== null && !instant(item.approved_at)
      || item.state === 'approved' && item.approved_at === null) return false;
    const key = `${item.client_slot}:${item.generation}`;
    if (identities.has(key)) return false;
    identities.add(key); return true;
  });
}
export function validateGitPushPolicy(value: unknown, repository: GitPushRepository): GitPushPolicy {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalidPolicy();
  const item = value as Record<string, unknown>;
  if (Object.keys(item).length !== POLICY_FIELDS.length || POLICY_FIELDS.some((field) => !Object.hasOwn(item, field))
    || !SHA256.test(repository.repositoryId) || !positiveRevision(item.project_id)
    || item.repository_id !== repository.repositoryId || repository.projectId !== null && item.project_id !== repository.projectId
    || item.root_path !== repository.root || item.git_directory !== repository.gitDirectory
    || typeof item.name !== 'string' || item.name.length < 1 || item.name.length > 120
    || item.name !== item.name.trim() || /[\p{Cc}\p{Cf}]/u.test(item.name)
    || !positiveRevision(item.revision) || typeof item.enabled !== 'boolean'
    || !['not_installed', 'installed', 'needs_repair'].includes(item.observed_state as string)
    || item.observed_revision !== null && (!positiveRevision(item.observed_revision) || item.observed_revision > item.revision)
    || item.observed_at !== null && !instant(item.observed_at)
    || item.hook_digest !== null && (typeof item.hook_digest !== 'string' || !SHA256.test(item.hook_digest))
    || ![null, 'host_setup_required', 'hook_missing_or_changed', 'policy_changed'].includes(item.reason_code as string | null)
    || item.observed_state === 'installed' && (!item.hook_digest || !item.observed_revision || !item.observed_at)
    || !members(item.members)
  ) throw invalidPolicy();
  return Object.freeze({ ...item, members: Object.freeze(item.members.map((member) => Object.freeze({ ...member }))) }) as GitPushPolicy;
}

function approved(policy: GitPushPolicy | null, repository: GitPushRepository): boolean {
  return policy?.members.some((member) => member.client_slot === repository.clientSlot
    && member.generation === repository.generation && member.state === 'approved') === true;
}

export function pushProtectionStatus(policy: GitPushPolicy | null, host: GitPushHostStatus): string {
  const requested = policy ? policy.enabled ? 'On' : 'Off' : 'Not set up';
  const applied = host.state === 'not_installed' ? 'Not installed'
    : host.state === 'needs_repair' ? 'Needs repair'
      : host.enabled === null ? 'Unknown' : host.enabled ? 'On' : 'Off';
  const matching = policy && host.state === 'installed' && host.revision === policy.revision && host.enabled === policy.enabled;
  return `Requested: ${requested} · Local hook: ${applied}${matching ? ' · current setting applied' : policy ? ' · review/apply required' : ''}`;
}

function validateHostStatus(host: GitPushHostStatus): GitPushHostStatus {
  if (!host || typeof host !== 'object'
    || Object.keys(host).sort().join(',') !== 'enabled,hookDigest,revision,state'
    || !['not_installed', 'installed', 'needs_repair'].includes(host.state)
    || host.enabled !== null && typeof host.enabled !== 'boolean'
    || host.revision !== null && !positiveRevision(host.revision)
    || host.hookDigest !== null && (typeof host.hookDigest !== 'string' || !SHA256.test(host.hookDigest))
    || host.state === 'installed' && (host.enabled === null || host.revision === null || host.hookDigest === null)) {
    throw new CodeSecurityRequestError('The local hook state could not be verified. No installed protection is claimed.');
  }
  return Object.freeze({ ...host });
}

/** UI orchestration only; Git identity, host writes and gate policy have separate owners. */
export async function runGitPushProtection(adapters: GitPushUiAdapters): Promise<void> {
  let repository = await adapters.chooseRepository();
  if (!repository) return;
  const current = () => adapters.assertCurrent(repository!);
  current();
  const indexedProjectId = repository.projectId;
  let serviceUnavailable = false;
  const path = `${BASE}/${repository.repositoryId}`;
  const read = async (): Promise<GitPushPolicy | null> => {
    current();
    try {
      const value = await adapters.request(path);
      current();
      // Management can reveal an old binding for explicit removal, but must
      // never turn that observation into an automatic project reassignment.
      return validateGitPushPolicy(value, { ...repository!, projectId: null });
    } catch (error) {
      if (error instanceof CodeSecurityRequestError && error.status === 404 && error.code === 'push_setup_required') {
        current(); return null;
      }
      throw error;
    }
  };
  const inspect = async (policy: GitPushPolicy | null): Promise<GitPushHostStatus> => {
    current();
    const host = await adapters.inspectPolicy(repository!, policy);
    current();
    return validateHostStatus(host);
  };
  let policy: GitPushPolicy | null;
  try { policy = await read(); }
  catch (error) {
    if (!(error instanceof CodeSecurityRequestError) || !(error.retryable || error.status !== undefined && error.status >= 500)) throw error;
    serviceUnavailable = true; policy = null;
  }
  if (policy) repository = Object.freeze({ ...repository, projectId: policy.project_id });
  let host = await inspect(policy);
  const hasApproval = approved(policy, repository);
  const bindingChanged = policy !== null && indexedProjectId !== null && indexedProjectId !== policy.project_id;
  const pendingLocalReview = !policy && host.state !== 'not_installed'
    || host.state === 'needs_repair' && host.enabled === null && host.revision !== null;
  const choices: Choice[] = serviceUnavailable || bindingChanged || pendingLocalReview ? [] : hasApproval ? [
    { id: 'toggle', label: policy!.enabled ? 'Turn protection off…' : 'Turn protection on…', detail: 'Save the requested setting, then apply it to this exact repository hook.' },
    { id: 'apply', label: 'Apply requested setting…', detail: 'Review and apply the requested setting to the local hook.' },
    { id: 'refresh', label: 'Refresh host status', detail: 'Inspect this clone and refresh its saved policy without changing the hook.' },
    { id: 'settings', label: 'Open protection settings', detail: 'View requested settings and last host observations in the dashboard.' },
  ] : [
    { id: 'setup', label: 'Request push protection access…', detail: 'Request approval for this exact repository and IDE profile in the paired dashboard. No hook is installed yet.' },
    { id: 'settings', label: 'Open protection settings', detail: 'View requested settings and last host observations in the dashboard.' },
  ];
  if (policy || host.state !== 'not_installed') choices.push({ id: 'remove', label: 'Remove push protection from this clone…',
    detail: 'Remove only this profile’s exact hook and registration. Scans, projects, findings and other hooks remain.' });
  if (serviceUnavailable || bindingChanged || pendingLocalReview) choices.push({ id: 'settings', label: 'Open protection settings', detail: 'Review the existing registration without rebinding it.' });
  const description = serviceUnavailable ? 'Control plane unavailable. Local removal can retain an exact server-cleanup retry receipt.'
    : bindingChanged ? `Retained protection belongs to project #${policy!.project_id}; current workspace project is #${indexedProjectId}. Remove the old registration before explicit setup; no automatic rebinding.`
      : pushProtectionStatus(policy, host);
  const choice = await adapters.choose(choices, `Protect pushes · ${repository.name}`, description);
  if (!choice) return;
  if (!choices.some((item) => item.id === choice)) throw invalidPolicy();
  current();
  if (choice === 'settings') { await adapters.openSettings(); return; }
  if (choice === 'remove') {
    if (!await adapters.confirm('Remove push protection from this clone?',
      `Repository: ${repository.root}\n\nRemoving this local check allows failed or unscanned commits to be pushed. `
      + 'Only the exact owning profile’s unchanged Lomo hook, repository registration and repository-specific editor grants are removed. Global IDE/browser pairing remains. No scans, projects, findings, credentials, remotes or other hooks are deleted. '
      + 'If server cleanup is interrupted, its exact private retry receipt is retained. No replacement project is registered. '
      + BYPASS_WARNING, 'Remove push protection')) return;
    current();
    const result = await adapters.removePolicy(repository, policy);
    current();
    if (!result || Object.keys(result).sort().join(',') !== 'cleanup,localRemoved,reasonCode,registrationRemoved'
      || result.localRemoved !== true || typeof result.registrationRemoved !== 'boolean'
      || !['complete', 'retryable', 'review_required'].includes(result.cleanup)
      || result.registrationRemoved !== (result.cleanup === 'complete')
      || result.reasonCode !== null && (typeof result.reasonCode !== 'string' || !/^[a-z][a-z0-9_]{0,79}$/u.test(result.reasonCode))) {
      throw new CodeSecurityRequestError('Hook removal could not be confirmed. Review the exact host state before retrying.');
    }
    await adapters.showStatus(result.registrationRemoved
      ? `${repository.name}: local push protection and its server registration were removed. Scans, projects and findings remain. No new registration was created.`
      : result.cleanup === 'retryable'
        ? `${repository.name}: the local hook is removed, but server cleanup is pending. Reconnect, then choose Remove again to retry the same retained request; no new or changed hook will be removed.`
        : `${repository.name}: the local hook is removed, but server cleanup needs owner review${result.reasonCode ? ` (${result.reasonCode})` : ''}. Review the original registration and exact IDE generation in Settings. The retained request is not rebound to a new revision or project.`);
    return;
  }
  if (choice === 'refresh') {
    policy = await read(); host = await inspect(policy);
    await adapters.showStatus(`${repository.name}: ${pushProtectionStatus(policy, host)}. No hook was changed or push approved.`);
    return;
  }
  if (choice !== 'setup' && !hasApproval) throw invalidPolicy();
  if (choice === 'setup') {
    if (!await adapters.confirm('Request repository push protection access?',
      `Repository: ${repository.root}\n\nAuthorize immutable committed files from this exact repository for local scanner snapshots. No filesystem mount or remote changes. `
        + `Approve this exact IDE profile in the paired dashboard before applying a hook. ${BYPASS_WARNING}`, 'Request access')) return;
    current();
    policy = validateGitPushPolicy(await adapters.request(BASE, {
      method: 'POST', body: JSON.stringify({ repository_id: repository.repositoryId, name: repository.name,
        root_path: repository.root, git_directory: repository.gitDirectory, project_id: repository.projectId }),
    }), repository);
    current();
    const member = policy.members.find((item) => item.client_slot === repository!.clientSlot && item.generation === repository!.generation);
    if (!member || member.state === 'revoked') throw new CodeSecurityRequestError('Repository access was not requested. Review this exact profile in Settings.');
    // The paired Settings panel shows the exact pending editor request and
    // current protection state. A VS Code information toast can cover its native browser
    // view immediately after opening, hiding the approval action.
    current(); await adapters.openSettings(); return;
  }
  const enabled = choice === 'toggle' ? !policy!.enabled : policy!.enabled;
  const action = enabled ? 'Apply protection on' : 'Apply protection off';
  const disableWarning = !enabled ? 'Turning protection off allows failed or unscanned commits to be pushed. ' : '';
  if (!await adapters.confirm(
    `${enabled ? 'Protect' : 'Allow unchecked'} pushes from ${repository.name}?`,
    `Repository: ${repository.root}\n\n${disableWarning}${BYPASS_WARNING}\n\n`
      + 'Only this clone’s Lomo hook and its private configuration are changed. Existing hooks are never overwritten.',
    action,
  )) return;
  current();
  if (policy === null) throw invalidPolicy();
  if (policy.enabled !== enabled) {
    const before = policy;
    policy = validateGitPushPolicy(await adapters.request(path, {
      method: 'PATCH', body: JSON.stringify({ expected_revision: before.revision, enabled, confirm_bypass: !enabled }),
    }), repository);
    current();
    if (policy.enabled !== enabled || policy.revision !== before.revision + 1) throw invalidPolicy();
  }
  // A Web/other-profile edit after confirmation must not be silently applied.
  const latest = await read();
  if (!latest || !approved(latest, repository) || latest.project_id !== policy.project_id || latest.revision !== policy.revision || latest.enabled !== policy.enabled) {
    throw new CodeSecurityRequestError('Push protection changed before host setup. Review the current requested setting again.', 409);
  }
  current();
  host = await adapters.applyPolicy(repository, policy);
  current();
  if (host.state !== 'installed' || host.enabled !== policy.enabled || host.revision !== policy.revision
    || !host.hookDigest || !SHA256.test(host.hookDigest)) {
    throw new CodeSecurityRequestError('The requested setting was saved, but the local hook was not confirmed. Refresh or apply it again; no push was approved.');
  }
  policy = validateGitPushPolicy(await adapters.request(`${path}/observation`, {
    method: 'POST', body: JSON.stringify({ expected_revision: policy.revision, state: 'installed', hook_digest: host.hookDigest }),
  }), repository);
  current();
  if (policy.observed_state !== 'installed' || policy.observed_revision !== host.revision
    || policy.hook_digest !== host.hookDigest || policy.enabled !== host.enabled || policy.revision !== host.revision) throw invalidPolicy();
  await adapters.showStatus(`${repository.name}: ${pushProtectionStatus(policy, host)}. ${policy.enabled
    ? 'The next push still needs an exact outgoing-commit check.'
    : 'Lomo will not check or block pushes; your remote may still enforce its own rules.'}`);
}
