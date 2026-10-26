import { RefreshCw, Shield } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { subscribeToExactSettingsDeepLink } from './settingsDeepLink';
import type { SettingsDeepLinkSubscription } from './settingsDeepLink';

import { api } from './api';
import type { GitPushMember, GitPushPolicy, GitPushPolicyUpdate } from './api';
import { useConfirmation } from './ConfirmationDialog';
import type { RequestConfirmation } from './ConfirmationDialog';

const setupGuidance = 'Open this exact repository in VS Code and choose Protect Pushes to review host setup.';

export function pushProtectionPresentation(policy: GitPushPolicy) {
  if (policy.observed_revision !== policy.revision) return {
    label: 'Change pending · Apply in VS Code',
    detail: `Requested ${policy.enabled ? 'On' : 'Off'} has not been applied on the host. ${policy.enabled
      ? 'Pushes may still be unprotected.' : 'The previously applied protection may still block pushes.'} Open this repository in VS Code and use Protect Pushes → Apply / Refresh.`,
    verifiedAt: null,
  };
  if (policy.observed_state === 'needs_repair') return {
    label: 'Needs repair',
    detail: `The repository hook was missing or changed at its last check. ${setupGuidance}`,
    verifiedAt: null,
  };
  const observedAt = policy.observed_at ? new Date(policy.observed_at) : null;
  if (policy.observed_state === 'installed'
    && policy.observed_revision === policy.revision
    && policy.hook_digest && /^[0-9a-f]{64}$/u.test(policy.hook_digest)
    && observedAt && Number.isFinite(observedAt.getTime())) return {
    label: policy.enabled ? 'On · last verified' : 'Off · last applied',
    detail: policy.enabled
      ? 'The host reported the installed hook for this setting. This is a past observation, not verification of the next push.'
      : 'At the last host check, Lomo checks were turned off. Scanning remains available; your remote may still enforce its own rules.',
    verifiedAt: observedAt.toLocaleString(),
  };
  return {
    label: 'Setup required',
    detail: `${policy.reason_code === 'policy_changed' ? 'The setting changed since the last host check. ' : ''}${setupGuidance}`,
    verifiedAt: null,
  };
}

/** The Web requests policy only; the host owns hook installation and observation. */
export async function changePushProtection(
  policy: GitPushPolicy,
  enabled: boolean,
  confirm: RequestConfirmation,
  submit: (id: string, update: GitPushPolicyUpdate) => Promise<GitPushPolicy>,
  canSubmit: () => boolean,
): Promise<GitPushPolicy | null> {
  if (enabled === policy.enabled) return null;
  if (!enabled && !await confirm({
    title: 'Turn off push protection?',
    message: `Commits containing security findings or unscanned changes may be sent to your remote. Existing remote protections are not changed. Repository: ${policy.name}. Source: ${policy.root_path}. Project ${policy.project_id}. This saves requested Off; apply it in VS Code to change the host setting.`,
    cancelLabel: 'Keep protection on',
    confirmLabel: 'Turn off protection',
    tone: 'warning',
  })) return null;
  if (!canSubmit()) return null;
  const saved = await submit(policy.repository_id, {
    expected_revision: policy.revision, enabled, confirm_bypass: !enabled,
  });
  if (saved.repository_id !== policy.repository_id || saved.enabled !== enabled
    || saved.revision !== policy.revision + 1) {
    throw new Error('The changed protection setting could not be confirmed. Refresh protection before trying again.');
  }
  return saved;
}

export async function changePushProtectionMember(
  policy: GitPushPolicy,
  member: GitPushMember,
  approve: boolean,
  confirm: RequestConfirmation,
  submit: typeof api.decideGitPushMember,
  canSubmit: () => boolean,
): Promise<GitPushPolicy | null> {
  if (approve ? member.state === 'approved' : member.state === 'revoked') return null;
  const verb = approve ? 'Approve' : member.state === 'requested' ? 'Reject' : 'Revoke';
  if (!await confirm({
    title: `${verb} ${member.name} for ${policy.name}?`,
    message: approve
      ? `Allow this editor to manage local push protection and check this repository’s outgoing commits. It does not change remotes or authorize external Advisor. Source: ${policy.root_path}. Project ${policy.project_id}. Profile …${member.client_slot.slice(-8)}, generation ${member.generation}. Host installation still requires Apply / Refresh in VS Code.`
      : `Remove only this editor generation’s Git permission for ${policy.name}. Source: ${policy.root_path}. Project ${policy.project_id}. Other editor grants and ordinary IDE pairing remain unchanged. A previously enabled hook may block pushes until an authorized editor applies the current setting.`,
    cancelLabel: approve ? member.state === 'revoked' ? 'Keep access revoked' : 'Keep request pending' : 'Keep current access',
    confirmLabel: `${verb} editor`,
    tone: 'warning',
  }) || !canSubmit()) return null;
  const saved = await submit(policy.repository_id, member, { expected_revision: policy.revision, approve });
  const observed = saved.members.find((entry) => entry.client_slot === member.client_slot && entry.generation === member.generation);
  if (saved.repository_id !== policy.repository_id || saved.project_id !== policy.project_id
    || saved.root_path !== policy.root_path || saved.git_directory !== policy.git_directory
    || saved.revision !== policy.revision + 1 || observed?.state !== (approve ? 'approved' : 'revoked')) {
    throw new Error('The editor permission change could not be confirmed. Refresh protection before trying again.');
  }
  return saved;
}

type PanelProps = {
  repositories: GitPushPolicy[];
  loading: boolean;
  busyId: string | null;
  error: string | null;
  status: string | null;
  onRefresh: () => void;
  onChange: (policy: GitPushPolicy, enabled: boolean) => void;
  onMemberChange: (policy: GitPushPolicy, member: GitPushMember, approve: boolean) => void;
};

export function GitPushProtectionPanel({ repositories, loading, busyId, error, status, onRefresh, onChange, onMemberChange }: PanelProps) {
  const busy = loading || busyId !== null;
  return (
    <div className="band span-2" id="git-push-protection" aria-busy={busy} tabIndex={-1}>
      <div className="band-head ide-client-management-head">
        <div>
          <h2><Shield size={18} /> Git push protection</h2>
          <p className="helper-text">Require a passing security check for the exact outgoing commits. Local commits remain allowed.</p>
        </div>
        <button type="button" className="secondary-action" disabled={busy} onClick={onRefresh}>
          <RefreshCw size={15} /> {loading ? 'Refreshing protection…' : 'Refresh protection'}
        </button>
      </div>
      <p className="helper-text">These controls save the requested repository policy. VS Code handles host setup; saving here does not install a hook. Hook checks can be bypassed with Git’s --no-verify option or from another clone. This does not configure remote enforcement.</p>
      {error ? <p className="status-note error" role="alert">{error} Refresh protection to verify the current setting before retrying.</p> : null}
      {status ? <p className="status-note" role="status">{status}</p> : null}
      {!loading && !error && repositories.length === 0 ? (
        <p className="status-note neutral">No repositories are set up yet. {setupGuidance}</p>
      ) : null}
      {repositories.length ? (
        <ul className="ide-client-list" aria-label="Repository push protection">
          {repositories.map((policy) => {
            const presentation = pushProtectionPresentation(policy);
            return (
              <li className="ide-client-row" id={`git-push-protection-${policy.repository_id}`} tabIndex={-1} key={policy.repository_id}>
                <div className="ide-client-main">
                  <strong>{policy.name}</strong>
                  <span className="badge">{error ? 'Status unavailable' : presentation.label}</span>
                  <code title={policy.repository_id}>Repository …{policy.repository_id.slice(-8)}</code>
                  <code className="git-push-source-path">Source: {policy.root_path}</code>
                  <span className="ide-client-detail">Project {policy.project_id}</span>
                  <span className="ide-client-detail">{presentation.detail}</span>
                  {presentation.verifiedAt ? <span className="ide-client-detail">Last verified <time dateTime={policy.observed_at!}>{presentation.verifiedAt}</time></span> : null}
                </div>
                <div className="ide-client-actions form">
                  <label className="check">
                    <input type="checkbox" checked={policy.enabled} disabled={busy || Boolean(error)}
                      aria-label={`Protect pushes from ${policy.name} (repository …${policy.repository_id.slice(-8)})`}
                      onChange={(event) => onChange(policy, event.target.checked)} />
                    <span>{busyId === policy.repository_id ? 'Saving requested setting…' : 'Protect pushes from this repository'}</span>
                  </label>
                  <span className="helper-text">Requested: {policy.enabled ? 'On' : 'Off'}</span>
                </div>
                <details className="ide-client-detail" open={policy.members.some((member) => member.state === 'requested')}>
                  <summary>Editor access for this repository{policy.members.some((member) => member.state === 'requested') ? ' · approval requested' : ''}</summary>
                  <p className="helper-text">Approve each recognizable editor generation once. Revoking its ordinary IDE access also prevents it from using this permission. These grants do not prove the hook is currently installed.</p>
                  {!policy.members.length ? <p>No editor has requested access. Start setup from this repository in VS Code.</p> : (
                    <ul className="ide-client-list" aria-label={`Editor Git permissions for ${policy.name}`}>
                      {policy.members.map((member) => (
                        <li className="ide-client-row" key={`${member.client_slot}:${member.generation}`}>
                          <div className="ide-client-main">
                            <strong>{member.name}</strong><span className="badge">{member.state}</span>
                            <code>Profile …{member.client_slot.slice(-8)} · generation {member.generation}</code>
                          </div>
                          <div className="ide-client-actions">
                            {member.state !== 'approved' ? <button type="button" disabled={busy || Boolean(error)}
                              onClick={() => onMemberChange(policy, member, true)}
                              aria-label={`Approve ${member.name} profile …${member.client_slot.slice(-8)} generation ${member.generation} for ${policy.name}`}>{member.state === 'revoked' ? 'Approve again' : 'Approve editor'}</button> : null}
                            {member.state !== 'revoked' ? <button type="button" className="secondary-action" disabled={busy || Boolean(error)}
                              onClick={() => onMemberChange(policy, member, false)}
                              aria-label={`${member.state === 'requested' ? 'Reject' : 'Revoke'} ${member.name} profile …${member.client_slot.slice(-8)} generation ${member.generation} for ${policy.name}`}>{member.state === 'requested' ? 'Reject request' : 'Revoke Git access'}</button> : null}
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </details>
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}

export function SettingsGitPushProtection({ routeReady = true }: { routeReady?: boolean }) {
  const confirm = useConfirmation();
  const deepLink = useRef<SettingsDeepLinkSubscription | null>(null);
  const [repositories, setRepositories] = useState<GitPushPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const mounted = useRef(false);
  const changing = useRef(false);
  const reading = useRef(true);
  const loadController = useRef<AbortController | null>(null);

  useEffect(() => {
    const exactHash = /^#git-push-protection(?:-[0-9a-f]{64})?$/u.test(window.location.hash)
      ? window.location.hash : '#git-push-protection';
    const subscription = subscribeToExactSettingsDeepLink(window, exactHash,
      () => document.getElementById(exactHash.slice(1)) || document.getElementById('git-push-protection'));
    deepLink.current = subscription;
    return () => { subscription.dispose(); deepLink.current = null; };
  }, []);
  useEffect(() => { deepLink.current?.setReady(routeReady && !loading); }, [routeReady, loading]);

  async function load(announce: boolean) {
    if (changing.current) return;
    loadController.current?.abort();
    const controller = new AbortController();
    loadController.current = controller;
    reading.current = true;
    setLoading(true);
    setError(null);
    if (announce) setStatus(null);
    try {
      const result = await api.gitPushPolicies(controller.signal);
      if (!controller.signal.aborted && mounted.current) {
        setRepositories(result.repositories);
        if (announce) setStatus('Requested settings and last host observations refreshed. No Git push was approved.');
      }
    } catch (failure) {
      if (!controller.signal.aborted && mounted.current) setError(failure instanceof Error ? failure.message : String(failure));
    } finally {
      if (!controller.signal.aborted && mounted.current) {
        reading.current = false;
        setLoading(false);
      }
    }
  }

  useEffect(() => {
    mounted.current = true;
    void load(false);
    const onFocus = () => { if (document.visibilityState === 'visible') void load(false); };
    window.addEventListener('focus', onFocus);
    return () => {
      mounted.current = false;
      loadController.current?.abort();
      window.removeEventListener('focus', onFocus);
    };
  }, []);

  async function save(policy: GitPushPolicy, perform: () => Promise<GitPushPolicy | null>, message: (saved: GitPushPolicy) => string) {
    if (changing.current || reading.current || error) return;
    changing.current = true;
    setBusyId(policy.repository_id);
    setError(null);
    setStatus(null);
    try {
      const saved = await perform();
      if (!mounted.current) return;
      if (saved) {
        setRepositories((current) => current.map((item) => item.repository_id === saved.repository_id ? saved : item));
        setStatus(message(saved));
      } else setStatus('No setting was changed.');
    } catch (failure) {
      if (mounted.current) setError(failure instanceof Error ? failure.message : String(failure));
    } finally {
      changing.current = false;
      if (mounted.current) setBusyId(null);
    }
  }

  return <GitPushProtectionPanel repositories={repositories} loading={loading} busyId={busyId}
    error={error} status={status} onRefresh={() => void load(true)}
    onChange={(policy, enabled) => void save(policy,
      () => changePushProtection(policy, enabled, confirm, api.updateGitPushPolicy, () => mounted.current),
      (saved) => `${saved.name}: requested protection ${saved.enabled ? 'On' : 'Off'}. Apply / Refresh in VS Code to change the host setting. Scanning remains available.`)}
    onMemberChange={(policy, member, approve) => void save(policy,
      () => changePushProtectionMember(policy, member, approve, confirm, api.decideGitPushMember, () => mounted.current),
      () => `${member.name}: Git access ${approve ? 'approved' : 'revoked'} for this repository only. Apply / Refresh in VS Code to reconcile the host setting.`)} />;
}
