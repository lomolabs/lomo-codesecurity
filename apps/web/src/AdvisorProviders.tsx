import {
  Ban,
  CheckCircle2,
  Copy,
  Play,
  Plus,
  RefreshCw,
  Save,
  SlidersHorizontal,
  Square,
  Trash2,
  XCircle,
} from 'lucide-react';
import { FormEvent, memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AdvisorLocalCatalog,
  AdvisorLocalModel,
  AdvisorProvider,
  AdvisorProviderAction,
  AdvisorProviderCollection,
  AdvisorProviderInput,
  AdvisorProviderTransport,
  Job,
} from './api';
import {
  advisorLocalCatalogSummary,
  advisorProviderDisableReason,
  advisorProviderOperationLabel,
  detectedLocalProviderAction,
  detectedLocalProviderIsReady,
  localModelSelectorDisabled,
  selectedLocalModel,
} from './advisorLocalDiscovery';
import { advisorProviderRemediation, advisorReasonText } from './advisorProviderGuidance';
import { InfoTip } from './InfoTip';
import { jobRetryTimingNote, jobWaitingGuidance } from './jobPresentation';
import { subscribeToExactSettingsDeepLink } from './settingsDeepLink';
import type { SettingsDeepLinkSubscription } from './settingsDeepLink';

const timeFormatter = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
});

function formatBytes(value?: number) {
  if (!value) return '0 B';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${Math.round(value / 1024)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  if (value < 1024 * 1024 * 1024 * 1024) return `${(value / 1024 / 1024 / 1024).toFixed(1)} GB`;
  return `${(value / 1024 / 1024 / 1024 / 1024).toFixed(1)} TB`;
}

function formatModelSize(value: number) {
  if (value < 1_000) return `${value} B`;
  if (value < 1_000_000) return `${Math.round(value / 1_000)} KB`;
  if (value < 1_000_000_000) return `${(value / 1_000_000).toFixed(1)} MB`;
  if (value < 1_000_000_000_000) return `${(value / 1_000_000_000).toFixed(1)} GB`;
  return `${(value / 1_000_000_000_000).toFixed(1)} TB`;
}

function formatTime(value?: string) {
  if (!value) return '-';
  return timeFormatter.format(new Date(value));
}


function StatusPill({ value, label }: { value: string; label?: string }) {
  return <span className={`pill pill-${value || 'unknown'}`}>{label || value || 'unknown'}</span>;
}


function normalizedJobActivity(job: Job) {
  const activity = job.activity;
  const componentId = activity?.component_id;
  const componentIndex = activity?.component_index;
  const componentTotal = activity?.component_total;
  if (
    !activity
    || typeof componentId !== 'string'
    || !componentId
    || componentId.length > 120
    || typeof componentIndex !== 'number'
    || !Number.isSafeInteger(componentIndex)
    || componentIndex < 1
    || typeof componentTotal !== 'number'
    || !Number.isSafeInteger(componentTotal)
    || componentTotal < componentIndex
    || componentTotal > 64
    || !Number.isFinite(Date.parse(activity.updated_at))
    || activity.bytes_completed != null && (!Number.isSafeInteger(activity.bytes_completed) || activity.bytes_completed < 0)
    || activity.bytes_total != null && (!Number.isSafeInteger(activity.bytes_total) || activity.bytes_total < 0)
    || activity.bytes_completed != null && activity.bytes_total != null && activity.bytes_completed > activity.bytes_total
  ) return null;
  return { ...activity, component_id: componentId, component_index: componentIndex, component_total: componentTotal };
}

function jobHeartbeatState(job: Job, activityUpdatedAt?: string | null) {
  const value = activityUpdatedAt || job.heartbeat_at;
  if (!value) return null;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return null;
  return {
    stale: advisorProviderActiveStatuses.has(job.status) && Date.now() - timestamp > 45_000,
    value,
  };
}

function formatLiveElapsed(milliseconds: number): string {
  const totalSeconds = Math.max(0, Math.floor(milliseconds / 1000));
  const days = Math.floor(totalSeconds / 86_400);
  const hours = Math.floor(totalSeconds % 86_400 / 3_600);
  const minutes = Math.floor(totalSeconds % 3_600 / 60);
  const seconds = totalSeconds % 60;
  return [
    days ? `${days}d` : '',
    days || hours ? `${hours}h` : '',
    days || hours || minutes ? `${minutes}m` : '',
    `${seconds}s`,
  ].filter(Boolean).join(' ');
}

function useLiveJobElapsed(startedAt: string | undefined, active: boolean): string | null {
  const startedAtMs = startedAt ? Date.parse(startedAt) : Number.NaN;
  const [currentTimeMs, setCurrentTimeMs] = useState(() => Date.now());
  useEffect(() => {
    if (!active || !Number.isFinite(startedAtMs)) return undefined;
    setCurrentTimeMs(Date.now());
    const timer = window.setInterval(() => setCurrentTimeMs(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [active, startedAtMs]);
  if (!active || !Number.isFinite(startedAtMs)) return null;
  return formatLiveElapsed(currentTimeMs - startedAtMs);
}


type AdvisorProviderDraft = {
  id: string;
  name: string;
  transport: AdvisorProviderTransport;
  priority: number;
  enabled: boolean;
  baseUrl: string;
  model: string;
  modelDigest: string;
  sshHost: string;
  sshPort: number;
  sshUser: string;
};

export type AdvisorProviderOperation = {
  providerId: string;
  action: AdvisorProviderAction;
  job: Job;
};

export const advisorProviderActiveStatuses = new Set(['queued', 'leased', 'pending', 'running', 'analyzing', 'cancelling']);

function safeAdvisorDisplayText(value: unknown, fallback = ''): string {
  if (typeof value !== 'string') return fallback;
  return value
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/gu, ' ')
    .replace(/-----BEGIN[^-]{0,120}PRIVATE KEY-----[\s\S]*/giu, '[redacted credential]')
    .replace(/\b(password|token|secret|private[_ -]?key|key[_ -]?path|known_hosts)\s*[:=]\s*\S+/giu, '$1=[redacted]')
    .replace(/\/(?:[^/\s]+\/)+(?:id_rsa|id_ed25519|known_hosts)\b/giu, '[redacted path]')
    .replace(/\s+/gu, ' ')
    .trim()
    .slice(0, 500) || fallback;
}

function emptyAdvisorProviderDraft(providers: readonly AdvisorProvider[]): AdvisorProviderDraft {
  const occupiedPriorities = new Set(providers.map((provider) => provider.priority));
  const nextPriority = Array.from({ length: 8 }, (_, priority) => priority)
    .find((priority) => !occupiedPriorities.has(priority)) ?? 0;
  const providerId = `provider-${globalThis.crypto.randomUUID().replace(/-/gu, '').slice(0, 24)}`;
  return {
    id: providerId,
    name: '',
    transport: 'local',
    priority: nextPriority,
    enabled: true,
    baseUrl: '',
    model: '',
    modelDigest: '',
    sshHost: '',
    sshPort: 22,
    sshUser: '',
  };
}

function advisorProviderDraft(provider: AdvisorProvider): AdvisorProviderDraft {
  return {
    id: provider.id,
    name: provider.name,
    transport: provider.transport,
    priority: provider.priority,
    enabled: provider.enabled,
    baseUrl: provider.base_url || '',
    model: provider.model,
    modelDigest: provider.model_digest,
    sshHost: provider.ssh_host || '',
    sshPort: provider.ssh_port || 22,
    sshUser: provider.ssh_user || '',
  };
}

function advisorProviderInput(draft: AdvisorProviderDraft): AdvisorProviderInput {
  return {
    id: draft.id,
    name: draft.name.trim(),
    transport: draft.transport,
    priority: draft.priority,
    enabled: draft.enabled,
    base_url: draft.transport === 'direct' ? draft.baseUrl.trim() : null,
    model: draft.model.trim(),
    model_digest: draft.modelDigest.trim().toLowerCase(),
    ssh_host: draft.transport === 'ssh' ? draft.sshHost.trim() : null,
    ssh_port: draft.transport === 'ssh' ? 22 : null,
    ssh_user: draft.transport === 'ssh' ? draft.sshUser.trim() : null,
  };
}

function normalizeSafeAdvisorIpv4(value: string): string | null {
  const candidate = value.trim().replace(/\.+$/u, '');
  const parts = candidate.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) return null;
  const octets = parts.map(Number);
  if (octets.some((octet) => octet > 255)) return null;
  if (
    octets.every((octet) => octet === 0)
    || octets[0] === 127
    || (octets[0] === 169 && octets[1] === 254)
    || octets[0] >= 224
  ) return null;
  return octets.join('.');
}

function normalizeExactDirectAdvisorUrl(value: string): string | null {
  const candidate = value.trim().replace(/\/+$/u, '');
  if (candidate.length === 0 || candidate.length > 500) return null;
  const match = /^http:\/\/([^/:?#]+):11434$/iu.exec(candidate);
  const host = match ? normalizeSafeAdvisorIpv4(match[1]) : null;
  return host ? `http://${host}:11434` : null;
}

function advisorProviderDraftError(
  draft: AdvisorProviderDraft,
  providers: readonly AdvisorProvider[],
  existing: AdvisorProvider | null,
): string | null {
  const name = draft.name.trim();
  const model = draft.model.trim();
  if (!/^[a-z][a-z0-9-]{0,39}$/u.test(draft.id)) {
    return 'The generated provider identity is invalid. Cancel and reopen this form.';
  }
  if (!name || name.length > 80 || /[\u0000-\u001f\u007f-\u009f]/u.test(name)) {
    return 'Name must contain 1–80 printable characters.';
  }
  if (!Number.isSafeInteger(draft.priority) || draft.priority < 0 || draft.priority > 7) {
    return 'Priority must be between 1 and 8.';
  }
  if (!existing && providers.some((provider) => provider.priority === draft.priority)) {
    return `Priority ${draft.priority + 1} is already assigned. Choose an unused priority.`;
  }
  if (!model || model.length > 120 || /[\u0000-\u001f\u007f-\u009f]/u.test(model)) {
    return 'Enter the exact configured model name using at most 120 characters.';
  }
  if (!/^[a-f0-9]{64}$/iu.test(draft.modelDigest.trim())) {
    return 'Model digest must be the exact 64-character SHA-256 digest.';
  }
  if (draft.transport === 'direct') {
    if (!normalizeExactDirectAdvisorUrl(draft.baseUrl)) {
      return 'Direct remote URL must use one safe literal IPv4 address over HTTP on port 11434, without credentials, path, query, or fragment.';
    }
  }
  if (draft.transport === 'ssh') {
    if (!normalizeSafeAdvisorIpv4(draft.sshHost)) {
      return 'SSH host must be one safe literal IPv4 address without a scheme, wildcard, path, or port.';
    }
    if (!/^[A-Za-z_][A-Za-z0-9._-]{0,63}$/u.test(draft.sshUser.trim())) {
      return 'SSH user must be an explicit account name using letters, numbers, dot, underscore, or hyphen.';
    }
  }
  return null;
}

function advisorProviderTransportLabel(transport: AdvisorProviderTransport) {
  if (transport === 'local') return 'Local · this device';
  if (transport === 'direct') return 'Direct remote';
  return 'SSH remote · outbound local forward';
}

function advisorProviderAuthorizationCommand(provider: AdvisorProvider): string | null {
  if (provider.transport === 'local') return null;
  let host = provider.ssh_host || '';
  if (provider.transport === 'direct') {
    const target = normalizeExactDirectAdvisorUrl(provider.base_url || '');
    if (!target) return null;
    host = target.slice('http://'.length, -':11434'.length);
  }
  host = normalizeSafeAdvisorIpv4(host) || '';
  if (!host) return null;
  const authorization = provider.transport === 'direct'
    ? { schema: 'lomo-advisor-host-authorization/v1', provider_id: provider.id, transport: 'direct', host }
    : {
      schema: 'lomo-advisor-host-authorization/v1',
      provider_id: provider.id,
      transport: 'ssh',
      host,
      port: 22,
      user: provider.ssh_user,
    };
  const bytes = new TextEncoder().encode(JSON.stringify(authorization));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
  return `KODESEC_ADVISOR_AUTHORIZATION_B64=${encoded} make authorize-advisor-host && make up`;
}

type AdvisorProviderFormProps = {
  existing: AdvisorProvider | null;
  providers: readonly AdvisorProvider[];
  saving: boolean;
  blockedReason: string | null;
  onCancel: () => void;
  onSave: (provider: AdvisorProviderInput, existing: boolean) => Promise<void>;
};

function AdvisorProviderForm({ existing, providers, saving, blockedReason, onCancel, onSave }: AdvisorProviderFormProps) {
  const [draft, setDraft] = useState<AdvisorProviderDraft>(() => existing
    ? advisorProviderDraft(existing)
    : emptyAdvisorProviderDraft(providers));
  const [validationError, setValidationError] = useState<string | null>(null);
  const updateDraft = useCallback((update: Partial<AdvisorProviderDraft>) => {
    setDraft((current) => ({ ...current, ...update }));
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (saving || blockedReason) return;
    const error = advisorProviderDraftError(draft, providers, existing);
    setValidationError(error);
    if (error) return;
    try {
      await onSave(advisorProviderInput(draft), Boolean(existing));
    } catch {
      // A failed mutation may have reconciled a newer provider collection.
      // Discard this draft so it can never be replayed against that newer revision.
      onCancel();
    }
  }

  return (
    <form className="form advisor-provider-form" onSubmit={(event) => void submit(event)}>
      <div className="advisor-provider-form-head">
        <div>
          <h3>{existing ? `Edit ${existing.name}` : 'Add Advisor provider'}</h3>
          <p className="helper-text">Store an exact model identity. CodeSecurity never discovers LAN hosts or sends prompt content while choosing a provider.</p>
        </div>
        <button type="button" className="secondary-action" onClick={onCancel} disabled={saving}>Cancel edit</button>
      </div>
      <div className="advisor-provider-fields">
        <label>
          Name
          <input
            autoFocus
            value={draft.name}
            maxLength={80}
            onChange={(event) => updateDraft({ name: event.currentTarget.value })}
            placeholder="Build workstation"
            disabled={saving}
            required
          />
        </label>
        <label>
          Connection
          <select
            value={draft.transport}
            onChange={(event) => updateDraft({ transport: event.currentTarget.value as AdvisorProviderTransport })}
            disabled={saving || Boolean(existing)}
          >
            <option value="local">Local · this device</option>
            <option value="direct">Direct remote</option>
            <option value="ssh">SSH remote</option>
          </select>
        </label>
        <label>
          Priority
          <select
            value={draft.priority}
            onChange={(event) => updateDraft({ priority: Number(event.currentTarget.value) })}
            disabled={saving}
          >
            {Array.from({ length: 8 }, (_, index) => (
              <option
                disabled={!existing && providers.some((provider) => provider.priority === index)}
                value={index}
                key={index}
              >
                {index + 1}
              </option>
            ))}
          </select>
        </label>
        <label>
          Exact model
          <input
            value={draft.model}
            maxLength={120}
            onChange={(event) => updateDraft({ model: event.currentTarget.value })}
            placeholder="qwen3:8b"
            disabled={saving}
            required
          />
        </label>
        <label className="advisor-provider-digest">
          Exact model SHA-256 digest
          <input
            value={draft.modelDigest}
            minLength={64}
            maxLength={64}
            spellCheck={false}
            onChange={(event) => updateDraft({ modelDigest: event.currentTarget.value })}
            placeholder="64 hexadecimal characters"
            disabled={saving}
            required
          />
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(event) => updateDraft({ enabled: event.currentTarget.checked })}
            disabled={saving}
          />
          <span>Enabled in the ordered provider chain</span>
        </label>
      </div>
      {draft.transport === 'local' ? (
        <div className="advisor-provider-mode-note" role="status">
          Local uses this device’s product-managed Ollama route. Its endpoint is auto-detected and cannot be overridden here.
        </div>
      ) : null}
      {draft.transport === 'direct' ? (
        <fieldset className="advisor-provider-advanced">
          <legend>Direct remote</legend>
          <p className="helper-text">Use one previously authorized safe IPv4 address. DNS names and special-purpose destinations are rejected; Direct success starts no SSH process.</p>
          <label>
            Exact Ollama URL
            <input
              type="url"
              value={draft.baseUrl}
              onChange={(event) => updateDraft({ baseUrl: event.currentTarget.value })}
              placeholder="http://192.0.2.44:11434"
              disabled={saving}
              required
            />
          </label>
        </fieldset>
      ) : null}
      {draft.transport === 'ssh' ? (
        <details className="advisor-provider-advanced" open>
          <summary>Advanced SSH tunnel</summary>
          <p className="helper-text">CodeSecurity opens only an outbound loopback forward from one safe literal IPv4 address to Ollama. DNS names are rejected. A separately authorized credential reference is required; keys and trust files are never shown here.</p>
          <div className="advisor-provider-ssh-fields">
            <label>
              Exact SSH host
              <input
                value={draft.sshHost}
                onChange={(event) => updateDraft({ sshHost: event.currentTarget.value })}
                placeholder="192.0.2.45"
                disabled={saving}
                required
              />
            </label>
            <label>
              SSH port
              <input value="22" disabled aria-describedby="advisor-provider-ssh-port-help" />
              <small id="advisor-provider-ssh-port-help">Fixed by policy</small>
            </label>
            <label>
              SSH user
              <input
                value={draft.sshUser}
                onChange={(event) => updateDraft({ sshUser: event.currentTarget.value })}
                placeholder="ollama-forward"
                disabled={saving}
                required
              />
            </label>
          </div>
        </details>
      ) : null}
      {validationError ? <p className="status-note error" role="alert">{validationError}</p> : null}
      {blockedReason ? <p id="advisor-provider-draft-status" className="status-note" role="status">{blockedReason}</p> : null}
      <div className="advisor-provider-form-actions">
        <button disabled={saving || Boolean(blockedReason)} aria-describedby={blockedReason ? 'advisor-provider-draft-status' : undefined}><Save size={16} /> {existing ? 'Save provider' : 'Add provider'}</button>
        <button type="button" className="secondary-action" onClick={onCancel} disabled={saving}>Cancel</button>
      </div>
    </form>
  );
}

export function AdvisorProviderOperationStatus({ operation }: { operation: AdvisorProviderOperation }) {
  const { job } = operation;
  const active = advisorProviderActiveStatuses.has(job.status);
  const elapsed = useLiveJobElapsed(job.started_at || job.created_at, active);
  const waitingGuidance = jobWaitingGuidance(job);
  const activity = waitingGuidance ? null : normalizedJobActivity(job);
  const heartbeat = active && !waitingGuidance ? jobHeartbeatState(job, activity?.updated_at) : null;
  const progress = Math.max(0, Math.min(job.progress ?? (job.status === 'completed' ? 100 : 0), 100));
  const failure = safeAdvisorDisplayText(job.error_detail || job.error);
  return (
    <div className="advisor-provider-operation" role="status" aria-label={`${operation.action} provider job #${job.id}`}>
      <div className="advisor-provider-operation-head">
        <strong>{advisorProviderOperationLabel(operation.action, job.status, active)}</strong>
        <StatusPill value={job.status} />
      </div>
      <progress max="100" value={progress}>{progress}%</progress>
      <span>
        Phase {safeAdvisorDisplayText(job.stage, 'queued')}
        {job.attempt !== undefined && job.max_attempts !== undefined ? ` · attempt ${job.attempt}/${job.max_attempts}` : ''}
        {job.started_at ? ` · First started ${formatTime(job.started_at)}` : ''}
        {elapsed ? ` · ${job.started_at ? 'Since first start' : 'Since queued'} ${elapsed}` : ''}
      </span>
      {jobRetryTimingNote(job) ? <span className="helper-text">{jobRetryTimingNote(job)}</span> : null}
      {waitingGuidance ? <span className="helper-text">{waitingGuidance}</span> : null}
      <span>
        {waitingGuidance ? 'Last job update ' : 'Last activity '}
        {formatTime(waitingGuidance ? job.updated_at : activity?.updated_at || job.heartbeat_at || job.updated_at)}
        {activity?.component_id ? ` · ${safeAdvisorDisplayText(activity.component_id)}` : ''}
        {activity?.bytes_completed != null ? ` · ${formatBytes(activity.bytes_completed)}${activity.bytes_total != null ? ` of ${formatBytes(activity.bytes_total)}` : ''}` : ''}
      </span>
      {heartbeat?.stale ? <strong className="advisor-provider-stalled">No worker heartbeat for 45 seconds. The job may be stalled; cancel it or wait for bounded retry.</strong> : null}
      {failure ? <strong className="advisor-provider-failure">{failure}</strong> : null}
      {job.detail ? <span>Last phase detail: {safeAdvisorDisplayText(job.detail)}</span> : null}
      {job.error_code ? <span>Failure code: <code>{safeAdvisorDisplayText(job.error_code)}</code></span> : null}
    </div>
  );
}

type SettingsAdvisorProvidersPanelProps = {
  collection: AdvisorProviderCollection | null;
  deepLinkReady: boolean;
  error: string | null;
  localCatalog: AdvisorLocalCatalog | null;
  localDetectionError: string | null;
  localDetectionLoading: boolean;
  loadState: 'loading' | 'success' | 'error';
  mutationsEnabled: boolean;
  operation: AdvisorProviderOperation | null;
  saving: boolean;
  status: string | null;
  onCancelOperation: () => Promise<void>;
  onUseDetectedLocal: (model: AdvisorLocalModel) => Promise<void>;
  onCommand: (provider: AdvisorProvider, action: AdvisorProviderAction) => Promise<void>;
  onDetectLocal: () => Promise<void>;
  onRemove: (provider: AdvisorProvider) => Promise<void>;
  onRetryOperation: () => Promise<void>;
  onSave: (provider: AdvisorProviderInput, existing: boolean, expectedRevision: number) => Promise<void>;
  onToggle: (provider: AdvisorProvider) => Promise<void>;
};

export const SettingsAdvisorProvidersPanel = memo(function SettingsAdvisorProvidersPanel({
  collection,
  deepLinkReady,
  error,
  localCatalog,
  localDetectionError,
  localDetectionLoading,
  loadState,
  mutationsEnabled,
  operation,
  saving,
  status,
  onCancelOperation,
  onUseDetectedLocal,
  onCommand,
  onDetectLocal,
  onRemove,
  onRetryOperation,
  onSave,
  onToggle,
}: SettingsAdvisorProvidersPanelProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const deepLinkSubscriptionRef = useRef<SettingsDeepLinkSubscription | null>(null);
  const [editor, setEditor] = useState<{ id: string; existing: AdvisorProvider | null; revision: number } | null>(null);
  const editorId = editor?.id ?? null;
  const [authorizationCopyStatus, setAuthorizationCopyStatus] = useState<{ providerId: string; message: string } | null>(null);
  const [selectedLocalModelName, setSelectedLocalModelName] = useState<string | null>(null);
  const providers = useMemo(
    () => [...(collection?.providers || [])].sort((left, right) => left.priority - right.priority || left.name.localeCompare(right.name)),
    [collection?.providers],
  );
  const draftBlockedReason = !mutationsEnabled || !collection
    ? 'Verify current Settings before saving. Your provider draft is retained.'
    : editor && editor.revision !== collection.revision
      ? 'Provider configuration changed while you were editing. Your draft is retained; copy any changes you need, then cancel and reopen the provider to review its current settings.'
      : null;
  const operationActive = Boolean(operation && advisorProviderActiveStatuses.has(operation.job.status));
  const canAdd = providers.length < 8 && !operationActive && !saving && mutationsEnabled;
  const detectedModel = localCatalog
    ? selectedLocalModel(localCatalog, selectedLocalModelName)
    : null;
  const detectedModelAction = detectedModel
    ? detectedLocalProviderAction(detectedModel, providers)
    : null;
  const detectedModelReady = Boolean(
    detectedModel
    && collection
    && detectedLocalProviderIsReady(detectedModel, collection),
  );
  const localProviderLimitReached = detectedModelAction === 'add' && providers.length >= 8;

  useEffect(() => {
    const subscription = subscribeToExactSettingsDeepLink(
      window,
      '#advisor-providers',
      () => panelRef.current,
    );
    deepLinkSubscriptionRef.current = subscription;
    return () => {
      deepLinkSubscriptionRef.current = null;
      subscription.dispose();
    };
  }, []);

  useEffect(() => {
    deepLinkSubscriptionRef.current?.setReady(deepLinkReady);
  }, [deepLinkReady]);

  useEffect(() => {
    if (mutationsEnabled) return;
    setAuthorizationCopyStatus(null);
  }, [mutationsEnabled]);

  useEffect(() => {
    if (!localCatalog) {
      setSelectedLocalModelName(null);
      return;
    }
    setSelectedLocalModelName((current) => selectedLocalModel(localCatalog, current)?.name || null);
  }, [localCatalog]);

  async function save(provider: AdvisorProviderInput, existing: boolean) {
    if (!editor || draftBlockedReason) return;
    await onSave(provider, existing, editor.revision);
    setEditor(null);
  }

  async function copyAuthorization(provider: AdvisorProvider) {
    const command = advisorProviderAuthorizationCommand(provider);
    if (!command) {
      setAuthorizationCopyStatus({ providerId: provider.id, message: 'A safe owner authorization command could not be generated. Review the exact host fields.' });
      return;
    }
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(command);
      setAuthorizationCopyStatus({ providerId: provider.id, message: 'Owner authorization command copied. Run it from the CodeSecurity checkout; no authorization was applied by the browser.' });
    } catch {
      setAuthorizationCopyStatus({ providerId: provider.id, message: 'Automatic copy is unavailable. Select the bounded command and copy it manually.' });
    }
  }

  return (
    <div
      className="band span-2 advisor-providers"
      id="advisor-providers"
      ref={panelRef}
      tabIndex={-1}
      aria-busy={loadState === 'loading' || saving ? true : undefined}
    >
      <div className="band-head">
        <div>
          <h2>Advisor Providers <InfoTip text="CodeSecurity automatically resolves only an eligible local profile. An active, tested, authorized Direct or SSH profile remains outside automatic routing and may be used only after an exact single-finding disclosure preview is explicitly confirmed." /></h2>
          <p className="section-subtitle">Automatic local routing; explicit one-finding remote review</p>
        </div>
      </div>
      <p className="helper-text">Use locally verifies reachability plus the exact model digest and records the same-device provider in one step without sending finding content. Direct and SSH providers retain separate Test and Activate controls, remain ineligible for automatic, scan-wide, and bulk routing, and require an explicit one-finding disclosure confirmation before a remote Advisor job is created.</p>
      {collection ? (
        <div className="advisor-provider-resolution" role="status">
          <span><strong>Resolved provider</strong> {collection.resolution.provider_id ? providers.find((provider) => provider.id === collection.resolution.provider_id)?.name || 'configured provider' : 'none'}</span>
          <span><strong>Transport</strong> {collection.resolution.transport === 'unavailable' ? 'unavailable' : advisorProviderTransportLabel(collection.resolution.transport)}</span>
          <span><strong>Resolution</strong> {advisorReasonText(
            safeAdvisorDisplayText(collection.resolution.reason),
            collection.resolution.provider_id ? 'The selected provider is eligible.' : 'No eligible provider is available.',
          )}</span>
        </div>
      ) : null}
      <div className="advisor-local-discovery" aria-busy={localDetectionLoading ? true : undefined}>
          <div className="advisor-local-discovery-head">
            <div>
              <h3>Use Ollama on this device</h3>
              <p className="helper-text">Checks only CodeSecurity’s dedicated same-device Ollama connector. It never searches the LAN and sends no source, finding, or prompt content.</p>
            </div>
            <button type="button" className="secondary-action" onClick={() => void onDetectLocal()} disabled={!mutationsEnabled || localDetectionLoading || saving || editorId !== null}>
              <RefreshCw size={15} /> {localDetectionLoading ? 'Detecting local Ollama' : 'Detect local Ollama'}
            </button>
          </div>
          {localCatalog ? (
            <>
              <label className="advisor-local-model-select">
                Local model to pin
                <select
                  value={detectedModel?.name || ''}
                  onChange={(event) => setSelectedLocalModelName(event.currentTarget.value)}
                  disabled={localModelSelectorDisabled({
                    mutationsEnabled,
                    modelAvailable: Boolean(detectedModel),
                    saving,
                    operationActive,
                    editorOpen: editorId !== null,
                    detectionLoading: localDetectionLoading,
                  })}
                >
                  {localCatalog.models.filter((model) => model.storage === 'local_weights').map((model) => (
                    <option key={`${model.name}-${model.digest}`} value={model.name}>
                      {model.name}{model.name === localCatalog.recommended_model ? ' · recommended' : ''}
                    </option>
                  ))}
                  {!detectedModel ? <option value="">No model with local weights</option> : null}
                </select>
              </label>
              {!localCatalog.models.length ? <p className="status-note">Ollama is reachable, but it reports no installed models.</p> : null}
              {!detectedModel && localCatalog.models.some((model) => model.storage === 'cloud_stub') ? (
                <p className="status-note">Ollama reports only cloud-only aliases. Pull a model with local weights, then detect again for private local Advisor work.</p>
              ) : null}
              {localProviderLimitReached ? (
                <p className="status-note">All eight provider slots are occupied. Remove one provider before adding this local model.</p>
              ) : null}
              {detectedModel ? (
                <div className="advisor-local-selection" role="status">
                  <div>
                    <strong>{detectedModel.name}</strong>
                    <StatusPill value={detectedModel.storage} label="local weights" />
                  </div>
                  <span>{formatModelSize(detectedModel.size_bytes)} on this device</span>
                  <code title={detectedModel.digest}>
                    <span className="visually-hidden">Full SHA-256 digest {detectedModel.digest}</span>
                    <span aria-hidden="true">{detectedModel.digest.slice(0, 12)}…</span>
                  </code>
                </div>
              ) : null}
              <button
                type="button"
                onClick={() => detectedModel && void onUseDetectedLocal(detectedModel)}
                disabled={!mutationsEnabled || !detectedModel || detectedModelReady || localProviderLimitReached || saving || operationActive || localDetectionLoading}
              >
                {detectedModelReady ? <CheckCircle2 size={15} /> : detectedModelAction === 'update' || detectedModelAction === 'current' ? <Save size={15} /> : <Plus size={15} />}
                {detectedModel
                  ? detectedModelReady
                    ? `${detectedModel.name} ready locally`
                    : `Use ${detectedModel.name} locally`
                  : 'Use local model'}
              </button>
              {localCatalog.models.length ? (
                <details className="advisor-local-catalog">
                  <summary>{advisorLocalCatalogSummary(localCatalog)}</summary>
                  <div className="advisor-local-model-list" role="list" aria-label="Detected local Ollama model details">
                    {localCatalog.models.map((model) => (
                      <div className="advisor-local-model" role="listitem" key={`${model.name}-${model.digest}`}>
                        <div>
                          <strong>{model.name}</strong>
                          <StatusPill value={model.storage} label={model.storage === 'local_weights' ? 'local weights' : 'cloud-only'} />
                        </div>
                        <span>
                          {model.storage === 'local_weights'
                            ? `${formatModelSize(model.size_bytes)} · ${model.size_bytes.toLocaleString()} bytes`
                            : `${formatModelSize(model.size_bytes)} · ${model.size_bytes.toLocaleString()} bytes metadata only · no local weights`}
                        </span>
                        <code><span className="visually-hidden">{model.name} full SHA-256 digest </span>{model.digest}</code>
                      </div>
                    ))}
                  </div>
                  {localCatalog.models.some((model) => model.storage === 'cloud_stub') ? (
                    <p className="helper-text">Cloud-only aliases are shown for an exact Ollama inventory, but cannot be selected for local Advisor work.</p>
                  ) : null}
                </details>
              ) : null}
            </>
          ) : null}
          {localDetectionError ? <p className="status-note error" role="alert">{safeAdvisorDisplayText(localDetectionError, 'Local Ollama detection failed.')}</p> : null}
        </div>
      <section className="advisor-provider-advanced advisor-provider-manual" aria-labelledby="advisor-provider-manual-title">
        <div>
          <strong id="advisor-provider-manual-title">Advanced: configure a provider manually</strong>
          <p className="helper-text">Use this only for an additional local profile or an explicitly authorized Direct or SSH destination.</p>
        </div>
        <button type="button" className="secondary-action" onClick={() => collection && setEditor({ id: 'new', existing: null, revision: collection.revision })} disabled={!canAdd || editorId !== null}>
          <Plus size={16} /> Add provider
        </button>
      </section>
      {editor ? (
        <AdvisorProviderForm
          key={editor.id}
          existing={editor.existing}
          providers={providers}
          saving={saving}
          blockedReason={draftBlockedReason}
          onCancel={() => setEditor(null)}
          onSave={save}
        />
      ) : null}
      <ol className="advisor-provider-list" aria-label="Ordered Advisor providers">
        {providers.map((provider) => {
          const currentOperation = operation?.providerId === provider.id ? operation : null;
          const selected = collection?.resolution.provider_id === provider.id;
          const explicitlyActive = collection?.active_provider_id === provider.id;
          const disableReason = advisorProviderDisableReason(explicitlyActive);
          const disableReasonId = `advisor-provider-${provider.id}-disable-reason`;
          const mutating = saving || operationActive || !mutationsEnabled;
          const reason = advisorReasonText(
            provider.reason,
            provider.status === 'idle'
              ? 'This provider has not been tested yet.'
              : 'No additional provider readiness detail is available.',
          );
          const authorizationCommand = provider.authorization === 'required' ? advisorProviderAuthorizationCommand(provider) : null;
          return (
            <li className={`advisor-provider-card advisor-provider-${provider.status}${selected ? ' advisor-provider-active' : ''}`} key={provider.id}>
              <div className="advisor-provider-card-head">
                <span className="advisor-provider-priority"><span className="visually-hidden">Priority </span>{provider.priority + 1}</span>
                <div>
                  <h3>{provider.name}</h3>
                  <span>{advisorProviderTransportLabel(provider.transport)}</span>
                </div>
                <div className="advisor-provider-pills">
                  <StatusPill value={!provider.enabled ? 'disabled' : selected ? 'resolved' : provider.status === 'active' ? 'activated' : provider.status} />
                </div>
              </div>
              <dl className="advisor-provider-details">
                <dt>Target</dt>
                <dd>{provider.transport === 'local' ? 'This device · auto-detect' : provider.transport === 'direct' ? provider.base_url : `${provider.ssh_user}@${provider.ssh_host}:22`}</dd>
                <dt>Model</dt>
                <dd>{provider.model}</dd>
                <dt>Digest</dt>
                <dd><code>{provider.model_digest}</code></dd>
                <dt>Configuration</dt>
                <dd>revision {provider.config_revision} · <code>{provider.config_digest}</code></dd>
                <dt>Authorization</dt>
                <dd>{provider.authorization.replace(/_/gu, ' ')}</dd>
                <dt>Eligible for resolution</dt>
                <dd>{provider.eligible ? 'yes' : 'no'}</dd>
                <dt>Activation record</dt>
                <dd>{explicitlyActive ? 'active for this exact configuration' : 'not active'}</dd>
                <dt>Evidence sharing</dt>
                <dd>{provider.transport === 'local' ? 'Local weights only; verified before each run.' : provider.content_disclosure_approved ? 'approved for this exact host' : 'not approved'}</dd>
                <dt>Last verified activity</dt>
                <dd>{provider.last_activity_at ? formatTime(provider.last_activity_at) : 'never'}</dd>
              </dl>
              <div className="advisor-provider-reason">
                <strong>Readiness</strong><span>{reason}</span>
                <strong>Next step</strong><span>{advisorProviderRemediation(provider, currentOperation?.job.status || null)}</span>
              </div>
              {provider.authorization === 'required' ? (
                <div className="advisor-provider-authorization">
                  <strong>Owner authorization required</strong>
                  <p>{provider.transport === 'ssh'
                      ? 'Run this narrow host workflow locally. It will prompt outside the browser for the owner-only identity, known-hosts file, and separately confirmed host-key fingerprint, then re-apply the stack without deleting volumes.'
                    : 'Run this narrow host workflow locally to authorize only the exact direct host, then re-apply the stack without deleting volumes. The browser cannot expand the network boundary.'}</p>
                  {authorizationCommand ? (
                    <div className="source-authorization-command">
                      <textarea aria-label={`${provider.name} host authorization command`} readOnly rows={3} value={authorizationCommand} />
                      <button type="button" className="secondary-action" onClick={() => void copyAuthorization(provider)}>
                        <Copy size={15} /> Copy authorization command
                      </button>
                    </div>
                  ) : <p className="status-note error" role="alert">The exact host fields are invalid; edit this profile before authorization.</p>}
                  {authorizationCopyStatus?.providerId === provider.id ? <p className="status-note" role="status">{authorizationCopyStatus.message}</p> : null}
                </div>
              ) : null}
              {currentOperation ? <AdvisorProviderOperationStatus operation={currentOperation} /> : null}
              <div className="advisor-provider-actions" role="group" aria-label={`${provider.name} provider actions`}>
                <button type="button" className="secondary-action" onClick={() => collection && setEditor({ id: provider.id, existing: provider, revision: collection.revision })} disabled={mutating || editorId !== null}>
                  <SlidersHorizontal size={15} /> Edit
                </button>
                <button
                  type="button"
                  className="secondary-action"
                  onClick={() => void onToggle(provider)}
                  disabled={mutating || editorId !== null || explicitlyActive}
                  aria-describedby={disableReason ? disableReasonId : undefined}
                  title={disableReason || undefined}
                >
                  {provider.enabled ? <Ban size={15} /> : <CheckCircle2 size={15} />} {provider.enabled ? 'Disable' : 'Enable'}
                </button>
                {provider.transport !== 'local' ? (
                  <button type="button" className="secondary-action" onClick={() => void onCommand(provider, 'test')} disabled={mutating || !provider.enabled || editorId !== null}>
                    <RefreshCw size={15} /> Test connection
                  </button>
                ) : null}
                {!explicitlyActive && provider.transport === 'local' ? (
                  <button type="button" onClick={() => void onCommand(provider, 'activate')} disabled={mutating || !provider.enabled || editorId !== null}>
                    <Play size={15} /> Use locally
                  </button>
                ) : !explicitlyActive ? (
                  <button type="button" onClick={() => void onCommand(provider, 'activate')} disabled={mutating || !provider.enabled || editorId !== null}>
                    <Play size={15} /> Activate
                  </button>
                ) : explicitlyActive ? (
                  <button type="button" className="danger" onClick={() => void onCommand(provider, 'disconnect')} disabled={mutating || editorId !== null}>
                    <Square size={15} /> Disconnect
                  </button>
                ) : null}
                <button type="button" className="icon-button danger" title={`Remove ${provider.name}`} aria-label={`Remove ${provider.name}`} onClick={() => void onRemove(provider)} disabled={mutating || editorId !== null}>
                  <Trash2 size={15} />
                </button>
              </div>
              {disableReason ? <p className="disabled-action-reason" id={disableReasonId} role="status">{disableReason}</p> : null}
            </li>
          );
        })}
      </ol>
      {loadState === 'loading' ? <div className="empty-state" role="status">Loading the bounded Advisor provider chain.</div> : null}
      {loadState === 'success' && !providers.length && !editorId ? <div className="empty-state">No Advisor providers configured. Detect local Ollama above, then use a model with local weights for the simplest private setup.</div> : null}
      {operationActive ? (
        <button type="button" className="secondary-action advisor-provider-cancel" onClick={() => void onCancelOperation()} disabled={saving || !mutationsEnabled || operation?.job.status === 'cancelling'}>
          <XCircle size={15} /> Cancel operation
        </button>
      ) : null}
      {operation && !operationActive && operation.job.can_retry ? (
        <button type="button" className="secondary-action advisor-provider-retry" onClick={() => void onRetryOperation()} disabled={saving || !mutationsEnabled}>
          <RefreshCw size={15} /> Retry original snapshot
        </button>
      ) : null}
      {error ? <p className="status-note error" role="alert">{safeAdvisorDisplayText(error, 'Advisor provider operation failed.')}</p> : null}
      {status ? <p className="status-note" role="status">{status}</p> : null}
    </div>
  );
});


export function advisorProviderInputFromProfile(provider: AdvisorProvider): AdvisorProviderInput {
  return advisorProviderInput(advisorProviderDraft(provider));
}
