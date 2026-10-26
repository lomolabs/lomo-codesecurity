import {
  ideCapabilityRevocationRequest,
  idePendingCancellationRequest,
  invalidIdeCapabilityRecoveryRequest,
  requireIdePendingCancellationResponse,
  requireIdeRevocationResponse,
  requireInvalidIdeRecoveryResponse,
} from './idePairing';
import {
  invalidAdvisorProviderReadMessage,
  requireAdvisorProviderCollection,
  unconfirmedAdvisorProviderWriteMessage,
} from './advisorProviderResponse';


export const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

let csrfToken = '';
const authRequiredListeners = new Set<() => void>();

export function setCsrfToken(value: string) {
  csrfToken = value;
}

export function onAuthRequired(listener: () => void) {
  authRequiredListeners.add(listener);
  return () => {
    authRequiredListeners.delete(listener);
  };
}

function requireAuthentication() {
  csrfToken = '';
  authRequiredListeners.forEach((listener) => listener());
}

export type AdvisorAiMode = 'auto' | 'on' | 'off';

export type Health = {
  ok: boolean;
  version: string;
  db: boolean;
  scanner: boolean;
  worker: boolean;
  ai: {
    mode: AdvisorAiMode;
    available: boolean;
    base_url: string;
    model: string;
    thinking: boolean;
    models: string[];
    reason?: string;
  };
};

export type Project = {
  id: number;
  name: string;
  repo_path: string;
  remote_url?: string;
  default_branch: string;
  revision: number;
  created_at: string;
};

export type GatePolicyValues = {
  active: boolean;
  max_critical: number;
  max_high: number;
  block_secrets: boolean;
};
export type ProjectGatePolicy = GatePolicyValues & { project_id: number };

export type GitPushMember = {
  client_slot: string;
  generation: number;
  name: string;
  state: 'requested' | 'approved' | 'revoked';
  requested_at: string;
  approved_at: string | null;
};

export type GitPushPolicy = {
  repository_id: string;
  project_id: number;
  name: string;
  root_path: string;
  git_directory: string;
  revision: number;
  enabled: boolean;
  observed_state: 'not_installed' | 'installed' | 'needs_repair';
  observed_revision: number | null;
  observed_at: string | null;
  hook_digest: string | null;
  reason_code: 'host_setup_required' | 'hook_missing_or_changed' | 'policy_changed' | null;
  members: GitPushMember[];
};

export type GitPushPolicyUpdate = {
  expected_revision: number;
  enabled: boolean;
  confirm_bypass: boolean;
};

export type Scan = {
  id: number;
  project_id: number;
  mode: string;
  base_ref?: string;
  head_ref?: string;
  status: string;
  gate_decision?: string;
  gate_reasons: string[];
  scanner_summary: Record<string, unknown>;
  error?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  revision: number;
  findings_revision: number;
};

export type Job = {
  id: number;
  kind: string;
  title: string;
  status: string;
  original_job_id?: number | null;
  stage?: string;
  detail?: string;
  progress?: number;
  scan_id?: number;
  finding_id?: number;
  finding_display_id?: string;
  finding_scan_number?: number;
  finding_rule_id?: string;
  error?: string;
  error_code?: string;
  error_detail?: string;
  attempt?: number;
  max_attempts?: number;
  revision?: number;
  cancel_requested_at?: string;
  can_cancel?: boolean;
  can_retry?: boolean;
  can_reconcile_cache?: boolean;
  retry_blocked_reason?: string | null;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  updated_at: string;
  heartbeat_at?: string | null;
  activity?: {
    component_id: string | null;
    component_index: number | null;
    component_total: number | null;
    bytes_completed?: number | null;
    bytes_total?: number | null;
    updated_at: string;
  } | null;
};

const commandIdempotencyKeyPattern = /^web-[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export function createCommandIdempotencyKey(): string {
  const key = globalThis.crypto?.randomUUID?.();
  if (!key) {
    throw new Error('This browser cannot create a durable command identity.');
  }
  return `web-${key}`;
}

function commandHeaders(idempotencyKey = createCommandIdempotencyKey()): Record<string, string> {
  if (!commandIdempotencyKeyPattern.test(idempotencyKey)) {
    throw new Error('The durable command identity is invalid.');
  }
  return { 'Idempotency-Key': idempotencyKey };
}

export type Finding = {
  id: number;
  scan_id: number;
  scan_finding_number: number;
  display_id: string;
  scanner: string;
  rule_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  file_path: string;
  start_line?: number;
  start_column?: number;
  end_line?: number;
  end_column?: number;
  message: string;
  code_snippet?: string;
  fingerprint: string;
  metadata_json?: Record<string, unknown>;
  ai_verdict?: string;
  ai_confidence?: number;
  ai_reasoning?: string;
  ai_fix?: string;
  suppressed: boolean;
  suppression_reason?: string;
  lifecycle_status: 'open' | 'needs_review' | 'gate_exempt' | 'accepted_risk' | 'ignore' | 'false_positive' | 'fixed' | string;
  lifecycle_reason?: string;
  lifecycle_updated_at?: string;
  gate_exempt: boolean;
  gate_effect: 'blocking' | 'non_blocking' | 'excluded';
  gate_exempt_reason?: string;
  occurrence_count: number;
  is_repeat: boolean;
  first_seen_display_id?: string;
  first_seen_scan_id?: number;
  advisor_verdict?: string;
  advisor_confidence?: number;
  revision: number;
  findings_revision?: number;
  created_at?: string;
};

export type FindingPage = {
  items: Finding[];
  total: number;
  truncated: boolean;
  next_cursor: string | null;
  revision: number;
};

export type IdeValidCapability = {
  state: 'valid';
  id: string;
  client_name: string;
  scopes: string[];
  created_at: string | null;
  revoked: boolean;
  active: boolean;
  connected: boolean;
  active_generation: number | null;
  latest_generation: number;
  pending_activation: boolean;
  pending_generation: number | null;
  pending_client_name: string | null;
  pending_activation_expires_at: string | null;
  source_open_available: boolean;
  source_open_disabled_reason: string | null;
  invalid_recovery_token: null;
};

export type IdeInvalidCapability = {
  state: 'invalid';
  id: string;
  client_name: 'Invalid IDE client record';
  scopes: [];
  created_at: null;
  revoked: false;
  active: false;
  connected: false;
  active_generation: null;
  latest_generation: null;
  pending_activation: false;
  pending_generation: null;
  pending_client_name: null;
  pending_activation_expires_at: null;
  source_open_available: false;
  source_open_disabled_reason: 'This IDE client record is invalid or not active.';
  invalid_recovery_token: string;
};

export type IdeCapability = IdeValidCapability | IdeInvalidCapability;

export type IdeEnrollment = {
  request_id: string;
  state: 'awaiting_approval';
  revision: number;
  verification_code: string;
  scopes: string[];
  client_slot: string;
  client_name: string;
  generation: number;
  requested_at: string;
  activation_expires_at: string;
};

export type IdeEnrollmentStatus = {
  request_id: string;
  state: 'awaiting_approval' | 'approved' | 'rejected' | 'expired';
  revision: number;
  decision_at: string | null;
  activation_expires_at: string;
};

export type BrowserPairingTokenIssue = {
  bootstrap_token: string;
  issued_at: string;
  expires_at: string;
  expires_in: number;
};

export type BrowserMember = {
  id: string;
  member_name: string;
  member_kind: 'owner' | 'browser' | 'ide_dashboard';
  created_at: string;
  last_seen_at: string;
  current: boolean;
};

export type SourceOpenCommand = {
  id: string;
  finding_id: number;
  project_id: number;
  scan_id: number;
  scan_finding_number: number;
  expected_finding_revision: number;
  expected_findings_revision: number;
  target_capability_id: string;
  expected_target_generation: number;
  status: 'queued' | 'opened' | 'failed' | 'expired';
  revision: number;
  error_code?: string | null;
  created_at: string;
  expires_at: string;
  acknowledged_at?: string | null;
};

export type LoadedFindings = {
  items: Finding[];
  total: number;
  revision: number;
};

export type LoadFindingsOptions = {
  signal?: AbortSignal;
  expectedRevision?: number;
  anchorScanFindingNumber?: number;
  onInitialPage?: (page: LoadedFindings) => void;
};

export type ScanSummary = {
  scan: Pick<Scan,
    | 'id'
    | 'project_id'
    | 'mode'
    | 'status'
    | 'gate_decision'
    | 'gate_reasons'
    | 'error'
    | 'created_at'
    | 'started_at'
    | 'completed_at'
    | 'duration_ms'>;
  findings: {
    total: number;
    active: number;
    suppressed: number;
    gate_exempt: number;
    severity_counts: Record<string, number>;
    scanner_counts: Record<string, number>;
  };
  revision: number;
  findings_revision: number;
};

export type Summary = {
  projects: number;
  scans: number;
  findings: number;
  finding_occurrences: number;
  artifacts: number;
  severity_counts: Record<string, number>;
  scanner_counts: Record<string, number>;
  scanner_severity_counts: Record<string, Record<string, number>>;
  top_rules: Array<{ scanner: string; rule_id: string; severity: string; count: number }>;
  recent_scans: Scan[];
};

export type RuntimeConfig = {
  installation_id: string;
  allowed_roots: string[];
  scanner_url: string;
  ai_mode: AdvisorAiMode;
  ollama_base_url: string;
  ollama_available: boolean;
  ollama_model: string;
  ollama_thinking: boolean;
  ollama_models: string[];
  ollama_reason?: string;
  auto_triage_limit: number;
  component_monitoring_enabled: boolean;
  component_git_proxy_enabled: boolean;
  component_db_admin_enabled: boolean;
  gate_preset: 'observe' | 'baseline' | 'strict' | 'custom';
  gate_active: boolean;
  gate_max_critical: number;
  gate_max_high: number;
  gate_block_secrets: boolean;
  component_apply_command: string;
  components: Array<{
    id: string;
    required: boolean;
    desired_enabled: boolean;
    healthy: boolean;
    desired_state: 'enabled' | 'disabled';
    observed_state: 'running' | 'running_undesired' | 'not_running' | 'not_observed' | 'disabled' | 'unhealthy' | 'unknown';
    reachable: boolean;
    reason_code: string;
    message: string;
    url: string;
    profile: string;
    apply_command: string;
  }>;
  schema_init: {
    id: 'schema-init';
    lifecycle: 'one-shot';
    startable: false;
    state: 'completed' | 'unverified';
    message: string;
    schema_id: string | null;
    schema_fingerprint: string | null;
    initialized_at: string | null;
    evidence: 'schema-identity-and-api-startup-verification' | null;
  };
};

export type AdvisorProviderTransport = 'local' | 'direct' | 'ssh';

export type AdvisorProvider = {
  id: string;
  name: string;
  transport: AdvisorProviderTransport;
  priority: number;
  enabled: boolean;
  base_url: string | null;
  model: string;
  model_digest: string;
  ssh_host: string | null;
  ssh_port: number | null;
  ssh_user: string | null;
  authorization: 'not_required' | 'required' | 'authorized';
  status: 'idle' | 'testing' | 'available' | 'unavailable' | 'active' | 'disconnected';
  reason: string | null;
  reason_code: string | null;
  remediation: 'none' | 'authorize' | 'test' | 'activate' | 'retry' | 'refresh';
  last_activity_at: string | null;
  content_disclosure_approved: boolean;
  config_revision: number;
  config_digest: string;
  eligible: boolean;
};

export type AdvisorProviderInput = Pick<AdvisorProvider,
  | 'id'
  | 'name'
  | 'transport'
  | 'priority'
  | 'enabled'
  | 'base_url'
  | 'model'
  | 'model_digest'
  | 'ssh_host'
  | 'ssh_port'
  | 'ssh_user'
>;

export type AdvisorProviderCollection = {
  revision: number;
  active_provider_id: string | null;
  providers: AdvisorProvider[];
  resolution: {
    provider_id: string | null;
    transport: AdvisorProviderTransport | 'unavailable';
    reason: string | null;
    eligible_provider_ids: string[];
  };
};

export type AdvisorLocalModel = {
  name: string;
  digest: string;
  size_bytes: number;
  storage: 'local_weights' | 'cloud_stub';
};

export type AdvisorLocalCatalog = {
  schema: 'lomo-advisor-local-catalog/v1';
  source: 'dedicated_local_connector';
  models: AdvisorLocalModel[];
  recommended_model: string | null;
};

export type AdvisorProviderActivationApproval = {
  schema: 'lomo-advisor-activation-approval/v1';
  provider_id: string;
  provider_config_revision: number;
  provider_config_digest: string;
  transport: Exclude<AdvisorProviderTransport, 'local'>;
  destination: string;
  disclosure_mode: 'finding_evidence';
  payload_categories: string[];
  model: string;
  model_digest: string;
};

export type AdvisorDisclosureConfirmation = {
  schema: 'lomo-advisor-run-confirmation/v1';
  authorization_id: string;
  provider_id: string;
  provider_config_revision: number;
  provider_config_digest: string;
  transport: Exclude<AdvisorProviderTransport, 'local'>;
  destination: string;
  disclosure_mode: 'finding_evidence';
  payload_categories: string[];
  model: string;
  model_digest: string;
  consent_approved_at: string;
  finding_id: number;
  finding_revision: number;
  prompt_sha256: string;
  confirmation_digest: string;
};

export type AdvisorDisclosurePacket = {
  schema_version: 1;
  finding: {
    id: number;
    display_id: string;
    scanner: string;
    rule_id: string;
    severity: string;
    message: string;
    fingerprint: string;
  };
  location: {
    file_path: string;
    start_line: number | null;
    start_column: number | null;
    end_line: number | null;
    end_column: number | null;
  };
  repo_context: {
    project: string;
    repo_path: string;
    remote_url: string | null;
    scan_id: number;
    mode: string;
    base_ref: string | null;
    head_ref: string | null;
  };
  scanner_evidence: {
    code_snippet: string | null;
    metadata: Record<string, unknown>;
  };
};

export type AdvisorDisclosurePreview = {
  confirmation: AdvisorDisclosureConfirmation;
  packet: AdvisorDisclosurePacket;
  packet_utf8_bytes: number;
};

export type AdvisorTriageProviderPin = {
  provider_collection_revision: number;
  provider_id: string;
  transport: AdvisorProviderTransport;
  provider_config_revision: number;
  provider_config_digest: string;
  model: string;
  model_digest: string;
};

export type TriageRequest = {
  expected_revision: number;
  model?: string;
} & (
  | {
    advisor_provider_pin: AdvisorTriageProviderPin;
    acknowledge_remote_source_disclosure?: never;
    remote_advisor_confirmation?: never;
  }
  | {
    advisor_provider_pin?: never;
    acknowledge_remote_source_disclosure: true;
    remote_advisor_confirmation: AdvisorDisclosureConfirmation;
  }
);

export type AdvisorProviderAction = 'test' | 'activate' | 'disconnect';

export type RuntimeConfigUpdate = {
  ai_mode: RuntimeConfig['ai_mode'];
  ollama_base_url: string;
  ollama_model: string;
  ollama_thinking: boolean;
  auto_triage_limit: number;
  component_monitoring_enabled: boolean;
  component_git_proxy_enabled: boolean;
  component_db_admin_enabled: boolean;
  gate_preset: RuntimeConfig['gate_preset'];
  gate_active: boolean;
  gate_max_critical: number;
  gate_max_high: number;
  gate_block_secrets: boolean;
  gate_apply_to_existing: boolean;
};

export type RuntimeConfigScope = 'advisor' | 'gate' | 'components';

export type RuntimeAdvisorConfigUpdate = Pick<RuntimeConfigUpdate,
  | 'ai_mode'
  | 'ollama_base_url'
  | 'ollama_model'
  | 'ollama_thinking'
  | 'auto_triage_limit'
>;

export type RuntimeGateConfigUpdate = Pick<RuntimeConfigUpdate,
  | 'gate_preset'
  | 'gate_active'
  | 'gate_max_critical'
  | 'gate_max_high'
  | 'gate_block_secrets'
  | 'gate_apply_to_existing'
>;

export type RuntimeComponentsConfigUpdate = Pick<RuntimeConfigUpdate,
  | 'component_monitoring_enabled'
  | 'component_git_proxy_enabled'
  | 'component_db_admin_enabled'
>;

export type RuntimeConfigScopedUpdates = {
  advisor: RuntimeAdvisorConfigUpdate;
  gate: RuntimeGateConfigUpdate;
  components: RuntimeComponentsConfigUpdate;
};

export type RuntimeConfigScopedUpdate = RuntimeConfigScopedUpdates[RuntimeConfigScope];

export type ScannerTool = {
  id: string;
  name: string;
  category: string;
  lifecycle: string;
  source: string;
  output_format: string;
  description: string;
  enabled: boolean;
  current_version: string;
  latest_version: string;
  installed_version?: string;
  available: boolean;
  pinned_version?: string;
  status: string;
  update_available: boolean;
  findings_count: number;
  artifacts_count: number;
  candidate_release_id?: string | null;
  candidate_manifest_sha256?: string | null;
  published_at?: string;
  last_error?: string;
  last_checked_at?: string;
  updated_at?: string;
  readiness?: ScannerToolReadiness | null;
  runtime_ready?: boolean;
};

export type ScannerReadinessState = 'ready' | 'not_required' | 'unattested' | 'unavailable' | 'stale' | 'invalid' | 'verifying' | 'verification_timeout' | 'verification_failed';

export type ScannerReadinessFacet = {
  state: ScannerReadinessState;
  reason: string | null;
  component_ids: string[];
};

export type ScannerToolReadiness = {
  binary: ScannerReadinessFacet;
  data: ScannerReadinessFacet;
  rules: ScannerReadinessFacet;
  execution: ScannerReadinessFacet;
};

export type ScannerCacheComponentId =
  | 'trivy-db'
  | 'trivy-java-db'
  | 'trivy-checks'
  | 'opengrep-reviewed-rules'
  | 'bearer-rules'
  | 'grype-db';

export type ScannerCatalogComponentState =
  | 'current'
  | 'candidate_available'
  | 'requires_lock_refresh'
  | 'unavailable'
  | 'unattested';

export type ScannerLifecycleStatus = 'idle' | 'queued' | 'leased' | 'running' | 'cancelling' | 'completed' | 'failed' | 'cancelled';

export type ScannerLifecycleScope = {
  scope: 'catalog' | 'cache';
  status: ScannerLifecycleStatus;
  revision: number;
  job_id: number | null;
  job_url: string | null;
  active_generation: string | null;
  previous_generation: string | null;
  receipt: Record<string, unknown>;
  error_code: string | null;
  error_detail: string | null;
  started_at: string | null;
  completed_at: string | null;
  updated_at: string;
};

export type ScannerLifecycle = {
  catalog: ScannerLifecycleScope;
  cache: ScannerLifecycleScope;
};

export type ScannerLifecycleCommandOut = {
  job: Job;
  lifecycle: ScannerLifecycleScope;
};

export type ScannerReconciliationCommandOut = ScannerLifecycleCommandOut & {
  original_job_id: number;
};

export type ScannerPreparationCommandOut = {
  catalog: ScannerLifecycleCommandOut;
  cache?: ScannerLifecycleCommandOut | null;
  required_component_ids: ScannerCacheComponentId[];
};

export type ScannerPreflightBlockedTool = {
  id: string;
  name: string;
  blocking_reasons: string[];
  required_component_ids: ScannerCacheComponentId[];
  preparation_blocking_reasons: string[];
};

export type ScannerCacheVerification = {
  state: 'verifying' | 'timed_out' | 'failed';
  target: 'active' | 'previous_good';
  generation_id: string;
  phase: 'queued' | 'validating' | 'hashing';
  component_id: ScannerCacheComponentId | null;
  started_at: string;
  last_activity_at: string;
  bytes_verified: number | null;
  bytes_total: number | null;
};

export type ScannerPreflight = {
  schema_version: 1;
  revision: string;
  ready: boolean;
  enabled_tool_ids: string[];
  ready_tool_ids: string[];
  blocked_tools: ScannerPreflightBlockedTool[];
  required_component_ids: ScannerCacheComponentId[];
  preparation_available: boolean;
  active_generation: string | null;
  catalog_revision: number | null;
  cache_revision: number | null;
  cache_verification?: ScannerCacheVerification;
  cache_rollback: {
    eligible: boolean;
    reason_code: 'eligible' | 'no_previous_generation' | 'cache_pointer_invalid' | 'previous_generation_invalid' | 'previous_generation_verifying' | 'previous_generation_verification_timeout' | 'previous_generation_verification_failed' | 'different_reviewed_locks' | 'previous_generation_incompatible' | 'scanner_unavailable' | 'scanner_eligibility_invalid' | 'state_mismatch';
    reason: string;
    target_generation: string | null;
    verification?: ScannerCacheVerification;
  };
  recommended_action: 'scan' | 'prepare_scanners' | 'enable_scanner' | 'repair_scanner_runtime' | 'wait_for_scanner_verification' | 'retry_scanner_verification';
};

export type ApiProblemContextScalar = string | number | boolean | null;
export type ApiProblemContextValue = ApiProblemContextScalar | ApiProblemContextScalar[];

export type ApiProblem = {
  code: string;
  message: string;
  action: string | null;
  context: Record<string, ApiProblemContextValue>;
};

const API_PROBLEM_TEXT_LIMIT = 2_048;
const API_PROBLEM_CONTEXT_FIELDS = 16;

function boundedProblemText(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value
    .replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu, ' ')
    .replace(/\s+/gu, ' ')
    .trim();
  return normalized ? normalized.slice(0, API_PROBLEM_TEXT_LIMIT) : null;
}

function boundedProblemContext(value: unknown): Record<string, ApiProblemContextValue> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return Object.fromEntries(Object.entries(value)
    .slice(0, API_PROBLEM_CONTEXT_FIELDS)
    .flatMap(([rawKey, rawValue]) => {
      const key = boundedProblemText(rawKey)?.slice(0, 80);
      if (!key) return [];
      if (Array.isArray(rawValue)) {
        const nextValues = rawValue.slice(0, 16).flatMap((item): ApiProblemContextScalar[] => {
          if (item === null) return [null];
          if (typeof item === 'string') {
            const nextItem = boundedProblemText(item);
            return nextItem === null ? [] : [nextItem];
          }
          return ['number', 'boolean'].includes(typeof item) ? [item as number | boolean] : [];
        });
        return nextValues.length ? [[key, nextValues]] : [];
      }
      if (!['string', 'number', 'boolean'].includes(typeof rawValue) && rawValue !== null) return [];
      const nextValue = typeof rawValue === 'string' ? boundedProblemText(rawValue) : rawValue;
      return nextValue === null && rawValue !== null ? [] : [[key, nextValue as ApiProblemContextValue]];
    }));
}

function normalizeApiProblem(response: Response, rawBody: string): ApiProblem {
  let body: unknown = null;
  try {
    body = rawBody ? JSON.parse(rawBody) : null;
  } catch {
    body = rawBody;
  }
  if (body && typeof body === 'object' && !Array.isArray(body)) {
    const envelope = body as Record<string, unknown>;
    body = envelope.detail ?? envelope.error ?? envelope;
  }
  if (typeof body === 'string') {
    return {
      code: `http_${response.status}`,
      message: boundedProblemText(body) || `${response.status} ${response.statusText}`,
      action: null,
      context: {},
    };
  }
  const detail = body && typeof body === 'object' && !Array.isArray(body)
    ? body as Record<string, unknown>
    : {};
  return {
    code: boundedProblemText(detail.code)?.slice(0, 120) || `http_${response.status}`,
    message: boundedProblemText(detail.message)
      || boundedProblemText(detail.detail)
      || `${response.status} ${response.statusText}`,
    action: boundedProblemText(detail.action),
    context: boundedProblemContext(detail.context),
  };
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly action: string | null;
  readonly context: Record<string, ApiProblemContextValue>;

  constructor(status: number, problem: ApiProblem) {
    super(problem.message);
    this.name = 'ApiError';
    this.status = status;
    this.code = problem.code;
    this.action = problem.action;
    this.context = problem.context;
  }
}

export function isApiError(error: unknown): error is ApiError;
export function isApiError<Code extends string>(error: unknown, code: Code): error is ApiError & { code: Code };
export function isApiError(error: unknown, code?: string) {
  return error instanceof ApiError && (code === undefined || error.code === code);
}

export type ScanArtifact = {
  id: number;
  scan_id: number;
  scanner: string;
  artifact_type: string;
  format: string;
  path: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
};

async function request<T>(
  path: string,
  init?: RequestInit,
  options: Readonly<{ broadcastAuthenticationFailure?: boolean }> = {},
): Promise<T> {
  const method = (init?.method || 'GET').toUpperCase();
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...((init?.headers || {}) as Record<string, string>) };
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: 'same-origin',
    ...init,
    headers,
  });
  if (!response.ok) {
    if (response.status === 401 && options.broadcastAuthenticationFailure !== false) {
      requireAuthentication();
    }
    const problem = normalizeApiProblem(response, await response.text());
    throw new ApiError(response.status, problem);
  }
  return response.json() as Promise<T>;
}

async function requestAdvisorProviderCollection(path: string, init: RequestInit): Promise<AdvisorProviderCollection> {
  const message = init.method && init.method !== 'GET'
    ? unconfirmedAdvisorProviderWriteMessage : invalidAdvisorProviderReadMessage;
  try {
    return requireAdvisorProviderCollection(await request<unknown>(path, init), message);
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(message);
    throw error;
  }
}

const FINDINGS_PAGE_LIMIT = 200;
const MAX_FINDINGS_PAGES = 500;

export class FindingsSnapshotChangedError extends Error {
  constructor(message = 'Findings changed while the page set was loading.') {
    super(message);
    this.name = 'FindingsSnapshotChangedError';
  }
}

export function isFindingsSnapshotChangedError(error: unknown): error is FindingsSnapshotChangedError {
  return error instanceof FindingsSnapshotChangedError;
}

function normalizeFindingListItem(scanId: number, item: Finding): Finding {
  return {
    ...item,
    ai_verdict: item.ai_verdict ?? item.advisor_verdict,
    ai_confidence: item.ai_confidence ?? item.advisor_confidence,
  };
}

function validateFindingPage(
  scanId: number,
  page: FindingPage,
  previousOrdinal: number | null,
  expectedRevision?: number,
  allowShortTruncatedPage = false,
): number | null {
  if (
    !page
    || !Array.isArray(page.items)
    || page.items.length > FINDINGS_PAGE_LIMIT
    || !Number.isSafeInteger(page.total)
    || page.total < 0
    || page.items.length > page.total
    || !Number.isSafeInteger(page.revision)
    || page.revision < 1
    || expectedRevision !== undefined && page.revision !== expectedRevision
    || typeof page.truncated !== 'boolean'
    || page.next_cursor !== null && (typeof page.next_cursor !== 'string' || !page.next_cursor)
    || page.truncated !== (page.next_cursor !== null)
    || page.truncated && !allowShortTruncatedPage && page.items.length !== FINDINGS_PAGE_LIMIT
  ) {
    if (expectedRevision !== undefined && page?.revision !== expectedRevision) {
      throw new FindingsSnapshotChangedError('Findings changed before the requested page could be reconciled.');
    }
    throw new Error('CodeSecurity returned an invalid findings page.');
  }
  let ordinal = previousOrdinal;
  const pageIds = new Set<number>();
  for (const item of page.items) {
    const expectedGateEffect = item.suppressed ? 'excluded' : item.gate_exempt ? 'non_blocking' : 'blocking';
    const hasInvalidRange = (
      item.start_line != null && (!Number.isSafeInteger(item.start_line) || item.start_line < 1)
      || item.end_line != null && (!Number.isSafeInteger(item.end_line) || item.end_line < 1)
      || item.start_column != null && (!Number.isSafeInteger(item.start_column) || item.start_column < 1)
      || item.end_column != null && (!Number.isSafeInteger(item.end_column) || item.end_column < 1)
      || item.start_line != null && item.end_line != null && item.end_line < item.start_line
      || item.start_line === item.end_line
        && item.start_column != null
        && item.end_column != null
        && item.end_column < item.start_column
    );
    if (
      !Number.isSafeInteger(item.id)
      || item.id < 1
      || item.scan_id !== scanId
      || !Number.isSafeInteger(item.scan_finding_number)
      || item.scan_finding_number < 1
      || !Number.isSafeInteger(item.revision)
      || item.revision < 1
      || item.display_id !== `S${scanId}-F${String(item.scan_finding_number).padStart(3, '0')}`
      || !item.scanner
      || !item.rule_id
      || typeof item.file_path !== 'string'
      || typeof item.message !== 'string'
      || !['critical', 'high', 'medium', 'low', 'info'].includes(item.severity)
      || !['open', 'needs_review', 'gate_exempt', 'accepted_risk', 'ignore', 'false_positive', 'fixed'].includes(item.lifecycle_status)
      || !['blocking', 'non_blocking', 'excluded'].includes(item.gate_effect)
      || item.gate_effect !== expectedGateEffect
      || item.advisor_confidence != null && (!Number.isFinite(item.advisor_confidence) || item.advisor_confidence < 0 || item.advisor_confidence > 1)
      || hasInvalidRange
      || pageIds.has(item.id)
      || ordinal !== null && item.scan_finding_number <= ordinal
    ) {
      throw new Error('CodeSecurity returned an invalid or unordered findings page.');
    }
    pageIds.add(item.id);
    ordinal = item.scan_finding_number;
  }
  return ordinal;
}

async function requestFindingPage(
  scanId: number,
  parameters: URLSearchParams,
  signal?: AbortSignal,
): Promise<FindingPage> {
  try {
    return await request<FindingPage>(`/v1/scans/${scanId}/findings?${parameters}`, { signal });
  } catch (error) {
    if (isApiError(error, 'cursor_stale')) {
      throw new FindingsSnapshotChangedError('Findings changed while the page set was loading.');
    }
    throw error;
  }
}

async function loadFindings(scanId: number, options: LoadFindingsOptions = {}): Promise<LoadedFindings> {
  const { signal, expectedRevision, anchorScanFindingNumber, onInitialPage } = options;
  const items: Finding[] = [];
  const seenCursors = new Set<string>();
  const seenIds = new Set<number>();
  const seenNumbers = new Set<number>();
  let cursor: string | null = null;
  let total: number | null = null;
  let revision: number | null = null;
  let anchorTotal: number | null = null;
  let seededPageCount = 0;

  if (anchorScanFindingNumber !== undefined) {
    const anchorParameters = new URLSearchParams({
      limit: String(FINDINGS_PAGE_LIMIT),
      anchor_scan_finding_number: String(anchorScanFindingNumber),
    });
    const anchorPage = await requestFindingPage(scanId, anchorParameters, signal);
    validateFindingPage(scanId, anchorPage, null, expectedRevision, true);
    if (!anchorPage.items.some((item) => item.scan_finding_number === anchorScanFindingNumber)) {
      throw new Error('CodeSecurity did not include the requested finding in its anchor page.');
    }
    anchorTotal = anchorPage.total;
    onInitialPage?.({
      items: anchorPage.items.map((item) => normalizeFindingListItem(scanId, item)),
      total: anchorPage.total,
      revision: anchorPage.revision,
    });
    // An anchor page beginning at ordinal one is already a complete ordered
    // prefix of the unfiltered query. Reuse it instead of requesting page one
    // again; its opaque cursor safely continues the same revision-bound set.
    if (anchorPage.items[0]?.scan_finding_number === 1) {
      total = anchorPage.total;
      revision = anchorPage.revision;
      for (const item of anchorPage.items) {
        seenIds.add(item.id);
        seenNumbers.add(item.scan_finding_number);
      }
      items.push(...anchorPage.items.map((item) => normalizeFindingListItem(scanId, item)));
      seededPageCount = 1;
      if (!anchorPage.next_cursor) {
        if (anchorPage.truncated || items.length !== total) {
          throw new Error('The findings query ended before its declared total was loaded.');
        }
        return { items, total, revision };
      }
      seenCursors.add(anchorPage.next_cursor);
      cursor = anchorPage.next_cursor;
    }
  }

  for (let pageNumber = seededPageCount; pageNumber < MAX_FINDINGS_PAGES; pageNumber += 1) {
    const parameters = new URLSearchParams({ limit: String(FINDINGS_PAGE_LIMIT) });
    if (cursor) parameters.set('cursor', cursor);
    const page = await requestFindingPage(scanId, parameters, signal);
    const previousOrdinal = items.length ? items[items.length - 1].scan_finding_number : null;
    validateFindingPage(scanId, page, previousOrdinal, expectedRevision);
    if (total === null) total = page.total;
    if (revision === null) revision = page.revision;
    if (page.total !== total || page.revision !== revision || anchorTotal !== null && page.total !== anchorTotal) {
      throw new FindingsSnapshotChangedError('Findings changed while the page set was loading.');
    }
    for (const item of page.items) {
      if (seenIds.has(item.id) || seenNumbers.has(item.scan_finding_number)) {
        throw new Error('The findings query returned a duplicate finding identity.');
      }
      seenIds.add(item.id);
      seenNumbers.add(item.scan_finding_number);
    }
    items.push(...page.items.map((item) => normalizeFindingListItem(scanId, item)));
    if (items.length > total) throw new Error('The findings query exceeded its declared total.');
    if (pageNumber === 0 && anchorScanFindingNumber === undefined) {
      onInitialPage?.({ items: [...items], total, revision });
    }
    if (!page.next_cursor) {
      if (page.truncated || items.length !== total) {
        throw new Error('The findings query ended before its declared total was loaded.');
      }
      return { items, total, revision };
    }
    if (!page.truncated || seenCursors.has(page.next_cursor)) {
      throw new Error('The findings query returned an invalid or repeated cursor.');
    }
    seenCursors.add(page.next_cursor);
    cursor = page.next_cursor;
    await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 0));
  }
  throw new Error(`The findings query exceeded its explicit ${MAX_FINDINGS_PAGES * FINDINGS_PAGE_LIMIT}-item safety bound.`);
}

export const api = {
  authSession: () => request<{ authenticated: boolean; csrf_token: string; expires_in: number }>('/v1/auth/session'),
  bootstrap: (bootstrapToken: string) =>
    request<{ authenticated: boolean; csrf_token: string; expires_in: number }>('/v1/auth/bootstrap', {
      method: 'POST',
      body: JSON.stringify({ bootstrap_token: bootstrapToken }),
    }, { broadcastAuthenticationFailure: false }),
  logout: async () => {
    const result = await request<{ authenticated: boolean }>('/v1/auth/logout', { method: 'POST' });
    requireAuthentication();
    return result;
  },
  health: (signal?: AbortSignal) => request<Health>('/healthz', { signal }),
  gitPushPolicies: (signal?: AbortSignal) =>
    request<{ repositories: GitPushPolicy[] }>('/v1/git/push-protection', { signal }),
  updateGitPushPolicy: (repositoryId: string, payload: GitPushPolicyUpdate) =>
    request<GitPushPolicy>(`/v1/git/push-protection/${encodeURIComponent(repositoryId)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
  decideGitPushMember: (repositoryId: string, member: Pick<GitPushMember, 'client_slot' | 'generation'>,
    payload: { expected_revision: number; approve: boolean }) =>
    request<GitPushPolicy>(`/v1/git/push-protection/${encodeURIComponent(repositoryId)}/members/${encodeURIComponent(member.client_slot)}/${member.generation}`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  ideCapabilities: (signal?: AbortSignal) => request<IdeCapability[]>('/v1/auth/ide/capabilities', { signal }),
  pendingIdeEnrollments: (signal?: AbortSignal) => request<IdeEnrollment[]>('/v1/auth/ide/enrollments', { signal }),
  decideIdeEnrollment: (
    enrollment: Pick<IdeEnrollment, 'request_id' | 'revision' | 'generation'>,
    decision: 'approved' | 'rejected',
  ) => request<IdeEnrollmentStatus>(
    `/v1/auth/ide/enrollments/${encodeURIComponent(enrollment.request_id)}/decision`,
    {
      method: 'POST',
      body: JSON.stringify({
        decision,
        expected_revision: enrollment.revision,
        expected_generation: enrollment.generation,
      }),
    },
  ),
  issueBrowserPairingToken: () => request<BrowserPairingTokenIssue>('/v1/auth/browser/pairing-token', { method: 'POST' }),
  browserMembers: (signal?: AbortSignal) => request<BrowserMember[]>('/v1/auth/browser/sessions', { signal }),
  revokeBrowserMember: (member: BrowserMember) =>
    request<{ revoked: boolean; current: boolean }>(`/v1/auth/browser/sessions/${encodeURIComponent(member.id)}`, {
      method: 'DELETE',
      body: JSON.stringify({ expected_created_at: member.created_at }),
    }),
  revokeIdeCapability: async (capability: IdeValidCapability) => {
    const revocation = ideCapabilityRevocationRequest(capability);
    return requireIdeRevocationResponse(await request<unknown>(revocation.path, revocation.init));
  },
  cancelPendingIdeCapability: async (capabilityId: string, expectedPendingGeneration: number) => {
    const cancellation = idePendingCancellationRequest(capabilityId, expectedPendingGeneration);
    return requireIdePendingCancellationResponse(await request<unknown>(cancellation.path, cancellation.init));
  },
  recoverInvalidIdeCapability: async (capability: IdeInvalidCapability) => {
    const recovery = invalidIdeCapabilityRecoveryRequest(capability);
    return requireInvalidIdeRecoveryResponse(await request<unknown>(recovery.path, recovery.init));
  },
  openSourceInIde: (payload: {
    finding_id: number;
    expected_finding_revision: number;
    expected_findings_revision: number;
    target_capability_id: string;
    expected_target_generation: number;
  }) => request<SourceOpenCommand>('/v1/ide/source-open-commands', {
    method: 'POST',
    headers: commandHeaders(),
    body: JSON.stringify(payload),
  }),
  waitForSourceOpen: (commandId: string, signal?: AbortSignal) =>
    request<SourceOpenCommand>(`/v1/ide/source-open-commands/${encodeURIComponent(commandId)}/wait`, { signal }),
  sourceOpenStatus: (commandId: string, signal?: AbortSignal) =>
    request<SourceOpenCommand>(`/v1/ide/source-open-commands/${encodeURIComponent(commandId)}`, { signal }),
  config: (signal?: AbortSignal) => request<RuntimeConfig>('/v1/config', { signal }),
  advisorProviders: (signal?: AbortSignal) => requestAdvisorProviderCollection('/v1/advisor/providers', { signal }),
  localAdvisorModels: () => request<AdvisorLocalCatalog>('/v1/advisor/local-models'),
  createAdvisorProvider: (expectedRevision: number, provider: AdvisorProviderInput) =>
    requestAdvisorProviderCollection('/v1/advisor/providers', {
      method: 'POST',
      body: JSON.stringify({ expected_revision: expectedRevision, provider }),
    }),
  updateAdvisorProvider: (providerId: string, expectedRevision: number, provider: AdvisorProviderInput) =>
    requestAdvisorProviderCollection(`/v1/advisor/providers/${encodeURIComponent(providerId)}`, {
      method: 'PUT',
      body: JSON.stringify({ expected_revision: expectedRevision, provider }),
    }),
  deleteAdvisorProvider: (providerId: string, expectedRevision: number) =>
    requestAdvisorProviderCollection(`/v1/advisor/providers/${encodeURIComponent(providerId)}`, {
      method: 'DELETE',
      body: JSON.stringify({ expected_revision: expectedRevision }),
    }),
  commandAdvisorProvider: (
    providerId: string,
    expectedRevision: number,
    action: AdvisorProviderAction,
    acknowledgeSourceDisclosure: boolean,
    sourceDisclosureApproval: AdvisorProviderActivationApproval | null,
    idempotencyKey?: string,
  ) =>
    request<Job>(`/v1/advisor/providers/${encodeURIComponent(providerId)}/commands`, {
      method: 'POST',
      headers: commandHeaders(idempotencyKey),
      body: JSON.stringify({
        expected_revision: expectedRevision,
        action,
        acknowledge_source_disclosure: acknowledgeSourceDisclosure,
        source_disclosure_approval: sourceDisclosureApproval,
      }),
    }),
  advisorDisclosurePreview: (findingId: number, expectedRevision: number, providerId?: string) =>
    request<AdvisorDisclosurePreview>(`/v1/findings/${findingId}/advisor-disclosure-preview`, {
      method: 'POST',
      body: JSON.stringify({
        expected_revision: expectedRevision,
        provider_id: providerId,
      }),
    }),
  updateConfig: (payload: RuntimeConfigUpdate) => request<RuntimeConfig>('/v1/config', { method: 'PUT', body: JSON.stringify(payload) }),
  updateScopedConfig: <Scope extends RuntimeConfigScope>(scope: Scope, payload: RuntimeConfigScopedUpdates[Scope]) => request<RuntimeConfig>(`/v1/config/${scope}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  }),
  tools: (signal?: AbortSignal) => request<ScannerTool[]>('/v1/scanner/tools', { signal }),
  scannerPreflight: (signal?: AbortSignal) => request<ScannerPreflight>('/v1/scanner/preflight', { signal }),
  retryScannerVerification: (target: ScannerCacheVerification['target'], expectedGeneration: string) =>
    request<ScannerCacheVerification>('/v1/scanner/cache/verification/retry', {
      method: 'POST',
      headers: commandHeaders(),
      body: JSON.stringify({ target, expected_generation: expectedGeneration }),
    }),
  scannerLifecycle: (signal?: AbortSignal) => request<ScannerLifecycle>('/v1/scanner/lifecycle', { signal }),
  checkTools: () => request<ScannerLifecycleCommandOut>('/v1/scanner/tools/check-latest', {
    method: 'POST',
    headers: commandHeaders(),
  }),
  prepareScanners: () => request<ScannerPreparationCommandOut>('/v1/scanner/prepare', {
    method: 'POST',
    headers: commandHeaders(),
  }),
  updateScannerCache: (componentIds: ScannerCacheComponentId[], catalogDigest: string | null = null) =>
    request<ScannerLifecycleCommandOut>('/v1/scanner/cache/update', {
      method: 'POST',
      headers: commandHeaders(),
      body: JSON.stringify({ component_ids: componentIds, catalog_digest: catalogDigest }),
    }),
  rollbackScannerCache: () =>
    request<ScannerLifecycleCommandOut>('/v1/scanner/cache/rollback', {
      method: 'POST',
      headers: commandHeaders(),
    }),
  updateTool: (toolId: string) => request<ScannerTool>(`/v1/scanner/tools/${toolId}/update`, { method: 'POST' }),
  patchTool: (toolId: string, payload: { enabled?: boolean; pinned_version?: string | null }) =>
    request<ScannerTool>(`/v1/scanner/tools/${toolId}`, { method: 'PATCH', body: JSON.stringify(payload) }),
  summary: (signal?: AbortSignal) => request<Summary>('/v1/dashboard/summary', { signal }),
  jobs: (signal?: AbortSignal) => request<Job[]>('/v1/jobs', { signal }),
  activeJobs: (signal?: AbortSignal) => request<Job[]>('/v1/jobs?status=active&limit=500', { signal }),
  job: (jobId: number, signal?: AbortSignal) => request<Job>(`/v1/jobs/${jobId}`, { signal }),
  cancelJob: (jobId: number) => request<Job>(`/v1/jobs/${jobId}/cancel`, { method: 'POST' }),
  retryJob: (jobId: number, expectedRevision: number) =>
    request<Job>(`/v1/jobs/${jobId}/retry`, {
      method: 'POST',
      body: JSON.stringify({ expected_revision: expectedRevision }),
    }),
  reconcileScannerCacheJob: (jobId: number, expectedRevision: number) => {
    if (!Number.isSafeInteger(jobId) || jobId < 1 || !Number.isSafeInteger(expectedRevision) || expectedRevision < 1) {
      throw new Error('An exact failed job and current revision are required to check the cache outcome.');
    }
    return request<ScannerReconciliationCommandOut>(`/v1/jobs/${jobId}/reconcile`, {
      method: 'POST',
      headers: commandHeaders(),
      body: JSON.stringify({ expected_revision: expectedRevision }),
    });
  },
  projects: (signal?: AbortSignal) => request<Project[]>('/v1/projects', { signal }),
  projectGate: (projectId: number, signal?: AbortSignal) =>
    request<ProjectGatePolicy>(`/v1/gate-policies/${projectId}`, { signal }),
  saveProjectGate: (projectId: number, draft: GatePolicyValues, expectedPolicy: GatePolicyValues) =>
    request<ProjectGatePolicy>(`/v1/gate-policies/${projectId}`, {
      method: 'PUT', body: JSON.stringify({ ...draft, expected_policy: expectedPolicy }),
    }),
  // History includes gate, coverage and failure explanations. Full engine
  // receipts remain available through the exact scan resource.
  scans: (signal?: AbortSignal) => request<Scan[]>('/v1/scans?view=history', { signal }),
  scan: (scanId: number, signal?: AbortSignal) => request<Scan>(`/v1/scans/${scanId}`, { signal }),
  scanSummary: (scanId: number, signal?: AbortSignal) =>
    request<ScanSummary>(`/v1/scans/${scanId}/summary`, { signal }),
  findings: loadFindings,
  finding: (
    scanId: number,
    scanFindingNumber: number,
    options: { signal?: AbortSignal; expectedRevision: number; expectedFindingsRevision: number },
  ) => {
    const parameters = new URLSearchParams({
      expected_revision: String(options.expectedRevision),
      expected_findings_revision: String(options.expectedFindingsRevision),
    });
    return request<Finding>(`/v1/scans/${scanId}/findings/${scanFindingNumber}?${parameters}`, { signal: options.signal });
  },
  artifacts: (scanId: number, signal?: AbortSignal) => request<ScanArtifact[]>(`/v1/scans/${scanId}/artifacts`, { signal }),
  artifactOpenUrl: (artifactId: number) => `${API_BASE}/v1/artifacts/${artifactId}/open`,
  artifactDownloadUrl: (artifactId: number) => `${API_BASE}/v1/artifacts/${artifactId}/download`,
  createProject: (payload: { name: string; repo_path: string; remote_url?: string; default_branch: string }) =>
    request<Project>('/v1/projects', { method: 'POST', body: JSON.stringify(payload) }),
  deleteProject: (projectId: number) => request<{ deleted: boolean }>(`/v1/projects/${projectId}`, { method: 'DELETE' }),
  deleteScan: (scanId: number) => request<{ deleted: boolean }>(`/v1/scans/${scanId}`, { method: 'DELETE' }),
  deleteFinding: (findingId: number, expectedRevision: number) =>
    request<{ deleted: boolean }>(`/v1/findings/${findingId}?expected_revision=${expectedRevision}`, { method: 'DELETE' }),
  updateFindingLifecycle: (findingId: number, payload: { action: string; reason?: string; expected_revision: number }) =>
    request<Finding>(`/v1/findings/${findingId}/lifecycle`, { method: 'PATCH', body: JSON.stringify(payload) }),
  bulkFindings: (payload: {
    finding_ids: number[];
    action: string;
    reason?: string;
    model?: string;
    expected_revisions?: Record<number, number>;
    advisor_provider_pin?: AdvisorTriageProviderPin;
  }) =>
    request<{ updated: number; deleted: number; scan_ids: number[]; job?: Job }>('/v1/findings/bulk', {
      method: 'POST',
      headers: payload.action === 'triage' ? commandHeaders() : undefined,
      body: JSON.stringify(payload),
    }),
  startScan: (payload: {
    project_id: number;
    mode: string;
    base_ref?: string;
    head_ref?: string;
    use_ai?: boolean;
    coverage?: 'complete' | 'limited';
    acknowledge_limited_coverage?: boolean;
    preflight_revision?: string;
  }) =>
    request<Scan>('/v1/scans', { method: 'POST', headers: commandHeaders(), body: JSON.stringify(payload) }),
  triageScan: (scanId: number, payload: {
    include_existing?: boolean;
    limit?: number;
    model?: string;
    advisor_provider_pin: AdvisorTriageProviderPin;
  }) =>
    request<Job>(`/v1/scans/${scanId}/triage`, { method: 'POST', headers: commandHeaders(), body: JSON.stringify(payload) }),
  triage: (findingId: number, payload: TriageRequest) =>
    request<Job>(`/v1/findings/${findingId}/triage`, {
      method: 'POST',
      headers: commandHeaders(),
      body: JSON.stringify(payload),
    }),
};
