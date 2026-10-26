import {
  Activity,
  AlertTriangle,
  Ban,
  Bot,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
  CheckSquare2,
  Clock as ClockIcon,
  Code2,
  Copy,
  Database,
  Download,
  EyeOff,
  ExternalLink,
  FileSearch,
  Gauge,
  GitBranch,
  ListChecks,
  LogOut,
  Play,
  Plus,
  PackageCheck,
  RefreshCw,
  Save,
  Search,
  ServerCog,
  Shield,
  ShieldOff,
  Sparkles,
  SlidersHorizontal,
  Square,
  Target,
  TerminalSquare,
  Trash2,
  Undo2,
  Wrench,
  XCircle,
} from 'lucide-react';
import { cancellationOutcome } from './jobCancellation';
import { revealFindingNavigation } from './findingNavigation';
import { navigationRefreshCollections } from './navigationRefresh';
import { canReconcileScannerCacheJob, jobCacheOutcomeGuidance, jobKindLabel, jobRetryGuidance, jobRetryTimingNote, jobStageLabel, jobStatusLabel, jobWaitingGuidance } from './jobPresentation';
import { CSSProperties, FormEvent, memo, useCallback, useDeferredValue, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import {
  AdvisorProviderOperation,
  SettingsAdvisorProvidersPanel,
  advisorProviderActiveStatuses,
  advisorProviderInputFromProfile,
} from './AdvisorProviders';
import { ConfirmationProvider, useConfirmation, useTextEntry } from './ConfirmationDialog';
import { evidenceHeightControl } from './evidenceHeight';
import { SettingsSection } from './SettingsSection';
import { ProjectGate } from './ProjectGate';
import { buildScopedSettingsPayload, invalidSettingsReadMessage, mergeScopedSettingsResponse, requireLoadedSettingsResponse, requireSavedSettingsResponse, settingsFormFromConfig, unconfirmedSettingsSaveMessage, type SettingsFormState, type SettingsSaveTarget } from './settingsForm';
import { FindingEvidence } from './FindingEvidencePane';
import { otherReportsAtLocation, type FindingReportView } from './findingRelatedReports';
import { FindingProtectionContext } from './FindingProtectionContext';
import { protectionSettingsHash } from './findingProtection';
import { findingEvidenceMetadataKey, findingEvidencePresentation, findingLocation, preserveFindingEvidence } from './findingEvidence';
import {
  findingAdvisorVerdictLabel,
  findingBulkSelectionDisabledReason,
  findingGateEffectLabel,
  findingLifecycleActionDisabledReason,
  findingLifecycleActionLabel,
} from './findingLifecycle';
import { SettingsBrowserMembers } from './BrowserMembers';
import { SettingsGitPushProtection } from './GitPushProtection';
import { InfoTip } from './InfoTip';
import {
  settingsDeepLinkReady,
  subscribeToExactSettingsDeepLink,
} from './settingsDeepLink';
import type { SettingsDeepLinkSubscription } from './settingsDeepLink';
import {
  detectedLocalProviderInput,
  exactEnabledLocalProvider,
  localAdvisorAutoDetectionKey,
  consumeLocalAdvisorDiscoveryPollAttempt,
  localAdvisorDiscoveryPollAllowed,
  localProviderWriteReconciliationReason,
  normalizeAdvisorLocalCatalog,
} from './advisorLocalDiscovery';
import { advisorReasonText } from './advisorProviderGuidance';
import {
  applyAcceptedScannerVerification,
  catalogComponentState,
  scannerDataCatalogSelection,
  catalogNeedsRefreshAfterCache,
  requiredLockRefreshComponents,
  scannerCacheComponents,
  scannerPreparationDisabledReason,
  scannerPreparationCommandCopy,
  scannerVerificationCopy,
  scannerVerificationDisabledReason,
  scannerVerificationPollRequired,
  scannerVerificationRecommendedAction,
  validScannerCacheVerification,
  validScannerVerificationPreflight,
} from './scannerPreparation';
import {
  API_BASE,
  AdvisorAiMode,
  AdvisorDisclosurePreview,
  AdvisorLocalCatalog,
  AdvisorLocalModel,
  AdvisorProvider,
  AdvisorProviderAction,
  AdvisorProviderActivationApproval,
  AdvisorProviderCollection,
  AdvisorProviderInput,
  BrowserPairingTokenIssue,
  Finding,
  Health,
  IdeCapability,
  IdeEnrollment,
  IdeInvalidCapability,
  IdeValidCapability,
  Job,
  Project,
  RuntimeConfig,
  Scan,
  ScanArtifact,
  ScanSummary,
  ScannerCacheComponentId,
  ScannerCacheVerification,
  ScannerLifecycle,
  ScannerLifecycleScope,
  ScannerPreflight,
  ScannerReadinessFacet,
  ScannerTool,
  SourceOpenCommand,
  Summary,
  api,
  createCommandIdempotencyKey,
  isApiError,
  isFindingsSnapshotChangedError,
} from './api';
import {
  compareIdeCapabilities,
  ideCapabilityMutationRequiresAuthoritativeRefresh,
  ideClientDisplayName,
  ideClientStatus,
  ideClientTargetLabel,
  idePendingClientDisplayName,
  ideSourceOpenAuthorityRecovery,
  ideSourceOpenTarget,
  isValidIdeCapability,
  sourceOpenIdeCapabilities,
  validIdeCapabilities,
} from './idePairing';
import { scanCoverageTarget, sourceCoverageFailures } from './scanScope';
import {
  authoritativeSourceRoots,
  commitCurrentSourceBoundaryLoad,
  mountedProjectIsAuthorized,
  projectSourceAdapter,
  projectSourceNavigationDisabledReason,
  resolveSourceBoundaryLoad,
  safeAllowedSourceRoots,
  snapshotProjectScanGuidance,
  sourceAuthorizationCommand,
  summarizeSourceRegistrations,
} from './sourceBoundary';
import type { SourceBoundaryLoadState } from './sourceBoundary';
import { ideEnrollmentPresentation, pairingKeyExpiryDelay, pairingKeyIsExpired } from './pairingKeyState';
import { submitScanOnce } from './scanSubmission';
import { schemaInitIsVerified } from './schemaStatus';
import {
  advisorDisclosurePacketFields,
  claimRemoteAdvisorSubmission,
  releaseRemoteAdvisorSubmission,
} from './advisorDisclosure';
import {
  AdvisorProviderReadiness,
  ResolvedAdvisorRoute,
  advisorStatusPresentation,
  failedAdvisorProviderReadiness,
  newScanAdvisorAvailability,
  resolveAdvisorRoute,
  scanAdvisorAvailability,
} from './advisorRouting';
import {
  AdvisorFindingReconciliationError,
  findingIdentityAndEvidenceMatches,
  retryLocalAdvisorAfterRevisionConflict,
} from './advisorFindingReconciliation';

type View = 'overview' | 'projects' | 'jobs' | 'scans' | 'findings' | 'tools' | 'settings';
type Toast = { id: number; tone: 'info' | 'success' | 'error'; title: string; message: string };
type RouteErrorOwnership = Readonly<{ owner: View; routeEpoch: number }>;
type RouteError = RouteErrorOwnership & Readonly<{ message: string }>;
type SourceAuthorizationRecovery = Readonly<{
  selectedPath: string;
  allowedRoots: readonly string[];
}>;
type JobHandoffTarget = Readonly<{
  id: number;
  generation: number;
}>;
type JobHandoff = JobHandoffTarget & Readonly<{
  loading: boolean;
  error: string | null;
}>;
type RefreshReason = 'initial' | 'manual' | 'mutation' | 'poll' | 'visibility' | 'navigation';
type RevisionScalar = string | number | boolean | null | undefined;
type RevisionKey = RevisionScalar[][];
type FindingsRenderStage = 'summary' | 'list' | 'detail-static' | 'detail-evidence' | 'ready';
type FindingDetailRenderStage = 'static' | 'evidence' | 'advisor' | 'ready';
type SettingsRenderStage = 'components' | 'ready';
type PaintedBatchState = {
  committedCount: number;
  ready: boolean;
};

type RouteSurfaceAttributes = {
  'aria-hidden'?: true;
  'data-route-surface': View;
  inert: boolean;
};

const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
const activeWorkStatuses = new Set(['queued', 'leased', 'pending', 'running', 'analyzing', 'cancelling']);
const workbenchViews = new Set<View>(['overview', 'projects', 'jobs', 'scans', 'findings', 'tools', 'settings']);
const findingsPageSize = 25;
const findingsMaximumBatchSize = findingsPageSize;
const findingListRowHeightRem = 8;
const findingListRowGapRem = 0.625;
const findingListRowExtentRem = findingListRowHeightRem + findingListRowGapRem;
const findingsSnapshotAttempts = 3;
const lifecycleReasonLimit = 500;
const lifecycleReasonActions = new Set(['gate_exempt', 'accepted_risk', 'ignore', 'false_positive', 'fixed']);
const timeFormatter = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const fullDateTimeFormatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
const relativeTimeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

const gatePresetDefinitions: Record<RuntimeConfig['gate_preset'], {
  label: string;
  active: boolean;
  maxCritical: number;
  maxHigh: number;
  blockSecrets: boolean;
  description: string;
}> = {
  observe: {
    label: 'Observe',
    active: false,
    maxCritical: -1,
    maxHigh: -1,
    blockSecrets: false,
    description: 'Record every finding and never fail the local gate. Useful while adopting scanners.',
  },
  baseline: {
    label: 'Baseline',
    active: true,
    maxCritical: 0,
    maxHigh: -1,
    blockSecrets: true,
    description: 'Fail on critical findings or leaked secrets. High findings remain visible warnings.',
  },
  strict: {
    label: 'Strict',
    active: true,
    maxCritical: 0,
    maxHigh: 0,
    blockSecrets: true,
    description: 'Fail on any high or critical finding, and fail on leaked secrets.',
  },
  custom: {
    label: 'Custom',
    active: true,
    maxCritical: 0,
    maxHigh: -1,
    blockSecrets: true,
    description: 'Use the manual limits below for your team policy.',
  },
};

function countBySeverity(items: Finding[]) {
  return severityOrder.reduce<Record<string, number>>((acc, severity) => {
    acc[severity] = items.filter((item) => item.severity === severity).length;
    return acc;
  }, {});
}

function totalFromCounts(counts: Record<string, number>) {
  return severityOrder.reduce((sum, severity) => sum + (counts[severity] || 0), 0);
}

function findingTotal(scan: Scan | null | undefined) {
  const value = scan?.scanner_summary?.findings_total;
  return typeof value === 'number' ? value : 0;
}

function formatDuration(ms?: number) {
  if (!ms) return '-';
  if (ms < 1000) return `${ms}ms`;
  return `${Math.round(ms / 1000)}s`;
}

function confidence(value?: number) {
  if (value === undefined || value === null || !Number.isFinite(value) || value < 0 || value > 1) return '-';
  return `${Math.round(value * 100)}%`;
}

function scanAdvisorFailure(scan?: Scan) {
  const value = scan?.scanner_summary?.advisor;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const advisor = value as Record<string, unknown>;
  if (advisor.status !== 'failed') return null;
  return {
    code: typeof advisor.error_code === 'string' ? advisor.error_code : 'advisor_failed',
    detail: typeof advisor.detail === 'string'
      ? advisor.detail
      : 'Optional local advisor work did not complete.',
  };
}

const incrementalFallbackWarning = 'incremental-diff-fallback-full';

const advisorDisclosureCategories = [
  'finding_identity',
  'source_location',
  'repository_context',
  'bounded_code_snippet',
  'bounded_scanner_metadata',
] as const;

function advisorProviderDestination(provider: AdvisorProvider): string {
  if (provider.transport === 'direct') return provider.base_url || 'invalid direct destination';
  if (provider.transport === 'ssh') {
    return `ssh://${provider.ssh_user}@${provider.ssh_host}:22/ollama/127.0.0.1:11434`;
  }
  return 'local://ollama';
}

function remoteProviderActivationApproval(provider: AdvisorProvider): AdvisorProviderActivationApproval {
  if (provider.transport === 'local') throw new Error('Local providers do not require source-disclosure approval.');
  return {
    schema: 'lomo-advisor-activation-approval/v1',
    provider_id: provider.id,
    provider_config_revision: provider.config_revision,
    provider_config_digest: provider.config_digest,
    transport: provider.transport,
    destination: advisorProviderDestination(provider),
    disclosure_mode: 'finding_evidence',
    payload_categories: [...advisorDisclosureCategories],
    model: provider.model,
    model_digest: provider.model_digest,
  };
}

function remoteProviderActivationConfirmation(provider: AdvisorProvider): string {
  return [
    `Activate ${provider.name}?`,
    '',
    `Transport: ${provider.transport}`,
    `Destination: ${advisorProviderDestination(provider)}`,
    `Provider configuration revision: ${provider.config_revision}`,
    `Provider configuration digest: ${provider.config_digest}`,
    `Model: ${provider.model}`,
    `Model digest: ${provider.model_digest}`,
    '',
    'This approval records exactly these five potential payload categories for the profile:',
    ...advisorDisclosureCategories.map((category) => `- ${category}`),
    '',
    'Connection tests and activation send no finding content and start no Advisor request. An active remote profile remains excluded from automatic, scan-wide, and bulk routing. Each remote review requires a new exact single-finding disclosure preview and explicit authorization.',
  ].join('\n');
}

type RemoteAdvisorConfirmationState = {
  finding: Finding;
  provider: AdvisorProvider;
  preview: AdvisorDisclosurePreview;
};

function exactAdvisorDisclosurePreview(
  preview: AdvisorDisclosurePreview,
  provider: AdvisorProvider,
  finding: Finding,
): AdvisorDisclosurePreview {
  const confirmation = preview.confirmation;
  const validDigest = (value: string) => /^[0-9a-f]{64}$/u.test(value);
  const validAuthorizationId = (value: string) => /^[0-9a-f]{32}$/u.test(value);
  const categoriesMatch = confirmation.payload_categories.length === advisorDisclosureCategories.length
    && confirmation.payload_categories.every((category, index) => category === advisorDisclosureCategories[index]);
  const valid = (
    confirmation.schema === 'lomo-advisor-run-confirmation/v1'
    && validAuthorizationId(confirmation.authorization_id)
    && confirmation.provider_id === provider.id
    && confirmation.provider_config_revision === provider.config_revision
    && confirmation.provider_config_digest === provider.config_digest
    && confirmation.transport === provider.transport
    && confirmation.destination === advisorProviderDestination(provider)
    && confirmation.disclosure_mode === 'finding_evidence'
    && categoriesMatch
    && confirmation.model === provider.model
    && confirmation.model_digest === provider.model_digest
    && confirmation.finding_id === finding.id
    && confirmation.finding_revision === finding.revision
    && validDigest(confirmation.prompt_sha256)
    && validDigest(confirmation.confirmation_digest)
    && Number.isFinite(Date.parse(confirmation.consent_approved_at))
    && preview.packet.schema_version === 1
    && preview.packet.finding.id === finding.id
    && preview.packet.finding.display_id === findingLabel(finding)
    && Number.isSafeInteger(preview.packet_utf8_bytes)
    && preview.packet_utf8_bytes > 0
  );
  if (!valid) {
    throw new Error('CodeSecurity returned an inconsistent remote Advisor disclosure preview. No finding evidence was sent; refresh providers and the finding before retrying.');
  }
  return preview;
}

function RemoteAdvisorConfirmationDialog({
  busy,
  confirmation,
  onCancel,
  onConfirm,
}: {
  busy: boolean;
  confirmation: RemoteAdvisorConfirmationState;
  onCancel: () => boolean;
  onConfirm: () => Promise<void>;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descriptionId = useId();
  const [approved, setApproved] = useState(false);
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog || dialog.open) return undefined;
    dialog.showModal();
    return () => {
      if (dialog.open) dialog.close();
    };
  }, []);

  function cancel() {
    if (busy) return;
    if (!onCancel()) return;
    dialogRef.current?.close();
  }

  const { finding, preview, provider } = confirmation;
  const signed = preview.confirmation;
  const packetFields = advisorDisclosurePacketFields(preview.packet);
  return (
    <dialog
      ref={dialogRef}
      aria-busy={busy ? true : undefined}
      aria-describedby={descriptionId}
      aria-labelledby={titleId}
      className="advisor-confirmation-dialog"
      onCancel={(event) => {
        event.preventDefault();
        cancel();
      }}
    >
      <div className="advisor-confirmation-head">
        <div>
          <span className="section-subtitle">Remote Advisor disclosure</span>
          <h2 id={titleId}>Review one Advisor disclosure</h2>
        </div>
        <AlertTriangle size={24} aria-hidden="true" />
      </div>
      <p id={descriptionId}>
        Review the exact server-built disclosure below. This preview identifies the bounded evidence that a separately authorized single-finding request would send to the named remote destination.
      </p>
      <dl className="advisor-confirmation-facts">
        <dt>Provider</dt>
        <dd>{provider.name} · <code>{signed.provider_id}</code></dd>
        <dt>Transport</dt>
        <dd>{signed.transport}</dd>
        <dt>Destination</dt>
        <dd><code>{signed.destination}</code></dd>
        <dt>Provider configuration</dt>
        <dd>revision {signed.provider_config_revision} · <code>{signed.provider_config_digest}</code></dd>
        <dt>Finding</dt>
        <dd>{findingLabel(finding)} · revision {signed.finding_revision}</dd>
        <dt>Model</dt>
        <dd>{signed.model} · <code>{signed.model_digest}</code></dd>
        <dt>Exact packet size</dt>
        <dd>{preview.packet_utf8_bytes.toLocaleString()} UTF-8 bytes</dd>
        <dt>Prompt hash</dt>
        <dd><code>{signed.prompt_sha256}</code></dd>
        <dt>Disclosure confirmation hash</dt>
        <dd><code>{signed.confirmation_digest}</code></dd>
      </dl>
      <section className="advisor-confirmation-packet" aria-labelledby={`${titleId}-packet`}>
        <div>
          <h3 id={`${titleId}-packet`}>Exact redacted finding packet</h3>
          <span>{preview.packet_utf8_bytes.toLocaleString()} UTF-8 bytes in the serialized JSON block</span>
        </div>
        <dl>
          {packetFields.map((field) => (
            <div key={field.key}>
              <dt><code>{field.key}</code><span>{field.label}</span></dt>
              <dd><pre className={field.multiline ? 'multiline' : undefined}>{field.value}</pre></dd>
            </div>
          ))}
        </dl>
      </section>
      <div className="advisor-confirmation-categories">
        <h3>Exactly five payload categories</h3>
        <ul>
          {signed.payload_categories.map((category) => <li key={category}><code>{category}</code></li>)}
        </ul>
      </div>
      <p className="advisor-confirmation-boundary">
        The packet above is the exact server-redacted evidence block. Credentials, browser deep-link data, and bulk findings are excluded. Fixed Advisor instructions wrap this block and are bound by the prompt hash. This authorization applies only to this finding revision and the exact provider, destination, model digest, and configuration shown above.
      </p>
      <label className="advisor-confirmation-approval">
        <input
          type="checkbox"
          checked={approved}
          disabled={busy}
          onChange={(event) => setApproved(event.target.checked)}
        />
        I authorize sending this one bounded finding disclosure to this exact remote destination.
      </label>
      <div className="advisor-confirmation-actions">
        <button type="button" className="secondary-action" autoFocus onClick={cancel} disabled={busy}>Cancel — send nothing</button>
        <button type="button" onClick={() => void onConfirm()} disabled={busy || !approved}>
          {busy ? 'Authorizing durable job…' : 'Authorize & send one finding'}
        </button>
      </div>
    </dialog>
  );
}

function scanModeReceipt(scan?: Scan) {
  if (!scan) return { label: '-', warning: null, requested: null, effective: null };
  const requestedMode = scan.scanner_summary?.requested_mode;
  const effectiveMode = scan.scanner_summary?.effective_mode;
  const requested = requestedMode === 'full' || requestedMode === 'incremental_diff' ? requestedMode : scan.mode;
  const effective = effectiveMode === 'full' || effectiveMode === 'incremental_diff' ? effectiveMode : requested;
  const warnings = Array.isArray(scan.scanner_summary?.warnings) ? scan.scanner_summary.warnings : [];
  return {
    label: requested !== effective ? `${requested} → ${effective}` : effective,
    warning: warnings.slice(0, 8).includes(incrementalFallbackWarning) ? incrementalFallbackWarning : null,
    requested,
    effective,
  };
}

function findingLabel(finding?: Finding | null) {
  return finding?.display_id || (finding ? `S${finding.scan_id}-DB${finding.id}` : '-');
}

function gateLimit(value: number) {
  return value < 0 ? 'not blocking' : String(value);
}

function jobFindingLabel(job: Job) {
  return job.finding_display_id || (job.scan_id && job.finding_id ? `S${job.scan_id}-DB${job.finding_id}` : null);
}

function canCancelJob(job: Job) {
  return job.can_cancel ?? ['queued', 'leased', 'running'].includes(job.status);
}

function canRetryJob(job: Job) {
  return job.kind !== 'scanner_cache_reconcile' && job.error_code !== 'scanner_preparation_commit_uncertain'
    && !canReconcileScannerCacheJob(job)
    && job.status === 'failed' && job.can_retry === true && Number.isInteger(job.revision) && (job.revision ?? 0) > 0;
}

function isScannerLifecycleJob(job: Job) {
  return [
    'scanner_catalog_check',
    'scanner_cache_update',
    'scanner_cache_reconcile',
    'scanner_cache_rollback',
  ].includes(job.kind);
}

type JobCancellationCopy = {
  acknowledgement: string;
  completed: string;
  consequence: string;
  pending: string;
};

function jobCancellationCopy(job: Job): JobCancellationCopy {
  if (job.kind === 'scanner_cache_reconcile') return {
    acknowledgement: 'Stopping only the read-only cache outcome check; no scanner data will be changed.',
    completed: 'The read-only check was cancelled. The original preparation remains failed and its cache outcome may remain uncertain.',
    consequence: 'Only this read-only verification stops. The original preparation remains failed; no cache is downloaded, activated, rolled back or pruned.',
    pending: 'Cancellation is persisted; waiting for the read-only check to stop. The original preparation remains failed.',
  };
  if (isScannerLifecycleJob(job)) {
    return {
      acknowledgement: 'The durable worker will cancel the exact updater operation and wait for its terminal receipt.',
      completed: 'Updater cancellation is complete. The active verified cache generation and running scanner image remain authoritative.',
      consequence: 'The source-blind updater will stop at a safe boundary. The active verified cache generation and running scanner image will be kept.',
      pending: "Updater cancellation is persisted; waiting for the updater's terminal receipt. The active verified cache generation and running scanner image remain authoritative.",
    };
  }
  if (job.kind === 'advisor') {
    return {
      acknowledgement: 'Cancellation requested. Waiting for this Advisor connection to close and cleanup to finish.',
      completed: 'Advisor cancellation is complete. No unfinished result was published. Completed reviews remain available.',
      consequence: 'This Advisor request will stop and its connection will close. Completed reviews remain available. Cancellation cannot undo processing or disclosure that already occurred.',
      pending: 'Stopping this Advisor request and confirming cleanup. Completed reviews remain available.',
    };
  }
  if (job.kind === 'scan') {
    return {
      acknowledgement: 'The durable worker will stop the exact scanner run and confirm temporary-output cleanup before marking it cancelled.',
      completed: 'Scanner cancellation is complete. Findings and sanitized artifacts published by completed stages remain available.',
      consequence: 'The exact scanner run will stop. Findings and sanitized artifacts already published by completed stages will be kept; worker-owned temporary output will be cleaned.',
      pending: "Scanner cancellation is persisted; waiting for temporary-output cleanup and the worker's terminal receipt.",
    };
  }
  return {
    acknowledgement: 'The durable worker will stop the exact operation at a safe boundary and wait for its terminal receipt.',
    completed: 'Cancellation is complete.',
    consequence: 'The exact durable operation will stop at a safe boundary. Completed persisted work will be kept.',
    pending: "Cancellation is persisted; waiting for the worker's terminal receipt.",
  };
}

function preservedEvidenceCopy(findingsCount: number, artifactCount: number) {
  const findingLabel = `${findingsCount} ${findingsCount === 1 ? 'finding is' : 'findings are'}`;
  const artifactLabel = `${artifactCount} publishable ${artifactCount === 1 ? 'artifact is' : 'artifacts are'}`;
  if (findingsCount > 0 && artifactCount > 0) {
    return `${findingsCount} ${findingsCount === 1 ? 'finding' : 'findings'} and ${artifactCount} publishable ${artifactCount === 1 ? 'artifact' : 'artifacts'} are preserved for review.`;
  }
  if (findingsCount > 0) return `${findingLabel} preserved for review; no publishable artifacts were preserved.`;
  if (artifactCount > 0) return `${artifactLabel} preserved for review; no findings were preserved.`;
  return 'No findings or publishable artifacts were preserved for this scan.';
}

type LimitedCoverageEvidence = {
  requestedToolIds: string[];
  readyToolIds: string[];
  omittedTools: Array<{ id: string; name: string; reasons: string[] }>;
  preflightRevision: string;
};

function limitedCoverageEvidence(scan: Scan): LimitedCoverageEvidence | null {
  const raw = scan.scanner_summary?.coverage;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const coverage = raw as Record<string, unknown>;
  const boundedToolIds = (value: unknown) => Array.isArray(value)
    ? value.slice(0, 32).filter((item): item is string => typeof item === 'string' && item.length > 0 && item.length <= 80)
    : [];
  if (coverage.mode !== 'limited' || coverage.complete !== false) return null;
  const omittedTools = Array.isArray(coverage.omitted_tools)
    ? coverage.omitted_tools.slice(0, 32).flatMap((rawTool) => {
        if (!rawTool || typeof rawTool !== 'object' || Array.isArray(rawTool)) return [];
        const tool = rawTool as Record<string, unknown>;
        if (typeof tool.id !== 'string' || !tool.id || tool.id.length > 80) return [];
        const name = typeof tool.name === 'string' && tool.name.length > 0 && tool.name.length <= 120
          ? tool.name
          : tool.id;
        const reasons = Array.isArray(tool.blocking_reasons)
          ? tool.blocking_reasons.slice(0, 8).filter((reason): reason is string => (
              typeof reason === 'string' && reason.length > 0 && reason.length <= 512
            ))
          : [];
        return [{ id: tool.id, name, reasons }];
      })
    : [];
  const omittedToolIds = boundedToolIds(coverage.omitted_tool_ids);
  const describedIds = new Set(omittedTools.map((tool) => tool.id));
  omittedTools.push(...omittedToolIds
    .filter((toolId) => !describedIds.has(toolId))
    .map((toolId) => ({ id: toolId, name: toolId, reasons: [] })));
  const preflightRevision = typeof coverage.preflight_revision === 'string' && /^[a-f0-9]{64}$/u.test(coverage.preflight_revision)
    ? coverage.preflight_revision
    : '';
  return {
    requestedToolIds: boundedToolIds(coverage.requested_tool_ids),
    readyToolIds: boundedToolIds(coverage.ready_tool_ids),
    omittedTools,
    preflightRevision,
  };
}

function scannerFailureReasons(scan: Scan): string[] {
  const tools = scan.scanner_summary?.tools;
  if (!Array.isArray(tools)) return [];
  const bearerCategories: Record<string, string> = {
    analysis_error: 'analysis error',
    file_timeout: 'file processing timed out',
    memory_limit: 'memory limit reached',
    worker_failure: 'scanner worker failed',
    unknown: 'unclassified analysis error',
  };
  const bearerAnalysisCategories: Record<string, string> = {
    d: 'directory admission failed',
    e: 'dependency classification failed',
    f: 'framework classification failed',
    p: 'recovered analysis panic',
    s: 'source analysis failed',
    t: 'detector processing failed',
    u: 'unclassified analysis error',
  };
  const reasons = [...new Set(tools.slice(0, 32).flatMap((rawTool) => {
    if (!rawTool || typeof rawTool !== 'object' || Array.isArray(rawTool)) return [];
    const tool = rawTool as Record<string, unknown>;
    if (tool.enabled === false || typeof tool.status !== 'string'
      || !['failed', 'unavailable', 'partial', 'cancelled'].includes(tool.status)) return [];
    const name = typeof tool.name === 'string' && tool.name.trim() && tool.name.length <= 120
      ? tool.name
      : typeof tool.id === 'string' && tool.id.trim() && tool.id.length <= 80 ? tool.id : 'Scanner';
    const error = typeof tool.error === 'string' ? tool.error.trim().slice(0, 400) : '';
    let reason = error || 'No additional failure reason was recorded.';
    if (tool.id === 'bearer' && error.startsWith('bearer_analysis_incomplete:')) {
      const categories = error.slice('bearer_analysis_incomplete:'.length).split(',');
      if (categories.length <= 5) {
        const translated = [...new Set(categories)].map((category) => {
          if (Object.prototype.hasOwnProperty.call(bearerCategories, category)) return [bearerCategories[category]];
          const match = /^aerr_([defpstu]{1,7})$/u.exec(category);
          if (!match || match[1] === 'u' || [...new Set(match[1])].sort().join('') !== match[1]) return null;
          return [...match[1]].map((letter) => bearerAnalysisCategories[letter]);
        });
        if (translated.every((category) => category !== null)) {
          reason = `${[...new Set(translated.flat())].join('; ')}. Bearer findings were not published.`;
        }
      }
    } else if (error === 'timeout') {
      reason = 'The scanner command exceeded its time limit.';
    } else if (tool.id === 'bearer' && error === 'bearer_native_report_invalid') {
      reason = 'The scanner report did not meet the required format. Bearer findings were not published.';
    }
    return [`${name} (${tool.status}): ${reason}`];
  }))];
  const visible = reasons.slice(0, 8);
  if (reasons.length > visible.length) visible.push(`${reasons.length - visible.length} additional scanner failure reasons are not shown.`);
  if (tools.length > 32) visible.push('Additional scanner records are not shown.');
  return visible;
}

export function scanEvidenceNotice(scan: Scan | undefined, findingsCount: number, artifactCount: number) {
  if (!scan) return null;
  if (['pending', 'running', 'analyzing'].includes(scan.status)) {
    return {
      detail: 'Scanner evidence and advisor output may still change. Wait for a terminal scan before requesting advisor review.',
      title: scan.status === 'pending' ? 'Scan is waiting to start'
        : scan.status === 'running' ? 'Scanner execution is in progress' : 'Scan analysis is still in progress',
      scannerFailures: [] as string[],
      sourceFailures: [] as string[],
      nextAction: '',
      tone: 'warning',
    } as const;
  }
  if (!['partial', 'failed', 'cancelled'].includes(scan.status)) return null;
  const title = scan.status === 'partial'
    ? 'Scanner evidence is incomplete'
    : scan.status === 'failed'
      ? 'Scan execution failed'
      : 'Scan was cancelled';
  const cause = scan.error || scan.gate_reasons[0] || (scan.status === 'cancelled'
    ? 'The scanner run stopped before every required stage completed.'
    : 'The scan did not produce a complete required-scanner result.');
  const coverage = limitedCoverageEvidence(scan);
  const omitted = coverage?.omittedTools.map((tool) => (
    tool.reasons.length ? `${tool.name} (${tool.reasons.join('; ')})` : tool.name
  ));
  const coverageDetail = coverage
    ? ` This was an explicitly limited scan: ${coverage.readyToolIds.length} of ${coverage.requestedToolIds.length || coverage.readyToolIds.length + coverage.omittedTools.length} requested scanners ran.${omitted?.length ? ` Omitted scanners: ${omitted.join(', ')}.` : ''} Its deterministic gate is permanently incomplete.`
    : '';
  const scannerFailures = scannerFailureReasons(scan);
  const sourceFailures = sourceCoverageFailures(scan);
  const nextAction = scan.status === 'cancelled'
    ? 'Start a new scan when ready.'
    : coverage
      ? 'Review omitted scanners in Tools and start a new scan when all required scanners are ready.'
      : sourceFailures.length
        ? 'Resolve these source coverage gaps before scanning again. Repeating unchanged source will not fix them.'
        : scannerFailures.length
          ? 'Review these scanner failures before starting a new scan.'
          : 'Review the incomplete evidence above before starting a new scan.';
  return {
    detail: `${cause}${coverageDetail} ${preservedEvidenceCopy(findingsCount, artifactCount)}`,
    scannerFailures,
    sourceFailures,
    nextAction: `${nextAction} A new scan must finish all required scanners before its gate can pass.`,
    title,
    tone: 'error',
  } as const;
}

function jobObservationTime(job: Job) {
  return Math.max(...[
    job.updated_at,
    job.heartbeat_at,
    job.activity?.updated_at,
  ].map((value) => {
    const parsed = value ? Date.parse(value) : Number.NaN;
    return Number.isFinite(parsed) ? parsed : Number.NEGATIVE_INFINITY;
  }));
}

function latestJobObservation(current: Job | undefined, job: Job): Job {
  const currentRevision = current?.revision;
  const incomingRevision = job.revision;
  return current
    && Number.isInteger(currentRevision)
    && Number.isInteger(incomingRevision)
    && (
      (currentRevision ?? 0) > (incomingRevision ?? 0)
      || currentRevision === incomingRevision && jobObservationTime(current) > jobObservationTime(job)
    )
    ? current
    : job;
}

function upsertJob(jobs: Job[], job: Job) {
  const selected = latestJobObservation(jobs.find((item) => item.id === job.id), job);
  return [selected, ...jobs.filter((item) => item.id !== job.id)];
}

type HealthObservation =
  | { status: 'pending'; lossEpoch: number }
  | { status: 'unavailable'; lossEpoch: number }
  | { status: 'ready'; lossEpoch: number; value: Health };

function observedAdvisorPresentation(observation: HealthObservation, providerReadiness: AdvisorProviderReadiness) {
  if (observation.status === 'unavailable') {
    return {
      label: 'Unknown',
      detail: 'Current Advisor status could not be verified. Restore the control plane, then use Refresh; saved findings and reviews are unchanged.',
      model: null,
      pill: 'pending' as const,
    };
  }
  return advisorStatusPresentation({
    health: observation.status === 'ready' ? observation.value : null,
    providerReadiness,
  });
}

function WorkProcessingStatus({ health, compact = false }: { health: Health | null; compact?: boolean }) {
  const worker = health?.worker;
  return (
    <div className={`work-processing-status${worker === false ? ' unavailable' : compact && worker === true ? ' compact' : ''}`} role="status">
      {worker === true ? <CheckCircle2 size={18} aria-hidden="true" /> : worker === false ? <XCircle size={18} aria-hidden="true" /> : <ClockIcon size={18} aria-hidden="true" />}
      <div>
        <strong>{worker === true ? 'Work processing healthy' : worker === false ? 'Work processing unavailable' : 'Work processing status unknown'}</strong>
        <span>
          {worker === true
            ? (compact ? 'Queued work can start.' : 'The durable worker is heartbeating and can claim queued jobs.')
            : worker === false
              ? 'Queued work is safe, but it will not start. Run make up to restore the worker, then use Refresh to verify recovery.'
              : 'The durable-worker health check is not available. Use Refresh to verify current status; cached jobs are not a live processing receipt.'}
        </span>
      </div>
    </div>
  );
}

function findingRepeatTitle(finding: Finding) {
  const count = finding.occurrence_count || 1;
  if (count <= 1) return `Unique finding in stored scan history. Internal database ID #${finding.id}.`;
  const firstSeen = finding.first_seen_display_id ? ` First seen as ${finding.first_seen_display_id}.` : '';
  const prefix = finding.is_repeat ? 'Repeat finding.' : 'Repeated fingerprint.';
  return `${prefix} Same fingerprint appears ${count} times across stored scans.${firstSeen} Internal database ID #${finding.id}.`;
}

function lifecycleLabel(finding: Finding) {
  if (finding.suppressed && finding.lifecycle_status === 'false_positive') return 'false positive';
  if (finding.suppressed && finding.lifecycle_status === 'fixed') return 'fixed';
  if (finding.suppressed) return 'ignored';
  if (finding.lifecycle_status === 'accepted_risk') return 'accepted risk';
  if (finding.gate_exempt) return 'non-blocking';
  if (finding.lifecycle_status === 'needs_review') return 'needs review';
  return 'open';
}

function lifecycleTitle(finding: Finding) {
  const label = lifecycleLabel(finding);
  if (finding.suppressed) return `${label}: present in this scan, but excluded from counts and gate evaluation.`;
  if (finding.gate_exempt) return `${label}: still counted in scan totals, but excluded from gate failure evaluation.`;
  return `${label}: counted and evaluated by the scan gate.`;
}

function lifecycleClass(finding: Finding) {
  return lifecycleLabel(finding).replace(/[^a-z0-9]+/g, '-');
}

function findingLifecycleReason(finding: Finding) {
  return finding.lifecycle_reason || finding.gate_exempt_reason || finding.suppression_reason || '';
}

function detailMatchesFindingSummary(detail: Finding, summary: Finding) {
  return (
    detail.id === summary.id
    && detail.scan_id === summary.scan_id
    && detail.scan_finding_number === summary.scan_finding_number
    && detail.display_id === summary.display_id
    && detail.revision === summary.revision
    && detail.scanner === summary.scanner
    && detail.rule_id === summary.rule_id
    && detail.severity === summary.severity
    && detail.file_path === summary.file_path
    && detail.start_line === summary.start_line
    && detail.start_column === summary.start_column
    && detail.end_line === summary.end_line
    && detail.end_column === summary.end_column
    && detail.message === summary.message
    && detail.fingerprint === summary.fingerprint
    && detail.suppressed === summary.suppressed
    && detail.lifecycle_status === summary.lifecycle_status
    && detail.gate_exempt === summary.gate_exempt
    && detail.gate_effect === summary.gate_effect
    && detail.occurrence_count === summary.occurrence_count
    && detail.is_repeat === summary.is_repeat
    && detail.first_seen_scan_id === summary.first_seen_scan_id
    && detail.first_seen_display_id === summary.first_seen_display_id
    && detail.ai_verdict === (summary.ai_verdict ?? summary.advisor_verdict)
    && detail.ai_confidence === (summary.ai_confidence ?? summary.advisor_confidence)
  );
}

function findingEvidenceMatchesSummary(detail: Finding, summary: Finding) {
  return (
    detail.id === summary.id
    && detail.scan_id === summary.scan_id
    && detail.fingerprint === summary.fingerprint
    && detail.scanner === summary.scanner
    && detail.rule_id === summary.rule_id
    && detail.severity === summary.severity
    && detail.file_path === summary.file_path
    && detail.start_line === summary.start_line
    && detail.start_column === summary.start_column
    && detail.end_line === summary.end_line
    && detail.end_column === summary.end_column
    && detail.message === summary.message
  );
}

function mergeScanSummary(existing: Scan | undefined, summary: ScanSummary): Scan {
  return {
    id: summary.scan.id,
    project_id: summary.scan.project_id,
    mode: summary.scan.mode,
    base_ref: existing?.base_ref,
    head_ref: existing?.head_ref,
    status: summary.scan.status,
    gate_decision: summary.scan.gate_decision,
    gate_reasons: summary.scan.gate_reasons,
    scanner_summary: {
      ...(existing?.scanner_summary || {}),
      findings_total: summary.findings.total,
      findings_active: summary.findings.active,
      findings_suppressed: summary.findings.suppressed,
      findings_gate_exempt: summary.findings.gate_exempt,
    },
    error: summary.scan.error,
    created_at: summary.scan.created_at,
    started_at: summary.scan.started_at,
    completed_at: summary.scan.completed_at,
    duration_ms: summary.scan.duration_ms,
    revision: summary.revision,
    findings_revision: summary.findings_revision,
  };
}

function sameScanSummaryRevision(left: ScanSummary | null, right: ScanSummary) {
  return Boolean(
    left
    && left.scan.id === right.scan.id
    && left.revision === right.revision
    && left.findings_revision === right.findings_revision
    && JSON.stringify(left.scan) === JSON.stringify(right.scan)
    && JSON.stringify(left.findings) === JSON.stringify(right.findings)
  );
}

function validCountMap(counts: Record<string, number>) {
  return Object.values(counts).every((count) => Number.isSafeInteger(count) && count >= 0);
}

function validScanSummary(scanId: number, summary: ScanSummary) {
  const counts = summary.findings;
  return (
    summary.scan.id === scanId
    && Number.isSafeInteger(summary.scan.project_id)
    && summary.scan.project_id > 0
    && Array.isArray(summary.scan.gate_reasons)
    && Number.isSafeInteger(summary.revision)
    && summary.revision >= 1
    && Number.isSafeInteger(summary.findings_revision)
    && summary.findings_revision >= 1
    && Number.isSafeInteger(counts.total)
    && counts.total >= 0
    && Number.isSafeInteger(counts.active)
    && counts.active >= 0
    && Number.isSafeInteger(counts.suppressed)
    && counts.suppressed >= 0
    && Number.isSafeInteger(counts.gate_exempt)
    && counts.gate_exempt >= 0
    && counts.active + counts.suppressed === counts.total
    && counts.gate_exempt <= counts.active
    && validCountMap(counts.severity_counts)
    && validCountMap(counts.scanner_counts)
    && Object.keys(counts.severity_counts).every((severity) => severityOrder.includes(severity))
    && Object.keys(counts.scanner_counts).every((scanner) => scanner.trim().length > 0)
    && Object.values(counts.severity_counts).reduce((sum, count) => sum + count, 0) === counts.active
    && Object.values(counts.scanner_counts).reduce((sum, count) => sum + count, 0) === counts.active
  );
}

function fullFindingPath(project: Project | undefined, finding: Finding) {
  if (!finding.file_path) return project?.repo_path || '';
  if (finding.file_path.startsWith('/')) return finding.file_path;
  const root = (project?.repo_path || '').replace(/\/$/, '');
  return root ? `${root}/${finding.file_path}` : finding.file_path;
}

function formatBytes(value?: number) {
  if (!value) return '0 B';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${Math.round(value / 1024)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function formatTime(value?: string) {
  if (!value) return '-';
  return timeFormatter.format(new Date(value));
}

function FullLocalTime({ value }: { value?: string }) {
  const timestamp = value ? Date.parse(value) : Number.NaN;
  if (!value || !Number.isFinite(timestamp)) return <>-</>;
  return <time dateTime={value}>{fullDateTimeFormatter.format(timestamp)}</time>;
}

function ExpiryTime({ now, value }: { now: number; value?: string }) {
  const timestamp = value ? Date.parse(value) : Number.NaN;
  if (!value || !Number.isFinite(timestamp)) return <>unknown</>;
  const seconds = (timestamp - now) / 1_000;
  const magnitude = Math.abs(seconds);
  const [divisor, unit]: [number, Intl.RelativeTimeFormatUnit] = magnitude < 60
    ? [1, 'second']
    : magnitude < 3_600
      ? [60, 'minute']
      : magnitude < 86_400
        ? [3_600, 'hour']
        : [86_400, 'day'];
  const amount = seconds > 0 ? Math.ceil(seconds / divisor) : Math.floor(seconds / divisor);
  return (
    <span className="expiry-time">
      <FullLocalTime value={value} /> <span>({relativeTimeFormatter.format(amount, unit)})</span>
    </span>
  );
}

function isAbortError(error: unknown) {
  return error instanceof DOMException && error.name === 'AbortError';
}

function useEventCallback<Arguments extends unknown[], Result>(callback: (...args: Arguments) => Result) {
  const callbackRef = useRef(callback);
  useLayoutEffect(() => {
    callbackRef.current = callback;
  }, [callback]);
  return useCallback((...args: Arguments) => callbackRef.current(...args), []);
}

function usePaintedBatch(
  total: number,
  maximumBatchSize: number,
  structuralKey: string,
  settled = true,
  preferredBatchCount = 3,
): PaintedBatchState {
  const batchSize = Math.max(
    1,
    Math.min(maximumBatchSize, Math.ceil(Math.max(1, total) / Math.max(1, preferredBatchCount))),
  );
  // Settlement controls when a structural batch may begin; it is deliberately
  // not part of identity. A same-structure background refresh must keep the
  // already-painted rows mounted, focused, and scrolled while its revision is
  // reconciled.
  const targetKey = `${total}:${structuralKey}`;
  // A settled structural response may commit its first bounded slice in the
  // response render itself. Subsequent slices still cross paint boundaries;
  // this overlaps batching with the route's existing summary/detail staging
  // instead of adding an otherwise-empty frame before the first row.
  const initialCount = settled ? Math.min(total, batchSize) : 0;
  const [batch, setBatch] = useState(() => ({
    committedCount: initialCount,
    key: targetKey,
    ready: false,
  }));
  const resetting = batch.key !== targetKey;
  const priming = !resetting
    && settled
    && !batch.ready
    && batch.committedCount === 0
    && initialCount > 0;

  // Structural changes must be clamped during the response render itself.
  // Waiting for a layout effect alone would briefly commit the complete new
  // collection before the first bounded batch replaces it.
  const committedCount = resetting || priming ? initialCount : Math.min(batch.committedCount, total);
  const ready = !resetting && batch.ready;

  useLayoutEffect(() => {
    if (resetting) {
      setBatch({ committedCount: initialCount, key: targetKey, ready: false });
      return;
    }
    if (!priming) return;
    setBatch((current) => current.key === targetKey && !current.ready && current.committedCount === 0
      ? { ...current, committedCount: initialCount }
      : current);
  }, [initialCount, priming, resetting, targetKey]);

  useEffect(() => {
    if (resetting || batch.ready) return undefined;
    if (!settled) {
      if (batch.committedCount === 0) return undefined;
      setBatch((current) => current.key === targetKey
        ? { ...current, committedCount: 0 }
        : current);
      return undefined;
    }
    if (batch.committedCount >= total) {
      // Passive effects run after React committed the last bounded slice and
      // the browser had its paint opportunity. Marking it ready here avoids a
      // redundant animation frame while retaining the renderer-work fence.
      setBatch((current) => current.key === targetKey ? { ...current, ready: true } : current);
      return undefined;
    }
    let frame: number | undefined;
    const timer = window.setTimeout(() => {
      frame = window.requestAnimationFrame(() => {
        setBatch((current) => current.key === targetKey
          ? { ...current, committedCount: Math.min(total, current.committedCount + batchSize) }
          : current);
      });
    }, 0);
    return () => {
      window.clearTimeout(timer);
      if (frame !== undefined) window.cancelAnimationFrame(frame);
    };
  }, [batch.committedCount, batch.ready, batchSize, resetting, settled, targetKey, total]);

  return {
    committedCount: ready ? total : committedCount,
    ready,
  };
}

function sameRevisionKey(left: RevisionKey | null, right: RevisionKey): boolean {
  if (!left || left.length !== right.length) return false;
  for (let rowIndex = 0; rowIndex < left.length; rowIndex += 1) {
    const leftRow = left[rowIndex];
    const rightRow = right[rowIndex];
    if (leftRow.length !== rightRow.length) return false;
    for (let fieldIndex = 0; fieldIndex < leftRow.length; fieldIndex += 1) {
      if (!Object.is(leftRow[fieldIndex], rightRow[fieldIndex])) return false;
    }
  }
  return true;
}

function countRevisionRows(prefix: string, counts: Record<string, number>): RevisionKey {
  return Object.keys(counts)
    .sort()
    .map((name) => [prefix, name, counts[name]]);
}

function scanRevisionRows(scans: Scan[], prefix = 'scan'): RevisionKey {
  const rows: RevisionKey = [];
  scans.forEach((scan) => {
    const durableScan = scan as Scan & { job_id?: number; job_revision?: number };
    rows.push([
      prefix,
      scan.id,
      scan.project_id,
      scan.mode,
      scan.base_ref,
      scan.head_ref,
      scan.status,
      scan.gate_decision,
      scan.error,
      scan.created_at,
      scan.started_at,
      scan.completed_at,
      scan.duration_ms,
      scan.revision,
      scan.findings_revision,
      durableScan.job_id,
      durableScan.job_revision,
      typeof scan.scanner_summary?.findings_total === 'number' ? scan.scanner_summary.findings_total : undefined,
    ]);
    scan.gate_reasons.forEach((reason, index) => rows.push([`${prefix}-gate-reason`, scan.id, index, reason]));
  });
  return rows;
}

function healthRevisionKey(health: Health): RevisionKey {
  return [
    [
      'health',
      health.ok,
      health.version,
      health.db,
      health.scanner,
      health.worker,
      health.ai.mode,
      health.ai.available,
      health.ai.base_url,
      health.ai.model,
      health.ai.thinking,
      health.ai.reason,
    ],
    ...health.ai.models.map((model, index) => ['health-ai-model', index, model]),
  ];
}

function advisorProviderReadinessRevisionKey(readiness: AdvisorProviderReadiness): RevisionKey {
  if (readiness.status !== 'ready') {
    return [['advisor-provider-readiness', readiness.status, 'reason' in readiness ? readiness.reason : undefined]];
  }
  const { collection } = readiness;
  return [
    [
      'advisor-provider-collection',
      collection.revision,
      collection.active_provider_id,
      collection.resolution.provider_id,
      collection.resolution.transport,
      collection.resolution.reason,
      ...collection.resolution.eligible_provider_ids,
    ],
    ...collection.providers.map((provider) => [
      'advisor-provider',
      provider.id,
      provider.transport,
      provider.enabled,
      provider.authorization,
      provider.status,
      provider.reason,
      provider.reason_code,
      provider.remediation,
      provider.content_disclosure_approved,
      provider.config_revision,
      provider.config_digest,
      provider.model,
      provider.model_digest,
      provider.eligible,
    ]),
  ];
}

function summaryRevisionKey(summary: Summary): RevisionKey {
  const scannerSeverityRows = Object.keys(summary.scanner_severity_counts)
    .sort()
    .flatMap((scanner) => countRevisionRows(`summary-scanner-severity:${scanner}`, summary.scanner_severity_counts[scanner]));
  return [
    [
      'summary',
      summary.projects,
      summary.scans,
      summary.findings,
      summary.finding_occurrences,
      summary.artifacts,
    ],
    ...countRevisionRows('summary-severity', summary.severity_counts),
    ...countRevisionRows('summary-scanner', summary.scanner_counts),
    ...scannerSeverityRows,
    ...summary.top_rules.map((rule, index) => ['summary-top-rule', index, rule.scanner, rule.rule_id, rule.severity, rule.count]),
    ...scanRevisionRows(summary.recent_scans, 'summary-recent-scan'),
  ];
}

function projectsRevisionKey(projects: Project[]): RevisionKey {
  return projects.map((project) => [
    'project',
    project.id,
    project.name,
    project.repo_path,
    project.remote_url,
    project.default_branch,
    project.revision,
    project.created_at,
  ]);
}

function toolsRevisionKey(tools: ScannerTool[]): RevisionKey {
  return tools.map((tool) => [
    'tool',
    tool.id,
    tool.name,
    tool.category,
    tool.lifecycle,
    tool.source,
    tool.output_format,
    tool.description,
    tool.enabled,
    tool.current_version,
    tool.latest_version,
    tool.installed_version,
    tool.available,
    tool.pinned_version,
    tool.status,
    tool.update_available,
    tool.findings_count,
    tool.artifacts_count,
    tool.candidate_release_id,
    tool.candidate_manifest_sha256,
    tool.published_at,
    tool.last_error,
    tool.last_checked_at,
    tool.updated_at,
    tool.runtime_ready,
    tool.readiness ? JSON.stringify(tool.readiness) : undefined,
  ]);
}

function scannerLifecycleRevisionKey(lifecycle: ScannerLifecycle): RevisionKey {
  return [lifecycle.catalog, lifecycle.cache].map((scope) => [
    'scanner-lifecycle',
    scope.scope,
    scope.status,
    scope.revision,
    scope.job_id,
    scope.job_url,
    scope.active_generation,
    scope.previous_generation,
    scope.error_code,
    scope.error_detail,
    scope.started_at,
    scope.completed_at,
    scope.updated_at,
    JSON.stringify(scope.receipt),
  ]);
}

function scannerPreflightRevisionKey(preflight: ScannerPreflight): RevisionKey {
  return [[
    'scanner-preflight',
    preflight.schema_version,
    preflight.revision,
    preflight.ready,
    preflight.catalog_revision,
    preflight.cache_revision,
    preflight.active_generation,
    preflight.recommended_action,
    preflight.preparation_available,
    JSON.stringify(preflight.enabled_tool_ids),
    JSON.stringify(preflight.ready_tool_ids),
    JSON.stringify(preflight.blocked_tools),
    JSON.stringify(preflight.required_component_ids),
    JSON.stringify(preflight.cache_rollback),
    JSON.stringify(preflight.cache_verification),
  ]];
}

export function validScannerPreflight(preflight: ScannerPreflight) {
  const toolIds = (items: string[]) => (
    Array.isArray(items)
    && items.every((item) => typeof item === 'string' && item.length > 0 && item.length <= 80)
    && new Set(items).size === items.length
  );
  const componentIds = new Set(scannerCacheComponents.map((component) => component.id));
  const enabled = new Set(preflight.enabled_tool_ids);
  const ready = new Set(preflight.ready_tool_ids);
  const blocked = new Set(preflight.blocked_tools?.map((tool) => tool.id));
  const rollback = preflight.cache_rollback;
  const rollbackCodes = new Set([
    'eligible',
    'no_previous_generation',
    'cache_pointer_invalid',
    'previous_generation_invalid',
    'previous_generation_verifying',
    'previous_generation_verification_timeout',
    'previous_generation_verification_failed',
    'different_reviewed_locks',
    'previous_generation_incompatible',
    'scanner_unavailable',
    'scanner_eligibility_invalid',
    'state_mismatch',
  ]);
  return (
    preflight.schema_version === 1
    && validScannerVerificationPreflight(preflight)
    && typeof preflight.revision === 'string'
    && /^[a-f0-9]{64}$/u.test(preflight.revision)
    && typeof preflight.ready === 'boolean'
    && toolIds(preflight.enabled_tool_ids)
    && toolIds(preflight.ready_tool_ids)
    && Array.isArray(preflight.blocked_tools)
    && preflight.blocked_tools.length === blocked.size
    && preflight.blocked_tools.every((tool) => (
      enabled.has(tool.id)
      && !ready.has(tool.id)
      && typeof tool.name === 'string'
      && tool.name.length > 0
      && tool.name.length <= 120
      && Array.isArray(tool.blocking_reasons)
      && tool.blocking_reasons.length > 0
      && tool.blocking_reasons.length <= 8
      && tool.blocking_reasons.every((reason) => typeof reason === 'string' && reason.length > 0 && reason.length <= 512)
      && Array.isArray(tool.required_component_ids)
      && tool.required_component_ids.every((componentId) => componentIds.has(componentId))
      && Array.isArray(tool.preparation_blocking_reasons)
      && tool.preparation_blocking_reasons.length <= 4
      && tool.preparation_blocking_reasons.every((reason) => (
        typeof reason === 'string' && reason.length > 0 && reason.length <= 512
      ))
    ))
    && preflight.ready_tool_ids.every((toolId) => enabled.has(toolId))
    && Array.isArray(preflight.required_component_ids)
    && new Set(preflight.required_component_ids).size === preflight.required_component_ids.length
    && preflight.required_component_ids.every((componentId) => componentIds.has(componentId))
    && typeof preflight.preparation_available === 'boolean'
    && preflight.preparation_available === (
      !preflight.cache_verification
      && blocked.size > 0
      && preflight.required_component_ids.length > 0
      && preflight.blocked_tools.every((tool) => tool.preparation_blocking_reasons.length === 0)
    )
    && (preflight.active_generation === null || /^[a-f0-9]{64}$/u.test(preflight.active_generation))
    && (preflight.catalog_revision === null || Number.isSafeInteger(preflight.catalog_revision) && preflight.catalog_revision >= 1)
    && (preflight.cache_revision === null || Number.isSafeInteger(preflight.cache_revision) && preflight.cache_revision >= 1)
    && rollback !== null
    && typeof rollback === 'object'
    && typeof rollback.eligible === 'boolean'
    && typeof rollback.reason_code === 'string'
    && rollbackCodes.has(rollback.reason_code)
    && typeof rollback.reason === 'string'
    && rollback.reason.length > 0
    && rollback.reason.length <= 256
    && (rollback.target_generation === null || /^[a-f0-9]{64}$/u.test(rollback.target_generation))
    && rollback.eligible === (rollback.reason_code === 'eligible')
    && (!rollback.eligible || rollback.target_generation !== null)
    && ['scan', 'prepare_scanners', 'enable_scanner', 'repair_scanner_runtime', 'wait_for_scanner_verification', 'retry_scanner_verification'].includes(preflight.recommended_action)
    && preflight.recommended_action === (
      preflight.cache_verification
        ? scannerVerificationRecommendedAction(preflight.cache_verification)
        : enabled.size === 0
        ? 'enable_scanner'
        : blocked.size === 0
          ? 'scan'
          : preflight.preparation_available
            ? 'prepare_scanners'
            : 'repair_scanner_runtime'
    )
    && preflight.ready === (!preflight.cache_verification && enabled.size > 0 && ready.size === enabled.size && blocked.size === 0)
  );
}

function jobsRevisionKey(jobs: Job[]): RevisionKey {
  // Finding identity and retry eligibility are projected from current
  // findings, so they can change without advancing the persisted job revision.
  // Lease heartbeats and bounded updater activity also advance independently.
  return jobs.map((job) => [
    'job',
    job.id,
    job.revision,
    job.updated_at,
    job.title,
    job.finding_id,
    job.finding_display_id,
    job.finding_scan_number,
    job.finding_rule_id,
    job.can_cancel,
    job.can_retry,
    job.retry_blocked_reason,
    job.heartbeat_at,
    job.activity?.component_id,
    job.activity?.component_index,
    job.activity?.component_total,
    job.activity?.bytes_completed,
    job.activity?.bytes_total,
    job.activity?.updated_at,
  ]);
}

function findingsRevisionKey(findings: Finding[]): RevisionKey {
  // Finding evidence (including snippets and scanner metadata) is immutable
  // after admission. Only include the fields that supported lifecycle and
  // advisor operations may change, plus occurrence metadata used by the UI.
  return findings.map((finding) => [
    'finding',
    finding.id,
    finding.scan_id,
    finding.scan_finding_number,
    finding.revision,
    finding.ai_verdict,
    finding.ai_confidence,
    finding.ai_reasoning,
    finding.ai_fix,
    finding.suppressed,
    finding.suppression_reason,
    finding.lifecycle_status,
    finding.gate_exempt,
    finding.gate_exempt_reason,
    finding.occurrence_count,
    finding.is_repeat,
    finding.first_seen_display_id,
  ]);
}

function artifactsRevisionKey(artifacts: ScanArtifact[]): RevisionKey {
  return artifacts.map((artifact) => [
    'artifact',
    artifact.id,
    artifact.scan_id,
    artifact.scanner,
    artifact.artifact_type,
    artifact.format,
    artifact.path,
    artifact.size_bytes,
    artifact.sha256,
    artifact.created_at,
  ]);
}

function positiveInteger(value: string | null) {
  if (!value || !/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function sourcePrefillFromFragment(requested: boolean): string | null {
  if (!requested || !window.location.hash.startsWith('#')) return null;
  const encoded = new URLSearchParams(window.location.hash.slice(1)).get('source');
  if (!encoded || encoded.length > 683 || !/^[A-Za-z0-9_-]+$/u.test(encoded)) return null;
  try {
    const padded = `${encoded}${'='.repeat((4 - encoded.length % 4) % 4)}`;
    const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (bytes.length === 0 || bytes.length > 512) return null;
    const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (!value.startsWith('/') || value !== value.trim() || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) return null;
    return value;
  } catch {
    return null;
  }
}

function initialWorkbenchLocation() {
  const parameters = new URLSearchParams(window.location.search);
  const requestedView = parameters.get('view') as View | null;
  const scanId = positiveInteger(parameters.get('scan'));
  const findingNumber = scanId ? positiveInteger(parameters.get('finding')) : null;
  const sourceSetupRequested = requestedView === 'projects' && parameters.get('setup') === 'source';
  const automaticLanding = window.location.pathname === '/'
    && !['view', 'scan', 'finding', 'setup'].some((key) => parameters.has(key))
    && !window.location.hash;
  return {
    automaticLanding,
    view: scanId || findingNumber || automaticLanding ? 'findings' as View : requestedView && workbenchViews.has(requestedView) ? requestedView : 'overview' as View,
    scanId,
    findingNumber,
    sourceSetupRequested,
    sourceSetupPrefill: sourcePrefillFromFragment(sourceSetupRequested),
  };
}

function replaceWorkbenchLocation(
  view: View,
  scanId: number | null = null,
  scanFindingNumber: number | null = null,
) {
  // Preserve non-routing query context such as the VS Code retained-browser
  // discriminator, while replacing the complete workbench route atomically.
  // Bootstrap authority never belongs in the query string and the fragment is
  // deliberately cleared after ordinary navigation.
  const parameters = new URLSearchParams(window.location.search);
  parameters.set('view', view);
  parameters.delete('scan');
  parameters.delete('finding');
  parameters.delete('setup');
  if (view === 'findings' && scanId) {
    parameters.set('scan', String(scanId));
    if (scanFindingNumber) parameters.set('finding', String(scanFindingNumber));
  }
  const query = parameters.toString();
  const nextLocation = `${window.location.pathname}${query ? `?${query}` : ''}`;
  if (`${window.location.pathname}${window.location.search}` === nextLocation) return;
  window.history.replaceState(window.history.state, '', nextLocation);
}

function replaceFindingLocation(scanId: number, scanFindingNumber: number | null) {
  replaceWorkbenchLocation('findings', scanId, scanFindingNumber);
}

function Pager({ page, total, pageSize, setPage }: { page: number; total: number; pageSize: number; setPage: (page: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="pager">
      <button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)} title="Previous page">
        <ChevronLeft size={15} />
      </button>
      <span>
        {page} / {pages}
      </span>
      <button type="button" disabled={page >= pages} onClick={() => setPage(page + 1)} title="Next page">
        <ChevronRight size={15} />
      </button>
    </div>
  );
}

function StatusPill({ value, label }: { value: string; label?: string }) {
  return <span className={`pill pill-${value || 'unknown'}`}>{label || value || 'unknown'}</span>;
}

function Severity({ value }: { value: string }) {
  return <span className={`severity severity-${value}`}>{value}</span>;
}

function Stat({ icon: Icon, label, value }: { icon: typeof Shield; label: string; value: string | number }) {
  return (
    <div className="stat">
      <Icon size={18} />
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function WorkbenchSummary({ label, items }: { label: string; items: readonly (readonly [string, string | number])[] }) {
  return (
    <dl className="workbench-summary" aria-label={label}>
      {items.map(([name, value]) => (
        <div key={name}>
          <dt>{name}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

type FindingListRowProps = {
  finding: Finding;
  active: boolean;
  index: number;
  setSize: number;
  selected: boolean;
  fullPath: string;
  onOpen: (id: number) => void;
  onToggleSelected: (id: number) => void;
  registerRef: (id: number, node: HTMLDivElement | null) => void;
};

function sameFindingListRow(left: FindingListRowProps, right: FindingListRowProps) {
  const previous = left.finding;
  const next = right.finding;
  return (
    left.active === right.active
    && left.index === right.index
    && left.setSize === right.setSize
    && left.selected === right.selected
    && left.fullPath === right.fullPath
    && left.onOpen === right.onOpen
    && left.onToggleSelected === right.onToggleSelected
    && left.registerRef === right.registerRef
    && previous.id === next.id
    && previous.scan_id === next.scan_id
    && previous.display_id === next.display_id
    && previous.severity === next.severity
    && previous.scanner === next.scanner
    && previous.rule_id === next.rule_id
    && findingEvidenceMetadataKey(previous) === findingEvidenceMetadataKey(next)
    && previous.file_path === next.file_path
    && previous.start_line === next.start_line
    && previous.start_column === next.start_column
    && previous.end_line === next.end_line
    && previous.end_column === next.end_column
    && previous.message === next.message
    && previous.suppressed === next.suppressed
    && previous.lifecycle_status === next.lifecycle_status
    && previous.gate_exempt === next.gate_exempt
    && previous.occurrence_count === next.occurrence_count
    && previous.is_repeat === next.is_repeat
    && previous.first_seen_display_id === next.first_seen_display_id
    && previous.ai_verdict === next.ai_verdict
  );
}

export const FindingListRow = memo(function FindingListRow({
  finding,
  active,
  index,
  setSize,
  selected,
  fullPath,
  onOpen,
  onToggleSelected,
  registerRef,
}: FindingListRowProps) {
  const repeatTitle = findingRepeatTitle(finding);
  const evidencePresentation = findingEvidencePresentation(finding);
  return (
    <div
      className={`finding-list-item ${active ? 'active' : ''} ${selected ? 'selected' : ''} ${finding.suppressed ? 'suppressed' : ''}`}
      aria-posinset={index + 1}
      aria-setsize={setSize}
      role="listitem"
      ref={(node) => registerRef(finding.id, node)}
      style={{ top: `${index * findingListRowExtentRem}rem` }}
    >
      <label className="finding-select" title="Select finding for bulk actions">
        <input
          type="checkbox"
          aria-label={`Select ${findingLabel(finding)}`}
          checked={selected}
          onChange={() => onToggleSelected(finding.id)}
        />
      </label>
      <button
        type="button"
        className="finding-list-main"
        aria-label={[
          findingLabel(finding),
          finding.severity,
          lifecycleLabel(finding),
          finding.occurrence_count > 1 ? (finding.is_repeat ? 'repeat' : `${finding.occurrence_count}x`) : '',
          finding.scanner,
          finding.rule_id,
          findingLocation(finding),
          finding.message,
          findingAdvisorVerdictLabel(finding.ai_verdict),
        ].filter(Boolean).join(' ')}
        aria-pressed={active}
        onClick={() => onOpen(finding.id)}
      >
        <span className="finding-item-top">
          <span className="finding-number">{findingLabel(finding)}</span>
          <span className={`finding-list-severity severity-${finding.severity}`}>{finding.severity}</span>
          <span className={`finding-list-lifecycle lifecycle-${lifecycleClass(finding)}`} title={lifecycleTitle(finding)}>
            {lifecycleLabel(finding)}
          </span>
          {finding.occurrence_count > 1 ? (
            <span className="finding-list-repeat" title={repeatTitle}>
              {finding.is_repeat ? 'repeat' : `${finding.occurrence_count}x`}
            </span>
          ) : null}
          <span className="finding-scanner" title={finding.scanner}>{finding.scanner}</span>
        </span>
        <strong className="finding-rule" title={`${evidencePresentation.title} · ${finding.rule_id}`}>{evidencePresentation.title}</strong>
        <span className="finding-location" title={`${fullPath}${finding.start_line ? ` · ${findingLocation(finding)}` : ''}`}>{findingLocation(finding)}</span>
        <span className="finding-message" title={finding.rule_id}>{evidencePresentation.label} · {finding.rule_id}</span>
      </button>
    </div>
  );
}, sameFindingListRow);

type FindingListPaneProps = {
  activeFindingId: number | null;
  activeFindingsCount: number;
  allVisibleSelected: boolean;
  busy: boolean;
  filteredFindings: Finding[];
  renderedFindingCount: number;
  findingsLoading: boolean;
  emptyMessage: string;
  gateExemptCount: number;
  ignoredCount: number;
  page: number;
  pageSize: number;
  onOpen: (id: number) => void;
  onRunBulk: (action: string) => void;
  onToggleSelected: (id: number) => void;
  onToggleVisibleSelection: () => void;
  onClearSelection: () => void;
  registerRef: (id: number, node: HTMLDivElement | null) => void;
  visible: boolean;
  selectedFindingIds: ReadonlySet<number>;
  selectedIdsCount: number;
  selectedProject?: Project;
  setPage: (page: number) => void;
  totalFilteredCount: number;
  triageSelectionValid: boolean;
};

function DisabledReason({ id, reason }: { id: string; reason: string | null }) {
  if (!reason) return null;
  return <p className="disabled-action-reason" id={id} role="status">{reason}</p>;
}

export const FindingListPane = memo(function FindingListPane({
  activeFindingId,
  activeFindingsCount,
  allVisibleSelected,
  busy,
  filteredFindings,
  renderedFindingCount,
  findingsLoading,
  emptyMessage,
  gateExemptCount,
  ignoredCount,
  page,
  pageSize,
  onOpen,
  onRunBulk,
  onToggleSelected,
  onToggleVisibleSelection,
  onClearSelection,
  registerRef,
  visible,
  selectedFindingIds,
  selectedIdsCount,
  selectedProject,
  setPage,
  totalFilteredCount,
  triageSelectionValid,
}: FindingListPaneProps) {
  const hasSelection = selectedIdsCount > 0;
  const bulkLifecycleDisabledReason = busy
    ? 'Finding actions are unavailable while the current update is being reconciled.'
    : findingBulkSelectionDisabledReason(selectedIdsCount);
  const bulkLifecycleReasonId = 'bulk-lifecycle-disabled-reason';
  const bulkAdvisorDisabledReason = bulkLifecycleDisabledReason || (!triageSelectionValid
    ? 'Advisor review accepts active findings from a terminal scan only.'
    : null);
  const bulkAdvisorReasonId = bulkLifecycleDisabledReason ? bulkLifecycleReasonId : 'bulk-advisor-disabled-reason';
  const renderedFindings = filteredFindings.slice(0, renderedFindingCount);
  const findingTrackHeight = renderedFindingCount > 0
    ? (renderedFindingCount * findingListRowHeightRem) + ((renderedFindingCount - 1) * findingListRowGapRem)
    : 0;
  return (
    <div className="finding-list">
      {visible ? (
        <>
          <div className="list-head">
            <div>
              <strong>{totalFilteredCount} {totalFilteredCount === 1 ? 'finding' : 'findings'}</strong>
              <span>{activeFindingsCount} active · {gateExemptCount} non-blocking · {ignoredCount} ignored</span>
            </div>
            <div className="finding-list-controls">
              <button className="secondary-action" onClick={onToggleVisibleSelection} disabled={!filteredFindings.length}>
                {allVisibleSelected ? <CheckSquare2 size={15} /> : <Square size={15} />}
                {allVisibleSelected ? 'Clear' : 'Select visible'}
              </button>
              {totalFilteredCount > pageSize ? <Pager page={page} total={totalFilteredCount} pageSize={pageSize} setPage={setPage} /> : null}
            </div>
          </div>
          <div
            aria-label="Bulk finding actions"
            aria-live="polite"
            className={`bulk-actions ${hasSelection ? '' : 'bulk-actions-empty'}`}
            role="region"
            tabIndex={0}
          >
            {hasSelection ? <strong>{selectedIdsCount} selected</strong> : null}
            {hasSelection ? (
              <button type="button" className="secondary-action" onClick={onClearSelection}>Clear selection</button>
            ) : null}
            <details className="bulk-action-disclosure">
              <summary>{hasSelection ? 'Review actions' : 'No findings selected · Review actions'}</summary>
              <div className="bulk-action-controls">
                <button
                  aria-describedby={bulkAdvisorDisabledReason ? bulkAdvisorReasonId : undefined}
                  onClick={() => onRunBulk('triage')}
                  disabled={Boolean(bulkAdvisorDisabledReason)}
                  title={bulkAdvisorDisabledReason || 'Queue advisor review for the selected active findings.'}
                >
                  <Bot size={15} /> Advisor
                </button>
                <button aria-describedby={bulkLifecycleDisabledReason ? bulkLifecycleReasonId : undefined} onClick={() => onRunBulk('gate_exempt')} disabled={Boolean(bulkLifecycleDisabledReason)}><ShieldOff size={15} /> Non-blocking</button>
                <button aria-describedby={bulkLifecycleDisabledReason ? bulkLifecycleReasonId : undefined} onClick={() => onRunBulk('ignore')} disabled={Boolean(bulkLifecycleDisabledReason)}><EyeOff size={15} /> Ignore</button>
                <button aria-describedby={bulkLifecycleDisabledReason ? bulkLifecycleReasonId : undefined} onClick={() => onRunBulk('accepted_risk')} disabled={Boolean(bulkLifecycleDisabledReason)}><Shield size={15} /> Accept Risk</button>
                <button aria-describedby={bulkLifecycleDisabledReason ? bulkLifecycleReasonId : undefined} onClick={() => onRunBulk('false_positive')} disabled={Boolean(bulkLifecycleDisabledReason)}><Ban size={15} /> False positive</button>
                <button aria-describedby={bulkLifecycleDisabledReason ? bulkLifecycleReasonId : undefined} onClick={() => onRunBulk('fixed')} disabled={Boolean(bulkLifecycleDisabledReason)}><CheckCircle2 size={15} /> Fixed</button>
                <button aria-describedby={bulkLifecycleDisabledReason ? bulkLifecycleReasonId : undefined} onClick={() => onRunBulk('needs_review')} disabled={Boolean(bulkLifecycleDisabledReason)}><AlertTriangle size={15} /> Needs review</button>
                <button aria-describedby={bulkLifecycleDisabledReason ? bulkLifecycleReasonId : undefined} onClick={() => onRunBulk('open')} disabled={Boolean(bulkLifecycleDisabledReason)}><Undo2 size={15} /> Reopen</button>
                <button aria-describedby={bulkLifecycleDisabledReason ? bulkLifecycleReasonId : undefined} className="danger" onClick={() => onRunBulk('delete')} disabled={Boolean(bulkLifecycleDisabledReason)}><Trash2 size={15} /> Delete</button>
                <DisabledReason id={bulkLifecycleReasonId} reason={bulkLifecycleDisabledReason} />
                {!bulkLifecycleDisabledReason ? <DisabledReason id={bulkAdvisorReasonId} reason={bulkAdvisorDisabledReason} /> : null}
              </div>
            </details>
          </div>
          <div
            aria-label="Findings list viewport"
            className="finding-list-scroll"
            role="region"
            tabIndex={0}
          >
            <div className="finding-list-track" role={renderedFindings.length ? 'list' : undefined} aria-label={renderedFindings.length ? 'Findings in the current page' : undefined} style={{ height: `${findingTrackHeight}rem` }}>
              {renderedFindings.map((finding, index) => (
                <FindingListRow
                  active={activeFindingId === finding.id}
                  finding={finding}
                  fullPath={fullFindingPath(selectedProject, finding)}
                  index={index}
                  key={finding.id}
                  onOpen={onOpen}
                  onToggleSelected={onToggleSelected}
                  registerRef={registerRef}
                  selected={selectedFindingIds.has(finding.id)}
                  setSize={renderedFindingCount}
                />
              ))}
            </div>
          </div>
          {!filteredFindings.length ? <div className="empty-state">{findingsLoading ? 'Loading findings for the selected scan.' : emptyMessage}</div> : null}
        </>
      ) : (
        <div className="empty-state" role="status">Preparing the findings list.</div>
      )}
    </div>
  );
});

type FindingDetailContentProps = {
  detailPending: boolean;
  pendingLifecycleReason: string;
  advisorAllowed: boolean;
  busy: boolean;
  finding: Finding;
  fullPath: string;
  showEvidence: boolean;
  snippetHeight: number;
  setSnippetHeight: (height: number) => void;
  sourceNavigationDisabledReason: string | null;
  ideCapabilities: IdeCapability[];
  sourceOpenCommand: SourceOpenCommand | null;
  onTriage: (findingId: number) => void;
  onLifecycle: (findingId: number, action: string) => void;
  onDelete: (findingId: number) => void;
  onOpenSource: (finding: Finding, capability: IdeValidCapability) => void;
  onRefreshIdeClients: () => void;
};

function sameFindingDetailContent(left: FindingDetailContentProps, right: FindingDetailContentProps) {
  const previous = left.finding;
  const next = right.finding;
  // Keep this detail ownership boundary in lockstep
  // with every finding field read below; advisor fields belong to the sibling panel.
  return (
    left.advisorAllowed === right.advisorAllowed
    && left.detailPending === right.detailPending
    && left.pendingLifecycleReason === right.pendingLifecycleReason
    && left.busy === right.busy
    && left.fullPath === right.fullPath
    && left.showEvidence === right.showEvidence
    && left.snippetHeight === right.snippetHeight
    && left.setSnippetHeight === right.setSnippetHeight
    && left.sourceNavigationDisabledReason === right.sourceNavigationDisabledReason
    && left.ideCapabilities === right.ideCapabilities
    && left.sourceOpenCommand === right.sourceOpenCommand
    && left.onTriage === right.onTriage
    && left.onLifecycle === right.onLifecycle
    && left.onDelete === right.onDelete
    && left.onOpenSource === right.onOpenSource
    && left.onRefreshIdeClients === right.onRefreshIdeClients
    && previous.id === next.id
    && previous.scan_id === next.scan_id
    && previous.display_id === next.display_id
    && previous.severity === next.severity
    && previous.scanner === next.scanner
    && previous.rule_id === next.rule_id
    && findingEvidenceMetadataKey(previous) === findingEvidenceMetadataKey(next)
    && previous.message === next.message
    && previous.occurrence_count === next.occurrence_count
    && previous.is_repeat === next.is_repeat
    && previous.first_seen_display_id === next.first_seen_display_id
    && previous.suppressed === next.suppressed
    && previous.lifecycle_status === next.lifecycle_status
    && previous.gate_exempt === next.gate_exempt
    && previous.file_path === next.file_path
    && previous.start_line === next.start_line
    && previous.start_column === next.start_column
    && previous.end_line === next.end_line
    && previous.end_column === next.end_column
    && previous.gate_effect === next.gate_effect
    && findingLifecycleReason(previous) === findingLifecycleReason(next)
    && previous.code_snippet === next.code_snippet
  );
}

const FindingDetailContent = memo(function FindingDetailContent({
  detailPending,
  pendingLifecycleReason,
  advisorAllowed,
  busy,
  finding,
  fullPath,
  showEvidence,
  snippetHeight,
  setSnippetHeight,
  sourceNavigationDisabledReason,
  ideCapabilities,
  sourceOpenCommand,
  onTriage,
  onLifecycle,
  onDelete,
  onOpenSource,
  onRefreshIdeClients,
}: FindingDetailContentProps) {
  const evidencePresentation = findingEvidencePresentation(finding);
  const lifecycleReason = findingLifecycleReason(finding);
  const lifecycleLayoutReason = lifecycleReason || (detailPending ? pendingLifecycleReason : '');
  const validIdeClients = useMemo(() => validIdeCapabilities(ideCapabilities), [ideCapabilities]);
  const availableIdeClients = useMemo(() => sourceOpenIdeCapabilities(ideCapabilities), [ideCapabilities]);
  const invalidIdeClientCount = ideCapabilities.length - validIdeClients.length;
  const [selectedIdeClient, setSelectedIdeClient] = useState('');
  useEffect(() => {
    if (availableIdeClients.some((client) => client.id === selectedIdeClient)) return;
    setSelectedIdeClient(availableIdeClients.length === 1 ? availableIdeClients[0].id : '');
  }, [availableIdeClients, selectedIdeClient]);
  const selectedCapability = availableIdeClients.find((client) => client.id === selectedIdeClient);
  const sourceCommandForFinding = sourceOpenCommand?.finding_id === finding.id ? sourceOpenCommand : null;
  const noAvailableIdeReason = validIdeClients.length === 0 && invalidIdeClientCount > 0
    ? 'Only invalid IDE client records are available. Open Settings → IDE access, remove each exact invalid profile record, then let VS Code request access again before opening source.'
    : validIdeClients[0]?.source_open_disabled_reason
      || 'No paired IDE has exactly one active CodeSecurity event-stream connection. Pair or reconnect VS Code, then refresh IDE clients.';
  const unavailableReason = sourceNavigationDisabledReason || (availableIdeClients.length === 0
    ? noAvailableIdeReason
    : !selectedIdeClient
      ? 'Choose one connected editor under IDE.'
      : selectedCapability?.source_open_disabled_reason || null);
  const advisorBusyReason = 'Updating finding…';
  const advisorDisabledReason = finding.suppressed
    ? 'Reopen this finding before requesting Advisor review.'
    : !advisorAllowed
      ? 'Advisor review requires a terminal scan with persisted findings.'
      : busy
        ? advisorBusyReason
        : null;
  const advisorDisabledReasonId = 'finding-advisor-disabled-reason';
  const lifecycleCurrentReasonId = 'finding-lifecycle-current-reason';
  const lifecycleCurrentReason = findingLifecycleActionDisabledReason(
    finding.lifecycle_status,
    finding.lifecycle_status,
  );
  const lifecycleActions = [
    { action: 'gate_exempt', label: 'Non-blocking for gate', icon: <ShieldOff size={14} /> },
    { action: 'accepted_risk', label: 'Accept risk', icon: <Shield size={14} /> },
    { action: 'ignore', label: 'Ignore / not counted', icon: <EyeOff size={14} /> },
    { action: 'false_positive', label: 'False positive', icon: <Ban size={14} /> },
    { action: 'fixed', label: 'Mark fixed', icon: <CheckCircle2 size={14} /> },
    { action: 'needs_review', label: 'Needs review', icon: <AlertTriangle size={14} /> },
    { action: 'open', label: 'Reopen as blocking', icon: <Undo2 size={14} /> },
  ] as const;
  return (
    <>
      <div className="finding-detail-head">
        <div className="finding-detail-identity">
          <h2 tabIndex={-1}>{findingLabel(finding)}</h2>
          <Severity value={finding.severity} />
          <button className="danger finding-delete-action" aria-label="Delete this finding from the selected scan" disabled={busy} onClick={() => onDelete(finding.id)} title="Delete this finding from the selected scan">
            <Trash2 size={15} />
          </button>
        </div>
        <h3 className="finding-readable-title">{evidencePresentation.title}</h3>
        <span>{evidencePresentation.label}{evidencePresentation.verifiedSecret ? ' · Scanner verified' : ''} · Detected by {finding.scanner} · Rule {finding.rule_id}</span>
      </div>
      <section className="finding-primary-actions" aria-label="Actions for the selected finding">
        <div className="finding-detail-actions">
          <button
            aria-describedby={unavailableReason ? 'finding-source-unavailable-reason' : undefined}
            disabled={busy || Boolean(unavailableReason)}
            onClick={() => selectedCapability && onOpenSource(finding, selectedCapability)}
            title={unavailableReason || 'Queue this exact finding for the selected connected IDE and wait for its acknowledgement.'}
          >
            <Code2 size={15} /> {sourceCommandForFinding?.status === 'queued' ? 'Check IDE result' : 'Open source in VS Code'}
          </button>
          <details className="finding-ide-menu">
            <summary aria-label="IDE connection" title="Choose or reconnect an IDE">IDE</summary>
            <div>
              <label className="source-open-target">
                <span>IDE target</span>
                <select
                  aria-label="IDE target for source navigation"
                  disabled={Boolean(sourceNavigationDisabledReason)}
                  value={selectedIdeClient}
                  onChange={(event) => setSelectedIdeClient(event.target.value)}
                >
                  <option value="">Select IDE</option>
                  {validIdeClients.map((client) => (
                    <option key={client.id} value={client.id} disabled={!client.source_open_available}>
                      {ideClientTargetLabel(client, validIdeClients)}{client.source_open_available ? '' : ' — unavailable'}
                    </option>
                  ))}
                </select>
              </label>
              <button
                className="secondary-action"
                aria-label="Refresh connected IDE clients"
                disabled={busy}
                onClick={onRefreshIdeClients}
                title="Refresh connected IDE clients"
              >
                <RefreshCw size={15} /> Refresh IDEs
              </button>
            </div>
          </details>
          <button
            aria-describedby={advisorDisabledReason ? advisorDisabledReasonId : undefined}
            disabled={Boolean(advisorDisabledReason)}
            onClick={() => onTriage(finding.id)}
            title={advisorDisabledReason || 'Review the authoritative Advisor route and queue one durable finding review.'}
          >
            <Bot size={15} /> Run Advisor
          </button>
          <details
            className="finding-action-menu"
            onToggle={(event) => {
              const details = event.currentTarget;
              if (!details.open) return;
              requestAnimationFrame(() => {
                const owner = details.closest<HTMLElement>('.finding-detail');
                const menu = details.querySelector<HTMLElement>(':scope > div');
                // Reveal a compact menu in a bounded desktop pane. Natural-height
                // mobile content and oversized menus retain keyboard focus position.
                if (!details.open || !owner || !menu || getComputedStyle(owner).overflowY !== 'auto'
                  || details.offsetHeight > Math.min(owner.clientHeight, window.innerHeight - 24)) return;
                menu.scrollIntoView({ block: 'nearest', inline: 'nearest' });
              });
            }}
          >
            <summary>
              <SlidersHorizontal size={15} /> Lifecycle
            </summary>
            <div>
              {lifecycleActions.map(({ action, icon, label }) => {
                const currentReason = findingLifecycleActionDisabledReason(action, finding.lifecycle_status);
                return (
                  <button
                    aria-describedby={currentReason ? lifecycleCurrentReasonId : undefined}
                    disabled={busy || Boolean(currentReason)}
                    key={action}
                    onClick={() => onLifecycle(finding.id, action)}
                    title={currentReason || `Set this finding to ${findingLifecycleActionLabel(action)}.`}
                  >
                    {icon} {label}
                  </button>
                );
              })}
              <DisabledReason id={lifecycleCurrentReasonId} reason={lifecycleCurrentReason} />
              <button className="danger" disabled={busy} onClick={() => onDelete(finding.id)}>
                <Trash2 size={14} /> Delete finding
              </button>
            </div>
          </details>
        </div>
        <div className="finding-advisor-guidance">
          <p className="disabled-action-reason finding-advisor-guidance-reserve" aria-hidden="true">{advisorBusyReason}</p>
          <DisabledReason id={advisorDisabledReasonId} reason={advisorDisabledReason} />
        </div>
        {unavailableReason ? <p id="finding-source-unavailable-reason" className="source-open-status" role="status">{unavailableReason}</p> : null}
        {sourceCommandForFinding ? (
          <p className={`source-open-status source-open-${sourceCommandForFinding.status}`} role="status">
            VS Code source request: {sourceCommandForFinding.status}
            {sourceCommandForFinding.error_code ? ` (${sourceCommandForFinding.error_code})` : ''}.
          </p>
        ) : null}
      </section>
      <div className="identity-strip">
        <span title={lifecycleTitle(finding)}>
          Lifecycle <strong>{lifecycleLabel(finding)}</strong>
        </span>
        <span title="Authoritative deterministic gate effect for this finding revision.">
          Gate effect <strong>{findingGateEffectLabel(finding.gate_effect)}</strong>
        </span>
      </div>
      {lifecycleLayoutReason ? (
        <p
          aria-hidden={!lifecycleReason ? true : undefined}
          className={`finding-summary${!lifecycleReason ? ' finding-layout-reserve' : ''}`}
        >
          Lifecycle reason: {lifecycleLayoutReason}
        </p>
      ) : null}
      {showEvidence ? (
        <FindingEvidence finding={finding} setSnippetHeight={setSnippetHeight} snippetHeight={snippetHeight} />
      ) : null}
      <details className="finding-description">
        <summary>Scanner description</summary>
        <p className="finding-summary">{finding.message}</p>
        {finding.metadata_json?.message_truncated === true ? <p className="evidence-boundary-note">The scanner message was shortened at the evidence boundary.</p> : null}
      </details>
      <div className="finding-provenance">
        <div className="path-line" title={fullPath}><small>{fullPath}</small></div>
        <div className="identity-strip">
          <span title="Scan-local label: stable inside this scan, sorted by severity, file, line, scanner, and rule.">
            Scan-local ID <strong>{findingLabel(finding)}</strong>
          </span>
          <span title={findingRepeatTitle(finding)}>
            Repeat status <strong>{finding.occurrence_count > 1 ? (finding.is_repeat ? 'already seen' : `${finding.occurrence_count} matches`) : 'unique'}</strong>
          </span>
          {finding.first_seen_display_id && finding.first_seen_display_id !== findingLabel(finding) ? (
            <span title="The earliest stored finding with the same fingerprint.">
              First seen <strong>{finding.first_seen_display_id}</strong>
            </span>
          ) : null}
        </div>
      </div>
    </>
  );
}, sameFindingDetailContent);

type FindingAdvisorPanelProps = {
  verdict?: string;
  confidenceValue?: number;
  reasoning?: string;
  fix?: string;
  loading?: boolean;
};

// Primitive-only advisor props keep confidence reconciliation out of static evidence.
const FindingAdvisorPanel = memo(function FindingAdvisorPanel({ verdict, confidenceValue, reasoning, fix, loading }: FindingAdvisorPanelProps) {
  const verdictLabel = findingAdvisorVerdictLabel(verdict);
  const explanation = reasoning?.trim()
    ? reasoning
    : loading && verdict
      ? 'Loading the exact Advisor explanation for this resource revision.'
      : 'The advisor returned no explanation.';
  const remediation = fix?.trim()
    ? fix
    : loading && verdict
      ? 'Loading the exact Advisor remediation for this resource revision.'
      : 'The advisor returned no remediation suggestion.';
  return (
    <div className={`advisor-panel ${verdict ? 'advisor-panel-on' : ''}`}>
      <div className="detail-section-head">
        <Sparkles size={16} />
        <strong>Advisor Analysis</strong>
      </div>
      {verdict ? (
        <>
          <div className="advisor-verdict">
            <span><span className="visually-hidden">Verdict: </span>{verdictLabel}</span>
            <small><span className="visually-hidden">Confidence </span>{confidence(confidenceValue)}</small>
          </div>
          <div className="advisor-explanation">
            <strong>Reasoning</strong>
            <p role="region" aria-label="Advisor reasoning" tabIndex={0}>{explanation}</p>
          </div>
          <div className="fix-box">
            <strong>Fix</strong>
            <p role="region" aria-label="Advisor fix" tabIndex={0}>{remediation}</p>
          </div>
          <p className="advisor-boundary">Advisory only. This review does not change finding lifecycle or the deterministic gate.</p>
        </>
      ) : (
        <div className="empty-state">Advisor reviews start only when you request them. An active, tested, authorized Direct or SSH provider supports one explicit finding submission after its exact disclosure preview is reviewed and confirmed. Automatic remote routing, scan-wide review, and bulk review remain unavailable.</div>
      )}
    </div>
  );
});

type PendingLifecycleLayout = { findingId: number; scanId: number; reason: string } | null;

type FindingDetailPaneProps = {
  reportView: FindingReportView | null;
  onSelectRelated: (findingId: number) => void;
  pendingLifecycleLayout: PendingLifecycleLayout;
  advisorAllowed: boolean;
  busy: boolean;
  fallbackFindingId: number | null;
  findings: Finding[];
  findingsLoading: boolean;
  ideCapabilities: IdeCapability[];
  detailLoading: boolean;
  detailError: string | null;
  emptyMessage: string;
  onDelete: (findingId: number) => void;
  onLifecycle: (findingId: number, action: string) => void;
  onTriage: (findingId: number) => void;
  onOpenSource: (finding: Finding, capability: IdeValidCapability) => void;
  onRefreshIdeClients: () => void;
  renderStage: FindingsRenderStage;
  selectedFindingId: number | null;
  selectedProject?: Project;
  sourceOpenCommand: SourceOpenCommand | null;
  setSnippetHeight: (height: number) => void;
  snippetHeight: number;
};

const FindingDetailPane = memo(function FindingDetailPane({
  reportView,
  onSelectRelated,
  pendingLifecycleLayout,
  advisorAllowed,
  busy,
  fallbackFindingId,
  findings,
  findingsLoading,
  ideCapabilities,
  detailLoading,
  detailError,
  emptyMessage,
  onDelete,
  onLifecycle,
  onTriage,
  onOpenSource,
  onRefreshIdeClients,
  renderStage,
  selectedFindingId,
  selectedProject,
  sourceOpenCommand,
  setSnippetHeight,
  snippetHeight,
}: FindingDetailPaneProps) {
  const activeFinding = findings.find((finding) => finding.id === selectedFindingId)
    || findings.find((finding) => finding.id === fallbackFindingId)
    || null;
  const [presentedFinding, setPresentedFinding] = useState<Finding | null>(activeFinding);
  const [detailRenderStage, setDetailRenderStage] = useState<FindingDetailRenderStage>('ready');
  const routeReady = renderStage === 'ready';
  const targetFindingId = activeFinding?.id ?? null;
  const presentedFindingId = presentedFinding?.id ?? null;
  const selectionPending = routeReady && (
    targetFindingId !== presentedFindingId || detailRenderStage !== 'ready'
  );
  const livePresentedFinding = presentedFinding
    ? findings.find((finding) => finding.id === presentedFinding.id) || presentedFinding
    : null;
  const detailFinding = routeReady ? livePresentedFinding : activeFinding;
  const detailFindingFullPath = detailFinding ? fullFindingPath(selectedProject, detailFinding) : '';
  const routeHasStatic = ['detail-static', 'detail-evidence', 'ready'].includes(renderStage);
  const routeHasEvidence = ['detail-evidence', 'ready'].includes(renderStage);
  const routeHasAdvisor = routeHasEvidence;
  const selectionHasEvidence = ['evidence', 'advisor', 'ready'].includes(detailRenderStage);
  const selectionHasAdvisor = ['advisor', 'ready'].includes(detailRenderStage);
  const showStatic = routeReady || routeHasStatic;
  const showEvidence = routeReady ? selectionHasEvidence : routeHasEvidence;
  const showAdvisor = routeReady ? selectionHasAdvisor : routeHasAdvisor;
  const relatedReports = useMemo(() => reportView && detailFinding && selectedProject && !detailLoading
    ? otherReportsAtLocation(reportView, detailFinding, selectedProject.id) : [],
  [reportView, detailFinding, selectedProject, detailLoading]);

  useLayoutEffect(() => {
    if (routeReady) return;
    setPresentedFinding((current) => (current?.id ?? null) === targetFindingId ? current : activeFinding);
    setDetailRenderStage('ready');
  }, [activeFinding, routeReady, targetFindingId]);

  useEffect(() => {
    if (!routeReady || targetFindingId === presentedFindingId) return undefined;
    let frame: number | undefined;
    const timer = window.setTimeout(() => {
      frame = window.requestAnimationFrame(() => {
        setPresentedFinding(activeFinding);
        setDetailRenderStage('static');
      });
    }, 0);
    return () => {
      window.clearTimeout(timer);
      if (frame !== undefined) window.cancelAnimationFrame(frame);
    };
  }, [activeFinding, presentedFindingId, routeReady, targetFindingId]);

  useEffect(() => {
    if (!routeReady || targetFindingId !== presentedFindingId || detailRenderStage === 'ready') return undefined;
    const nextStage: FindingDetailRenderStage = detailRenderStage === 'static'
      ? 'evidence'
      : detailRenderStage === 'evidence'
        ? 'advisor'
        : 'ready';
    let frame: number | undefined;
    const timer = window.setTimeout(() => {
      frame = window.requestAnimationFrame(() => {
        setDetailRenderStage((current) => current === detailRenderStage ? nextStage : current);
      });
    }, 0);
    return () => {
      window.clearTimeout(timer);
      if (frame !== undefined) window.cancelAnimationFrame(frame);
    };
  }, [detailRenderStage, presentedFindingId, routeReady, targetFindingId]);

  return (
    <article
      aria-busy={!routeReady || selectionPending || detailLoading}
      aria-hidden={selectionPending ? true : undefined}
      className="finding-detail"
      data-finding-id={detailFinding?.id}
      inert={selectionPending}
    >
      {!showStatic ? (
        <div className="empty-state" role="status">Preparing finding detail.</div>
      ) : detailError ? (
        <div className="notice" role="alert">
          <AlertTriangle size={18} aria-hidden="true" />
          <span>Finding detail is unavailable: {detailError}</span>
        </div>
      ) : detailFinding ? (
        <>
          <FindingDetailContent
            key={`${detailFinding.scan_id}:${detailFinding.id}`}
            advisorAllowed={advisorAllowed}
            busy={busy || detailLoading}
            detailPending={detailLoading}
            pendingLifecycleReason={pendingLifecycleLayout?.findingId === detailFinding.id
              && pendingLifecycleLayout.scanId === detailFinding.scan_id ? pendingLifecycleLayout.reason : ''}
            finding={detailFinding}
            fullPath={detailFindingFullPath}
            showEvidence={showEvidence}
            snippetHeight={snippetHeight}
            setSnippetHeight={setSnippetHeight}
            sourceNavigationDisabledReason={projectSourceNavigationDisabledReason(selectedProject?.repo_path)}
            ideCapabilities={ideCapabilities}
            onTriage={onTriage}
            onLifecycle={onLifecycle}
            onDelete={onDelete}
            onOpenSource={onOpenSource}
            onRefreshIdeClients={onRefreshIdeClients}
            sourceOpenCommand={sourceOpenCommand}
          />
          {showEvidence && relatedReports.length > 0 ? (
            <section className="finding-related-reports" aria-label="Other reports at this location in this view">
              <h3>Other reports at this location in this view</h3>
              <p>Only the loaded page is compared; reports may describe different issues. Each keeps its own severity and actions.</p>
              <ul>{relatedReports.map((report) => <li key={report.id}>
                <button className="secondary-action" disabled={busy} onClick={() => onSelectRelated(report.id)}>
                  {findingLabel(report)} · {report.scanner}
                </button>
                <Severity value={report.severity} />
                <span>{findingEvidencePresentation(report).title}</span>
              </li>)}</ul>
            </section>
          ) : null}
          {showAdvisor ? (
            <FindingAdvisorPanel
              verdict={detailFinding.ai_verdict}
              confidenceValue={detailFinding.ai_confidence}
              reasoning={detailFinding.ai_reasoning}
              fix={detailFinding.ai_fix}
              loading={detailLoading}
            />
          ) : null}
          {detailLoading ? (
            <div className="empty-state" role="status">Loading exact finding detail for this resource revision.</div>
          ) : null}
        </>
      ) : (
        <div className="empty-state">{findingsLoading ? 'Loading finding detail.' : emptyMessage}</div>
      )}
    </article>
  );
});

export default function App() {
  return (
    <ConfirmationProvider>
      <Workbench />
    </ConfirmationProvider>
  );
}

function Workbench() {
  const confirmAction = useConfirmation();
  const requestTextEntry = useTextEntry();
  const initialLocation = useMemo(initialWorkbenchLocation, []);
  const automaticLandingRef = useRef(initialLocation.automaticLanding);
  const [automaticLandingPending, setAutomaticLandingPending] = useState(initialLocation.automaticLanding);
  const [view, setView] = useState<View>(initialLocation.view);
  const viewRef = useRef<View>(initialLocation.view);
  viewRef.current = view;
  const renderedView = useDeferredValue(view);
  const routePending = renderedView !== view;
  const routeSurfaceAttributes: RouteSurfaceAttributes = {
    'aria-hidden': routePending ? true : undefined,
    'data-route-surface': renderedView,
    inert: routePending,
  };
  const navigationRef = useRef<HTMLElement>(null);
  const mainScrollRef = useRef<HTMLElement>(null);
  const committedViewRef = useRef<View>(initialLocation.view);
  const refreshedViewRef = useRef<View>(initialLocation.view);
  const pendingRouteFocusRef = useRef<View | null>(null);
  const [healthObservation, setHealthObservation] = useState<HealthObservation>({ status: 'pending', lossEpoch: 0 });
  const health = healthObservation.status === 'ready' ? healthObservation.value : null;
  const [localAdvisorDiscoveryPollAttempts, setLocalAdvisorDiscoveryPollAttempts] = useState(0);
  const resetLocalAdvisorDiscoveryPollBudget = useCallback(
    () => setLocalAdvisorDiscoveryPollAttempts(0),
    [],
  );
  const [advisorProviderReadiness, setAdvisorProviderReadiness] = useState<AdvisorProviderReadiness>({ status: 'loading' });
  const [summary, setSummary] = useState<Summary | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [sourceBoundary, setSourceBoundary] = useState<SourceBoundaryLoadState>({ status: 'loading' });
  const [scans, setScans] = useState<Scan[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [dashboardAvailability, setDashboardAvailability] = useState<'loading' | 'ready' | 'unavailable'>('loading');
  const jobsRef = useRef<Job[]>([]);
  jobsRef.current = jobs;
  const [jobHandoff, setJobHandoff] = useState<JobHandoff | null>(null);
  const jobHandoffTargetRef = useRef<JobHandoffTarget | null>(null);
  const jobHandoffGenerationRef = useRef(0);
  const jobHandoffControllerRef = useRef<AbortController | null>(null);
  const activeJobIdsRef = useRef<number[]>([]);
  const activeJobsSnapshotRef = useRef<Job[]>([]);
  const [tools, setTools] = useState<ScannerTool[]>([]);
  const [scannerLifecycle, setScannerLifecycle] = useState<ScannerLifecycle | null>(null);
  const [scannerPreflight, setScannerPreflight] = useState<ScannerPreflight | null>(null);
  const retainedCollectionsRef = useRef({ summary, projects, scans, tools, scannerLifecycle, scannerPreflight, sourceBoundary });
  retainedCollectionsRef.current = { summary, projects, scans, tools, scannerLifecycle, scannerPreflight, sourceBoundary };
  const [ideCapabilities, setIdeCapabilities] = useState<IdeCapability[]>([]);
  const [ideCapabilitiesLoaded, setIdeCapabilitiesLoaded] = useState(false);
  const updateIdeCapabilities = useCallback((clients: IdeCapability[]) => {
    setIdeCapabilities(clients);
    setIdeCapabilitiesLoaded(true);
  }, []);
  const [sourceOpenCommand, setSourceOpenCommand] = useState<SourceOpenCommand | null>(null);
  const [dashboardSettled, setDashboardSettled] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(initialLocation.scanId);
  const selectedScanIdRef = useRef<number | null>(initialLocation.scanId);
  const selectionGenerationRef = useRef(0);
  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(null);
  const [pendingFindingFocusId, setPendingFindingFocusId] = useState<number | null>(null);
  const pendingFindingNumberRef = useRef<number | null>(initialLocation.findingNumber);
  const acknowledgedDeletedFindingRef = useRef<{
    scanId: number;
    scanFindingNumber: number;
  } | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedScanSummary, setSelectedScanSummary] = useState<ScanSummary | null>(null);
  const [selectedFindingDetail, setSelectedFindingDetail] = useState<Finding | null>(null);
  const selectedFindingDetailRef = useRef<Finding | null>(null);
  selectedFindingDetailRef.current = selectedFindingDetail;
  const [findingDetailLoading, setFindingDetailLoading] = useState(false);
  const [findingDetailError, setFindingDetailError] = useState<string | null>(null);
  const findingDetailErrorKeyRef = useRef<string | null>(null);
  const [findingDetailRetryGeneration, setFindingDetailRetryGeneration] = useState(0);
  const [findingsLoading, setFindingsLoading] = useState(Boolean(initialLocation.scanId));
  const [findingsHydrating, setFindingsHydrating] = useState(Boolean(initialLocation.scanId));
  const [artifacts, setArtifacts] = useState<ScanArtifact[]>([]);
  const [routeError, setRouteError] = useState<RouteError | null>(null);
  const routeEpochRef = useRef(0);
  const [busy, setBusy] = useState(false);
  const [remoteAdvisorConfirmation, setRemoteAdvisorConfirmation] = useState<RemoteAdvisorConfirmationState | null>(null);
  const remoteAdvisorSubmissionOwnershipRef = useRef(false);
  const scanSubmissionOwnershipRef = useRef(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [sourceAuthorizationRecovery, setSourceAuthorizationRecovery] = useState<SourceAuthorizationRecovery | null>(null);
  const refreshControllerRef = useRef<AbortController | null>(null);
  const refreshGenerationRef = useRef(0);
  const refreshPromiseRef = useRef<Promise<void> | null>(null);
  const visibilityRefreshPendingRef = useRef(false);
  const detailControllerRef = useRef<AbortController | null>(null);
  const detailControllerBackgroundRef = useRef(false);
  const detailGenerationRef = useRef(0);
  const findingDetailControllerRef = useRef<AbortController | null>(null);
  const sourceOpenControllerRef = useRef<AbortController | null>(null);
  const findingDetailGenerationRef = useRef(0);
  const dashboardRevisionRef = useRef<{
    advisorProviders: RevisionKey;
    summary: RevisionKey;
    projects: RevisionKey;
    scans: RevisionKey;
    tools: RevisionKey;
    scannerLifecycle: RevisionKey;
    scannerPreflight: RevisionKey;
    jobs: RevisionKey;
  } | null>(null);
  const detailRevisionRef = useRef<{
    scanId: number;
    scanRevision: number;
    findingsRevision: number;
    findings: RevisionKey;
    artifacts: RevisionKey;
  } | null>(null);

  useLayoutEffect(() => {
    if (routePending || committedViewRef.current === renderedView) return;
    committedViewRef.current = renderedView;
    mainScrollRef.current?.scrollTo({ top: 0, left: 0, behavior: 'auto' });
    window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
  }, [renderedView, routePending]);

  useLayoutEffect(() => {
    if (routePending) pendingRouteFocusRef.current = view;
    else if (pendingRouteFocusRef.current !== view) return;
    if (view === 'jobs' && jobHandoff) {
      pendingRouteFocusRef.current = null;
      return;
    }
    navigationRef.current
      ?.querySelector<HTMLButtonElement>(`[data-view-target="${view}"]`)
      ?.focus({ preventScroll: true });
    if (!routePending) pendingRouteFocusRef.current = null;
  }, [jobHandoff, routePending, view]);

  function notify(tone: Toast['tone'], title: string, message: string) {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    setToasts((current) => [...current.slice(-3), { id, tone, title, message }]);
    window.setTimeout(() => setToasts((current) => current.filter((toast) => toast.id !== id)), 6500);
  }

  const captureRouteErrorOwnership = useCallback((): RouteErrorOwnership => ({
    owner: viewRef.current,
    routeEpoch: routeEpochRef.current,
  }), []);

  const reportRouteError = useCallback((message: string, ownership: RouteErrorOwnership) => {
    if (
      viewRef.current !== ownership.owner
      || routeEpochRef.current !== ownership.routeEpoch
    ) return;
    setRouteError({ ...ownership, message });
  }, []);

  const clearRouteError = useCallback((ownership: RouteErrorOwnership) => {
    setRouteError((current) => current
      && current.owner === ownership.owner
      && current.routeEpoch === ownership.routeEpoch
      ? null
      : current);
  }, []);

  function navigate(nextView: View) {
    // Even a click on the provisional Findings route is explicit user intent.
    automaticLandingRef.current = false;
    setAutomaticLandingPending(false);
    if (nextView !== viewRef.current) {
      routeEpochRef.current += 1;
      setRouteError(null);
    }
    const currentFindingNumber = nextView === 'findings'
      ? findings.find((finding) => finding.id === selectedFindingId)?.scan_finding_number
        ?? pendingFindingNumberRef.current
      : null;
    replaceWorkbenchLocation(
      nextView,
      nextView === 'findings' ? selectedScanIdRef.current : null,
      currentFindingNumber,
    );
    setView(nextView);
  }

  function openJobs() {
    jobHandoffControllerRef.current?.abort();
    jobHandoffControllerRef.current = null;
    jobHandoffGenerationRef.current += 1;
    jobHandoffTargetRef.current = null;
    setJobHandoff(null);
    navigate('jobs');
  }

  function openJob(target: Job | number) {
    const jobId = typeof target === 'number' ? target : target.id;
    if (!Number.isSafeInteger(jobId) || jobId < 1) {
      notify('error', 'Job navigation failed', 'CodeSecurity did not receive a valid durable job identifier.');
      return;
    }

    jobHandoffControllerRef.current?.abort();
    const generation = ++jobHandoffGenerationRef.current;
    const handoffTarget = { id: jobId, generation };
    jobHandoffTargetRef.current = handoffTarget;
    setJobHandoff({
      ...handoffTarget,
      loading: typeof target === 'number',
      error: null,
    });
    if (typeof target !== 'number') {
      setJobs((current) => upsertJob(current, target));
      jobHandoffControllerRef.current = null;
      navigate('jobs');
      return;
    }

    const controller = new AbortController();
    jobHandoffControllerRef.current = controller;
    navigate('jobs');
    void api.job(jobId, controller.signal)
      .then((job) => {
        if (
          controller.signal.aborted
          || jobHandoffTargetRef.current?.id !== jobId
          || jobHandoffTargetRef.current.generation !== generation
        ) return;
        if (job.id !== jobId) {
          throw new Error(`CodeSecurity returned job #${job.id} while job #${jobId} was requested.`);
        }
        setJobs((current) => upsertJob(current, job));
        setJobHandoff((current) => current?.id === jobId && current.generation === generation
          ? current.loading || current.error !== null
            ? { ...current, loading: false, error: null }
            : current
          : current);
      })
      .catch((err) => {
        if (isAbortError(err)) return;
        if (
          jobHandoffTargetRef.current?.id !== jobId
          || jobHandoffTargetRef.current.generation !== generation
        ) return;
        const message = err instanceof Error ? err.message : String(err);
        setJobHandoff((current) => current?.id === jobId && current.generation === generation
          ? { ...current, loading: false, error: message }
          : current);
      })
      .finally(() => {
        if (jobHandoffControllerRef.current === controller) jobHandoffControllerRef.current = null;
      });
  }

  function acknowledgeJobCommand(title: string, message: string) {
    // Commit the visible acknowledgement before starting network work so the
    // operator always sees the command land within the interaction budget.
    flushSync(() => {
      setBusy(true);
      notify('info', title, message);
    });
  }

  function recordScannerLifecycleCommand(job: Job, lifecycle: ScannerLifecycleScope) {
    setJobs((current) => upsertJob(current, job));
    setScannerLifecycle((current) => current
      ? { ...current, [lifecycle.scope]: lifecycle }
      : current);
  }

  const focusFinding = useCallback((id: number | null) => {
    setPendingFindingFocusId(id);
    setSelectedFindingId(id);
  }, []);

  const clearPendingFindingFocus = useCallback(() => setPendingFindingFocusId(null), []);

  const loadScanDetails = useCallback(async (
    scanId: number,
    showLoading = true,
    summaryOnlyIfUnchanged = false,
    allowBackground = false,
    initialSummary: ScanSummary | null = null,
  ) => {
    if (viewRef.current !== 'findings' && !allowBackground) return;
    const errorOwnership = captureRouteErrorOwnership();
    detailControllerRef.current?.abort();
    const controller = new AbortController();
    detailControllerRef.current = controller;
    detailControllerBackgroundRef.current = allowBackground;
    const generation = ++detailGenerationRef.current;
    if (showLoading) {
      setFindingsLoading(true);
      setFindingsHydrating(true);
      // The exact-detail owner clears its revision-bound error when it starts
      // or validates a request. A collection refresh may keep the same key.
    }

    const requestIsCurrent = () => (
      !controller.signal.aborted
      && generation === detailGenerationRef.current
      && selectedScanIdRef.current === scanId
      && (allowBackground || viewRef.current === 'findings')
    );
    const commitSummary = (nextSummary: ScanSummary) => {
      if (!requestIsCurrent()) return;
      setSelectedScanSummary(nextSummary);
      setScans((current) => {
        const existing = current.find((scan) => scan.id === scanId);
        const merged = mergeScanSummary(existing, nextSummary);
        const next = [merged, ...current.filter((scan) => scan.id !== scanId)];
        return next.sort((left, right) => right.id - left.id);
      });
    };
    const reconcileFindingSelection = (
      nextFindings: Finding[],
      final: boolean,
      authoritative = false,
    ) => {
      const acknowledgedDeletion = acknowledgedDeletedFindingRef.current;
      const acknowledgedDeletionNeedsFallback = Boolean(
        authoritative
        && final
        && acknowledgedDeletion?.scanId === scanId,
      );
      if (acknowledgedDeletionNeedsFallback) {
        const fallback = nextFindings[0] ?? null;
        acknowledgedDeletedFindingRef.current = null;
        replaceFindingLocation(scanId, fallback?.scan_finding_number ?? null);
      }
      setSelectedFindingId((current) => {
        const pendingNumber = pendingFindingNumberRef.current;
        const linked = pendingNumber
          ? nextFindings.find((finding) => finding.scan_finding_number === pendingNumber)
          : undefined;
        if (linked) {
          pendingFindingNumberRef.current = null;
          setPendingFindingFocusId(linked.id);
          return linked.id;
        }
        const currentIsPresent = Boolean(current && nextFindings.some((finding) => finding.id === current));
        const routeNeedsFallback = authoritative && final && Boolean(
          pendingNumber
          || current && !currentIsPresent,
        );
        if (pendingNumber && authoritative && final) {
          pendingFindingNumberRef.current = null;
          setPendingFindingFocusId(null);
        }
        if (currentIsPresent) return current;
        const fallback = nextFindings[0] ?? null;
        if (routeNeedsFallback) {
          replaceFindingLocation(scanId, fallback?.scan_finding_number ?? null);
        }
        return fallback?.id ?? null;
      });
    };

    try {
      let lastRevisionConflict: Error | null = null;
      for (let attempt = 1; attempt <= findingsSnapshotAttempts; attempt += 1) {
        const before = attempt === 1 && initialSummary
          ? initialSummary : await api.scanSummary(scanId, controller.signal);
        if (!validScanSummary(scanId, before)) {
          throw new Error('CodeSecurity returned an invalid scan summary.');
        }
        if (!requestIsCurrent()) return;
        const previous = detailRevisionRef.current;
        // Retained rows and their summary form one revision-bound snapshot.
        // Publishing a newer summary first makes exact-detail reads combine
        // an old finding revision with the new collection revision.
        if (previous?.scanId !== scanId || previous.findingsRevision === before.findings_revision) {
          commitSummary(before);
        }
        if (
          summaryOnlyIfUnchanged
          && pendingFindingNumberRef.current === null
          && previous?.scanId === scanId
          && previous.scanRevision === before.revision
          && previous.findingsRevision === before.findings_revision
        ) {
          setFindingsLoading(false);
          setFindingsHydrating(false);
          return;
        }

        const anchorScanFindingNumber = pendingFindingNumberRef.current ?? undefined;
        setFindingsHydrating(true);
        try {
          const [nextFindingPage, nextArtifacts] = await Promise.all([
            api.findings(scanId, {
              signal: controller.signal,
              expectedRevision: before.findings_revision,
              anchorScanFindingNumber,
              onInitialPage: (initialPage) => {
                // First-page paint is only for a scan without a committed
                // snapshot. Replacing retained rows here loses later pages and
                // selection when the unchanged final revision is deduplicated.
                if (!showLoading || !requestIsCurrent() || previous?.scanId === scanId) return;
                setFindings(initialPage.items);
                reconcileFindingSelection(initialPage.items, initialPage.items.length === initialPage.total);
                setFindingsLoading(false);
              },
            }),
            api.artifacts(scanId, controller.signal),
          ]);
          const after = await api.scanSummary(scanId, controller.signal);
          if (!requestIsCurrent()) return;
          if (!validScanSummary(scanId, after)) {
            throw new Error('CodeSecurity returned an invalid scan summary.');
          }
          if (
            before.revision !== after.revision
            || before.findings_revision !== after.findings_revision
            || nextFindingPage.revision !== after.findings_revision
            || !sameScanSummaryRevision(before, after)
          ) {
            lastRevisionConflict = new Error('Findings changed while the snapshot was loading.');
            if (attempt < findingsSnapshotAttempts) continue;
            break;
          }

          const nextFindings = nextFindingPage.items;
          const nextFindingRevision = findingsRevisionKey(nextFindings);
          const nextArtifactRevision = artifactsRevisionKey(nextArtifacts);
          if (!previous || previous.scanId !== scanId || !sameRevisionKey(previous.findings, nextFindingRevision)) {
            setFindings(nextFindings);
          }
          reconcileFindingSelection(nextFindings, true, true);
          if (!previous || previous.scanId !== scanId || !sameRevisionKey(previous.artifacts, nextArtifactRevision)) {
            setArtifacts(nextArtifacts);
          }
          commitSummary(after);
          detailRevisionRef.current = {
            scanId,
            scanRevision: after.revision,
            findingsRevision: after.findings_revision,
            findings: nextFindingRevision,
            artifacts: nextArtifactRevision,
          };
          clearRouteError(errorOwnership);
          setFindingsLoading(false);
          setFindingsHydrating(false);
          return;
        } catch (err) {
          if (isAbortError(err)) throw err;
          if (isFindingsSnapshotChangedError(err)) {
            lastRevisionConflict = err;
            if (attempt < findingsSnapshotAttempts) continue;
            break;
          }
          throw err;
        }
      }
      throw new Error(
        `${lastRevisionConflict?.message || 'Findings changed while the snapshot was loading.'} `
        + `CodeSecurity stopped after ${findingsSnapshotAttempts} bounded reconciliation attempts. Refresh to try again.`,
      );
    } catch (err) {
      if (!isAbortError(err) && requestIsCurrent()) {
        reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
      }
    } finally {
      if (requestIsCurrent()) {
        setFindingsLoading(false);
        setFindingsHydrating(false);
      }
      if (detailControllerRef.current === controller) {
        detailControllerRef.current = null;
        detailControllerBackgroundRef.current = false;
      }
    }
  }, [captureRouteErrorOwnership, clearRouteError, reportRouteError]);

  const selectScan = useCallback((id: number | null, loadDetails = true) => {
    const changed = selectedScanIdRef.current !== id;
    if (changed) selectionGenerationRef.current += 1;
    selectedScanIdRef.current = id;
    setSelectedScanId(id);
    if (changed) {
      detailControllerRef.current?.abort();
      findingDetailControllerRef.current?.abort();
      detailRevisionRef.current = null;
      setFindings([]);
      setSelectedScanSummary(null);
      setSelectedFindingDetail(null);
      setFindingDetailError(null);
      setFindingDetailLoading(false);
      setArtifacts([]);
      setFindingsLoading(Boolean(id));
      setFindingsHydrating(Boolean(id));
    }
    if (!id) {
      detailControllerRef.current?.abort();
      setFindingsLoading(false);
      setFindingsHydrating(false);
    } else if (loadDetails && changed && viewRef.current === 'findings') {
      void loadScanDetails(id);
    }
  }, [loadScanDetails]);

  const refresh = useCallback((preferredScanId?: number | null, reason: RefreshReason = 'manual'): Promise<void> => {
    if (reason === 'manual') setLocalAdvisorDiscoveryPollAttempts(0);
    if (refreshPromiseRef.current) {
      if (reason === 'poll') return refreshPromiseRef.current;
      if (reason === 'visibility') {
        // An older request may already have read Jobs before another client
        // submitted work. Keep one fresh read after the current owner settles.
        visibilityRefreshPendingRef.current = true;
        return refreshPromiseRef.current;
      }
      if (reason === 'mutation') {
        const activeRefresh = refreshPromiseRef.current;
        return activeRefresh.then(
          () => refresh(preferredScanId, reason),
          () => refresh(preferredScanId, reason),
        );
      }
    }
    let errorOwnership = captureRouteErrorOwnership();
    refreshControllerRef.current?.abort();
    if (reason !== 'poll' || detailControllerBackgroundRef.current) {
      detailControllerRef.current?.abort();
    }
    const controller = new AbortController();
    refreshControllerRef.current = controller;
    const generation = ++refreshGenerationRef.current;
    const retained = retainedCollectionsRef.current;
    const routeCollections = reason === 'navigation' && retained.summary
      && retained.scannerLifecycle && retained.scannerPreflight
      ? navigationRefreshCollections(viewRef.current) : null;
    setDashboardAvailability((current) => current === 'ready' ? current : 'loading');
    // Navigation/manual reconciliation owns fresh Findings evidence before
    // its global reads settle. Keep retained data and toolbar interaction,
    // but do not announce readiness from the preceding snapshot meanwhile.
    if (viewRef.current === 'findings' && reason !== 'poll') setFindingsHydrating(true);
    if (reason !== 'poll' && (!routeCollections || routeCollections.sourceBoundary)) setSourceBoundary({ status: 'loading' });
    const selectionGeneration = selectionGenerationRef.current;
    const requestIsCurrent = () => !controller.signal.aborted && generation === refreshGenerationRef.current;
    // Start the exact read alongside history, not after it. It can only be
    // reused when the fresh history agrees on identity and both revisions;
    // changed selection/history falls back to the ordinary exact read.
    const summaryScanId = reason === 'navigation' && viewRef.current === 'findings'
      ? selectedScanIdRef.current : null;
    const operation = (async () => {
      try {
        const [navigationSummary, , nextSummary, nextProjects, listedScans, nextTools, nextScannerLifecycle, nextScannerPreflight, listedJobs, activeJobs, nextIdeCapabilities, nextAdvisorProviders, nextSourceBoundary] = await Promise.all([
          summaryScanId ? api.scanSummary(summaryScanId, controller.signal).catch((error) => {
            if (isAbortError(error)) throw error;
            return null;
          }) : null,
          // Health owns its observation, independently of unrelated collection
          // failures. A failed read invalidates readiness without erasing data.
          api.health(controller.signal).then((nextHealth) => {
            if (requestIsCurrent()) setHealthObservation((current) => (
              current.status === 'ready'
              && sameRevisionKey(healthRevisionKey(current.value), healthRevisionKey(nextHealth))
                ? current
                : { status: 'ready', value: nextHealth, lossEpoch: current.lossEpoch }
            ));
          }, (err) => {
            if (!isAbortError(err) && requestIsCurrent()) setHealthObservation((current) => (
              current.status === 'unavailable' ? current : { status: 'unavailable', lossEpoch: current.lossEpoch + 1 }
            ));
            throw err;
          }),
          routeCollections && !routeCollections.summary ? retained.summary! : api.summary(controller.signal),
          routeCollections && !routeCollections.projects ? retained.projects : api.projects(controller.signal),
          routeCollections && !routeCollections.scans ? retained.scans : api.scans(controller.signal),
          routeCollections && !routeCollections.tools ? retained.tools : api.tools(controller.signal),
          routeCollections && !routeCollections.lifecycle ? retained.scannerLifecycle! : api.scannerLifecycle(controller.signal),
          routeCollections && !routeCollections.preflight ? retained.scannerPreflight! : api.scannerPreflight(controller.signal),
          routeCollections && !routeCollections.jobs ? jobsRef.current : api.jobs(controller.signal),
          api.activeJobs(controller.signal),
          api.ideCapabilities(controller.signal),
          api.advisorProviders(controller.signal).then(
            (collection): AdvisorProviderReadiness => ({ status: 'ready', collection }),
            (error): AdvisorProviderReadiness => {
              if (isAbortError(error)) throw error;
              return failedAdvisorProviderReadiness();
            },
          ),
          routeCollections && !routeCollections.sourceBoundary ? retained.sourceBoundary
            : resolveSourceBoundaryLoad(() => api.config(controller.signal)),
        ]);
        if (generation !== refreshGenerationRef.current) return;
        commitCurrentSourceBoundaryLoad(
          generation,
          refreshGenerationRef.current,
          nextSourceBoundary,
          setSourceBoundary,
        );
        if (!validScannerPreflight(nextScannerPreflight)) {
          throw new Error('CodeSecurity returned an invalid scanner readiness preflight.');
        }
        const activeJobIds = new Set(activeJobs.map((job) => job.id));
        const transitionedJobIds = activeJobIdsRef.current.filter((jobId) => !activeJobIds.has(jobId));
        const transitionedJobs = await Promise.all(transitionedJobIds
          .map(async (jobId) => {
            try {
              return await api.job(jobId, controller.signal);
            } catch (err) {
              if (isAbortError(err)) throw err;
              return null;
            }
          }));
        if (generation !== refreshGenerationRef.current) return;
        const selectionChangedDuringRefresh = selectionGenerationRef.current !== selectionGeneration;
        const scanSelectedDuringRefresh = selectedScanIdRef.current;
        const requestedScanId = preferredScanId !== undefined && !selectionChangedDuringRefresh
          ? preferredScanId
          : scanSelectedDuringRefresh;
        let nextScans = listedScans;
        // Only a fresh history read can settle a previously active job.
        // Off-route history never renews that observation.
        const listedJobIds = new Set(routeCollections && !routeCollections.jobs
          ? [] : listedJobs.map((job) => job.id));
        const transitionedJobById = new Map(transitionedJobIds.map((jobId, index) => [
          jobId,
          transitionedJobs[index],
        ]));
        const nextJobById = new Map(listedJobs.map((job) => [job.id, job]));
        for (const observed of [
          ...activeJobs,
          ...transitionedJobs.map((job, index) => job ?? activeJobsSnapshotRef.current.find(
            (candidate) => candidate.id === transitionedJobIds[index],
          ) ?? null),
        ]) {
          if (observed) nextJobById.set(
            observed.id, latestJobObservation(nextJobById.get(observed.id), observed),
          );
        }
        let nextJobs = [...nextJobById.values()];
        const requestedJobTarget = jobHandoffTargetRef.current;
        if (requestedJobTarget && !nextJobs.some((job) => job.id === requestedJobTarget.id)) {
          try {
            const exactJob = await api.job(requestedJobTarget.id, controller.signal);
            if (exactJob.id !== requestedJobTarget.id) {
              throw new Error(
                `CodeSecurity returned job #${exactJob.id} while job #${requestedJobTarget.id} was requested.`,
              );
            }
            if (
              jobHandoffTargetRef.current?.id === requestedJobTarget.id
              && jobHandoffTargetRef.current.generation === requestedJobTarget.generation
            ) {
              nextJobs = upsertJob(nextJobs, exactJob);
              setJobHandoff((current) => current?.id === requestedJobTarget.id
                && current.generation === requestedJobTarget.generation
                ? current.loading || current.error !== null
                  ? { ...current, loading: false, error: null }
                  : current
                : current);
            }
          } catch (err) {
            if (isAbortError(err)) throw err;
            if (
              jobHandoffTargetRef.current?.id === requestedJobTarget.id
              && jobHandoffTargetRef.current.generation === requestedJobTarget.generation
            ) {
              const message = err instanceof Error ? err.message : String(err);
              setJobHandoff((current) => current?.id === requestedJobTarget.id
                && current.generation === requestedJobTarget.generation
                ? { ...current, loading: false, error: message }
                : current);
            }
          }
        } else if (requestedJobTarget) {
          setJobHandoff((current) => current?.id === requestedJobTarget.id
            && current.generation === requestedJobTarget.generation
            ? current.loading || current.error !== null
              ? { ...current, loading: false, error: null }
              : current
            : current);
        }
        if (
          requestedJobTarget
          && jobHandoffTargetRef.current?.id === requestedJobTarget.id
          && jobHandoffTargetRef.current.generation === requestedJobTarget.generation
        ) {
          const currentTarget = jobsRef.current.find((job) => job.id === requestedJobTarget.id);
          if (currentTarget) nextJobs = upsertJob(nextJobs, currentTarget);
        }
        let scanResolutionError: string | null = null;
        if (requestedScanId && !nextScans.some((scan) => scan.id === requestedScanId)) {
          try {
            const exactScan = await api.scan(requestedScanId, controller.signal);
            nextScans = [exactScan, ...nextScans.filter((scan) => scan.id !== exactScan.id)];
          } catch (err) {
            if (isAbortError(err)) throw err;
            scanResolutionError = `Scan #${requestedScanId} could not be resolved exactly. ${err instanceof Error ? err.message : String(err)}`;
          }
        }
        if (generation !== refreshGenerationRef.current) return;
        clearRouteError(errorOwnership);
        const nextRevisions = {
          advisorProviders: advisorProviderReadinessRevisionKey(nextAdvisorProviders),
          summary: summaryRevisionKey(nextSummary),
          projects: projectsRevisionKey(nextProjects),
          scans: scanRevisionRows(nextScans),
          tools: toolsRevisionKey(nextTools),
          scannerLifecycle: scannerLifecycleRevisionKey(nextScannerLifecycle),
          scannerPreflight: scannerPreflightRevisionKey(nextScannerPreflight),
          jobs: jobsRevisionKey(nextJobs),
        };
        const previous = dashboardRevisionRef.current;
        if (reason !== 'poll' || !sameRevisionKey(previous?.advisorProviders ?? null, nextRevisions.advisorProviders)) {
          setAdvisorProviderReadiness(nextAdvisorProviders);
        }
        if (reason !== 'poll' || !sameRevisionKey(previous?.summary ?? null, nextRevisions.summary)) setSummary(nextSummary);
        if (reason !== 'poll' || !sameRevisionKey(previous?.projects ?? null, nextRevisions.projects)) setProjects(nextProjects);
        if (reason !== 'poll' || !sameRevisionKey(previous?.scans ?? null, nextRevisions.scans)) setScans(nextScans);
        if (reason !== 'poll' || !sameRevisionKey(previous?.tools ?? null, nextRevisions.tools)) setTools(nextTools);
        if (reason !== 'poll' || !sameRevisionKey(previous?.scannerLifecycle ?? null, nextRevisions.scannerLifecycle)) setScannerLifecycle(nextScannerLifecycle);
        if (reason !== 'poll' || !sameRevisionKey(previous?.scannerPreflight ?? null, nextRevisions.scannerPreflight)) setScannerPreflight(nextScannerPreflight);
        if (reason !== 'poll' || !sameRevisionKey(previous?.jobs ?? null, nextRevisions.jobs)) {
          setJobs((current) => {
            const latestTarget = jobHandoffTargetRef.current;
            const currentTarget = latestTarget
              ? current.find((job) => job.id === latestTarget.id)
              : null;
            return currentTarget ? upsertJob(nextJobs, currentTarget) : nextJobs;
          });
        }
        updateIdeCapabilities(nextIdeCapabilities);
        setDashboardAvailability('ready');
        setDashboardSettled(true);
        dashboardRevisionRef.current = nextRevisions;
        const unresolvedTransitionIds = transitionedJobIds.filter((jobId) => {
          if (listedJobIds.has(jobId)) return false;
          const resolved = transitionedJobById.get(jobId);
          return !resolved || activeWorkStatuses.has(resolved.status);
        });
        const trackedActiveIds = [...new Set([...activeJobIds, ...unresolvedTransitionIds])];
        const trackedSnapshots = new Map(activeJobsSnapshotRef.current.map((job) => [job.id, job]));
        for (const job of activeJobs) trackedSnapshots.set(job.id, job);
        for (const job of transitionedJobs) {
          if (job && activeWorkStatuses.has(job.status)) trackedSnapshots.set(job.id, job);
        }
        activeJobIdsRef.current = trackedActiveIds;
        activeJobsSnapshotRef.current = trackedActiveIds
          .map((jobId) => trackedSnapshots.get(jobId))
          .filter((job): job is Job => job !== undefined);
        const activeScanId = requestedScanId
          ? nextScans.some((scan) => scan.id === requestedScanId) ? requestedScanId : null
          : nextScans[0]?.id ?? null;
        if (requestedScanId && activeScanId === null) {
          pendingFindingNumberRef.current = null;
          focusFinding(null);
        }
        if (reason === 'initial' && automaticLandingRef.current && requestIsCurrent()
          && !selectionChangedDuringRefresh && errorOwnership.routeEpoch === routeEpochRef.current) {
          // The successful initial read owns this one route decision. Reuse its
          // data and detail load rather than starting a navigation refresh that
          // would cancel it. Explicit links and user navigation never enter here.
          const destination: View = nextScans.length ? 'findings' : 'projects';
          automaticLandingRef.current = false;
          if (destination !== viewRef.current) routeEpochRef.current += 1;
          viewRef.current = destination;
          refreshedViewRef.current = destination;
          errorOwnership = { owner: destination, routeEpoch: routeEpochRef.current };
          replaceWorkbenchLocation(destination, destination === 'findings' ? activeScanId : null);
          setView(destination);
          setAutomaticLandingPending(false);
        }
        selectScan(activeScanId, false);
        if (scanResolutionError) reportRouteError(scanResolutionError, errorOwnership);
        if (selectionChangedDuringRefresh && activeScanId === scanSelectedDuringRefresh) {
          // The user's newer selection already owns its detail request. Do not
          // let this older global refresh clear or overwrite that surface.
          return;
        }
        const activeScan = nextScans.find((scan) => scan.id === activeScanId);
        const backgroundInitialDetails = reason === 'initial' && viewRef.current !== 'findings';
        if (
          activeScanId
          && activeScan
          && !activeWorkStatuses.has(activeScan.status)
          && (viewRef.current === 'findings' || backgroundInitialDetails)
        ) {
          await loadScanDetails(
            activeScanId,
            !backgroundInitialDetails && reason !== 'poll',
            // Navigation still waits for its fresh global reads and exact scan
            // summary. Reuse only an unchanged, already committed snapshot;
            // explicit refreshes and mutation reconciliation remain full reads.
            reason === 'poll' || reason === 'navigation',
            backgroundInitialDetails,
            navigationSummary?.scan?.id === activeScan.id
              && navigationSummary.scan.project_id === activeScan.project_id
              && navigationSummary.revision === activeScan.revision
              && navigationSummary.findings_revision === activeScan.findings_revision
              ? navigationSummary : null,
          );
        } else {
          if (!activeScanId) {
            detailRevisionRef.current = null;
            setFindings([]);
            setArtifacts([]);
          }
          setFindingsLoading(false);
          setFindingsHydrating(false);
        }
      } catch (err) {
        if (!isAbortError(err) && generation === refreshGenerationRef.current) {
          // A failed read is not proof of an empty installation. Show its error
          // on the provisional route; do not silently choose setup or retry it.
          automaticLandingRef.current = false;
          setAutomaticLandingPending(false);
          setDashboardAvailability((current) => current === 'ready' ? current : 'unavailable');
          setDashboardSettled(true);
          setFindingsLoading(false);
          setFindingsHydrating(false);
          reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
        }
      }
    })();
    refreshPromiseRef.current = operation;
    return operation.finally(() => {
      if (refreshControllerRef.current === controller) refreshControllerRef.current = null;
      if (refreshPromiseRef.current !== operation) return;
      refreshPromiseRef.current = null;
      if (visibilityRefreshPendingRef.current) {
        visibilityRefreshPendingRef.current = false;
        if (document.visibilityState === 'visible') return refresh(undefined, 'visibility');
      }
    });
  }, [captureRouteErrorOwnership, clearRouteError, focusFinding, loadScanDetails, reportRouteError, selectScan, updateIdeCapabilities]);

  const hasActiveWork = useMemo(
    () => jobs.some((job) => activeWorkStatuses.has(job.status))
      || scans.some((scan) => activeWorkStatuses.has(scan.status))
      || localAdvisorDiscoveryPollAllowed(health, localAdvisorDiscoveryPollAttempts)
      || scannerVerificationPollRequired(scannerPreflight)
      || Boolean(scannerLifecycle && (
        activeWorkStatuses.has(scannerLifecycle.catalog.status)
        || activeWorkStatuses.has(scannerLifecycle.cache.status)
      )),
    [health, jobs, localAdvisorDiscoveryPollAttempts, scans, scannerLifecycle, scannerPreflight],
  );
  const selectedScanSupportsFindings = useMemo(
    () => scans.some((scan) => scan.id === selectedScanId && !activeWorkStatuses.has(scan.status)),
    [scans, selectedScanId],
  );

  function reconcileDurableCommand(preferredScanId?: number | null, destination?: View) {
    // A newly requested route performs its own fresh collection read. Avoid
    // starting a command refresh that this same transition would immediately
    // cancel. Same-view actions, route bounces and different scan targets still
    // need their explicit reconciliation.
    if (
      destination !== undefined
      && destination !== viewRef.current
      && destination !== refreshedViewRef.current
      && (preferredScanId === undefined || preferredScanId === selectedScanIdRef.current)
    ) return;
    const errorOwnership = captureRouteErrorOwnership();
    void refresh(preferredScanId, 'mutation').catch((err) => {
      // A newer refresh intentionally supersedes this reconciliation. Any
      // unexpected rejection is still visible without undoing the accepted
      // command or holding its route transition open.
      if (isAbortError(err)) return;
      const message = err instanceof Error ? err.message : String(err);
      reportRouteError(message, errorOwnership);
      notify('error', 'Queued command refresh failed', `The durable command remains queued, but the latest dashboard state could not be loaded. ${message}`);
    });
  }

  useEffect(() => {
    void refresh(initialLocation.scanId, 'initial');
    return () => {
      visibilityRefreshPendingRef.current = false;
      refreshControllerRef.current?.abort();
      detailControllerRef.current?.abort();
      findingDetailControllerRef.current?.abort();
      sourceOpenControllerRef.current?.abort();
      jobHandoffControllerRef.current?.abort();
    };
  }, [initialLocation.scanId, refresh]);

  useEffect(() => {
    if (refreshedViewRef.current === view) return;
    refreshedViewRef.current = view;
    // Another editor/browser can submit work while this idle dashboard stays
    // visible. Entering a view must reconcile durable state, not just render
    // the last collection known to this browser.
    void refresh(undefined, 'navigation');
  }, [refresh, view]);

  useEffect(() => {
    if (view !== 'findings') {
      if (!detailControllerBackgroundRef.current) detailControllerRef.current?.abort();
      setFindingDetailLoading(false);
      setFindingsLoading(false);
      setFindingsHydrating(false);
      return;
    }
    // The current collection refresh owns its subsequent revision-bound detail
    // load. A fallback here would be aborted when that owner reaches the same
    // scan. Explicit same-view scan selection still starts its own detail read.
    if (!dashboardSettled || !selectedScanId || !selectedScanSupportsFindings || detailControllerRef.current || refreshControllerRef.current) {
      if (dashboardSettled && selectedScanId && !selectedScanSupportsFindings) {
        setFindingsLoading(false);
        setFindingsHydrating(false);
      }
      return;
    }
    const alreadyLoaded = detailRevisionRef.current?.scanId === selectedScanId;
    if (!alreadyLoaded) void loadScanDetails(selectedScanId);
  }, [dashboardSettled, loadScanDetails, selectedScanId, selectedScanSupportsFindings, view]);

  useEffect(() => {
    if (!hasActiveWork) return undefined;
    let cancelled = false;
    let timer: number | undefined;
    const poll = async () => {
      if (!document.hidden) {
        setLocalAdvisorDiscoveryPollAttempts((current) => (
          consumeLocalAdvisorDiscoveryPollAttempt(health, current, true)
        ));
        await refresh(undefined, 'poll');
      }
      if (!cancelled) timer = window.setTimeout(poll, 8000);
    };
    timer = window.setTimeout(poll, 8000);
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [hasActiveWork, health, refresh]);

  useEffect(() => {
    let scheduled = false;
    let disposed = false;
    const recoverWhenVisible = () => {
      if (document.visibilityState !== 'visible' || scheduled) return;
      scheduled = true;
      queueMicrotask(() => {
        scheduled = false;
        if (!disposed && document.visibilityState === 'visible') void refresh(undefined, 'visibility');
      });
    };
    document.addEventListener('visibilitychange', recoverWhenVisible);
    // Switching native applications does not necessarily hide the browser tab.
    // Coalesce focus + visibility events through the existing refresh owner.
    window.addEventListener('focus', recoverWhenVisible);
    return () => {
      disposed = true;
      document.removeEventListener('visibilitychange', recoverWhenVisible);
      window.removeEventListener('focus', recoverWhenVisible);
    };
  }, [refresh]);

  const selectedScan = useMemo(() => scans.find((scan) => scan.id === selectedScanId), [scans, selectedScanId]);
  const selectedProject = selectedScan ? projects.find((project) => project.id === selectedScan.project_id) : null;
  const selectedFindingSummary = useMemo(
    () => findings.find((finding) => finding.id === selectedFindingId) || null,
    [findings, selectedFindingId],
  );
  const selectedFindingDetailKey = selectedScanId && selectedFindingSummary && selectedScanSummary
    ? `${selectedScanId}:${selectedFindingSummary.id}:${selectedFindingSummary.scan_finding_number}:${selectedFindingSummary.revision}:${selectedScanSummary.findings_revision}`
    : null;
  const currentFindingDetailError = findingDetailErrorKeyRef.current === selectedFindingDetailKey
    ? findingDetailError
    : null;
  const selectedFindingAcknowledgedDeleted = Boolean(
    selectedFindingSummary
    && acknowledgedDeletedFindingRef.current?.scanId === selectedScanId
    && acknowledgedDeletedFindingRef.current.scanFindingNumber === selectedFindingSummary.scan_finding_number,
  );
  // A new summary revision is pending in this render, before its passive
  // request effect runs. Retained immutable evidence is not current detail.
  const findingDetailRevisionPending = Boolean(
    view === 'findings' && selectedFindingDetailKey && !selectedFindingAcknowledgedDeleted
    && !currentFindingDetailError
    && (!selectedFindingDetail || !selectedFindingSummary || !selectedScanSummary
      || selectedFindingDetail.findings_revision !== selectedScanSummary.findings_revision
      || !detailMatchesFindingSummary(selectedFindingDetail, selectedFindingSummary)),
  );
  const findingsWithSelectedDetail = useMemo(
    () => selectedFindingDetail
      ? findings.map((finding) => {
          if (detailMatchesFindingSummary(selectedFindingDetail, finding)) return selectedFindingDetail;
          if (findingEvidenceMatchesSummary(selectedFindingDetail, finding)) {
            // List rows deliberately omit large evidence. Preserve only the
            // immutable evidence fields while the exact mutable revision is
            // loading; lifecycle and Advisor state continue to come from the
            // current summary and are kept inert until detail validation.
            return preserveFindingEvidence(finding, selectedFindingDetail);
          }
          return finding;
        })
      : findings,
    [findings, selectedFindingDetail],
  );

  useEffect(() => {
    findingDetailControllerRef.current?.abort();
    const summaryFinding = selectedFindingSummary;
    const currentFindingDetail = selectedFindingDetailRef.current;
    if (view !== 'findings' || !selectedScanId || !summaryFinding || !selectedScanSummary) {
      setSelectedFindingDetail(null);
      setFindingDetailError(null);
      setFindingDetailLoading(false);
      return undefined;
    }
    const acknowledgedDeletion = acknowledgedDeletedFindingRef.current;
    if (
      acknowledgedDeletion?.scanId === selectedScanId
      && acknowledgedDeletion.scanFindingNumber === summaryFinding.scan_finding_number
    ) {
      // DELETE acknowledgement is already authoritative for this exact
      // resource. Keep its selection ownership until the collection refresh
      // can hand focus to a real fallback, but never issue a stale detail GET.
      setSelectedFindingDetail(null);
      setFindingDetailError(null);
      setFindingDetailLoading(false);
      return undefined;
    }
    if (
      currentFindingDetail
      && currentFindingDetail.findings_revision === selectedScanSummary.findings_revision
      && detailMatchesFindingSummary(currentFindingDetail, summaryFinding)
    ) {
      setFindingDetailError(null);
      setFindingDetailLoading(false);
      return undefined;
    }
    const controller = new AbortController();
    findingDetailControllerRef.current = controller;
    const generation = ++findingDetailGenerationRef.current;
    setFindingDetailLoading(true);
    setFindingDetailError(null);
    setSelectedFindingDetail((current) => (
      // Keep the already-painted immutable evidence mounted while a newer
      // advisor/lifecycle revision is fetched. The detail surface is marked
      // busy/inert above, and the memoized evidence boundary can then preserve
      // its DOM when only mutable review fields change.
      current?.id === summaryFinding.id ? current : null
    ));
    const requestIsCurrent = () => (
      !controller.signal.aborted
      && generation === findingDetailGenerationRef.current
      && selectedScanIdRef.current === selectedScanId
    );
    const loadFinding = (finding: Finding, findingsRevision: number) => api.finding(
      selectedScanId,
      finding.scan_finding_number,
      {
        signal: controller.signal,
        expectedRevision: finding.revision,
        expectedFindingsRevision: findingsRevision,
      },
    );
    void (async () => {
      let detail: Finding | null = null;
      let findingWasRemoved = false;
      try {
        detail = await loadFinding(summaryFinding, selectedScanSummary.findings_revision);
      } catch (err) {
        if (
          !isApiError(err, 'revision_conflict')
          && !isApiError(err, 'finding_removed')
          && !(isApiError(err) && err.status === 404)
        ) throw err;
        findingWasRemoved = isApiError(err, 'finding_removed') || isApiError(err) && err.status === 404;
      }
      if (!requestIsCurrent()) return;
      if (
        detail
        && detail.findings_revision === selectedScanSummary.findings_revision
        && detailMatchesFindingSummary(detail, summaryFinding)
      ) {
        setSelectedFindingDetail(detail);
        return;
      }
      if (detail && !findingIdentityAndEvidenceMatches(detail, summaryFinding)) {
        throw new Error('CodeSecurity returned finding detail with a different immutable identity or evidence binding.');
      }

      // One bounded reconciliation closes the ordinary race where Advisor or
      // lifecycle work advances a finding between the list and detail reads.
      // Selection remains owned by the user; only authoritative REST state is
      // replaced, and a second conflict is surfaced instead of looping.
      const before = await api.scanSummary(selectedScanId, controller.signal);
      if (!validScanSummary(selectedScanId, before)) {
        throw new Error('CodeSecurity returned an invalid scan summary while reconciling the finding.');
      }
      const nextFindingPage = await api.findings(selectedScanId, {
        signal: controller.signal,
        expectedRevision: before.findings_revision,
        anchorScanFindingNumber: findingWasRemoved ? undefined : summaryFinding.scan_finding_number,
      });
      const after = await api.scanSummary(selectedScanId, controller.signal);
      if (
        !validScanSummary(selectedScanId, after)
        || before.revision !== after.revision
        || before.findings_revision !== after.findings_revision
        || nextFindingPage.revision !== after.findings_revision
        || !sameScanSummaryRevision(before, after)
      ) {
        throw new Error('The finding changed again during one bounded reconciliation. Refresh when the current operation finishes.');
      }
      const reconciledSummary = nextFindingPage.items.find((finding) => (
        finding.id === summaryFinding.id
        && finding.scan_finding_number === summaryFinding.scan_finding_number
      ));
      if (!reconciledSummary) {
        if (findingWasRemoved) {
          const fallback = nextFindingPage.items[0] ?? null;
          setFindings(nextFindingPage.items);
          setSelectedScanSummary(after);
          setScans((current) => {
            const existing = current.find((scan) => scan.id === selectedScanId);
            const merged = mergeScanSummary(existing, after);
            return [merged, ...current.filter((scan) => scan.id !== selectedScanId)]
              .sort((left, right) => right.id - left.id);
          });
          const currentDetailRevision = detailRevisionRef.current;
          if (currentDetailRevision?.scanId === selectedScanId) {
            detailRevisionRef.current = {
              ...currentDetailRevision,
              // Only a complete snapshot read may advance the artifact-bound
              // scan revision. This reconciliation reads finding rows only.
              findingsRevision: after.findings_revision,
              findings: findingsRevisionKey(nextFindingPage.items),
            };
          }
          setSelectedFindingId(fallback?.id ?? null);
          setSelectedFindingDetail(null);
          pendingFindingNumberRef.current = null;
          replaceFindingLocation(selectedScanId, fallback?.scan_finding_number ?? null);
          return;
        }
        throw new Error('The selected finding changed or was removed while it was open. Refresh to continue with the current scan evidence.');
      }
      if (!findingIdentityAndEvidenceMatches(reconciledSummary, summaryFinding)) {
        throw new Error('The selected finding now has a different immutable identity or evidence binding.');
      }
      const reconciledDetail = await loadFinding(reconciledSummary, after.findings_revision);
      if (!requestIsCurrent()) return;
      if (
        reconciledDetail.findings_revision !== after.findings_revision
        || !detailMatchesFindingSummary(reconciledDetail, reconciledSummary)
      ) {
        if (!findingIdentityAndEvidenceMatches(reconciledDetail, reconciledSummary)) {
          throw new Error('CodeSecurity returned finding detail with a different immutable identity or evidence binding.');
        }
        throw new Error('The finding changed again after one bounded reconciliation. Refresh when the current operation finishes.');
      }

      setFindings(nextFindingPage.items);
      setSelectedScanSummary(after);
      setScans((current) => {
        const existing = current.find((scan) => scan.id === selectedScanId);
        const merged = mergeScanSummary(existing, after);
        return [merged, ...current.filter((scan) => scan.id !== selectedScanId)]
          .sort((left, right) => right.id - left.id);
      });
      const currentDetailRevision = detailRevisionRef.current;
      if (currentDetailRevision?.scanId === selectedScanId) {
        detailRevisionRef.current = {
          ...currentDetailRevision,
          // Preserve the revision of the artifacts actually read.
          findingsRevision: after.findings_revision,
          findings: findingsRevisionKey(nextFindingPage.items),
        };
      }
      setSelectedFindingDetail(reconciledDetail);
    })()
      .catch((err) => {
        if (!isAbortError(err) && generation === findingDetailGenerationRef.current) {
          setSelectedFindingDetail(null);
          findingDetailErrorKeyRef.current = selectedFindingDetailKey;
          setFindingDetailError(err instanceof Error ? err.message : String(err));
        }
      })
      .finally(() => {
        if (generation === findingDetailGenerationRef.current) setFindingDetailLoading(false);
        if (findingDetailControllerRef.current === controller) findingDetailControllerRef.current = null;
      });
    return undefined;
  }, [findingDetailRetryGeneration, selectedFindingDetailKey, selectedFindingSummary?.id, selectedFindingSummary?.revision, selectedFindingSummary?.scan_finding_number, selectedScanId, selectedScanSummary?.findings_revision, view]);

  const rememberFindingLocation = useCallback((scanId: number, scanFindingNumber: number | null) => {
    replaceFindingLocation(scanId, scanFindingNumber);
  }, []);

  const openFindings = useCallback((scanId: number, scanFindingNumber: number | null = null) => {
    const sameScan = selectedScanIdRef.current === scanId;
    pendingFindingNumberRef.current = scanFindingNumber;
    selectScan(scanId);
    const target = scanFindingNumber
      ? findings.find((finding) => finding.scan_id === scanId && finding.scan_finding_number === scanFindingNumber)
      : undefined;
    if (target) pendingFindingNumberRef.current = null;
    focusFinding(target?.id ?? null);
    rememberFindingLocation(scanId, scanFindingNumber);
    setView('findings');
    if (scanFindingNumber && !target && sameScan && viewRef.current === 'findings') {
      void loadScanDetails(scanId, false);
    }
  }, [findings, focusFinding, loadScanDetails, rememberFindingLocation, selectScan]);

  const openFinding = useCallback((findingId: number | null) => {
    const scanId = selectedScanIdRef.current;
    if (!scanId || viewRef.current !== 'findings') return;
    const finding = findings.find((item) => item.id === findingId && item.scan_id === scanId);
    if (findingId !== null && !finding) return;
    setSelectedFindingId(findingId);
    rememberFindingLocation(scanId, finding?.scan_finding_number ?? null);
  }, [findings, rememberFindingLocation]);

  const refreshIdeCapabilities = useCallback(async () => {
    try {
      updateIdeCapabilities(await api.ideCapabilities());
      return true;
    } catch (err) {
      notify('error', 'IDE client refresh failed', err instanceof Error ? err.message : String(err));
      return false;
    }
  }, [updateIdeCapabilities]);

  const openSourceInIde = useCallback(async (finding: Finding, capability: IdeValidCapability) => {
    const sourceProject = selectedScanSummary?.scan.id === finding.scan_id
      ? projects.find((project) => project.id === selectedScanSummary.scan.project_id)
      : undefined;
    const sourceReason = projectSourceNavigationDisabledReason(sourceProject?.repo_path);
    if (sourceReason) {
      notify('error', 'Source navigation unavailable', sourceReason);
      return;
    }
    const target = ideSourceOpenTarget(capability);
    if (!target) {
      notify('error', 'Source navigation unavailable', 'The selected IDE authority is no longer active and connected. Refresh IDE access and choose the current generation.');
      return;
    }
    const capabilityId = target.target_capability_id;
    const targetGeneration = target.expected_target_generation;
    const collectionRevision = selectedScanSummary?.scan.id === finding.scan_id
      ? selectedScanSummary.findings_revision
      : null;
    if (!collectionRevision) {
      notify('error', 'Source navigation unavailable', 'Refresh this scan before sending an exact finding to VS Code.');
      return;
    }
    sourceOpenControllerRef.current?.abort();
    const controller = new AbortController();
    sourceOpenControllerRef.current = controller;
    try {
      let command = sourceOpenCommand?.finding_id === finding.id
        && sourceOpenCommand.target_capability_id === capabilityId
        && sourceOpenCommand.expected_target_generation === targetGeneration
        && sourceOpenCommand.status === 'queued'
        ? sourceOpenCommand
        : await api.openSourceInIde({
          finding_id: finding.id,
          expected_finding_revision: finding.revision,
          expected_findings_revision: collectionRevision,
          ...target,
        });
      setSourceOpenCommand(command);
      notify(
        'info',
        `Opening ${findingLabel(finding)} in VS Code`,
        `The command is durably queued for generation ${targetGeneration} of exactly one connected IDE stream. CodeSecurity will report the IDE acknowledgement.`,
      );
      command = await api.waitForSourceOpen(command.id, controller.signal);
      setSourceOpenCommand(command);
      if (command.status === 'opened') {
        notify('success', `${findingLabel(finding)} opened in VS Code`, 'The selected IDE acknowledged the exact file and range.');
      } else if (command.status === 'failed' || command.status === 'expired') {
        notify(
          'error',
          'VS Code did not open the finding',
          command.status === 'expired'
            ? 'The recipient did not acknowledge the command before it expired. Reconnect the IDE and try again.'
            : `The recipient reported ${command.error_code || 'source_open_failed'}. Refresh its findings and try again.`,
        );
      }
    } catch (err) {
      if (!isAbortError(err)) {
        const authorityRecovery = isApiError(err)
          ? ideSourceOpenAuthorityRecovery(err)
          : null;
        if (authorityRecovery) {
          const refreshed = await refreshIdeCapabilities();
          notify(
            'error',
            authorityRecovery.title,
            `${authorityRecovery.detail} ${refreshed
              ? 'The IDE client list was refreshed from the control plane.'
              : 'The IDE client list could not be refreshed; use Refresh IDE access before retrying.'}`,
          );
          return;
        }
        notify('error', 'Source navigation failed', err instanceof Error ? err.message : String(err));
        await refreshIdeCapabilities();
      }
    } finally {
      if (sourceOpenControllerRef.current === controller) sourceOpenControllerRef.current = null;
    }
  }, [projects, refreshIdeCapabilities, selectedScanSummary, sourceOpenCommand]);

  async function onCreateProject(event: FormEvent<HTMLFormElement>): Promise<ProjectRegistrationFailure | undefined> {
    event.preventDefault();
    const errorOwnership = captureRouteErrorOwnership();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    setBusy(true);
    try {
      await api.createProject({
        name: String(form.get('name') || ''),
        repo_path: String(form.get('repo_path') || ''),
        remote_url: String(form.get('remote_url') || '') || undefined,
        default_branch: String(form.get('default_branch') || 'main'),
      });
      setSourceAuthorizationRecovery(null);
      notify('success', 'Project registered', 'CodeSecurity stored the local path. Scans will read files from that directory through the read-only Docker mount.');
      formElement.reset();
      await refresh(undefined, 'mutation');
    } catch (err) {
      const sourceDenied = isApiError(err, 'source_outside_allowed_root');
      const selectedPath = sourceDenied && typeof err.context.selected_path === 'string'
        ? err.context.selected_path
        : null;
      const allowedRoots = sourceDenied && Array.isArray(err.context.allowed_roots)
        ? err.context.allowed_roots.filter((root): root is string => typeof root === 'string')
        : [];
      const sourceGuidance = sourceDenied
        ? `${selectedPath ? ` Selected folder: ${selectedPath}.` : ''}${allowedRoots.length ? ` Authorized source roots: ${allowedRoots.join(', ')}.` : ''} Choose a folder inside an existing authorized root. If another repository is needed, review one narrow source root in local setup; broad parent folders cannot be authorized. Only the host-side review and apply step can change source access.`
        : '';
      setSourceAuthorizationRecovery(sourceDenied && selectedPath
        ? { selectedPath, allowedRoots }
        : null);
      const message = `${err instanceof Error ? err.message : String(err)}${sourceGuidance}`;
      notify('error', 'Project registration failed', message);
      reportRouteError(message, errorOwnership);
      if (viewRef.current === errorOwnership.owner && routeEpochRef.current === errorOwnership.routeEpoch) {
        return { message, invalidPath: sourceDenied };
      }
    } finally {
      setBusy(false);
    }
  }

  async function onStartScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const errorOwnership = captureRouteErrorOwnership();
    const form = new FormData(event.currentTarget);
    const coverage = form.get('coverage') === 'limited' ? 'limited' : 'complete';
    const acknowledgeLimitedCoverage = form.get('acknowledge_limited_coverage') === 'true';
    const verificationReason = scannerVerificationDisabledReason(scannerPreflight);
    if (verificationReason && coverage === 'complete') {
      notify('info', 'Scanner verification required', verificationReason);
      navigate('tools');
      return;
    }
    if (coverage === 'complete' && !scannerPreflight?.ready) {
      notify('error', 'Scanner preparation required', 'Prepare the blocked scanners before starting a complete scan. No scan or job was created.');
      navigate('tools');
      return;
    }
    if (coverage === 'limited' && (!acknowledgeLimitedCoverage || !scannerPreflight?.ready_tool_ids.length)) {
      notify('error', 'Limited scan was not acknowledged', 'Limited coverage requires an explicit acknowledgement and at least one ready scanner.');
      return;
    }
    await submitScanOnce(scanSubmissionOwnershipRef, async () => {
      acknowledgeJobCommand(
        'Queuing scan',
        coverage === 'limited'
          ? 'Persisting one explicitly acknowledged limited-coverage scan. Its deterministic gate will remain incomplete.'
          : 'Persisting one complete-coverage scanner command. The selected source and profile will remain visible while the worker claims it.',
      );
      try {
        const scan = await api.startScan({
          project_id: Number(form.get('project_id')),
          mode: String(form.get('mode') || 'full'),
          base_ref: String(form.get('base_ref') || '') || undefined,
          head_ref: String(form.get('head_ref') || '') || undefined,
          use_ai: form.get('use_ai') === 'on',
          coverage,
          acknowledge_limited_coverage: acknowledgeLimitedCoverage,
          preflight_revision: scannerPreflight?.revision,
        });
        notify('info', `Scan #${scan.id} queued`, 'The scanner job is visible in Jobs. Findings and sanitized publishable artifacts will update as soon as the worker finishes.');
        selectScan(scan.id, false);
        focusFinding(null);
        rememberFindingLocation(scan.id, null);
        setView('findings');
        reconcileDurableCommand(scan.id, 'findings');
      } catch (err) {
        notify('error', 'Scan failed to start', err instanceof Error ? err.message : String(err));
        reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
        if (
          isApiError(err, 'scanner_preparation_required')
          || isApiError(err, 'scanner_preflight_changed')
          || isApiError(err, 'no_scanner_tools_enabled')
        ) {
          navigate('tools');
          reconcileDurableCommand(undefined, 'tools');
        }
      } finally {
        setBusy(false);
      }
    });
  }

  async function triage(findingId: number) {
    const target = findings.find((finding) => finding.id === findingId);
    if (!target) {
      notify('error', 'Advisor selection is stale', 'Refresh the current scan and select the finding again.');
      return;
    }
    const errorOwnership = captureRouteErrorOwnership();
    setSelectedFindingId(findingId);
    setBusy(true);
    let attemptedLocalAdvisor = false;
    try {
      const route = await currentAdvisorRoute();
      if (route.kind === 'remote-confirmation') {
        const preview = exactAdvisorDisclosurePreview(
          await api.advisorDisclosurePreview(findingId, target.revision, route.provider.id),
          route.provider,
          target,
        );
        setRemoteAdvisorConfirmation({ finding: target, provider: route.provider, preview });
        return;
      }
      acknowledgeJobCommand(
        'Queuing advisor review',
        `Persisting one local advisor command for ${findingLabel(target)} through ${route.provider.name}.`,
      );
      attemptedLocalAdvisor = true;
      const job = await api.triage(findingId, {
        expected_revision: target.revision,
        advisor_provider_pin: route.pin,
      });
      notify('info', `Advisor job #${job.id} queued`, `${route.provider.name} will analyze ${findingLabel(target)} locally in the background. Watch Jobs for progress.`);
      openJob(job);
      reconcileDurableCommand(undefined, 'jobs');
    } catch (err) {
      if (attemptedLocalAdvisor && isApiError(err, 'revision_conflict')) {
        try {
          const retried = await retryLocalAdvisorAfterRevisionConflict(target, {
            reconcileOnce: reconcileAdvisorFindingOnce,
            resolveRoute: currentAdvisorRoute,
            queue: (current, pin) => api.triage(current.id, {
              expected_revision: current.revision,
              advisor_provider_pin: pin,
            }),
            isRevisionConflict: (error) => isApiError(error, 'revision_conflict'),
            isFindingRemoved: (error) => isApiError(error, 'finding_removed')
              || isApiError(error) && error.status === 404,
          });
          notify(
            'info',
            `Advisor job #${retried.job.id} queued after refresh`,
            `${retried.providerName} will analyze ${findingLabel(retried.finding)} locally. CodeSecurity preserved the selected finding and retried exactly once with current evidence.`,
          );
          openJob(retried.job);
          reconcileDurableCommand(retried.finding.scan_id, 'jobs');
          return;
        } catch (reconciliationError) {
          const terminal = reconciliationError instanceof AdvisorFindingReconciliationError;
          const message = terminal
            ? reconciliationError.message
            : reconciliationError instanceof Error ? reconciliationError.message : String(reconciliationError);
          notify('error', terminal ? 'Advisor reconciliation stopped safely' : 'Advisor unavailable', message);
          reportRouteError(message, errorOwnership);
          return;
        }
      }
      const stale = isApiError(err, 'revision_conflict') || isApiError(err, 'finding_removed');
      const message = stale
        ? 'The selected finding or remote disclosure changed before Advisor could queue a review. No evidence was sent.'
        : err instanceof Error ? err.message : String(err);
      notify('error', stale ? 'Finding changed; review again' : 'Advisor unavailable', message);
      reportRouteError(message, errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function reconcileAdvisorFindingOnce(target: Finding) {
    const before = await api.scanSummary(target.scan_id);
    if (!validScanSummary(target.scan_id, before)) {
      throw new Error('CodeSecurity returned an invalid scan summary while reconciling Advisor.');
    }
    let page;
    try {
      page = await api.findings(target.scan_id, {
        expectedRevision: before.findings_revision,
        anchorScanFindingNumber: target.scan_finding_number,
      });
    } catch (error) {
      if (isApiError(error, 'finding_removed') || isApiError(error) && error.status === 404) return null;
      throw error;
    }
    const current = page.items.find((candidate) => (
      candidate.id === target.id
      && candidate.scan_finding_number === target.scan_finding_number
    ));
    if (!current) return null;
    if (!findingIdentityAndEvidenceMatches(current, target)) {
      return { finding: current, detail: current, commit: () => undefined };
    }
    let detail: Finding;
    try {
      detail = await api.finding(target.scan_id, target.scan_finding_number, {
        expectedRevision: current.revision,
        expectedFindingsRevision: before.findings_revision,
      });
    } catch (error) {
      if (isApiError(error, 'finding_removed') || isApiError(error) && error.status === 404) return null;
      throw error;
    }
    const after = await api.scanSummary(target.scan_id);
    if (
      !validScanSummary(target.scan_id, after)
      || before.revision !== after.revision
      || before.findings_revision !== after.findings_revision
      || page.revision !== after.findings_revision
      || detail.findings_revision !== after.findings_revision
      || !sameScanSummaryRevision(before, after)
    ) {
      throw new AdvisorFindingReconciliationError(
        'second_revision_conflict',
        'The finding changed again during the single authoritative Advisor reconciliation.',
      );
    }
    return {
      finding: current,
      detail,
      commit: () => {
        setFindings(page.items);
        setSelectedScanSummary(after);
        setScans((existingScans) => {
          const existing = existingScans.find((scan) => scan.id === target.scan_id);
          const merged = mergeScanSummary(existing, after);
          return [merged, ...existingScans.filter((scan) => scan.id !== target.scan_id)]
            .sort((left, right) => right.id - left.id);
        });
        const previous = detailRevisionRef.current;
        // Advisor reconciliation does not read artifacts. Retain their older
        // revision for the same scan, or require a complete snapshot on handoff.
        detailRevisionRef.current = previous?.scanId === target.scan_id ? {
          ...previous,
          findingsRevision: after.findings_revision,
          findings: findingsRevisionKey(page.items),
        } : null;
        setSelectedFindingDetail(detail);
        setSelectedFindingId(current.id);
        pendingFindingNumberRef.current = null;
        rememberFindingLocation(target.scan_id, current.scan_finding_number);
        setView('findings');
      },
    };
  }

  async function currentAdvisorRoute(): Promise<ResolvedAdvisorRoute> {
    const [currentHealth, collection] = await Promise.all([
      api.health(),
      api.advisorProviders(),
    ]);
    return resolveAdvisorRoute({ aiMode: currentHealth.ai.mode, collection });
  }

  function cancelRemoteAdvisorConfirmation() {
    if (remoteAdvisorSubmissionOwnershipRef.current) return false;
    setRemoteAdvisorConfirmation(null);
    notify('info', 'Remote Advisor request cancelled', 'No finding evidence was sent and no Advisor job was created.');
    return true;
  }

  async function confirmRemoteAdvisorSubmission() {
    const confirmation = remoteAdvisorConfirmation;
    if (!confirmation) return;
    if (!claimRemoteAdvisorSubmission(remoteAdvisorSubmissionOwnershipRef)) return;
    const errorOwnership = captureRouteErrorOwnership();
    const { finding, preview, provider } = confirmation;
    try {
      acknowledgeJobCommand(
        'Authorizing one remote Advisor review',
        `Persisting one disclosure-bound ${provider.transport} Advisor job for ${findingLabel(finding)}. No scan-wide or bulk remote routing is enabled.`,
      );
      const job = await api.triage(finding.id, {
        expected_revision: finding.revision,
        acknowledge_remote_source_disclosure: true,
        remote_advisor_confirmation: preview.confirmation,
      });
      setRemoteAdvisorConfirmation(null);
      notify(
        'success',
        `Remote Advisor job #${job.id} queued`,
        `${provider.name} will receive only the confirmed ${findingLabel(finding)} disclosure through ${provider.transport}. Watch Jobs for transport and terminal status.`,
      );
      openJob(job);
      reconcileDurableCommand(finding.scan_id, 'jobs');
    } catch (err) {
      const stale = isApiError(err, 'revision_conflict')
        || isApiError(err, 'finding_changed')
        || isApiError(err, 'finding_removed')
        || isApiError(err, 'advisor_source_disclosure_confirmation_stale');
      const message = stale
        ? 'The finding or remote provider changed after preview. CodeSecurity sent nothing and is reconciling the selected finding once; review a fresh disclosure before retrying.'
        : err instanceof Error ? err.message : String(err);
      if (stale) {
        setRemoteAdvisorConfirmation(null);
        rememberFindingLocation(finding.scan_id, finding.scan_finding_number);
        setView('findings');
        focusFinding(finding.id);
        reconcileDurableCommand(finding.scan_id, 'findings');
      }
      notify('error', stale ? 'Remote disclosure changed; review again' : 'Remote Advisor was not queued', message);
      reportRouteError(message, errorOwnership);
    } finally {
      releaseRemoteAdvisorSubmission(remoteAdvisorSubmissionOwnershipRef);
      setBusy(false);
    }
  }

  async function triageScan(scanId: number) {
    const errorOwnership = captureRouteErrorOwnership();
    const scan = scans.find((item) => item.id === scanId);
    const project = scan ? projects.find((item) => item.id === scan.project_id) : null;
    setBusy(true);
    try {
      const route = await currentAdvisorRoute();
      if (route.kind === 'remote-confirmation') {
        throw new Error(`Remote Advisor review through ${route.provider.name} requires one selected finding and an exact disclosure confirmation. Select one finding and choose Run Advisor; no scan-wide request was sent.`);
      }
      acknowledgeJobCommand(
        'Queuing scan advisor',
        `Persisting one local advisor command for ${project?.name || `scan #${scanId}`} through ${route.provider.name}.`,
      );
      const job = await api.triageScan(scanId, {
        include_existing: false,
        advisor_provider_pin: route.pin,
      });
      notify('info', `Advisor job #${job.id} queued`, `${route.provider.name} will analyze untriaged active findings for ${project?.name || `scan #${scanId}`} locally. Watch Jobs for progress.`);
      openJob(job);
      reconcileDurableCommand(scanId, 'jobs');
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      notify('error', 'Scan Advisor unavailable', message);
      reportRouteError(message, errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function cancelJob(job: Job) {
    if (!canCancelJob(job)) return;
    const cancellationCopy = jobCancellationCopy(job);
    if (!await confirmAction({
      title: `Cancel job #${job.id}?`,
      message: `Cancel job #${job.id}? ${cancellationCopy.consequence}`,
      confirmLabel: 'Cancel job',
      cancelLabel: 'Keep job running',
      tone: 'warning',
    })) return;
    const errorOwnership = captureRouteErrorOwnership();
    acknowledgeJobCommand(
      `Cancelling job #${job.id}`,
      cancellationCopy.acknowledgement,
    );
    try {
      const updated = await api.cancelJob(job.id);
      setJobs((current) => upsertJob(current, updated));
      const outcome = cancellationOutcome(updated, cancellationCopy);
      notify(
        outcome.tone,
        `Job #${job.id} ${updated.status}`,
        outcome.detail,
      );
      await refresh(updated.scan_id, 'mutation');
    } catch (err) {
      notify('error', 'Job cancellation failed', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function retryJob(job: Job) {
    if (!canRetryJob(job) || job.revision === undefined) return;
    const errorOwnership = captureRouteErrorOwnership();
    acknowledgeJobCommand(
      `Retrying job #${job.id}`,
      'The retry command was acknowledged and is being persisted with the original bounded command snapshot.',
    );
    try {
      const updated = await api.retryJob(job.id, job.revision);
      setJobs((current) => upsertJob(current, updated));
      notify('success', `Job #${job.id} ${updated.status}`, 'The durable worker can claim the persisted retry when processing is healthy.');
      await refresh(updated.scan_id, 'mutation');
    } catch (err) {
      notify('error', 'Job retry failed', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function reconcileScannerCacheJob(job: Job) {
    if (busy || !canReconcileScannerCacheJob(job) || job.revision === undefined
      || jobs.some(item => ['scanner_cache_update', 'scanner_cache_rollback', 'scanner_cache_reconcile'].includes(item.kind) && activeWorkStatuses.has(item.status))) return;
    const errorOwnership = captureRouteErrorOwnership();
    acknowledgeJobCommand(`Checking cache outcome for failed job #${job.id}`,
      'Queuing a separate read-only check. Scanner data is unchanged; the original preparation remains failed.');
    try {
      const command = await api.reconcileScannerCacheJob(job.id, job.revision);
      if (command.original_job_id !== job.id || command.job.original_job_id !== job.id || command.job.kind !== 'scanner_cache_reconcile'
        || command.lifecycle.scope !== 'cache' || command.lifecycle.job_id !== command.job.id) {
        throw new Error('The cache check response did not match the exact failed preparation. Refresh Jobs before continuing.');
      }
      recordScannerLifecycleCommand(command.job, command.lifecycle);
      openJob(command.job);
      notify('info', `Cache outcome check #${command.job.id} ${command.job.status}`,
        `This read-only check has up to 15 minutes to prove the cache outcome. Preparation job #${job.id} remains failed.`);
      reconcileDurableCommand(undefined, 'jobs');
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      notify('error', 'Cache outcome check could not be confirmed', message);
      reportRouteError(message, errorOwnership);
      // Resolve a revision race or uncertain transport with one current read,
      // never a second automatic command or a generic preparation retry.
      reconcileDurableCommand(undefined, 'jobs');
    } finally {
      setBusy(false);
    }
  }

  async function collectLifecycleReason(action: string, scope: string): Promise<string | undefined | null> {
    if (!lifecycleReasonActions.has(action)) return undefined;
    const label = findingLifecycleActionLabel(action);
    return requestTextEntry({
      title: `Reason required: ${label}`,
      message: `Explain why ${scope} should be marked ${label}. This audit reason is stored only in the local CodeSecurity database.`,
      label: 'Local audit reason',
      submitLabel: `Mark ${label}`,
      cancelLabel: 'Keep unchanged',
      maxLength: lifecycleReasonLimit,
      required: true,
      tone: 'warning',
    });
  }

  async function updateFindingLifecycle(finding: Finding, action: string) {
    const reason = await collectLifecycleReason(action, findingLabel(finding));
    if (lifecycleReasonActions.has(action) && !reason) return false;
    const errorOwnership = captureRouteErrorOwnership();
    setBusy(true);
    try {
      await api.updateFindingLifecycle(finding.id, {
        action,
        reason: reason || undefined,
        expected_revision: finding.revision,
      });
      notify('success', `${findingLabel(finding)} updated`, `Lifecycle set to ${findingLifecycleActionLabel(action)}. Gate and scan counters were recalculated.`);
      await refresh(finding.scan_id, 'mutation');
      return true;
    } catch (err) {
      notify('error', 'Finding update failed', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function bulkFindingAction(findingIds: number[], action: string) {
    if (!findingIds.length) return null;
    const selectionDisabledReason = findingBulkSelectionDisabledReason(findingIds.length);
    if (selectionDisabledReason) {
      notify('info', 'Reduce the finding selection', selectionDisabledReason);
      return null;
    }
    const errorOwnership = captureRouteErrorOwnership();
    if (action === 'delete' && !await confirmAction({
      title: `Delete ${findingIds.length} selected findings?`,
      message: `Delete ${findingIds.length} selected findings from this scan?`,
      confirmLabel: 'Delete selected findings',
      cancelLabel: 'Keep findings',
      tone: 'danger',
    })) return null;
    const selectionLabel = `${findingIds.length} selected ${findingIds.length === 1 ? 'finding' : 'findings'}`;
    const reason = await collectLifecycleReason(action, selectionLabel);
    if (lifecycleReasonActions.has(action) && !reason) return null;
    let advisorRoute: Extract<ResolvedAdvisorRoute, { kind: 'local' }> | null = null;
    if (action === 'triage') {
      setBusy(true);
      try {
        const route = await currentAdvisorRoute();
        if (route.kind === 'remote-confirmation') {
          throw new Error(`Remote Advisor review through ${route.provider.name} requires one selected finding and an exact disclosure confirmation. Select one finding and choose Run Advisor; no bulk request was sent.`);
        }
        advisorRoute = route;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        notify('error', 'Selected Advisor unavailable', message);
        reportRouteError(message, errorOwnership);
        setBusy(false);
        return null;
      }
      acknowledgeJobCommand(
        'Queuing selected advisor reviews',
        `Persisting one bounded local advisor command for ${findingIds.length} active findings through ${advisorRoute.provider.name}.`,
      );
    } else {
      setBusy(true);
    }
    try {
      const expectedRevisions = Object.fromEntries(
        findings
          .filter((finding) => findingIds.includes(finding.id))
          .map((finding) => [finding.id, finding.revision]),
      );
      if (Object.keys(expectedRevisions).length !== findingIds.length) {
        throw new Error('One or more selected findings changed. Refresh before applying the lifecycle action.');
      }
      const result = await api.bulkFindings({
        finding_ids: findingIds,
        action,
        reason: reason || undefined,
        expected_revisions: expectedRevisions,
        advisor_provider_pin: advisorRoute?.pin,
      });
      const scanId = result.scan_ids[0] ?? selectedScanIdRef.current;
      if (result.job) {
        notify('info', `Advisor job #${result.job.id} queued`, `${advisorRoute?.provider.name || 'The local Advisor'} will analyze ${findingIds.length} selected findings locally. Watch Jobs for progress.`);
        openJob(result.job);
        reconcileDurableCommand(scanId, 'jobs');
      } else if (action === 'delete') {
        notify('success', `${result.deleted} findings deleted`, 'Gate and scan counters were recalculated.');
        await refresh(scanId, 'mutation');
      } else {
        notify('success', `${result.updated} findings updated`, `Lifecycle set to ${findingLifecycleActionLabel(action)}.`);
        await refresh(scanId, 'mutation');
      }
      return result;
    } catch (err) {
      notify('error', 'Bulk finding action failed', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
      return null;
    } finally {
      setBusy(false);
    }
  }

  async function checkTools() {
    const errorOwnership = captureRouteErrorOwnership();
    acknowledgeJobCommand(
      'Queuing curated catalog check',
      'Persisting one source-blind scanner catalog command. The API will not contact upstream services in this request.',
    );
    try {
      const command = await api.checkTools();
      recordScannerLifecycleCommand(command.job, command.lifecycle);
      notify('info', `Catalog job #${command.job.id} ${command.job.status}`, 'Track, cancel, or retry this durable check from Tools or Jobs. Running scanner binaries are unchanged.');
      await refresh(undefined, 'mutation');
    } catch (err) {
      notify('error', 'Catalog check was not queued', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function prepareScanners() {
    const verificationReason = scannerVerificationDisabledReason(scannerPreflight);
    if (verificationReason) {
      notify('info', 'Scanner verification required', verificationReason);
      return;
    }
    const errorOwnership = captureRouteErrorOwnership();
    acknowledgeJobCommand(
      'Preparing every required scanner',
      'Persisting one source-blind preparation request. CodeSecurity will check the curated catalog and prepare every required verified database and ruleset.',
    );
    try {
      const command = await api.prepareScanners();
      recordScannerLifecycleCommand(command.catalog.job, command.catalog.lifecycle);
      if (command.cache) {
        recordScannerLifecycleCommand(command.cache.job, command.cache.lifecycle);
      }
      const commandCopy = scannerPreparationCommandCopy(command);
      notify(
        'info',
        commandCopy.title,
        commandCopy.detail,
      );
      await refresh(undefined, 'mutation');
    } catch (err) {
      notify('error', 'Scanner preparation was not queued', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function updateScannerCache(componentIds: ScannerCacheComponentId[], catalogDigest: string | null) {
    if (!componentIds.length) return;
    const verificationReason = scannerVerificationDisabledReason(scannerPreflight);
    if (verificationReason) {
      notify('info', 'Scanner verification required', verificationReason);
      return;
    }
    const errorOwnership = captureRouteErrorOwnership();
    acknowledgeJobCommand(
      'Queuing verified cache update',
      `Persisting a source-blind update for ${componentIds.length} explicitly selected component${componentIds.length === 1 ? '' : 's'}. Scans and cache activation are serialized.`,
    );
    try {
      const command = await api.updateScannerCache(componentIds, catalogDigest);
      recordScannerLifecycleCommand(command.job, command.lifecycle);
      notify('info', `Cache job #${command.job.id} ${command.job.status}`, 'The previous verified generation remains available until validation and atomic activation complete.');
      await refresh(undefined, 'mutation');
    } catch (err) {
      notify('error', 'Cache update was not queued', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function retryScannerVerification(verification: ScannerCacheVerification) {
    if (busy || !scannerVerificationCopy(verification).canRetry) return;
    const current = verification.target === 'active'
      ? scannerPreflight?.cache_verification
      : scannerPreflight?.cache_rollback.verification;
    if (current?.generation_id !== verification.generation_id || current.state !== verification.state) return;
    const errorOwnership = captureRouteErrorOwnership();
    setBusy(true);
    try {
      const accepted = await api.retryScannerVerification(verification.target, verification.generation_id);
      if (!validScannerCacheVerification(accepted) || accepted.target !== verification.target
        || accepted.generation_id !== verification.generation_id || accepted.state !== 'verifying') {
        throw new Error('Scanner verification returned a different or invalid target. Refresh readiness before retrying.');
      }
      // A pre-command dashboard response must not overwrite this accepted
      // observation if the subsequent full refresh cannot complete.
      refreshGenerationRef.current += 1;
      refreshControllerRef.current?.abort();
      if (dashboardRevisionRef.current) {
        dashboardRevisionRef.current = { ...dashboardRevisionRef.current, scannerPreflight: [] };
      }
      setScannerPreflight((current) => applyAcceptedScannerVerification(current, verification, accepted));
      notify('info', 'Scanner verification restarted', 'The scanner is checking the same existing cache locally. No download or durable job was created.');
      await refresh(undefined, 'mutation');
    } catch (err) {
      notify('error', 'Scanner verification retry failed', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function rollbackScannerCache() {
    const previousGeneration = scannerLifecycle?.cache.previous_generation;
    if (!previousGeneration) return;
    const eligibility = scannerPreflight?.cache_rollback;
    if (
      !eligibility?.eligible
      || eligibility.target_generation !== previousGeneration
    ) {
      notify(
        'error',
        'Cache rollback is unavailable',
        eligibility?.reason || 'Refresh scanner status before retrying.',
      );
      return;
    }
    if (!await confirmAction({
      title: 'Roll back scanner cache?',
      message: 'Roll back to the previous verified scanner cache generation? The current generation will remain available as the new previous-good generation.',
      confirmLabel: 'Roll back cache',
      cancelLabel: 'Keep current cache',
      tone: 'warning',
    })) return;
    const errorOwnership = captureRouteErrorOwnership();
    acknowledgeJobCommand(
      'Queuing verified cache rollback',
      'Persisting one source-blind rollback command. Scans and cache activation remain serialized.',
    );
    try {
      const command = await api.rollbackScannerCache();
      recordScannerLifecycleCommand(command.job, command.lifecycle);
      notify('info', `Rollback job #${command.job.id} ${command.job.status}`, 'The updater will validate the previous-good generation before atomically switching the active pointer.');
      await refresh(undefined, 'mutation');
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      notify('error', 'Cache rollback was not queued', message);
      if (isApiError(err, 'scanner_cache_rollback_unavailable')) {
        // A refusal supersedes the snapshot used to open the confirmation.
        // Keep active scan readiness, but never offer the rejected target while
        // a fresh read is pending or unavailable. Older reads cannot restore it.
        refreshGenerationRef.current += 1;
        refreshControllerRef.current?.abort();
        if (dashboardRevisionRef.current) {
          dashboardRevisionRef.current = { ...dashboardRevisionRef.current, scannerPreflight: [] };
        }
        setScannerPreflight((current) => current?.cache_rollback.target_generation === previousGeneration
          ? { ...current, cache_rollback: {
            eligible: false,
            reason_code: 'state_mismatch',
            reason: message,
            target_generation: previousGeneration,
          } }
          : current);
        await refresh(undefined, 'mutation');
      }
      reportRouteError(message, errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function selectToolCandidate(toolId: string) {
    const errorOwnership = captureRouteErrorOwnership();
    setBusy(true);
    try {
      await api.updateTool(toolId);
      await refresh(undefined, 'mutation');
      notify('info', `${toolId} candidate selected`, 'Host confirmation is required to replace the immutable scanner image. This selection did not install or change the running binary.');
    } catch (err) {
      notify('error', 'Candidate selection failed', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function toggleTool(tool: ScannerTool) {
    const errorOwnership = captureRouteErrorOwnership();
    setBusy(true);
    try {
      await api.patchTool(tool.id, { enabled: !tool.enabled });
      await refresh(undefined, 'mutation');
      notify('success', `${tool.name} ${tool.enabled ? 'disabled' : 'enabled'}`, 'New scans will use the updated scanner selection.');
    } catch (err) {
      notify('error', 'Tool toggle failed', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function deleteProject(project: Project) {
    if (!await confirmAction({
      title: `Delete project ${project.name}?`,
      message: `Delete project ${project.name} and all related scans/findings/artifacts?`,
      confirmLabel: 'Delete project and data',
      cancelLabel: 'Keep project',
      tone: 'danger',
    })) return;
    const errorOwnership = captureRouteErrorOwnership();
    setBusy(true);
    try {
      await api.deleteProject(project.id);
      notify('success', 'Project deleted', 'Related scans, findings, and artifacts were cleaned up.');
      if (scans.some((scan) => scan.project_id === project.id && scan.id === selectedScanId)) {
        selectScan(null);
        setSelectedFindingId(null);
      }
      await refresh(undefined, 'mutation');
    } catch (err) {
      notify('error', 'Project delete failed', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function deleteScan(scan: Scan) {
    if (!await confirmAction({
      title: `Delete scan #${scan.id}?`,
      message: `Delete scan #${scan.id}, findings, and publishable artifacts?`,
      confirmLabel: 'Delete scan and data',
      cancelLabel: 'Keep scan',
      tone: 'danger',
    })) return;
    const errorOwnership = captureRouteErrorOwnership();
    setBusy(true);
    try {
      await api.deleteScan(scan.id);
      notify('success', `Scan #${scan.id} deleted`, 'Findings and sanitized publishable artifacts were cleaned up.');
      if (selectedScanId === scan.id) {
        selectScan(null);
        setSelectedFindingId(null);
      }
      await refresh(undefined, 'mutation');
    } catch (err) {
      notify('error', 'Scan delete failed', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
    } finally {
      setBusy(false);
    }
  }

  async function deleteFinding(finding: Finding, onConfirmed?: () => void) {
    if (!await confirmAction({
      title: `Delete ${findingLabel(finding)}?`,
      message: `Delete ${findingLabel(finding)} (${finding.rule_id}) from this scan?`,
      confirmLabel: 'Delete finding',
      cancelLabel: 'Keep finding',
      tone: 'danger',
    })) return false;
    const errorOwnership = captureRouteErrorOwnership();
    onConfirmed?.();
    setBusy(true);
    try {
      await api.deleteFinding(finding.id, finding.revision);
      // The exact DELETE acknowledgement proves this selected resource can no
      // longer own a detail request. Keep that proof separate from deep-link
      // pagination: a deleted scan-local number is not a valid page anchor.
      findingDetailControllerRef.current?.abort();
      acknowledgedDeletedFindingRef.current = {
        scanId: finding.scan_id,
        scanFindingNumber: finding.scan_finding_number,
      };
      setSelectedFindingDetail(null);
      notify('success', `${findingLabel(finding)} deleted`, 'The scan gate and counters were recalculated.');
      await refresh(selectedScanId, 'mutation');
      return true;
    } catch (err) {
      notify('error', 'Finding delete failed', err instanceof Error ? err.message : String(err));
      reportRouteError(err instanceof Error ? err.message : String(err), errorOwnership);
      return false;
    } finally {
      setBusy(false);
    }
  }

  const globalAdvisorPresentation = observedAdvisorPresentation(healthObservation, advisorProviderReadiness);
  const controlHealthLabel = health?.ok
    ? 'Control plane healthy'
    : health
      ? 'Control plane needs attention'
      : healthObservation.status === 'unavailable'
        ? 'Control plane status unknown'
        : 'Checking control plane health';

  return (
    <div className="shell">
      {remoteAdvisorConfirmation ? (
        <RemoteAdvisorConfirmationDialog
          busy={busy}
          confirmation={remoteAdvisorConfirmation}
          onCancel={cancelRemoteAdvisorConfirmation}
          onConfirm={confirmRemoteAdvisorSubmission}
        />
      ) : null}
      <aside className="side">
        <div className="brand">
          <img src="/lomo-icon-128.png" srcSet="/lomo-icon-128.png 1x, /lomo-icon-256.png 2x, /lomo-icon-512.png 3x" alt="Lomo.dev" />
          <div>
            <strong>Lomo CodeSecurity</strong>
            <span>local workbench</span>
          </div>
        </div>
        <nav ref={navigationRef} aria-label="Workbench views">
          <button data-view-target="overview" aria-current={view === 'overview' ? 'page' : undefined} className={view === 'overview' ? 'active' : ''} onClick={() => navigate('overview')}>
            <Gauge size={17} /> Overview
          </button>
          <button data-view-target="projects" aria-current={view === 'projects' ? 'page' : undefined} className={view === 'projects' ? 'active' : ''} onClick={() => navigate('projects')}>
            <GitBranch size={17} /> Projects
          </button>
          <button data-view-target="jobs" aria-current={view === 'jobs' ? 'page' : undefined} className={view === 'jobs' ? 'active' : ''} onClick={openJobs}>
            <ListChecks size={17} /> Jobs
          </button>
          <button data-view-target="scans" aria-current={view === 'scans' ? 'page' : undefined} className={view === 'scans' ? 'active' : ''} onClick={() => navigate('scans')}>
            <Activity size={17} /> Scans
          </button>
          <button data-view-target="findings" aria-current={view === 'findings' ? 'page' : undefined} className={view === 'findings' ? 'active' : ''} onClick={() => navigate('findings')}>
            <FileSearch size={17} /> Findings
          </button>
          <button data-view-target="tools" aria-current={view === 'tools' ? 'page' : undefined} className={view === 'tools' ? 'active' : ''} onClick={() => navigate('tools')}>
            <Wrench size={17} /> Tools
          </button>
          <button data-view-target="settings" aria-current={view === 'settings' ? 'page' : undefined} className={view === 'settings' ? 'active' : ''} onClick={() => navigate('settings')}>
            <SlidersHorizontal size={17} /> Settings
          </button>
        </nav>
      </aside>

      <main key={renderedView} ref={mainScrollRef} data-rendered-view={renderedView} data-requested-view={view} aria-busy={routePending || automaticLandingPending} aria-labelledby={`workbench-view-title-${view}`}>
        <header className="top">
          <div>
            <h1 id={`workbench-view-title-${view}`} data-view-title={view}>{automaticLandingPending ? 'Opening workspace' : titleFor(view)}</h1>
            {view !== 'findings' ? <span>localhost privacy mode</span> : null}
          </div>
          <div className="top-actions">
            {view !== 'findings' ? <StatusPill
              value={globalAdvisorPresentation.pill}
              label={`Advisor ${globalAdvisorPresentation.label.toLowerCase()}`}
            /> : null}
            {jobs.some((job) => activeWorkStatuses.has(job.status)) ? <StatusPill value="running" /> : null}
            <span
              aria-label={controlHealthLabel}
              role="status"
              title={controlHealthLabel}
            >
              <StatusPill
                value={health?.ok ? 'ready' : health ? 'failed' : 'pending'}
                label={healthObservation.status === 'pending' ? 'Checking health' : controlHealthLabel}
              />
            </span>
            <button className="icon-button" onClick={() => {
              // Only an explicit operator refresh retries a terminal detail
              // error. Polling the unchanged collection must not loop the read.
              if (view === 'findings' && currentFindingDetailError) {
                setFindingDetailRetryGeneration((current) => current + 1);
              }
              void refresh(undefined, 'manual');
            }} disabled={busy || automaticLandingPending} title="Refresh">
              <RefreshCw size={18} />
            </button>
          </div>
        </header>

        {healthObservation.status === 'unavailable' ? (
          <div className="notice" role="status">
            <AlertTriangle size={18} />
            <span>Current service status could not be verified. Displayed findings, jobs and settings are the last loaded data, not proof that services are running. Restore the control plane and use Refresh.</span>
          </div>
        ) : null}

        {routeError?.owner === renderedView && routeError.routeEpoch === routeEpochRef.current ? (
          <div className="notice" role="alert" aria-atomic="true">
            <AlertTriangle size={18} />
            <span>{routeError.message}</span>
          </div>
        ) : null}

        {automaticLandingPending ? <div className="empty-state" role="status">Loading current projects and scans.</div> : null}

        {!automaticLandingPending && renderedView === 'overview' ? <Overview surface={routeSurfaceAttributes} health={health} advisorPresentation={globalAdvisorPresentation} summary={summary} scans={scans} setView={navigate} openFindings={openFindings} /> : null}
        {!automaticLandingPending && renderedView === 'projects' ? (
          <Projects
            surface={routeSurfaceAttributes}
            advisorProviderReadiness={advisorProviderReadiness}
            projects={projects}
            busy={busy}
            health={health}
            preflight={scannerPreflight}
            sourceBoundary={sourceBoundary}
            onCreateProject={onCreateProject}
            onStartScan={onStartScan}
            onDeleteProject={deleteProject}
            onGateSaved={() => refresh(undefined, 'mutation')}
            onOpenSettings={() => navigate('settings')}
            onOpenTools={() => navigate('tools')}
            onReloadSourceBoundary={() => void refresh(undefined, 'manual')}
            sourceAuthorizationRecovery={sourceAuthorizationRecovery}
            sourceSetupPrefill={initialLocation.sourceSetupPrefill}
            sourceSetupRequested={initialLocation.sourceSetupRequested}
          />
        ) : null}
        {!automaticLandingPending && renderedView === 'jobs' ? (
          <Jobs
            surface={routeSurfaceAttributes}
            jobs={jobs}
            scans={scans}
            health={health}
            busy={busy}
            cancelJob={cancelJob}
            retryJob={retryJob}
            reconcileScannerCacheJob={reconcileScannerCacheJob}
            openJob={openJob}
            openFindings={openFindings}
            jobsAvailability={dashboardAvailability}
            jobHandoff={jobHandoff}
          />
        ) : null}
        {!automaticLandingPending && renderedView === 'scans' ? (
          <Scans
            surface={routeSurfaceAttributes}
            scans={scans}
            projects={projects}
            openFindings={(id) => openFindings(id)}
            onDeleteScan={deleteScan}
          />
        ) : null}
        {!automaticLandingPending && renderedView === 'findings' ? (
          <Findings
            surface={routeSurfaceAttributes}
            scans={scans}
            projects={projects}
            selectedScanId={selectedScanId}
            setSelectedScanId={(id) => openFindings(id)}
            selectedFindingId={selectedFindingId}
            setSelectedFindingId={setSelectedFindingId}
            openFinding={openFinding}
            pendingFindingFocusId={pendingFindingFocusId}
            clearPendingFindingFocus={clearPendingFindingFocus}
            findings={findingsWithSelectedDetail}
            findingsLoading={findingsLoading}
            findingsHydrating={findingsHydrating}
            findingDetailLoading={findingDetailLoading || findingDetailRevisionPending}
            pendingLifecycleLayout={findingDetailRevisionPending && selectedFindingDetail && selectedFindingSummary
              && findingEvidenceMatchesSummary(selectedFindingDetail, selectedFindingSummary)
              ? { findingId: selectedFindingDetail.id, scanId: selectedFindingDetail.scan_id, reason: findingLifecycleReason(selectedFindingDetail) }
              : null}
            findingDetailError={currentFindingDetailError}
            ideCapabilities={ideCapabilities}
            scanSummary={selectedScanSummary}
            artifacts={artifacts}
            advisorProviderReadiness={advisorProviderReadiness}
            busy={busy}
            health={health}
            triage={triage}
            triageScan={triageScan}
            updateFindingLifecycle={updateFindingLifecycle}
            bulkFindingAction={bulkFindingAction}
            deleteFinding={deleteFinding}
            openSourceInIde={openSourceInIde}
            refreshIdeCapabilities={refreshIdeCapabilities}
            sourceOpenCommand={sourceOpenCommand}
            onOpenProtection={(repositoryId) => {
              navigate('settings');
              window.location.hash = protectionSettingsHash(repositoryId);
            }}
          />
        ) : null}
        {!automaticLandingPending && renderedView === 'tools' ? (
          <Tools
            surface={routeSurfaceAttributes}
            tools={tools}
            lifecycle={scannerLifecycle}
            preflight={scannerPreflight}
            jobs={jobs}
            busy={busy}
            prepareScanners={prepareScanners}
            checkTools={checkTools}
            updateScannerCache={updateScannerCache}
            rollbackScannerCache={rollbackScannerCache}
            selectToolCandidate={selectToolCandidate}
            toggleTool={toggleTool}
            cancelJob={cancelJob}
            retryJob={retryJob}
            viewJob={openJob}
            refreshScannerStatus={() => void refresh(undefined, 'manual')}
            retryScannerVerification={retryScannerVerification}
            dashboardSettled={dashboardSettled}
          />
        ) : null}
        {!automaticLandingPending && renderedView === 'settings' ? (
          <Settings
            surface={routeSurfaceAttributes}
            health={health}
            healthLossEpoch={healthObservation.lossEpoch}
            ideCapabilities={ideCapabilities}
            ideCapabilitiesLoadState={ideCapabilitiesLoaded ? 'ready' : dashboardAvailability}
            onIdeCapabilitiesChange={updateIdeCapabilities}
            onOpenProjects={() => navigate('projects')}
            onAdvisorDiscoveryRetry={resetLocalAdvisorDiscoveryPollBudget}
            onSaved={refresh}
          />
        ) : null}
      </main>
      <div className="toast-stack" aria-live="polite" aria-relevant="additions text">
        {toasts.map((toast) => (
          <div className={`toast toast-${toast.tone}`} role={toast.tone === 'error' ? 'alert' : 'status'} key={toast.id}>
            <strong>{toast.title}</strong>
            <span>{toast.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function titleFor(view: View) {
  return {
    overview: 'Overview',
    projects: 'Projects',
    jobs: 'Jobs',
    scans: 'Scans',
    findings: 'Findings',
    tools: 'Tools',
    settings: 'Settings',
  }[view];
}

export function Overview({
  surface,
  health,
  advisorPresentation,
  summary,
  scans,
  setView,
  openFindings,
}: {
  surface: RouteSurfaceAttributes;
  health: Health | null;
  advisorPresentation: ReturnType<typeof observedAdvisorPresentation>;
  summary: Summary | null;
  scans: Scan[];
  setView: (view: View) => void;
  openFindings: (scanId: number) => void;
}) {
  const severityCounts = summary?.severity_counts || {};
  const scannerCounts = summary?.scanner_counts || {};
  const totalFindings = totalFromCounts(severityCounts);
  return (
    <section {...surface} className="stack">
      <WorkbenchSummary label="Overview summary" items={[
        ['Projects', summary?.projects ?? 'Not loaded'],
        ['Scans', summary?.scans ?? 'Not loaded'],
        ['Unique Findings', summary?.findings ?? 'Not loaded'],
        ['Artifacts', summary?.artifacts ?? 'Not loaded'],
        ['Advisor', advisorPresentation.label],
      ]} />
      {summary === null ? <p className="helper-text" role="status">Overview counts have not loaded yet.</p> : null}
      <p className="helper-text">Overview counters are deduplicated by scanner fingerprint. Re-running the same scan updates occurrences without inflating the headline finding count.</p>

      <div className="split">
        <div className="band risk-board">
          <div className="band-head">
            <h2>Findings by severity</h2>
            <button type="button" onClick={() => setView('findings')}>
              <FileSearch size={16} /> Findings
            </button>
          </div>
          <div className="risk-lines">
            {severityOrder.map((severity) => {
              const value = severityCounts[severity] || 0;
              const width = totalFindings && value > 0 ? Math.max(5, Math.round((value / totalFindings) * 100)) : 0;
              return (
                <div className="risk-line" key={severity}>
                  <span>{severity}</span>
                  <div className="risk-track">
                    <i className={`risk-fill risk-fill-${severity}`} style={{ width: `${width}%` }} />
                  </div>
                  <strong>{summary ? value : 'Not loaded'}</strong>
                </div>
              );
            })}
          </div>
        </div>

        <div className="band advisor-card">
          <div className="band-head">
            <h2>Advisor</h2>
            <Sparkles size={18} />
          </div>
          <div className="advisor-meter">
            <strong>{advisorPresentation.label}</strong>
            <span>{advisorPresentation.model || 'No model selected'}</span>
          </div>
          <p className="helper-text">{advisorPresentation.detail}</p>
          <dl className="kv compact-kv">
            <dt>Mode</dt>
            <dd>{health?.ai.mode || '-'}</dd>
            <dt>URL</dt>
            <dd>{health?.ai.base_url || '-'}</dd>
            <dt>Reason</dt>
            <dd>{health?.ai.available ? 'Local transport connected' : advisorPresentation.label}</dd>
          </dl>
          {advisorPresentation.label !== 'Ready' ? (
            <button type="button" onClick={() => setView('settings')}>
              <SlidersHorizontal size={16} /> Set up Advisor
            </button>
          ) : null}
        </div>
      </div>

      <div className="band">
        <div className="band-head">
          <h2>Scanner Coverage</h2>
          <button onClick={() => setView('tools')}>
            <Wrench size={16} /> Tools
          </button>
        </div>
        <div className="scanner-grid">
          {Object.entries(scannerCounts).map(([scanner, count]) => (
            <div className="scanner-tile" key={scanner}>
              <span>{scanner}</span>
              <strong>{count}</strong>
            </div>
          ))}
          {!Object.keys(scannerCounts).length ? <div className="empty-state">{summary
            ? 'No scanner findings have been recorded yet.'
            : 'Scanner findings have not loaded yet.'}</div> : null}
        </div>
      </div>

      <div className="band">
        <div className="band-head">
          <h2>Recent Scans</h2>
          <button onClick={() => setView('scans')}>
            <Activity size={16} /> Open
          </button>
        </div>
        {summary || scans.length ? <ScanTable scans={scans.slice(0, 8)} projects={[]} onOpen={openFindings} compact />
          : <div className="empty-state">Scan history has not loaded yet.</div>}
      </div>
    </section>
  );
}

type ProjectsContentStage = 0 | 1 | 2;
type ProjectsRenderStage = ProjectsContentStage | 3;

function useProjectsPaintedStage() {
  const [renderStage, setRenderStage] = useState<ProjectsRenderStage>(0);

  useEffect(() => {
    if (renderStage === 3) return undefined;
    const nextFrame = window.requestAnimationFrame(() => {
      if (renderStage < 2) {
        // The project collection is paged to ten rows, so its two remaining
        // bounded panels can share one render without a second idle frame.
        setRenderStage(2);
        return;
      }
      // Stage 2 committed the complete route. Cross its next paint before
      // exposing controls and declaring the surface ready.
      setRenderStage(3);
    });
    return () => window.cancelAnimationFrame(nextFrame);
  }, [renderStage]);

  return {
    contentStage: Math.min(renderStage, 2) as ProjectsContentStage,
    ready: renderStage === 3,
  };
}

type ProjectRegistrationFailure = Readonly<{ message: string; invalidPath: boolean }>;

type ProjectsBodyProps = {
  advisorProviderReadiness: AdvisorProviderReadiness;
  busy: boolean;
  contentStage: ProjectsContentStage;
  health: Health | null;
  onCreateProject: (event: FormEvent<HTMLFormElement>) => Promise<ProjectRegistrationFailure | undefined>;
  onDeleteProject: (project: Project) => void;
  onGateSaved: () => Promise<void>;
  onOpenSettings: () => void;
  onOpenTools: () => void;
  onReloadSourceBoundary: () => void;
  onStartScan: (event: FormEvent<HTMLFormElement>) => void;
  page: number;
  preflight: ScannerPreflight | null;
  projects: Project[];
  setPage: (page: number) => void;
  sourceBoundary: SourceBoundaryLoadState;
  sourceAuthorizationRecovery: SourceAuthorizationRecovery | null;
  sourceSetupPrefill: string | null;
  sourceSetupRequested: boolean;
};

const ProjectsBody = memo(function ProjectsBody({
  advisorProviderReadiness,
  busy,
  contentStage,
  health,
  onCreateProject,
  onDeleteProject,
  onGateSaved,
  onOpenSettings,
  onOpenTools,
  onReloadSourceBoundary,
  onStartScan,
  page,
  preflight,
  projects,
  setPage,
  sourceBoundary,
  sourceAuthorizationRecovery,
  sourceSetupPrefill,
  sourceSetupRequested,
}: ProjectsBodyProps) {
  const confirmAction = useConfirmation();
  const [acknowledgedPreflightRevision, setAcknowledgedPreflightRevision] = useState<string | null>(null);
  const [showSourceAuthorization, setShowSourceAuthorization] = useState(
    sourceSetupRequested || Boolean(sourceAuthorizationRecovery),
  );
  const [authorizationRoot, setAuthorizationRoot] = useState(sourceAuthorizationRecovery?.selectedPath || sourceSetupPrefill || '');
  const [authorizationCopyStatus, setAuthorizationCopyStatus] = useState('');
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(projects[0]?.id ?? null);
  const [scanMode, setScanMode] = useState<'full' | 'incremental_diff'>('full');
  // Keep the uncontrolled form mounted and never collapse a draft on refresh.
  const [registrationExpanded, setRegistrationExpanded] = useState(
    projects.length === 0 || sourceSetupRequested || Boolean(sourceSetupPrefill) || Boolean(sourceAuthorizationRecovery),
  );
  const projectNameInputRef = useRef<HTMLInputElement>(null);
  const [registrationFailure, setRegistrationFailure] = useState<ProjectRegistrationFailure | null>(null);
  const registrationErrorId = useId();
  const registrationErrorRef = useRef<HTMLParagraphElement>(null);
  const authorizationRootInputRef = useRef<HTMLInputElement>(null);
  const scanFormRef = useRef<HTMLFormElement>(null);
  const projectSelectRef = useRef<HTMLSelectElement>(null);
  const pageSize = 10;
  const visibleProjects = projects.slice((page - 1) * pageSize, page * pageSize);
  const configuredAllowedRoots = authoritativeSourceRoots(sourceBoundary);
  const coreServicesReady = Boolean(health?.db && health.scanner && health.worker);
  const advisorAiAvailability = newScanAdvisorAvailability({
    aiMode: health?.ai.mode ?? null,
    providerReadiness: advisorProviderReadiness,
  });
  const sourceRegistrationSummary = useMemo(
    () => summarizeSourceRegistrations(projects, configuredAllowedRoots),
    [configuredAllowedRoots, projects],
  );
  const registeredSourceReady = sourceBoundary.status === 'ready'
    && configuredAllowedRoots.length > 0
    && sourceRegistrationSummary.insideCount > 0;
  const selectedProject = useMemo(
    () => projects.find((project) => project.id === selectedProjectId) || null,
    [projects, selectedProjectId],
  );
  const selectedSourceAdapter = selectedProject ? projectSourceAdapter(selectedProject.repo_path) : null;
  const selectedSnapshotGuidance = snapshotProjectScanGuidance(selectedSourceAdapter);
  const selectedProjectSourceReady = Boolean(
    selectedProject && mountedProjectIsAuthorized(selectedProject.repo_path, sourceBoundary),
  );
  const selectedSourceStepReady = selectedProject
    ? selectedProjectSourceReady
    : registeredSourceReady;
  const scannerReady = Boolean(preflight?.ready);
  const verificationReason = scannerVerificationDisabledReason(preflight);
  const setupReady = coreServicesReady && selectedSourceStepReady && scannerReady;
  const setupChecklistRef = useRef<HTMLDetailsElement>(null);
  const setupInteractedRef = useRef(false);
  const [setupExpanded, setSetupExpanded] = useState(!setupReady || sourceSetupRequested || Boolean(sourceAuthorizationRecovery));
  const previousSetupReadyRef = useRef(setupReady);
  useEffect(() => {
    if (sourceSetupRequested || sourceAuthorizationRecovery) {
      previousSetupReadyRef.current = setupReady;
      setSetupExpanded(true);
      return;
    }
    if (previousSetupReadyRef.current === setupReady) return;
    previousSetupReadyRef.current = setupReady;
    // Recovery is visible again when current prerequisites are lost. Once the
    // user has entered the checklist, keep their disclosure choice on completion
    // even if a recovery button disappeared when its step became ready.
    if (!setupReady || !setupInteractedRef.current && !setupChecklistRef.current?.contains(document.activeElement)) {
      setSetupExpanded(!setupReady);
    }
  }, [setupReady, sourceAuthorizationRecovery, sourceSetupRequested]);
  const selectedCompleteScanReady = coreServicesReady && selectedProjectSourceReady && scannerReady;
  const blockedToolNames = preflight?.blocked_tools.map((tool) => tool.name) || [];
  const completeScanBlockedReason = !selectedProject
    ? 'Choose a registered project before starting a complete scan.'
    : !coreServicesReady
      ? health
        ? `Restore ${[!health.db ? 'database' : '', !health.scanner ? 'scanner API' : '', !health.worker ? 'worker' : ''].filter(Boolean).join(', ')} before starting a scan.`
        : 'Core service status is unknown. Use Refresh to verify database, scanner API, and worker health.'
    : selectedSnapshotGuidance
      ? selectedSnapshotGuidance
      : sourceBoundary.status === 'loading'
        ? 'Wait for the current read-only source boundary to finish loading.'
        : sourceBoundary.status === 'error'
          ? 'Reload the current read-only source boundary before scanning. No retained or previously reported root is trusted for admission.'
          : !selectedProjectSourceReady
            ? `${selectedProject.name} is outside the current read-only source boundary. Authorize this exact source or choose a project inside an authorized root.`
            : verificationReason
              ? verificationReason
            : preflight?.recommended_action === 'enable_scanner'
              ? 'Enable at least one scanner before starting a complete scan.'
              : blockedToolNames.length
                ? `Prepare the required data or rules for ${blockedToolNames.join(', ')} before starting a complete scan.`
                : 'Wait for scanner readiness to finish before starting a complete scan.';
  const canRunLimited = Boolean(preflight?.ready_tool_ids.length);
  const limitedCoverage = Boolean(
    preflight?.revision && acknowledgedPreflightRevision === preflight.revision,
  );
  useEffect(() => {
    if (projects.length === 0 || sourceSetupRequested || sourceSetupPrefill || sourceAuthorizationRecovery) {
      setRegistrationExpanded(true);
    }
  }, [projects.length, sourceSetupRequested, sourceSetupPrefill, sourceAuthorizationRecovery]);
  useEffect(() => {
    if (!sourceAuthorizationRecovery) return;
    setAuthorizationRoot(sourceAuthorizationRecovery.selectedPath);
    setShowSourceAuthorization(true);
    setAuthorizationCopyStatus('');
  }, [sourceAuthorizationRecovery]);
  useEffect(() => {
    setSelectedProjectId((current) => (
      current != null && projects.some((project) => project.id === current)
        ? current
        : projects[0]?.id ?? null
    ));
  }, [projects]);
  useEffect(() => {
    setAcknowledgedPreflightRevision(null);
  }, [selectedProjectId]);
  const authorizationCommand = useMemo(
    () => sourceAuthorizationCommand(authorizationRoot, sourceBoundary.status === 'ready' ? sourceBoundary.installationId : undefined),
    [authorizationRoot, sourceBoundary],
  );
  const selectedMountedSourceRequiresAuthorization = Boolean(
    selectedProject
      && selectedSourceAdapter === 'mounted_directory'
      && sourceBoundary.status === 'ready'
      && !selectedProjectSourceReady,
  );
  const sourceRequiresAuthorization = sourceBoundary.status === 'ready'
    && (configuredAllowedRoots.length === 0
      || projects.length > 0 && !registeredSourceReady
      || selectedMountedSourceRequiresAuthorization);

  function requestSourceSetup() {
    if (sourceBoundary.status !== 'ready') return;
    setRegistrationExpanded(true);
    if (sourceRequiresAuthorization) setShowSourceAuthorization(true);
    window.requestAnimationFrame(() => {
      const target = sourceRequiresAuthorization ? authorizationRootInputRef.current : projectNameInputRef.current;
      target?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      target?.focus({ preventScroll: true });
    });
  }

  function requestSelectedSourceSetup() {
    if (!selectedProject || selectedSourceAdapter !== 'mounted_directory') return;
    setRegistrationExpanded(true);
    setAuthorizationRoot(selectedProject.repo_path);
    setAuthorizationCopyStatus('');
    setShowSourceAuthorization(true);
    window.requestAnimationFrame(() => {
      authorizationRootInputRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      authorizationRootInputRef.current?.focus({ preventScroll: true });
    });
  }

  function openProject(project: Project) {
    setSelectedProjectId(project.id);
    window.requestAnimationFrame(() => {
      scanFormRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      projectSelectRef.current?.focus({ preventScroll: true });
    });
  }

  function submitSelectedProjectScan(event: FormEvent<HTMLFormElement>) {
    if (!coreServicesReady || !selectedProjectSourceReady) {
      event.preventDefault();
      return;
    }
    onStartScan(event);
  }

  async function copyAuthorizationCommand() {
    if (!authorizationCommand) return;
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(authorizationCommand);
      setAuthorizationCopyStatus('Host command copied. Run it from the Lomo CodeSecurity checkout.');
    } catch {
      setAuthorizationCopyStatus('Automatic copy is unavailable. Select the command and copy it manually.');
    }
  }
  return (
    <>
      <details
        className="band span-2 first-run-checklist"
        ref={setupChecklistRef}
        onFocusCapture={() => { setupInteractedRef.current = true; }}
        aria-labelledby="first-run-checklist-title"
        open={setupExpanded}
        onToggle={(event) => setSetupExpanded(event.currentTarget.open)}
      >
        <summary className="band-head">
          <div>
            <h2 id="first-run-checklist-title">Scan setup</h2>
            <p className="helper-text">{setupReady
              ? 'Scan prerequisites are ready. Expand to review the current checks.'
              : 'Complete these three local setup checks in order. Each status comes from the live control plane; no source contents or credentials are returned here.'}</p>
          </div>
          {setupReady ? <CheckCircle2 className="ok" size={20} aria-label="All scan prerequisites ready" /> : <ListChecks size={20} aria-hidden="true" />}
          <ChevronRight className="setup-disclosure-chevron" size={18} aria-hidden="true" />
        </summary>
        <ol className="first-run-steps" aria-label="First-run setup checklist">
          <li data-complete={coreServicesReady} aria-label="Step 1: Core services">
            <span className="first-run-step-number" aria-hidden="true">1</span>
            <div>
              <strong>Core services</strong>
              <span>
                {coreServicesReady
                  ? 'Database, scanner API, and durable worker are healthy.'
                  : health
                    ? `Restore ${[!health.db ? 'database' : '', !health.scanner ? 'scanner API' : '', !health.worker ? 'worker' : ''].filter(Boolean).join(', ')} before scanning.`
                    : 'Core service status is unknown. Use Refresh to verify database, scanner API, and worker health.'}
              </span>
            </div>
            {coreServicesReady ? (
              <span className="first-run-step-state"><CheckCircle2 size={15} aria-hidden="true" /> Ready</span>
            ) : (
              <button type="button" className="secondary-action" onClick={onOpenSettings}>
                <ServerCog size={15} /> Review core services
              </button>
            )}
          </li>
          <li data-complete={selectedSourceStepReady} aria-label="Step 2: Source authorization and registration">
            <span className="first-run-step-number" aria-hidden="true">2</span>
            <div>
              <strong>Authorize and register source</strong>
              <span>
                {selectedSnapshotGuidance
                  ? selectedSnapshotGuidance
                  : sourceBoundary.status === 'loading'
                    ? 'Checking the configured read-only source boundary.'
                    : sourceBoundary.status === 'error'
                      ? sourceBoundary.reason
                      : selectedProjectSourceReady && selectedProject
                        ? `${selectedProject.name} is inside the current read-only source boundary. ${sourceRegistrationSummary.message}`
                        : configuredAllowedRoots.length
                          ? `${selectedProject ? `${selectedProject.name} is outside the current boundary. ` : ''}${sourceRegistrationSummary.message} Authorized root${configuredAllowedRoots.length === 1 ? '' : 's'}: ${configuredAllowedRoots.join(', ')}.`
                          : 'Authorize one narrow read-only source root, then register its repository.'}
              </span>
            </div>
            {selectedSourceStepReady ? (
              <span className="first-run-step-state"><CheckCircle2 size={15} aria-hidden="true" /> Ready</span>
            ) : selectedSnapshotGuidance ? (
              <span className="first-run-step-state first-run-step-pending"><Code2 size={15} aria-hidden="true" /> VS Code required</span>
            ) : sourceBoundary.status === 'loading' ? (
              <span className="first-run-step-state first-run-step-pending"><RefreshCw size={15} aria-hidden="true" /> Checking</span>
            ) : sourceBoundary.status === 'error' ? (
              <button type="button" className="secondary-action" onClick={onReloadSourceBoundary}>
                <RefreshCw size={15} /> Reload source boundary
              </button>
            ) : (
              <button
                type="button"
                className="secondary-action"
                onClick={selectedMountedSourceRequiresAuthorization ? requestSelectedSourceSetup : requestSourceSetup}
              >
                <Shield size={15} /> {selectedMountedSourceRequiresAuthorization
                  ? 'Authorize selected source'
                  : sourceRequiresAuthorization
                    ? 'Authorize source'
                    : 'Register source'}
              </button>
            )}
          </li>
          <li data-complete={scannerReady} aria-label="Step 3: Scanner data and readiness">
            <span className="first-run-step-number" aria-hidden="true">3</span>
            <div>
              <strong>Prepare scanner data</strong>
              <span>
                {scannerReady
                  ? `${preflight?.ready_tool_ids.length || 0} enabled scanners have verified runtime data and rules.`
                  : verificationReason
                    ? verificationReason
                  : blockedToolNames.length
                    ? `Prepare ${blockedToolNames.join(', ')}${preflight?.required_component_ids.length ? ` (${preflight.required_component_ids.join(', ')})` : ''}.`
                    : 'Verify at least one enabled scanner and all of its required data and rules.'}
              </span>
            </div>
            {scannerReady ? (
              <span className="first-run-step-state"><CheckCircle2 size={15} aria-hidden="true" /> Ready</span>
            ) : (
              <button type="button" className="secondary-action" onClick={onOpenTools}>
                <Wrench size={15} /> {verificationReason ? 'View verification' : 'Prepare scanners'}
              </button>
            )}
          </li>
        </ol>
      </details>

      <details
        className="band span-2 project-registration"
        open={registrationExpanded}
        onToggle={(event) => setRegistrationExpanded(event.currentTarget.open)}
      >
        <summary className="band-head">
          <h2>Register Project</h2>
          <ChevronRight className="setup-disclosure-chevron" size={18} aria-hidden="true" />
        </summary>
        <p className="helper-text">Register a checkout already authorized for scanner access. This adds a scan target; it does not add a folder to your editor workspace or start a scan. To grant access to another path, use Authorize another source root. <InfoTip text="A registered project selects an exact authorized directory. Source authorization and editor workspace membership are separate." /></p>
        <form className="form" onSubmit={async (event) => {
          const form = event.currentTarget;
          let retainFocus = form.contains(document.activeElement);
          const moved = () => { retainFocus = false; };
          // A late response must not pull the user back after they navigate.
          document.addEventListener('pointerdown', moved, true);
          document.addEventListener('keydown', moved, true);
          setRegistrationFailure(null);
          try {
            const failure = await onCreateProject(event);
            if (!failure || !form.isConnected || form.closest('[inert]')) return;
            flushSync(() => {
              setRegistrationExpanded(true);
              setRegistrationFailure(failure);
            });
            if (retainFocus) {
              registrationErrorRef.current?.focus({ preventScroll: true });
              registrationErrorRef.current?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
            }
          } finally {
            document.removeEventListener('pointerdown', moved, true);
            document.removeEventListener('keydown', moved, true);
          }
        }}>
          <label>
            Name
            <input ref={projectNameInputRef} name="name" placeholder="my-service" required />
          </label>
          <label>
            Repository Path
            <input name="repo_path" placeholder={configuredAllowedRoots[0] ? `${configuredAllowedRoots[0]}/my-service` : '/Users/me/dev/my-service'} required
              aria-invalid={registrationFailure?.invalidPath || undefined}
              aria-describedby={registrationFailure ? registrationErrorId : undefined} />
          </label>
          {registrationFailure ? (
            <p id={registrationErrorId} ref={registrationErrorRef} role="alert" tabIndex={-1} className="helper-text">
              {registrationFailure.message}
            </p>
          ) : null}
          <label>
            Remote URL
            <input name="remote_url" placeholder="git@github.com:org/repo.git" />
          </label>
          <label>
            Default Branch
            <input name="default_branch" defaultValue="main" />
          </label>
          <button disabled={busy}>
            <Plus size={16} /> Add Project
          </button>
        </form>
        <button
          type="button"
          className="secondary-action source-authorization-toggle"
          aria-expanded={showSourceAuthorization}
          aria-controls="source-authorization-setup"
          onClick={() => setShowSourceAuthorization((current) => !current)}
        >
          <Shield size={15} /> {showSourceAuthorization ? 'Hide source setup' : 'Authorize another source root'}
        </button>
        {showSourceAuthorization ? (
          <div className="source-authorization" id="source-authorization-setup">
            <div>
              <strong>Authorize one narrow read-only source root</strong>
              <p>
                Source mounts are a host privilege, so the containerized UI cannot apply this change itself.
                The reviewed host command adds this root while preserving other authorizations and recreates only scanner, API,
                and worker from installed images. Database and scanner-cache volumes are preserved; no image is rebuilt.
              </p>
            </div>
            {sourceSetupPrefill && !sourceAuthorizationRecovery ? (
              <p className="source-boundary-copy" role="status">
                Suggested source path received from the editor. Review it before copying the host command; no source was authorized automatically.
              </p>
            ) : null}
            {sourceAuthorizationRecovery?.allowedRoots.length ? (
              <p className="source-boundary-copy">
                The rejected registration response reported {sourceAuthorizationRecovery.allowedRoots.length === 1 ? 'this root' : 'these roots'} as guidance:{' '}
                {sourceAuthorizationRecovery.allowedRoots.join(', ')}. This retained response is never used for scan admission; only a fresh successful configuration load is authoritative.
              </p>
            ) : null}
            <label>
              Exact source root
              <input
                ref={authorizationRootInputRef}
                aria-describedby="source-authorization-help"
                value={authorizationRoot}
                onChange={(event) => {
                  setAuthorizationRoot(event.currentTarget.value);
                  setAuthorizationCopyStatus('');
                }}
                placeholder="/Users/me/dev/team"
              />
            </label>
            <p className="helper-text" id="source-authorization-help">
              Choose an existing repository or narrow development tree. Broad roots such as /, /Users, /home,
              /Volumes, or your whole home directory are rejected again by the host verifier. Paths containing
              Compose interpolation or quoting characters are also refused rather than serialized ambiguously.
              {' '}Run the command with this installation's exact <code>STATE_DIR</code> if you use custom runtime state.
              Its installation guard refuses a different or missing runtime before changing anything; the browser does not know your private state path.
            </p>
            {authorizationCommand ? (
              <div className="source-authorization-command">
                <textarea aria-label="Source authorization host command" readOnly rows={3} value={authorizationCommand} />
                <button type="button" className="secondary-action" onClick={() => void copyAuthorizationCommand()}>
                  <Copy size={15} /> Copy host command
                </button>
              </div>
            ) : (
              <div className="inline-warning" role="status">
                Enter one narrow absolute POSIX path and reload the current installation configuration. No command is offered for an unsafe root or unknown installation.
              </div>
            )}
            {authorizationCopyStatus ? <p className="status-note" role="status">{authorizationCopyStatus}</p> : null}
          </div>
        ) : null}
      </details>

      {contentStage >= 1 && projects.length > 0 ? (
        <div className="band project-scan">
          <div className="band-head">
            <h2>{selectedCompleteScanReady ? 'Start Scan' : 'Scan Setup Required'} <InfoTip text="Queues a scanner job. Enabled tools run inside the scanner container; redacted findings go to Postgres and only publishable derived artifacts such as SBOMs are retained." /></h2>
            <Play size={18} />
          </div>
          <p className="helper-text">Full scans inspect the registered path. Incremental requests retain their refs but currently run full repository coverage so every enabled scanner sees the same source view.</p>
          <div className={`scan-readiness ${selectedCompleteScanReady ? 'scan-readiness-ready' : 'scan-readiness-blocked'}`}>
            {selectedCompleteScanReady ? <CheckCircle2 size={18} aria-hidden="true" /> : <AlertTriangle size={18} aria-hidden="true" />}
            <div role="status">
              <strong>{selectedCompleteScanReady ? 'Ready for a complete scan' : 'Complete scan setup required'}</strong>
              <span>
                {selectedCompleteScanReady
                  ? `${preflight?.ready_tool_ids.length || 0} enabled scanners are ready${preflight?.active_generation ? ' with a verified offline data generation' : ''}.`
                  : !selectedProjectSourceReady
                    ? completeScanBlockedReason
                    : verificationReason
                      ? verificationReason
                    : preflight?.recommended_action === 'enable_scanner'
                      ? 'Enable at least one scanner before starting a scan.'
                      : blockedToolNames.length
                        ? `Blocked: ${blockedToolNames.join(', ')}. Prepare their required data or rules before scanning.`
                        : 'Checking scanner readiness before admitting a complete scan.'}
              </span>
            </div>
            {selectedProjectSourceReady && !preflight?.ready ? (
              <button type="button" className="secondary-action" onClick={onOpenTools}>
                <Wrench size={15} /> {verificationReason ? 'View verification' : 'Prepare scanners'}
              </button>
            ) : null}
          </div>
          {coreServicesReady && selectedProjectSourceReady && !preflight?.ready && canRunLimited ? (
            <div className="limited-coverage-control" role="group" aria-labelledby="advanced-limited-coverage-title">
              <div className="limited-coverage-heading">
                <strong id="advanced-limited-coverage-title">Advanced choice: limited coverage</strong>
                <span>Run only scanners whose required binaries, databases, and rules are ready. Omitted evidence keeps the deterministic gate incomplete.</span>
              </div>
              {!limitedCoverage ? (
                <button
                  type="button"
                  className="secondary-action"
                  onClick={async () => {
                    const omitted = blockedToolNames.length ? blockedToolNames.join(', ') : 'one or more enabled scanners';
                    if (await confirmAction({
                      title: 'Run a limited-coverage scan?',
                      message: `Advanced limited-coverage scan: run only the ready scanners and omit ${omitted}? This scan will remain partial and its deterministic gate will be incomplete.`,
                      confirmLabel: 'Use limited coverage',
                      cancelLabel: 'Keep complete coverage',
                      tone: 'warning',
                    })) {
                      setAcknowledgedPreflightRevision(preflight?.revision || null);
                    }
                  }}
                >
                  Review Advanced Limited Scan
                </button>
              ) : (
                <div className="inline-warning" role="status">
                  <strong>Advanced limited coverage acknowledged.</strong>{' '}
                  Only {preflight?.ready_tool_ids.join(', ')} will run. {blockedToolNames.length ? `${blockedToolNames.join(', ')} will be omitted. ` : ''}The deterministic gate cannot pass.
                  <button type="button" className="text-action" onClick={() => setAcknowledgedPreflightRevision(null)}>Use complete coverage</button>
                </div>
              )}
            </div>
          ) : null}
          {coreServicesReady && selectedProject ? (
          <form className="form" onSubmit={submitSelectedProjectScan} ref={scanFormRef}>
            <input type="hidden" name="coverage" value={limitedCoverage ? 'limited' : 'complete'} />
            <input type="hidden" name="acknowledge_limited_coverage" value={limitedCoverage ? 'true' : 'false'} />
            <label>
              Project
              <select
                ref={projectSelectRef}
                name="project_id"
                required
                value={selectedProjectId ?? ''}
                onChange={(event) => setSelectedProjectId(Number(event.currentTarget.value))}
              >
                {projects.map((project) => (
                  <option value={project.id} key={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </label>
            {selectedProject ? (
              <p className="selected-project-status" role="status">
                Current project: <strong>{selectedProject.name}</strong>. {selectedSnapshotGuidance
                  ? selectedSnapshotGuidance
                  : selectedProjectSourceReady
                    ? 'Its path is inside the current read-only source boundary.'
                    : sourceBoundary.status === 'loading'
                      ? 'Checking its path against the current read-only source boundary.'
                      : sourceBoundary.status === 'error'
                        ? 'The current source boundary is unavailable, so scanning remains disabled.'
                        : 'Its retained registration is outside the current read-only source boundary, so scanning remains disabled.'}
              </p>
            ) : null}
            {selectedProject && selectedSnapshotGuidance ? (
              <div className="inline-warning selected-source-boundary-warning" role="status">
                <strong>{selectedSourceAdapter === 'git_commit_snapshot' ? 'Check outgoing Git commits from VS Code.' : 'Refresh this native Windows snapshot from VS Code.'}</strong>{' '}
                <code>{selectedProject.repo_path}</code> is a reserved local snapshot identity, not a host directory. {selectedSnapshotGuidance}
              </div>
            ) : selectedProject && sourceBoundary.status === 'error' ? (
              <div className="inline-warning selected-source-boundary-warning" role="status">
                <strong>Source boundary unavailable.</strong> No retained registration response or previously loaded root is trusted for scan admission.
                <button type="button" className="text-action" onClick={onReloadSourceBoundary}>Reload source boundary</button>
              </div>
            ) : selectedProject && sourceBoundary.status === 'ready' && !selectedProjectSourceReady ? (
              <div className="inline-warning selected-source-boundary-warning" role="status">
                <strong>Selected project is not authorized for scanning.</strong>{' '}
                <code>{selectedProject.repo_path}</code> remains visible as retained history, but CodeSecurity will not broaden the source mount or scan it silently.
                <button type="button" className="text-action" onClick={requestSelectedSourceSetup}>Authorize this source</button>
              </div>
            ) : null}
            {!selectedSnapshotGuidance ? <>
            <label>
              Mode
              <select
                name="mode"
                value={scanMode}
                onChange={(event) => setScanMode(event.currentTarget.value === 'incremental_diff' ? 'incremental_diff' : 'full')}
              >
                <option value="full">Full</option>
                <option value="incremental_diff">Incremental (currently full scan)</option>
              </select>
            </label>
            {scanMode === 'incremental_diff' ? (
              <>
                <label>
                  Base Ref
                  <input name="base_ref" placeholder="origin/main" />
                </label>
                <label>
                  Head Ref
                  <input name="head_ref" placeholder="HEAD" />
                </label>
                <p className="scan-ref-guidance" role="status">
                  These refs are retained in the scan receipt. This release still runs full repository coverage and labels that fallback explicitly.
                </p>
              </>
            ) : (
              <p className="scan-ref-guidance" role="status">
                Full mode scans the current registered checkout. Base and head refs are not requested or sent.
              </p>
            )}
            <label className="check">
              <input
                aria-describedby={!advisorAiAvailability.enabled ? 'scan-ai-advisor-disabled-reason' : undefined}
                disabled={!advisorAiAvailability.enabled}
                name="use_ai"
                type="checkbox"
              />
              <span>AI advisor</span>
            </label>
            {!advisorAiAvailability.enabled ? (
              <p className="inline-warning" id="scan-ai-advisor-disabled-reason" role="status">
                <strong>AI Advisor is unavailable.</strong> {advisorAiAvailability.reason}{' '}
                <button type="button" className="text-action" onClick={onOpenSettings}>Review Settings</button>
              </p>
            ) : null}
            </> : null}
            {!limitedCoverage && !selectedCompleteScanReady ? (
              <div className="inline-warning" id="complete-scan-disabled-reason" role="status">
                <strong>Complete Scan is disabled.</strong> {completeScanBlockedReason}{' '}
                {sourceBoundary.status === 'error' ? (
                  <button type="button" className="text-action" onClick={onReloadSourceBoundary}>Reload source boundary</button>
                ) : !coreServicesReady ? (
                  <button type="button" className="text-action" onClick={onOpenSettings}>Review core services</button>
                ) : selectedSourceAdapter === 'mounted_directory' && sourceBoundary.status === 'ready' && !selectedProjectSourceReady ? (
                  <button type="button" className="text-action" onClick={requestSelectedSourceSetup}>Authorize this source</button>
                ) : selectedSourceAdapter === 'mounted_directory' && selectedProjectSourceReady && !scannerReady ? (
                  <button type="button" className="text-action" onClick={onOpenTools}>Prepare scanners</button>
                ) : null}
              </div>
            ) : null}
            <button
              aria-describedby={!limitedCoverage && !selectedCompleteScanReady ? 'complete-scan-disabled-reason' : undefined}
              disabled={busy || !selectedProjectSourceReady || (!limitedCoverage && !selectedCompleteScanReady)}
              title={!selectedProjectSourceReady || !limitedCoverage && !selectedCompleteScanReady ? completeScanBlockedReason : undefined}
            >
              <Play size={16} /> {limitedCoverage ? 'Run Advanced Limited Scan' : 'Scan'}
            </button>
          </form>
          ) : null}
          {selectedProject ? <ProjectGate project={selectedProject} disabled={busy || !health?.db} onSaved={onGateSaved} /> : null}
        </div>
      ) : null}

      {contentStage >= 2 ? (
        <div className={`band project-registered${projects.length ? '' : ' span-2'}`}>
          <div className="band-head">
            <h2>Registered <InfoTip text="Deleting a project removes its scans, redacted findings, jobs, and publishable derived artifacts." /></h2>
            <Pager page={page} total={projects.length} pageSize={pageSize} setPage={setPage} />
          </div>
          <div className="project-list">
            {visibleProjects.map((project) => (
              <div
                className={`project-row${project.id === selectedProjectId ? ' is-selected' : ''}`}
                data-project-selected={project.id === selectedProjectId ? 'true' : 'false'}
                key={project.id}
              >
                <Code2 size={18} />
                <div>
                  <strong>{project.name}</strong>
                  <span>{project.repo_path}</span>
                  {projectSourceAdapter(project.repo_path) === 'git_commit_snapshot' ? <span>Immutable Git snapshots · Check Outgoing Commits in VS Code</span> : null}
                </div>
                <small>{project.default_branch}</small>
                <button type="button" onClick={() => openProject(project)} disabled={busy}>
                  Open
                </button>
                <button className="icon-button danger" onClick={() => onDeleteProject(project)} disabled={busy} title="Delete project and scan data">
                  <Trash2 size={15} />
                </button>
              </div>
            ))}
            {!projects.length ? <div className="empty-state">No projects registered yet. Add a local repository path above.</div> : null}
          </div>
        </div>
      ) : null}
    </>
  );
});

function Projects({
  surface,
  advisorProviderReadiness,
  projects,
  busy,
  health,
  onCreateProject,
  onStartScan,
  onDeleteProject,
  onGateSaved,
  onOpenSettings,
  onOpenTools,
  onReloadSourceBoundary,
  preflight,
  sourceBoundary,
  sourceAuthorizationRecovery,
  sourceSetupPrefill,
  sourceSetupRequested,
}: {
  surface: RouteSurfaceAttributes;
  advisorProviderReadiness: AdvisorProviderReadiness;
  projects: Project[];
  busy: boolean;
  health: Health | null;
  onCreateProject: (event: FormEvent<HTMLFormElement>) => Promise<ProjectRegistrationFailure | undefined>;
  onStartScan: (event: FormEvent<HTMLFormElement>) => void;
  onDeleteProject: (project: Project) => void;
  onGateSaved: () => Promise<void>;
  onOpenSettings: () => void;
  onOpenTools: () => void;
  onReloadSourceBoundary: () => void;
  preflight: ScannerPreflight | null;
  sourceBoundary: SourceBoundaryLoadState;
  sourceAuthorizationRecovery: SourceAuthorizationRecovery | null;
  sourceSetupPrefill: string | null;
  sourceSetupRequested: boolean;
}) {
  const [page, setPage] = useState(1);
  const { contentStage, ready } = useProjectsPaintedStage();
  const stableCreateProject = useEventCallback(onCreateProject);
  const stableStartScan = useEventCallback(onStartScan);
  const stableDeleteProject = useEventCallback(onDeleteProject);
  const blocked = surface.inert || !ready;

  useEffect(() => {
    const lastPage = Math.max(1, Math.ceil(projects.length / 10));
    setPage((current) => Math.min(current, lastPage));
  }, [projects.length]);

  return (
    <section
      {...surface}
      aria-busy={ready ? undefined : true}
      aria-hidden={blocked ? true : undefined}
      className="split"
      data-projects-render-stage={ready ? 'ready' : contentStage === 0 ? 'register' : contentStage === 1 ? 'scan' : 'registered'}
      inert={blocked}
    >
      <ProjectsBody
        advisorProviderReadiness={advisorProviderReadiness}
        busy={busy}
        contentStage={contentStage}
        health={health}
        onCreateProject={stableCreateProject}
        onDeleteProject={stableDeleteProject}
        onGateSaved={onGateSaved}
        onOpenSettings={onOpenSettings}
        onOpenTools={onOpenTools}
        onReloadSourceBoundary={onReloadSourceBoundary}
        onStartScan={stableStartScan}
        page={page}
        preflight={preflight}
        projects={projects}
        setPage={setPage}
        sourceBoundary={sourceBoundary}
        sourceAuthorizationRecovery={sourceAuthorizationRecovery}
        sourceSetupPrefill={sourceSetupPrefill}
        sourceSetupRequested={sourceSetupRequested}
      />
    </section>
  );
}

type JobRowProps = {
  busy: boolean;
  job: Job;
  onCancel: (job: Job) => void;
  onOpenFindings: (scanId: number, findingId?: number | null) => void;
  onRetry: (job: Job) => void;
  onReconcileCache?: (job: Job) => void;
  cacheRecoveryBusy?: boolean;
  cacheOutcomeJob?: Pick<Job, 'id' | 'status'> | null;
  onOpenJob?: (jobId: number) => void;
  scan: Scan | null;
  targeted: boolean;
};

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

function jobTimestampState(job: Job, value: string | null | undefined) {
  if (!value) return null;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return null;
  return {
    stale: activeWorkStatuses.has(job.status) && Date.now() - timestamp > 45_000,
    value,
  };
}

function jobHeartbeatState(job: Job) {
  return jobTimestampState(job, job.heartbeat_at);
}

function jobActivityVerb(stage: string | undefined): string {
  return {
    downloading: 'Downloading',
    retaining: 'Retaining',
    validating_active: 'Validating active',
    validating_generation: 'Validating candidate',
    validating_source: 'Validating source',
    scanner: 'Scanning with',
  }[stage || ''] || 'Preparing';
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

function sameJobRow(left: JobRowProps, right: JobRowProps) {
  const previous = left.job;
  const next = right.job;
  return (
    left.busy === right.busy
    && left.onCancel === right.onCancel
    && left.onOpenFindings === right.onOpenFindings
    && left.onRetry === right.onRetry
    && left.onReconcileCache === right.onReconcileCache
    && left.cacheRecoveryBusy === right.cacheRecoveryBusy
    && left.cacheOutcomeJob?.id === right.cacheOutcomeJob?.id
    && left.cacheOutcomeJob?.status === right.cacheOutcomeJob?.status
    && left.onOpenJob === right.onOpenJob
    && left.scan?.id === right.scan?.id
    && left.targeted === right.targeted
    && previous.id === next.id
    && previous.kind === next.kind
    && previous.original_job_id === next.original_job_id
    && previous.title === next.title
    && previous.status === next.status
    && previous.stage === next.stage
    && previous.detail === next.detail
    && previous.progress === next.progress
    && previous.scan_id === next.scan_id
    && previous.finding_id === next.finding_id
    && previous.finding_display_id === next.finding_display_id
    && previous.finding_scan_number === next.finding_scan_number
    && previous.finding_rule_id === next.finding_rule_id
    && previous.error === next.error
    && previous.error_code === next.error_code
    && previous.error_detail === next.error_detail
    && previous.attempt === next.attempt
    && previous.max_attempts === next.max_attempts
    && previous.revision === next.revision
    && previous.cancel_requested_at === next.cancel_requested_at
    && previous.can_cancel === next.can_cancel
    && previous.can_retry === next.can_retry
    && previous.retry_blocked_reason === next.retry_blocked_reason
    && previous.created_at === next.created_at
    && previous.started_at === next.started_at
    && previous.completed_at === next.completed_at
    && previous.updated_at === next.updated_at
    && previous.heartbeat_at === next.heartbeat_at
    && JSON.stringify(previous.activity) === JSON.stringify(next.activity)
  );
}

export const JobRow = memo(function JobRow({ busy, cacheRecoveryBusy, cacheOutcomeJob, job, onCancel, onOpenFindings, onOpenJob, onReconcileCache, onRetry, scan, targeted }: JobRowProps) {
  const progress = Math.max(0, Math.min(job.progress ?? (job.status === 'completed' ? 100 : 0), 100));
  const lifecycleJob = isScannerLifecycleJob(job);
  const active = activeWorkStatuses.has(job.status);
  const lifecycleActive = lifecycleJob && active;
  const scannerActive = job.kind === 'scan' && job.stage === 'scanner' && active;
  const indeterminate = lifecycleActive || scannerActive;
  const label = jobFindingLabel(job);
  const jobTitle = job.kind === 'advisor' && label ? `Advisor triage for ${label}` : job.title;
  const canCancel = canCancelJob(job);
  const canRetry = canRetryJob(job);
  const outcomeGuidance = jobCacheOutcomeGuidance(job, cacheOutcomeJob?.status);
  const canReconcile = Boolean(onReconcileCache && canReconcileScannerCacheJob(job)
    && !cacheOutcomeJob);
  const slowJobGuidance = canCancel
    ? 'Keep waiting, or cancel the job if you no longer need its result.'
    : job.status === 'cancelling'
      ? 'Cancellation is already in progress; the terminal result will appear here.'
      : 'Keep waiting; cancellation is unavailable during this phase.';
  const failureDetail = job.error_detail || job.error;
  const cancellationCopy = jobCancellationCopy(job);
  const jobDetail = job.status === 'cancelling'
    ? cancellationCopy.pending
    : job.status === 'cancelled'
      ? cancellationCopy.completed
      : job.detail;
  const recordedActivity = normalizedJobActivity(job);
  const waitingGuidance = jobWaitingGuidance(job);
  const executing = active && !waitingGuidance;
  const activity = executing ? recordedActivity : null;
  const elapsed = useLiveJobElapsed(job.started_at, active);
  const heartbeat = executing
    ? jobHeartbeatState(job)
    : null;
  const meaningfulActivityAt = lifecycleJob
    ? job.activity?.updated_at || job.updated_at
    : job.updated_at;
  const activityTimestamp = executing
    ? jobTimestampState(job, meaningfulActivityAt)
    : null;
  const activityName = lifecycleJob ? 'updater activity' : scannerActive ? 'scanner state change' : 'job activity';
  const byteProgress = activity?.bytes_completed != null
    ? `${formatBytes(activity.bytes_completed)}${activity.bytes_total != null ? ` of ${formatBytes(activity.bytes_total)}` : ''}`
    : null;
  return (
    <article
      aria-current={targeted ? 'true' : undefined}
      aria-label={`Job #${job.id}: ${jobTitle}`}
      className={`job-row job-row-${job.status}${targeted ? ' job-row-targeted' : ''}`}
      data-job-id={job.id}
      tabIndex={targeted ? -1 : undefined}
    >
      <div className="job-status-cell">
        <StatusPill value={job.status} label={jobStatusLabel(job.status)} />
      </div>
      <div className="job-main">
        <div>
          <div className="job-title-line">
            <strong>{jobTitle}</strong>
            <span>job #{job.id}</span>
          </div>
          <span className="job-meta">
            {jobKindLabel(job.kind)} · phase {jobStageLabel(job.stage)}
            {job.attempt !== undefined && job.max_attempts !== undefined ? ` · attempt ${job.attempt}/${job.max_attempts}` : ''}
            {job.started_at ? ` · First started ${formatTime(job.started_at)}` : ''}
            {elapsed ? <span className="job-elapsed"> · Since first start {elapsed}</span> : null}
            {' · '}updated {formatTime(job.updated_at)}
          </span>
          {jobRetryTimingNote(job) ? <p className="helper-text">{jobRetryTimingNote(job)}</p> : null}
          {label ? (
            <small className="job-ref" title={`Scan-local finding label. Internal database ID #${job.finding_id}${job.finding_rule_id ? `, rule ${job.finding_rule_id}` : ''}.`}>
              {label}
              {job.finding_rule_id ? <span>{job.finding_rule_id}</span> : null}
            </small>
          ) : null}
          {jobDetail ? <p>{jobDetail}</p> : null}
          {waitingGuidance ? <p className="helper-text" role="status">{waitingGuidance}</p> : null}
          {activity ? (
            <div className="job-activity" role="status">
              <strong>{jobActivityVerb(job.stage)} {activity.component_id}</strong>
              <span>
                Current component {activity.component_index} of {activity.component_total}
                {byteProgress ? ` · ${byteProgress}` : ''}
                {' · '}last {activityName} {formatTime(activity.updated_at)}
              </span>
            </div>
          ) : activityTimestamp ? (
            <div className="job-activity" role="status">
              <strong>Phase {jobStageLabel(job.stage || 'running')}</strong>
              <span>last {activityName} {formatTime(activityTimestamp.value)}</span>
            </div>
          ) : null}
          {heartbeat ? (
            <small className={`job-heartbeat${heartbeat.stale ? ' job-heartbeat-stale' : ''}`}>
              Worker heartbeat {heartbeat.stale ? 'stale' : 'active'} · last received {formatTime(heartbeat.value)}
            </small>
          ) : null}
          {activityTimestamp?.stale && heartbeat && !heartbeat.stale ? (
            <div className="job-slow-status" role="status">
              Worker heartbeat is active. No {activityName} has been reported for more than 45 seconds.
              {' '}This can be normal during a long-running step. {slowJobGuidance}
            </div>
          ) : activityTimestamp?.stale ? (
            <div className="inline-warning job-stale-warning" role="alert">
              No {activityName} or fresh worker heartbeat has been reported for more than 45 seconds.
              {' '}The job remains safely recorded. Check worker health before retrying or cancelling it.
            </div>
          ) : !activityTimestamp && heartbeat?.stale ? (
            <div className="inline-warning job-stale-warning" role="alert">
              No fresh worker heartbeat has been reported for more than 45 seconds. The job remains safely recorded. Check worker health before retrying or cancelling it.
            </div>
          ) : null}
          {failureDetail ? <p className="error-text">{job.error_code ? `${job.error_code}: ` : ''}{failureDetail}</p> : null}
          {jobRetryGuidance(job) ? <p className="inline-warning">{jobRetryGuidance(job)}</p> : null}
          {outcomeGuidance ? <p className={job.kind === 'scanner_cache_reconcile' && job.status !== 'failed' ? 'helper-text' : 'inline-warning'} id={`job-${job.id}-cache-outcome`}>{outcomeGuidance}</p> : null}
        </div>
      </div>
      <div className="job-side-panel">
        <div className="progress-label">
          <span>{lifecycleJob || indeterminate ? 'Operation' : 'Progress'}</span>
          <strong>{indeterminate ? jobStatusLabel(job.status) : `${progress}%`}</strong>
        </div>
        {indeterminate ? (
          <div
            className="progress-wrap progress-wrap-indeterminate"
            role="progressbar"
            aria-label={`Job #${job.id} activity`}
            aria-valuetext={`In progress: ${jobStageLabel(job.stage || job.status)}`}
            title="Progress is indeterminate; current stage and activity are shown beside this indicator."
          >
            <i />
          </div>
        ) : lifecycleJob && job.status !== 'completed' ? null : (
          <div
            className="progress-wrap"
            role="progressbar"
            aria-label={`Job #${job.id} progress`}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progress}
            title={`${progress}%`}
          >
            <i style={{ width: `${progress}%` }} />
          </div>
        )}
        <div className="job-actions">
          {cacheOutcomeJob && onOpenJob ? (
            <button type="button" className="secondary-action job-cache-outcome-action" onClick={() => onOpenJob(cacheOutcomeJob.id)}>
              <FileSearch size={15} /> View outcome check #{cacheOutcomeJob.id}
            </button>
          ) : null}
          {job.kind === 'scanner_cache_reconcile' && job.original_job_id && onOpenJob ? (
            <button type="button" className="secondary-action job-cache-outcome-action" onClick={() => onOpenJob(job.original_job_id!)}>
              <ListChecks size={15} /> Preparation #{job.original_job_id}
            </button>
          ) : null}
          {canReconcile ? (
            <button type="button" className="secondary-action job-cache-outcome-action" disabled={busy || cacheRecoveryBusy}
              aria-describedby={`job-${job.id}-cache-outcome`}
              title={cacheRecoveryBusy ? 'Wait for the active cache operation to finish before checking the outcome.' : 'Check cache outcome without downloading, activating, rolling back or pruning data; the failed preparation is preserved.'}
              onClick={() => onReconcileCache?.(job)}>
              <FileSearch size={15} /> Check cache outcome
            </button>
          ) : null}
          {canRetry ? (
            <button className="secondary-action" onClick={() => onRetry(job)} disabled={busy}>
              <RefreshCw size={15} /> Retry
            </button>
          ) : null}
          {canCancel ? (
            <button className="secondary-action" onClick={() => onCancel(job)} disabled={busy}>
              <XCircle size={15} /> Cancel
            </button>
          ) : null}
          {scan ? (
            <button className="secondary-action" onClick={() => onOpenFindings(scan.id)}>
              <FileSearch size={15} /> Scan #{scan.id}
            </button>
          ) : null}
          {scan && job.finding_scan_number ? (
            <button className="secondary-action" onClick={() => onOpenFindings(scan.id, job.finding_scan_number)}>
              <Target size={15} /> {label ? `Open ${label}` : `Finding #${job.finding_id}`}
            </button>
          ) : null}
        </div>
      </div>
    </article>
  );
}, sameJobRow);

function durableJobHandoffCopy(
  handoff: JobHandoff,
  present: boolean,
  hiddenByFilters: boolean,
  visible: boolean,
) {
  if (handoff.loading) {
    return {
      title: `Loading exact durable job #${handoff.id}`,
      detail: 'Recent history remains visible while CodeSecurity resolves the named job.',
    };
  }
  if (hiddenByFilters) {
    return {
      title: `Exact durable job #${handoff.id} is hidden by current filters`,
      detail: handoff.error
        ? `The last exact revision is loaded but hidden, and CodeSecurity could not refresh it: ${handoff.error}`
        : 'The current search, status, or kind filter excludes the selected job. Reset filters to show and focus it again.',
    };
  }
  if (handoff.error && present) {
    return {
      title: visible
        ? `Showing last loaded revision for durable job #${handoff.id}`
        : `Preparing last loaded revision for durable job #${handoff.id}`,
      detail: `The last exact revision remains loaded, but CodeSecurity could not refresh it: ${handoff.error}`,
    };
  }
  if (handoff.error) {
    return {
      title: `Durable job #${handoff.id} is unavailable`,
      detail: `CodeSecurity could not load this exact job: ${handoff.error} Recent history is not being presented as a substitute.`,
    };
  }
  if (visible) {
    return {
      title: `Showing exact durable job #${handoff.id}`,
      detail: 'Filters were reset for this handoff. This row may be older than the bounded recent-job window.',
    };
  }
  return {
    title: `Preparing exact durable job #${handoff.id}`,
    detail: 'The exact job is loaded and will be shown after the current result set finishes rendering.',
  };
}

function Jobs({
  surface,
  jobs,
  scans,
  health,
  busy,
  cancelJob,
  retryJob,
  reconcileScannerCacheJob,
  openJob,
  openFindings,
  jobsAvailability,
  jobHandoff,
}: {
  surface: RouteSurfaceAttributes;
  jobs: Job[];
  scans: Scan[];
  health: Health | null;
  busy: boolean;
  cancelJob: (job: Job) => void;
  retryJob: (job: Job) => void;
  reconcileScannerCacheJob: (job: Job) => void;
  openJob: (jobId: number) => void;
  openFindings: (scanId: number, findingId?: number | null) => void;
  jobsAvailability: 'loading' | 'ready' | 'unavailable';
  jobHandoff: JobHandoff | null;
}) {
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [kindFilter, setKindFilter] = useState('all');
  const jobListRef = useRef<HTMLDivElement>(null);
  const resetHandoffGenerationRef = useRef(0);
  const focusedHandoffGenerationRef = useRef(0);
  const resetJobFilters = () => {
    focusedHandoffGenerationRef.current = 0;
    setQuery('');
    setStatusFilter('all');
    setKindFilter('all');
  };
  useLayoutEffect(() => {
    if (!jobHandoff || resetHandoffGenerationRef.current === jobHandoff.generation) return;
    resetHandoffGenerationRef.current = jobHandoff.generation;
    resetJobFilters();
  }, [jobHandoff]);
  const counts = useMemo(() => ({
    advisor: jobs.filter((job) => job.kind === 'advisor').length,
    completed: jobs.filter((job) => job.status === 'completed').length,
    failed: jobs.filter((job) => job.status === 'failed').length,
    running: jobs.filter((job) => activeWorkStatuses.has(job.status)).length,
    scans: jobs.filter((job) => job.kind === 'scan').length,
  }), [jobs]);
  const jobKinds = useMemo(() => [...new Set(jobs.map((job) => job.kind))]
    .sort((left, right) => jobKindLabel(left).localeCompare(jobKindLabel(right))), [jobs]);
  const filteredJobs = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return jobs.filter((job) => {
      if (statusFilter === 'active' && !activeWorkStatuses.has(job.status)) return false;
      if (statusFilter !== 'all' && statusFilter !== 'active' && job.status !== statusFilter) return false;
      if (kindFilter !== 'all' && job.kind !== kindFilter) return false;
      if (!needle) return true;
      return [job.id, job.title, job.kind, job.status, job.stage, job.detail, job.finding_display_id]
        .some((value) => String(value ?? '').toLowerCase().includes(needle));
    });
  }, [jobs, kindFilter, query, statusFilter]);
  const scanById = useMemo(() => new Map(scans.map((scan) => [scan.id, scan])), [scans]);
  const stableCancelJob = useEventCallback(cancelJob);
  const stableRetryJob = useEventCallback(retryJob);
  const stableReconcileCache = useEventCallback(reconcileScannerCacheJob);
  const stableOpenJob = useEventCallback(openJob);
  const cacheRecoveryBusy = jobs.some(item => ['scanner_cache_update', 'scanner_cache_rollback', 'scanner_cache_reconcile'].includes(item.kind) && activeWorkStatuses.has(item.status));
  const cacheOutcomeByOriginal = useMemo(() => {
    const outcomes = new Map<number, Job>();
    for (const item of jobs) {
      if (item.kind === 'scanner_cache_reconcile' && Number.isSafeInteger(item.original_job_id) && (item.original_job_id ?? 0) > 0
        && (activeWorkStatuses.has(item.status) || item.status === 'completed') && !outcomes.has(item.original_job_id!)) {
        outcomes.set(item.original_job_id!, item);
      }
    }
    return outcomes;
  }, [jobs]);
  const stableOpenFindings = useEventCallback(openFindings);
  const jobStructure = useMemo(() => JSON.stringify(filteredJobs.map((job) => job.id)), [filteredJobs]);
  const { committedCount, ready } = usePaintedBatch(filteredJobs.length, 24, jobStructure, jobsAvailability !== 'loading');
  const historyAvailable = jobsAvailability === 'ready';
  const countUnavailableLabel = jobsAvailability === 'loading' ? 'Loading' : 'Unavailable';
  const listBlocked = surface.inert || !ready;
  const handoffJobPresent = Boolean(jobHandoff && jobs.some((job) => job.id === jobHandoff.id));
  const handoffJobFiltered = Boolean(jobHandoff && filteredJobs.some((job) => job.id === jobHandoff.id));
  const handoffJobVisible = Boolean(
    jobHandoff
    && !listBlocked
    && filteredJobs.slice(0, committedCount).some((job) => job.id === jobHandoff.id),
  );
  const handoffJobHiddenByFilters = handoffJobPresent && !handoffJobFiltered;
  const handoffCopy = jobHandoff
    ? durableJobHandoffCopy(jobHandoff, handoffJobPresent, handoffJobHiddenByFilters, handoffJobVisible)
    : null;
  useLayoutEffect(() => {
    if (
      !jobHandoff
      || jobHandoff.loading
      || listBlocked
      || focusedHandoffGenerationRef.current === jobHandoff.generation
    ) return;
    const row = jobListRef.current?.querySelector<HTMLElement>(`[data-job-id="${jobHandoff.id}"]`);
    if (!row) return;
    row.focus({ preventScroll: true });
    row.scrollIntoView({ block: 'nearest' });
    focusedHandoffGenerationRef.current = jobHandoff.generation;
  }, [jobHandoff, jobStructure, listBlocked]);
  return (
    <section
      {...surface}
      aria-busy={!ready || jobsAvailability === 'loading' ? true : undefined}
      className="stack"
      data-jobs-committed-count={committedCount}
      data-jobs-render-stage={ready ? 'ready' : 'rows'}
      inert={surface.inert}
    >
      <WorkProcessingStatus health={health} compact />
      <div className="job-summary" role="group" aria-label="Job summary">
        <div className="job-summary-group" role="group" aria-label="Job status counts">
          <span className="job-summary-label">Status</span>
          <dl>
            <div><dt>Active</dt><dd aria-label={historyAvailable ? undefined : countUnavailableLabel}>{historyAvailable ? counts.running : '—'}</dd></div>
            <div><dt>Completed</dt><dd aria-label={historyAvailable ? undefined : countUnavailableLabel}>{historyAvailable ? counts.completed : '—'}</dd></div>
            <div><dt>Failed</dt><dd aria-label={historyAvailable ? undefined : countUnavailableLabel}>{historyAvailable ? counts.failed : '—'}</dd></div>
          </dl>
        </div>
        <div className="job-summary-group" role="group" aria-label="Job kind counts">
          <span className="job-summary-label">Kind</span>
          <dl>
            <div><dt>Scans</dt><dd aria-label={historyAvailable ? undefined : countUnavailableLabel}>{historyAvailable ? counts.scans : '—'}</dd></div>
            <div><dt>Advisor</dt><dd aria-label={historyAvailable ? undefined : countUnavailableLabel}>{historyAvailable ? counts.advisor : '—'}</dd></div>
          </dl>
        </div>
      </div>
      {jobHandoff && handoffCopy ? (
        <div
          className={`job-handoff-status${jobHandoff.error ? ' job-handoff-status-error' : ''}`}
          role={jobHandoff.error ? 'alert' : 'status'}
        >
          <strong>{handoffCopy.title}</strong>
          <span>{handoffCopy.detail}</span>
          {handoffJobHiddenByFilters ? (
            <button className="secondary-action" onClick={resetJobFilters} type="button">
              <RefreshCw size={15} /> Reset filters
            </button>
          ) : null}
        </div>
      ) : null}
      <div className="band">
        <div className="band-head job-band-head">
          <h2>Task Manager <InfoTip text="Track scans, gate checks, and Advisor reviews. Jobs remain available after a refresh or restart." /></h2>
          <span className="job-count">{historyAvailable
            ? filteredJobs.length === jobs.length ? `${jobs.length} jobs` : `${filteredJobs.length} of ${jobs.length} jobs`
            : jobsAvailability === 'loading' ? 'Loading jobs…' : 'History unavailable'}</span>
        </div>
        <div className="toolbar job-toolbar" role="group" aria-label="Job filters">
          <label className="search-box">
            <Search size={16} />
            <input aria-label="Search jobs" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search jobs" />
          </label>
          <select aria-label="Job status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
            <option value="all">all statuses</option>
            <option value="active">active work</option>
            <option value="queued">queued</option>
            <option value="leased">leased</option>
            <option value="running">running</option>
            <option value="cancelling">cancelling</option>
            <option value="completed">completed</option>
            <option value="failed">failed</option>
            <option value="cancelled">cancelled</option>
          </select>
          <select aria-label="Job kind" value={kindFilter} onChange={(event) => setKindFilter(event.target.value)}>
            <option value="all">all kinds</option>
            {jobKinds.map((kind) => <option value={kind} key={kind}>{jobKindLabel(kind)}</option>)}
          </select>
        </div>
        {!historyAvailable ? (
          <div className="empty-state" role="status">
            {jobsAvailability === 'loading'
              ? 'Loading job history…'
              : 'Job history is unavailable. Use Refresh to load dashboard data.'}
          </div>
        ) : null}
        <div
          aria-busy={!ready || jobsAvailability === 'loading' ? true : undefined}
          aria-hidden={listBlocked ? true : undefined}
          className="job-list"
          inert={listBlocked}
          ref={jobListRef}
        >
          {filteredJobs.slice(0, committedCount).map((job) => (
            <JobRow
              busy={busy}
              job={job}
              key={job.id}
              onCancel={stableCancelJob}
              onOpenFindings={stableOpenFindings}
              onRetry={stableRetryJob}
              onReconcileCache={stableReconcileCache}
              cacheRecoveryBusy={cacheRecoveryBusy}
              cacheOutcomeJob={cacheOutcomeByOriginal.get(job.id) || null}
              onOpenJob={stableOpenJob}
              scan={job.scan_id ? scanById.get(job.scan_id) || null : null}
              targeted={jobHandoff?.id === job.id}
            />
          ))}
          {historyAvailable && !jobs.length ? <div className="empty-state">No jobs yet. Start a scan or run advisor triage to see work here.</div> : null}
          {historyAvailable && jobs.length && !filteredJobs.length ? <div className="empty-state">No jobs match the current filters.</div> : null}
        </div>
      </div>
    </section>
  );
}

function Scans({
  surface,
  scans,
  projects,
  openFindings,
  onDeleteScan,
}: {
  surface: RouteSurfaceAttributes;
  scans: Scan[];
  projects: Project[];
  openFindings: (id: number) => void;
  onDeleteScan: (scan: Scan) => void;
}) {
  const [page, setPage] = useState(1);
  const pageSize = 12;
  const visibleScans = scans.slice((page - 1) * pageSize, page * pageSize);
  return (
    <section {...surface} className="band">
      <div className="band-head">
        <h2>Scan History <InfoTip text="Each scan stores normalized findings in Postgres. Only bounded, sanitized CycloneDX SBOMs may enter the artifacts volume; raw tool output stays in temporary scratch space and is deleted. Delete scans to clean their published data." /></h2>
        <Pager page={page} total={scans.length} pageSize={pageSize} setPage={setPage} />
      </div>
      <ScanTable scans={visibleScans} projects={projects} onOpen={openFindings} onDeleteScan={onDeleteScan} />
    </section>
  );
}

function ScanTable({
  scans,
  projects,
  onOpen,
  compact,
  onDeleteScan,
}: {
  scans: Scan[];
  projects: Project[];
  onOpen?: (id: number) => void;
  compact?: boolean;
  onDeleteScan?: (scan: Scan) => void;
}) {
  const projectName = (id: number) => projects.find((project) => project.id === id)?.name || `#${id}`;
  return (
    <div className="table-wrap" role="region" tabIndex={0} aria-label="Scan history table">
      <table className={compact ? 'compact-scan-table' : 'scan-table'}>
        <thead>
          <tr>
            <th>ID</th>
            {!compact ? <th>Project</th> : null}
            <th>Status</th>
            <th>Gate</th>
            <th>Mode</th>
            <th>Findings</th>
            <th>Duration</th>
            {onOpen || onDeleteScan ? <th>Actions</th> : null}
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => {
            const modeReceipt = scanModeReceipt(scan);
            return (
              <tr
                key={scan.id}
                onClick={() => onOpen?.(scan.id)}
                onKeyDown={onOpen ? (event) => {
                  if (event.target !== event.currentTarget) return;
                  if (event.key !== 'Enter' && event.key !== ' ') return;
                  event.preventDefault();
                  onOpen(scan.id);
                } : undefined}
                tabIndex={onOpen ? 0 : undefined}
                aria-label={onOpen ? `Open findings for scan #${scan.id}` : undefined}
                className={onOpen ? 'clickable' : ''}
              >
                <td>#{scan.id}</td>
                {!compact ? <td>{projectName(scan.project_id)}</td> : null}
                <td><StatusPill value={scan.status} /></td>
                <td><StatusPill value={scan.gate_decision || 'pending'} /></td>
                <td>
                  <span className="scan-mode-receipt">
                    <span className="scan-mode-label">{modeReceipt.label}</span>
                    {modeReceipt.warning ? (
                      <small
                        className="scan-mode-warning"
                        title="The incremental request ran as a full scan so every enabled scanner inspected the same source view."
                      >
                        {modeReceipt.warning}
                      </small>
                    ) : null}
                  </span>
                </td>
                <td>{String(scan.scanner_summary?.findings_total ?? 0)}</td>
                <td>{scan.duration_ms ? `${Math.round(scan.duration_ms / 1000)}s` : '-'}</td>
                {onOpen || onDeleteScan ? (
                  <td className="scan-actions-cell">
                    <div className="scan-row-actions">
                      {onOpen ? (
                        <button className="secondary-action" onClick={(event) => { event.stopPropagation(); onOpen(scan.id); }}>
                          <FileSearch size={15} /> Open findings
                        </button>
                      ) : null}
                      {onDeleteScan ? (
                        <button
                          aria-label={`Delete scan #${scan.id}`}
                          className="icon-button danger"
                          onClick={(event) => { event.stopPropagation(); onDeleteScan(scan); }}
                          title="Delete scan, findings, and artifacts"
                        >
                          <Trash2 aria-hidden="true" size={15} />
                        </button>
                      ) : null}
                    </div>
                  </td>
                ) : null}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

type FindingsStaticContentProps = {
  activeFindingsCount: number;
  advisorProviderReadiness: AdvisorProviderReadiness;
  advisorCandidateCount: number;
  aiMode: AdvisorAiMode | null;
  artifacts: ScanArtifact[];
  busy: boolean;
  ignoredCount: number;
  findingsLoading: boolean;
  lifecycleFilter: string;
  onLifecycleFilterChange: (value: string) => void;
  onClearFilters: () => void;
  onQueryChange: (value: string) => void;
  onOpenProtection: (repositoryId?: string) => void;
  onScanChange: (scanId: number) => void;
  onScannerFilterChange: (value: string) => void;
  onSeverityFilterChange: (value: string) => void;
  onToggleScanner: (scanner: string) => void;
  onToggleSeverity: (severity: string) => void;
  onTriageScan: () => void;
  query: string;
  scannerCounts: Record<string, number>;
  scannerFilter: string;
  scans: Scan[];
  selectedProject?: Project;
  selectedScan?: Scan;
  selectedScanId: number | null;
  severityCounts: Record<string, number>;
  severityFilter: string;
  toolbarRef: { current: HTMLDivElement | null };
};

const FindingsStaticContent = memo(function FindingsStaticContent({
  activeFindingsCount,
  advisorProviderReadiness,
  advisorCandidateCount,
  aiMode,
  artifacts,
  busy,
  ignoredCount,
  findingsLoading,
  lifecycleFilter,
  onClearFilters,
  onLifecycleFilterChange,
  onQueryChange,
  onOpenProtection,
  onScanChange,
  onScannerFilterChange,
  onSeverityFilterChange,
  onToggleScanner,
  onToggleSeverity,
  onTriageScan,
  query,
  scannerCounts,
  scannerFilter,
  scans,
  selectedProject,
  selectedScan,
  selectedScanId,
  severityCounts,
  severityFilter,
  toolbarRef,
}: FindingsStaticContentProps) {
  const advisorFailure = scanAdvisorFailure(selectedScan);
  const modeReceipt = scanModeReceipt(selectedScan);
  const scanEvidenceProblem = findingsLoading
    ? null
    : scanEvidenceNotice(selectedScan, activeFindingsCount + ignoredCount, artifacts.length);
  const scanAdvisorAvailabilityState = scanAdvisorAvailability({
    advisorCandidateCount,
    aiMode,
    providerReadiness: advisorProviderReadiness,
    scan: selectedScan,
  });
  const scanAdvisorDisabledReason = !scanAdvisorAvailabilityState.enabled
    ? scanAdvisorAvailabilityState.reason
    : !selectedScanId
      ? 'Select a scan before requesting an Advisor review.'
      : busy
        ? 'Scan Advisor is disabled while another durable action is in progress.'
        : findingsLoading
          ? 'Scan Advisor is disabled while the selected scan findings are loading.'
          : null;
  const coverageTarget = scanCoverageTarget(selectedScan);
  const activeFilterLabels = [
    severityFilter !== 'all' ? severityFilter : null,
    scannerFilter !== 'all' ? scannerFilter : null,
    lifecycleFilter !== 'all' ? lifecycleFilter.replace(/_/g, ' ') : null,
  ].filter((label): label is string => label !== null);
  return (
    <div className="finding-review-header">
      <div className="finding-context-bar">
        <div className="finding-context-source">
          <strong>{selectedProject?.name || 'No project selected'}</strong>
          <span>{coverageTarget.label} · {selectedScan ? `Scan #${selectedScan.id} · ${modeReceipt.label}` : 'No scan selected'}</span>
          <details className="finding-source-path">
            <summary>Source root</summary>
            <code>{selectedProject?.repo_path || 'Select a scan to see its source root.'}</code>
          </details>
          {modeReceipt.warning ? <small className="scan-mode-warning">{modeReceipt.warning}</small> : null}
        </div>
        <div className="scan-metrics">
          <Stat icon={Activity} label="Status" value={selectedScan?.status || '-'} />
          <div className="finding-gate-metric" data-gate-decision={selectedScan?.gate_decision || 'pending'}>
            <Stat icon={Shield} label="Gate" value={selectedScan?.gate_decision || 'pending'} />
          </div>
          <Stat icon={FileSearch} label="Active Findings" value={activeFindingsCount} />
        </div>
        <FindingProtectionContext project={selectedProject} scanRevision={selectedScan?.revision} onOpen={onOpenProtection} />
      </div>

      {scanEvidenceProblem ? (
        <div className={`scan-evidence-notice scan-evidence-notice-${scanEvidenceProblem.tone}`} role="status">
          <AlertTriangle size={18} aria-hidden="true" />
          <div>
            <strong>{scanEvidenceProblem.title}</strong>
            <span>{scanEvidenceProblem.detail}</span>
            {scanEvidenceProblem.sourceFailures.map((reason) => <span key={reason}>{reason}</span>)}
            {scanEvidenceProblem.scannerFailures.map((reason) => <span key={reason}>{reason}</span>)}
            {scanEvidenceProblem.nextAction ? <span>{scanEvidenceProblem.nextAction}</span> : null}
          </div>
        </div>
      ) : null}

      {advisorFailure ? (
        <div className="scan-evidence-notice scan-evidence-notice-warning" role="status">
          <Bot size={18} aria-hidden="true" />
          <div>
            <strong>Advisor did not complete · {advisorFailure.code}</strong>
            <span>{advisorFailure.detail} Scanner evidence, finding lifecycle, and the deterministic gate are unchanged. Run Scan Advisor again when local Ollama is available; scanner job history remains in Jobs.</span>
          </div>
        </div>
      ) : null}

      <div className="toolbar finding-toolbar" ref={toolbarRef}>
        <div className="finding-primary-filters">
          <select aria-label="Scan" value={selectedScanId ?? ''} onChange={(event) => onScanChange(Number(event.target.value))}>
            {scans.map((scan) => (
              <option value={scan.id} key={scan.id}>
                #{scan.id} · {scan.status}
              </option>
            ))}
          </select>
          <label className="search-box">
            <Search size={16} />
            <input aria-label="Search findings" value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder="Search findings" />
          </label>
        </div>
        <div className="finding-filter-actions">
          <details className="finding-filter-details">
            <summary>
              <span>Filters and scanner counts{activeFilterLabels.length ? ` · ${activeFilterLabels.length} active` : ''}</span>
              {activeFilterLabels.length ? <small>{activeFilterLabels.join(' · ')}</small> : null}
            </summary>
            <div className="finding-filter-fields">
              <select aria-label="Severity" value={severityFilter} onChange={(event) => onSeverityFilterChange(event.target.value)}>
                <option value="all">all severities</option>
                {severityOrder.map((severity) => (
                  <option value={severity} key={severity}>
                    {severity}
                  </option>
                ))}
              </select>
              <select aria-label="Scanner" value={scannerFilter} onChange={(event) => onScannerFilterChange(event.target.value)}>
                <option value="all">all scanners</option>
                {Object.keys(scannerCounts).map((scanner) => (
                  <option value={scanner} key={scanner}>
                    {scanner}
                  </option>
                ))}
              </select>
              <select aria-label="Lifecycle" value={lifecycleFilter} onChange={(event) => onLifecycleFilterChange(event.target.value)}>
                <option value="all">all lifecycle states</option>
                <option value="active">active only</option>
                <option value="blocking">gate-blocking</option>
                <option value="non_blocking">non-blocking</option>
                <option value="ignored">ignored / not counted</option>
              </select>
            </div>
            <div className="scanner-grid">
              {Object.entries(scannerCounts).map(([scanner, count]) => (
                <button
                  key={scanner}
                  className={`scanner-tile ${scannerFilter === scanner ? 'selected' : ''}`}
                  aria-pressed={scannerFilter === scanner}
                  onClick={() => onToggleScanner(scanner)}
                >
                  <span>{scanner}</span>
                  <strong>{count}</strong>
                </button>
              ))}
            </div>
          </details>
          <button
            type="button"
            className="secondary-action finding-clear-filters"
            onClick={onClearFilters}
            disabled={!query && severityFilter === 'all' && scannerFilter === 'all' && lifecycleFilter === 'all'}
          >
            <XCircle size={16} /> Clear filters
          </button>
          <div className="finding-advisor-action">
            <button
              onClick={onTriageScan}
              aria-describedby={scanAdvisorDisabledReason ? 'scan-advisor-disabled-reason' : undefined}
              disabled={scanAdvisorDisabledReason !== null}
              title={scanAdvisorDisabledReason || scanAdvisorAvailabilityState.reason}
            >
              <Bot size={16} /> Scan Advisor
            </button>
            {scanAdvisorDisabledReason ? (
              <details className="finding-advisor-guidance">
                <summary aria-label="Why is Scan Advisor unavailable?">Why?</summary>
                <p className="helper-text" id="scan-advisor-disabled-reason">{scanAdvisorDisabledReason}</p>
              </details>
            ) : null}
          </div>
        </div>
      </div>
      <div className="severity-row compact-severity">
        {severityOrder.map((severity) => (
          <button
            key={severity}
            className={`severity-box severity-box-${severity} ${severityFilter === severity ? 'selected' : ''}`}
            aria-pressed={severityFilter === severity}
            onClick={() => onToggleSeverity(severity)}
          >
            <span>{severity}</span>
            <strong>{severityCounts[severity] || 0}</strong>
          </button>
        ))}
      </div>
    </div>
  );
});

const FindingsScanDetails = memo(function FindingsScanDetails({
  artifacts,
  selectedProject,
  selectedScan,
}: {
  artifacts: ScanArtifact[];
  selectedProject?: Project;
  selectedScan?: Scan;
}) {
  const coverageTarget = scanCoverageTarget(selectedScan);
  const modeReceipt = scanModeReceipt(selectedScan);
  return (
    <details className="finding-scan-details">
      <summary>Scan scope and derived artifacts · {artifacts.length} {artifacts.length === 1 ? 'artifact' : 'artifacts'}</summary>
      <div className="finding-scan-details-content">
        <div className="band scan-context">
          <div className="band-head">
            <h2>Scan Scope <InfoTip text="Shows the registered codebase and the exact workspace, folder, or file target inspected by this scan. Finding paths below are relative to the registered root unless they are already absolute." /></h2>
            <FileSearch size={18} />
          </div>
          <div className="scope-grid">
            <div>
              <span>Codebase</span>
              <strong>{selectedProject?.name || '-'}</strong>
            </div>
            <div className="scope-wide">
              <span>Root path</span>
              <strong title={selectedProject?.repo_path || ''}>{selectedProject?.repo_path || '-'}</strong>
            </div>
            <div className="scope-wide">
              <span>Coverage target</span>
              <strong title={coverageTarget.path || coverageTarget.label}>{coverageTarget.label}</strong>
            </div>
            <div className="scan-mode-scope">
              <span>Scan</span>
              <strong className="scan-mode-label">{selectedScan ? `#${selectedScan.id} · ${modeReceipt.label}` : '-'}</strong>
              {modeReceipt.warning ? (
                <small
                  className="scan-mode-warning"
                  title="The incremental request ran as a full scan so every enabled scanner inspected the same source view."
                >
                  {modeReceipt.warning}
                </small>
              ) : null}
            </div>
            <div>
              <span>Duration</span>
              <strong>{formatDuration(selectedScan?.duration_ms)}</strong>
            </div>
            <div>
              <span>Refs</span>
              <strong>{modeReceipt.requested === 'full'
                ? 'Not used — current checkout'
                : selectedScan?.base_ref || selectedScan?.head_ref
                  ? `${selectedScan.base_ref || '-'} → ${selectedScan.head_ref || '-'}`
                  : 'Not provided'}</strong>
            </div>
          </div>
        </div>
        <div className="band">
          <div className="band-head">
            <h2>Derived Artifacts <InfoTip text="Only explicitly publishable derived artifacts such as redacted SBOMs are retained. Raw scanner result files and logs are discarded after normalization." /></h2>
            <Database size={18} />
          </div>
          {artifacts.length ? (
            <div className="artifact-grid">
              {artifacts.map((artifact) => {
                const artifactIdentity = `${artifact.artifact_type} · ${artifact.format}`;
                return (
                  <article className="artifact-card" key={artifact.id}>
                    <div className="artifact-details">
                      <strong title={artifact.scanner}>{artifact.scanner}</strong>
                      <span title={artifactIdentity}>{artifactIdentity}</span>
                      <small>{formatBytes(artifact.size_bytes)}</small>
                    </div>
                    <div className="artifact-actions">
                      <a href={api.artifactOpenUrl(artifact.id)} target="_blank" rel="noreferrer">
                        <ExternalLink size={14} aria-hidden="true" /> Open
                      </a>
                      <a href={api.artifactDownloadUrl(artifact.id)} download>
                        <Download size={14} aria-hidden="true" /> Download
                      </a>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="empty-state">No publishable derived artifacts are stored for this scan.</div>
          )}
        </div>
      </div>
    </details>
  );
});

function Findings({
  surface,
  advisorProviderReadiness,
  scans,
  projects,
  selectedScanId,
  setSelectedScanId,
  selectedFindingId,
  setSelectedFindingId,
  openFinding,
  pendingFindingFocusId,
  clearPendingFindingFocus,
  findings,
  findingsLoading,
  findingsHydrating,
  findingDetailLoading,
  pendingLifecycleLayout,
  findingDetailError,
  ideCapabilities,
  scanSummary,
  artifacts,
  busy,
  health,
  triage,
  triageScan,
  updateFindingLifecycle,
  bulkFindingAction,
  deleteFinding,
  openSourceInIde,
  refreshIdeCapabilities,
  sourceOpenCommand,
  onOpenProtection,
}: {
  surface: RouteSurfaceAttributes;
  advisorProviderReadiness: AdvisorProviderReadiness;
  scans: Scan[];
  projects: Project[];
  selectedScanId: number | null;
  setSelectedScanId: (id: number) => void;
  selectedFindingId: number | null;
  setSelectedFindingId: (id: number | null) => void;
  openFinding: (id: number | null) => void;
  pendingFindingFocusId: number | null;
  clearPendingFindingFocus: () => void;
  findings: Finding[];
  findingsLoading: boolean;
  findingsHydrating: boolean;
  findingDetailLoading: boolean;
  pendingLifecycleLayout: PendingLifecycleLayout;
  findingDetailError: string | null;
  ideCapabilities: IdeCapability[];
  scanSummary: ScanSummary | null;
  artifacts: ScanArtifact[];
  busy: boolean;
  health: Health | null;
  triage: (findingId: number) => void;
  triageScan: (scanId: number) => void;
  updateFindingLifecycle: (finding: Finding, action: string) => Promise<boolean>;
  bulkFindingAction: (findingIds: number[], action: string) => Promise<unknown>;
  deleteFinding: (finding: Finding, onConfirmed?: () => void) => Promise<boolean>;
  openSourceInIde: (finding: Finding, capability: IdeValidCapability) => void;
  refreshIdeCapabilities: () => void;
  sourceOpenCommand: SourceOpenCommand | null;
  onOpenProtection: (repositoryId?: string) => void;
}) {
  const openProtectionSettings = useEventCallback(onOpenProtection);
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [scannerFilter, setScannerFilter] = useState('all');
  const [lifecycleFilter, setLifecycleFilter] = useState('all');
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<number>>(new Set());
  const [findingPage, setFindingPage] = useState(1);
  const [snippetHeight, setSnippetHeight] = useState<number>(evidenceHeightControl.initial);
  const [renderStage, setRenderStage] = useState<FindingsRenderStage>('summary');
  const [initiallyPublished, setInitiallyPublished] = useState(false);
  const stagedScanIdRef = useRef(selectedScanId);
  const findingRefs = useRef<Record<number, HTMLDivElement | null>>({});
  const findingsToolbarRef = useRef<HTMLDivElement>(null);
  const detailOwnedFocusRef = useRef(false);
  const focusedDetailFindingIdRef = useRef<number | null>(null);
  const [pendingDetailFocusHandoffId, setPendingDetailFocusHandoffId] = useState<number | null>(null);
  const selectedScan = useMemo(() => scans.find((scan) => scan.id === selectedScanId), [scans, selectedScanId]);
  const selectedProject = useMemo(() => projects.find((project) => project.id === selectedScan?.project_id), [projects, selectedScan?.project_id]);
  const findingsById = useMemo(() => new Map(findings.map((finding) => [finding.id, finding])), [findings]);
  const activeFindings = useMemo(() => findings.filter((finding) => !finding.suppressed), [findings]);
  const authoritativeCounts = scanSummary?.scan.id === selectedScanId ? scanSummary.findings : null;
  const advisorCandidateCount = useMemo(() => activeFindings.filter((finding) => !finding.ai_verdict).length, [activeFindings]);
  const advisorScanTerminal = Boolean(selectedScan && ['completed', 'partial', 'failed'].includes(selectedScan.status));
  const severityCounts = useMemo(
    () => authoritativeCounts?.severity_counts || countBySeverity(activeFindings),
    [activeFindings, authoritativeCounts?.severity_counts],
  );
  const gateExemptCount = authoritativeCounts?.gate_exempt
    ?? findings.filter((finding) => !finding.suppressed && finding.gate_exempt).length;
  const ignoredCount = authoritativeCounts?.suppressed
    ?? findings.filter((finding) => finding.suppressed).length;
  const activeFindingsCount = authoritativeCounts?.active ?? activeFindings.length;
  const scannerCounts = useMemo(
    () => authoritativeCounts?.scanner_counts || activeFindings.reduce<Record<string, number>>((acc, finding) => {
        acc[finding.scanner] = (acc[finding.scanner] || 0) + 1;
        return acc;
      }, {}),
    [activeFindings, authoritativeCounts?.scanner_counts],
  );
  const filteredFindings = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return findings.filter((finding) => {
      const severityMatch = severityFilter === 'all' || finding.severity === severityFilter;
      const scannerMatch = scannerFilter === 'all' || finding.scanner === scannerFilter;
      const lifecycleMatch =
        lifecycleFilter === 'all' ||
        (lifecycleFilter === 'active' && !finding.suppressed) ||
        (lifecycleFilter === 'blocking' && !finding.suppressed && !finding.gate_exempt) ||
        (lifecycleFilter === 'non_blocking' && !finding.suppressed && finding.gate_exempt) ||
        (lifecycleFilter === 'ignored' && finding.suppressed);
      const queryMatch =
        !needle ||
        `${finding.display_id} ${finding.id} ${finding.rule_id} ${finding.message} ${finding.file_path} ${fullFindingPath(selectedProject, finding)} ${finding.scanner} ${lifecycleLabel(finding)}`.toLowerCase().includes(needle);
      return severityMatch && scannerMatch && lifecycleMatch && queryMatch;
    });
  }, [findings, lifecycleFilter, query, scannerFilter, selectedProject, severityFilter]);
  const findingPageCount = Math.max(1, Math.ceil(filteredFindings.length / findingsPageSize));
  const clampedFindingPage = Math.min(findingPage, findingPageCount);
  const pendingFindingIndex = pendingFindingFocusId
    ? filteredFindings.findIndex((finding) => finding.id === pendingFindingFocusId)
    : -1;
  const pendingFindingPage = pendingFindingIndex >= 0
    ? Math.floor(pendingFindingIndex / findingsPageSize) + 1
    : null;
  const visibleFindingPage = pendingFindingPage ?? clampedFindingPage;
  const visibleFindings = useMemo(
    () => filteredFindings.slice((visibleFindingPage - 1) * findingsPageSize, visibleFindingPage * findingsPageSize),
    [filteredFindings, visibleFindingPage],
  );
  const visibleFindingIdsKey = useMemo(() => visibleFindings.map((finding) => finding.id).join(','), [visibleFindings]);
  const reportView = useMemo<FindingReportView | null>(() => scanSummary && selectedProject
    && scanSummary.scan.id === selectedScanId && scanSummary.scan.project_id === selectedProject.id
    ? { projectId: selectedProject.id, scanId: scanSummary.scan.id,
        findingsRevision: scanSummary.findings_revision, items: visibleFindings } : null,
  [scanSummary, selectedProject, selectedScanId, visibleFindings]);
  const filteredFindingIds = useMemo(() => new Set(filteredFindings.map((finding) => finding.id)), [filteredFindings]);
  const visibleFindingStructure = `${selectedScanId ?? 0}:${visibleFindingPage}:${visibleFindingIdsKey}`;
  const {
    committedCount: renderedFindingCount,
    ready: findingRowsReady,
  } = usePaintedBatch(
    visibleFindings.length,
    findingsMaximumBatchSize,
    visibleFindingStructure,
    !findingsLoading && !findingsHydrating,
    // A collection that fits one bounded slice needs no second row commit.
    visibleFindings.length <= findingsMaximumBatchSize ? 1 : 2,
  );
  const routeReady = !findingsLoading && !findingsHydrating
    && !findingDetailLoading && renderStage === 'ready' && findingRowsReady;
  // Keep staging mounted, but publish the initial evidence layout only once
  // its exact outcome is ready. Empty selections and terminal errors settle
  // through the same readiness path; later refreshes keep evidence visible.
  useLayoutEffect(() => {
    if (routeReady) setInitiallyPublished(true);
  }, [routeReady]);
  const selectedVisibleIds = useMemo(() => visibleFindings.map((finding) => finding.id), [visibleFindings]);
  const selectedIds = useMemo(
    () => [...selectedFindingIds].filter((id) => findingsById.has(id) && filteredFindingIds.has(id)),
    [filteredFindingIds, findingsById, selectedFindingIds],
  );
  const triageSelectionValid = useMemo(
    () => advisorScanTerminal && selectedIds.length > 0 && selectedIds.every((id) => !findingsById.get(id)?.suppressed),
    [advisorScanTerminal, findingsById, selectedIds],
  );
  const selectedExists = useMemo(() => Boolean(selectedFindingId && findingsById.has(selectedFindingId)), [findingsById, selectedFindingId]);
  const selectedVisible = useMemo(
    () => Boolean(selectedFindingId && filteredFindings.some((finding) => finding.id === selectedFindingId)),
    [filteredFindings, selectedFindingId],
  );
  useLayoutEffect(() => {
    if (findingPage !== visibleFindingPage) setFindingPage(visibleFindingPage);
  }, [findingPage, visibleFindingPage]);
  useEffect(() => {
    if (!pendingFindingFocusId || selectedFindingId !== pendingFindingFocusId || !selectedExists || selectedVisible) return;
    setQuery('');
    setSeverityFilter('all');
    setScannerFilter('all');
    setLifecycleFilter('all');
  }, [pendingFindingFocusId, selectedFindingId, selectedExists, selectedVisible]);
  useEffect(() => {
    setSelectedFindingIds((current) => {
      if (!current.size) return current;
      const next = new Set([...current].filter((id) => findingsById.has(id) && filteredFindingIds.has(id)));
      return next.size === current.size ? current : next;
    });
  }, [filteredFindingIds, findingsById]);
  useEffect(() => {
    setSelectedFindingIds((current) => (current.size ? new Set() : current));
    setFindingPage(1);
  }, [selectedScanId]);
  useLayoutEffect(() => {
    if (stagedScanIdRef.current === selectedScanId) return;
    stagedScanIdRef.current = selectedScanId;
    setRenderStage('summary');
  }, [selectedScanId]);
  useEffect(() => {
    if (renderStage === 'ready') return undefined;
    if (renderStage === 'summary' ? findingsLoading : findingsHydrating || findingDetailLoading) return undefined;
    if (renderStage === 'detail-evidence' && !findingRowsReady) return undefined;
    // Row batches begin while the cheap summary is visible. Once the final
    // slice reports its post-paint fence, no additional animation frame is
    // needed: detail/evidence has already painted alongside those slices.
    if (renderStage === 'detail-evidence') {
      setRenderStage('ready');
      return undefined;
    }
    const frame = window.requestAnimationFrame(() => {
      setRenderStage((current) => current === 'summary' ? 'detail-evidence' : current);
    });
    return () => {
      window.cancelAnimationFrame(frame);
    };
  }, [findingDetailLoading, findingRowsReady, findingsHydrating, renderStage, selectedScanId]);
  useEffect(() => {
    // A partial page must not replace a still-loading scan-local deep link.
    if (findingsLoading || findingsHydrating) return;
    if (!findings.length) {
      if (selectedFindingId) openFinding(null);
      return;
    }
    const selectedInScan = Boolean(selectedFindingId && findingsById.has(selectedFindingId));
    if (!selectedFindingId || !selectedInScan) {
      openFinding(filteredFindings[0]?.id ?? null);
      return;
    }
    if (pendingFindingFocusId && selectedFindingId === pendingFindingFocusId && !selectedVisible) return;
    if (!selectedVisible) {
      openFinding(filteredFindings[0]?.id ?? null);
      return;
    }
  }, [filteredFindings, findings, findingsById, findingsHydrating, findingsLoading, openFinding, pendingFindingFocusId, selectedFindingId, selectedVisible]);
  useEffect(() => {
    if (!initiallyPublished || !routeReady || !pendingFindingFocusId || selectedFindingId !== pendingFindingFocusId) return;
    const item = findingRefs.current[selectedFindingId];
    if (!item?.isConnected || findingRefs.current[pendingFindingFocusId] !== item) return;
    return revealFindingNavigation(item, selectedFindingId,
      () => item.isConnected && findingRefs.current[pendingFindingFocusId] === item,
      clearPendingFindingFocus);
  }, [clearPendingFindingFocus, initiallyPublished, pendingFindingFocusId, routeReady, selectedFindingId, selectedScanId, visibleFindingIdsKey, visibleFindingPage]);

  const fallbackFindingId = filteredFindings[0]?.id ?? null;
  const activeFindingId = selectedVisible ? selectedFindingId : fallbackFindingId;
  const emptyFindingMessage = !selectedScanId
    ? 'Select a scan to review its findings.'
    : findings.length
      ? 'No findings match the current filters. Clear filters to review this scan.'
      : 'No findings are available to display for this scan.';
  const allVisibleSelected = selectedVisibleIds.length > 0 && selectedVisibleIds.every((id) => selectedFindingIds.has(id));

  useEffect(() => {
    const recordFocusOwner = (event: FocusEvent) => {
      const target = event.target;
      if (!(target instanceof Element)) return;
      const detail = target.closest<HTMLElement>('.finding-detail[data-finding-id]');
      if (detail) {
        const findingId = Number(detail.dataset.findingId);
        focusedDetailFindingIdRef.current = Number.isSafeInteger(findingId) && findingId > 0 ? findingId : null;
        detailOwnedFocusRef.current = focusedDetailFindingIdRef.current !== null;
      } else if (target !== document.body) {
        detailOwnedFocusRef.current = false;
        focusedDetailFindingIdRef.current = null;
        setPendingDetailFocusHandoffId(null);
      }
    };
    document.addEventListener('focusin', recordFocusOwner);
    return () => document.removeEventListener('focusin', recordFocusOwner);
  }, []);

  useLayoutEffect(() => {
    const externallyReplacedFocusedDetail = focusedDetailFindingIdRef.current !== null
      && focusedDetailFindingIdRef.current !== activeFindingId;
    if (!detailOwnedFocusRef.current && !externallyReplacedFocusedDetail && pendingDetailFocusHandoffId === null) return;
    // Detail invalidation can paint before the authoritative collection removes
    // the finding. Keep its focus ownership until a real replacement exists.
    if (
      pendingDetailFocusHandoffId === null
      && focusedDetailFindingIdRef.current !== null
      && focusedDetailFindingIdRef.current === activeFindingId
    ) return;
    const handoffFindingId = pendingDetailFocusHandoffId ?? activeFindingId;
    const handOffFocus = () => {
      const replacement = handoffFindingId === null
        ? null
        : findingRefs.current[handoffFindingId]?.querySelector<HTMLButtonElement>('.finding-list-main');
      // When a finding still exists, wait for its bounded row batch rather
      // than prematurely sending focus to the toolbar and erasing ownership.
      const focusTarget = replacement || (handoffFindingId === null
        ? findingsToolbarRef.current?.querySelector<HTMLElement>('select, input, button')
        : null);
      if (!focusTarget) return;
      if (!focusTarget.isConnected || focusTarget.closest('[inert], [aria-hidden="true"]')) return;
      focusTarget.focus({ preventScroll: true });
      // A structural evidence update can briefly leave the target below an
      // inert paint fence. Retain ownership until the browser confirms the
      // handoff instead of clearing the only retry marker after a rejected
      // focus call.
      if (document.activeElement !== focusTarget) return;
      detailOwnedFocusRef.current = false;
      focusedDetailFindingIdRef.current = null;
      setPendingDetailFocusHandoffId(null);
    };
    if (handoffFindingId !== null && pendingDetailFocusHandoffId === null) {
      setPendingDetailFocusHandoffId(handoffFindingId);
    }
    handOffFocus();
    const frame = window.requestAnimationFrame(handOffFocus);
    return () => window.cancelAnimationFrame(frame);
  }, [activeFindingId, findingRowsReady, findings, pendingDetailFocusHandoffId, renderStage, renderedFindingCount, selectedFindingId]);

  const prepareDetailSelectionChange = useCallback(() => {
    detailOwnedFocusRef.current = detailOwnedFocusRef.current
      || focusedDetailFindingIdRef.current !== null
      || Boolean(document.activeElement?.closest('.finding-detail'));
  }, []);

  const detailTriage = useEventCallback(triage);
  const detailLifecycle = useEventCallback(async (findingId: number, action: string) => {
    const finding = findingsById.get(findingId);
    if (finding) {
      prepareDetailSelectionChange();
      if (!await updateFindingLifecycle(finding, action)) detailOwnedFocusRef.current = false;
    }
  });
  const detailDelete = useEventCallback(async (findingId: number) => {
    const finding = findingsById.get(findingId);
    if (finding) {
      // The confirmation dialog temporarily owns focus. Remember the exact
      // invoking detail before it opens, then restore that ownership only after
      // confirmation so cancellation cannot initiate a replacement handoff.
      const focusedDetail = document.activeElement?.closest<HTMLElement>('.finding-detail[data-finding-id]');
      const ownedFocus = focusedDetailFindingIdRef.current === finding.id
        || focusedDetail?.dataset.findingId === String(finding.id);
      if (!await deleteFinding(finding, () => {
        detailOwnedFocusRef.current = ownedFocus;
        focusedDetailFindingIdRef.current = ownedFocus ? finding.id : null;
      })) detailOwnedFocusRef.current = false;
    }
  });

  const registerFindingRef = useCallback((findingId: number, node: HTMLDivElement | null) => {
    findingRefs.current[findingId] = node;
  }, []);

  const toggleFindingSelection = useCallback((findingId: number) => {
    setSelectedFindingIds((current) => {
      const next = new Set(current);
      if (next.has(findingId)) next.delete(findingId);
      else next.add(findingId);
      return next;
    });
  }, []);

  const toggleVisibleSelection = useEventCallback(() => {
    setSelectedFindingIds((current) => {
      const next = new Set(current);
      if (allVisibleSelected) {
        selectedVisibleIds.forEach((id) => next.delete(id));
      } else {
        selectedVisibleIds.forEach((id) => next.add(id));
      }
      return next;
    });
  });

  const clearFindingSelection = useCallback(() => setSelectedFindingIds(new Set()), []);

  const runBulk = useEventCallback(async (action: string) => {
    const result = await bulkFindingAction(selectedIds, action);
    if (result && (action === 'delete' || action === 'triage')) setSelectedFindingIds(new Set());
  });

  const changeSelectedScan = useEventCallback((scanId: number) => {
    clearPendingFindingFocus();
    setFindingPage(1);
    setSelectedFindingId(null);
    setSelectedFindingIds(new Set());
    setSelectedScanId(scanId);
  });
  const triageSelectedScan = useEventCallback(() => {
    if (selectedScanId) triageScan(selectedScanId);
  });
  const toggleSeverity = useCallback((severity: string) => {
    clearPendingFindingFocus();
    setFindingPage(1);
    setSeverityFilter((current) => current === severity ? 'all' : severity);
  }, [clearPendingFindingFocus]);
  const toggleScanner = useCallback((scanner: string) => {
    clearPendingFindingFocus();
    setFindingPage(1);
    setScannerFilter((current) => current === scanner ? 'all' : scanner);
  }, [clearPendingFindingFocus]);

  const changeQuery = useCallback((value: string) => {
    clearPendingFindingFocus();
    setFindingPage(1);
    setQuery(value);
  }, [clearPendingFindingFocus]);
  const changeSeverityFilter = useCallback((value: string) => {
    clearPendingFindingFocus();
    setFindingPage(1);
    setSeverityFilter(value);
  }, [clearPendingFindingFocus]);
  const changeScannerFilter = useCallback((value: string) => {
    clearPendingFindingFocus();
    setFindingPage(1);
    setScannerFilter(value);
  }, [clearPendingFindingFocus]);
  const changeLifecycleFilter = useCallback((value: string) => {
    clearPendingFindingFocus();
    setFindingPage(1);
    setLifecycleFilter(value);
  }, [clearPendingFindingFocus]);
  const clearFindingFilters = useCallback(() => {
    clearPendingFindingFocus();
    setQuery('');
    setSeverityFilter('all');
    setScannerFilter('all');
    setLifecycleFilter('all');
    setFindingPage(1);
  }, [clearPendingFindingFocus]);

  const routeBlocked = surface.inert;
  const emptyWorkspace = routeReady && findingRowsReady && !findingsLoading && !findingsHydrating
    && activeFindingId === null && filteredFindings.length === 0;
  // Initial/scan-replacement staging is inert, but a same-scan structural
  // reconciliation keeps the already-ready workspace interactive. In
  // particular, a focused detail action must be able to hand focus to the
  // first replacement row in the commit that removes its finding.
  const workspaceBlocked = routeBlocked || renderStage === 'summary' || (renderStage !== 'ready' && !findingRowsReady);

  return (
    <>
      {!initiallyPublished && !routeBlocked ? (
        <div className="visually-hidden" role="status">Loading finding evidence…</div>
      ) : null}
      <section
        {...surface}
        aria-busy={routeReady ? undefined : true}
        aria-hidden={routeBlocked ? true : undefined}
        className="stack finding-review"
        data-findings-committed-count={renderedFindingCount}
        data-findings-render-stage={renderStage}
        inert={routeBlocked}
      >
        <FindingsStaticContent
          activeFindingsCount={activeFindingsCount}
          advisorProviderReadiness={advisorProviderReadiness}
          advisorCandidateCount={advisorCandidateCount}
          aiMode={health?.ai.mode ?? null}
          artifacts={artifacts}
          busy={busy}
          findingsLoading={findingsLoading}
          ignoredCount={ignoredCount}
          lifecycleFilter={lifecycleFilter}
          onLifecycleFilterChange={changeLifecycleFilter}
          onClearFilters={clearFindingFilters}
          onQueryChange={changeQuery}
          onOpenProtection={openProtectionSettings}
          onScanChange={changeSelectedScan}
          onScannerFilterChange={changeScannerFilter}
          onSeverityFilterChange={changeSeverityFilter}
          onToggleScanner={toggleScanner}
          onToggleSeverity={toggleSeverity}
          onTriageScan={triageSelectedScan}
          query={query}
          scannerCounts={scannerCounts}
          scannerFilter={scannerFilter}
          scans={scans}
          selectedProject={selectedProject}
          selectedScan={selectedScan}
          selectedScanId={selectedScanId}
          severityCounts={severityCounts}
          severityFilter={severityFilter}
          toolbarRef={findingsToolbarRef}
        />

        <div className="finding-entry">
          {!initiallyPublished ? (
            <div className="finding-initial-loading" aria-hidden="true">Loading finding evidence…</div>
          ) : null}
          <div className="finding-initial-content" data-pending={!initiallyPublished || undefined} aria-hidden={!initiallyPublished || undefined} inert={!initiallyPublished}>
            <div
              aria-busy={workspaceBlocked ? true : undefined}
              aria-hidden={workspaceBlocked ? true : undefined}
              className="finding-workspace"
              data-empty={emptyWorkspace || undefined}
              data-findings-page={visibleFindingPage}
              inert={workspaceBlocked}
            >
              <FindingListPane
                activeFindingId={activeFindingId}
                activeFindingsCount={activeFindingsCount}
                allVisibleSelected={allVisibleSelected}
                busy={busy}
                filteredFindings={visibleFindings}
                renderedFindingCount={renderedFindingCount}
                findingsLoading={findingsLoading}
                emptyMessage={emptyFindingMessage}
                gateExemptCount={gateExemptCount}
                ignoredCount={ignoredCount}
                page={visibleFindingPage}
                pageSize={findingsPageSize}
                onOpen={openFinding}
                onRunBulk={runBulk}
                onToggleSelected={toggleFindingSelection}
                onToggleVisibleSelection={toggleVisibleSelection}
                onClearSelection={clearFindingSelection}
                registerRef={registerFindingRef}
                // Mount the bounded server page while the workspace remains inert. This
                // makes the batch paint fence describe real rows (not the summary
                // placeholder) before deep-link scrolling and focus.
                visible={renderedFindingCount > 0 || findingRowsReady}
                selectedFindingIds={selectedFindingIds}
                selectedIdsCount={selectedIds.length}
                selectedProject={selectedProject}
                setPage={setFindingPage}
                totalFilteredCount={filteredFindings.length}
                triageSelectionValid={triageSelectionValid}
              />

              {!emptyWorkspace ? <FindingDetailPane
                reportView={reportView}
                onSelectRelated={openFinding}
                advisorAllowed={advisorScanTerminal}
                busy={busy}
                fallbackFindingId={fallbackFindingId}
                findings={findings}
                findingsLoading={findingsLoading}
                ideCapabilities={ideCapabilities}
                detailLoading={findingDetailLoading}
                pendingLifecycleLayout={pendingLifecycleLayout}
                detailError={findingDetailError}
                emptyMessage={emptyFindingMessage}
                onDelete={detailDelete}
                onLifecycle={detailLifecycle}
                onTriage={detailTriage}
                onOpenSource={openSourceInIde}
                onRefreshIdeClients={refreshIdeCapabilities}
                renderStage={renderStage}
                selectedFindingId={activeFindingId}
                selectedProject={selectedProject}
                sourceOpenCommand={sourceOpenCommand}
                setSnippetHeight={setSnippetHeight}
                snippetHeight={snippetHeight}
              /> : null}
            </div>
            <FindingsScanDetails artifacts={artifacts} selectedProject={selectedProject} selectedScan={selectedScan} />
          </div>
        </div>
      </section>
    </>
  );
}

type ToolCardProps = {
  busy: boolean;
  onToggle: (tool: ScannerTool) => void;
  onSelectCandidate: (toolId: string) => void;
  tool: ScannerTool;
};

function sameToolCard(left: ToolCardProps, right: ToolCardProps) {
  const previous = left.tool;
  const next = right.tool;
  return (
    left.busy === right.busy
    && left.onToggle === right.onToggle
    && left.onSelectCandidate === right.onSelectCandidate
    && previous.id === next.id
    && previous.name === next.name
    && previous.category === next.category
    && previous.lifecycle === next.lifecycle
    && previous.source === next.source
    && previous.output_format === next.output_format
    && previous.description === next.description
    && previous.enabled === next.enabled
    && previous.current_version === next.current_version
    && previous.latest_version === next.latest_version
    && previous.installed_version === next.installed_version
    && previous.available === next.available
    && previous.pinned_version === next.pinned_version
    && previous.status === next.status
    && previous.update_available === next.update_available
    && previous.findings_count === next.findings_count
    && previous.artifacts_count === next.artifacts_count
    && previous.candidate_release_id === next.candidate_release_id
    && previous.candidate_manifest_sha256 === next.candidate_manifest_sha256
    && previous.published_at === next.published_at
    && previous.last_error === next.last_error
    && previous.last_checked_at === next.last_checked_at
    && previous.updated_at === next.updated_at
    && previous.runtime_ready === next.runtime_ready
    && JSON.stringify(previous.readiness) === JSON.stringify(next.readiness)
  );
}

const readinessFacets: ReadonlyArray<{ key: keyof NonNullable<ScannerTool['readiness']>; label: string }> = [
  { key: 'binary', label: 'Binary' },
  { key: 'data', label: 'Data' },
  { key: 'rules', label: 'Rules' },
  { key: 'execution', label: 'Execution' },
];

function ReadinessFacetView({ facet, label }: { facet?: ScannerReadinessFacet; label: string }) {
  const state = facet?.state || 'not_reported';
  return (
    <div className={`readiness-facet readiness-${state}`}>
      <dt>{label}</dt>
      <dd>
        <strong>{state.replace(/_/g, ' ')}</strong>
        <span>{facet?.reason || (facet ? 'Verified requirement is satisfied.' : 'Scanner runtime has not reported this facet.')}</span>
        {facet?.component_ids.length ? <small>{facet.component_ids.join(', ')}</small> : null}
      </dd>
    </div>
  );
}

const ToolCard = memo(function ToolCard({ busy, onToggle, onSelectCandidate, tool }: ToolCardProps) {
  const candidateSelected = tool.status === 'host_confirmation_required' || tool.status === 'update_pending_rebuild' || Boolean(tool.pinned_version);
  const candidateAttested = Boolean(tool.candidate_manifest_sha256);
  const candidateDisabledReason = busy
    ? 'Another dashboard action is being reconciled.'
    : candidateSelected
      ? 'This candidate is already selected; host confirmation is still required.'
      : !tool.update_available
        ? 'No newer reviewed scanner image candidate is available.'
        : !candidateAttested ? 'An admitted candidate manifest is required.' : null;
  const readinessLabel = tool.runtime_ready === true ? 'ready' : tool.runtime_ready === false ? 'not ready' : 'not reported';
  return (
    <article className={`tool-card tool-card-${tool.source}`}>
      <div className="tool-head">
        <div>
          <strong>{tool.name}</strong>
          <span>{tool.id} · {tool.category}</span>
        </div>
        <StatusPill value={tool.enabled ? (tool.available ? 'enabled' : 'missing') : 'disabled'} />
      </div>
      <p>{tool.description}</p>
      <dl className="kv compact-kv">
        <dt>Source</dt>
        <dd>{tool.source === 'internal' ? 'internal fallback' : 'real scanner'}</dd>
        <dt>Lifecycle</dt>
        <dd>{tool.lifecycle}</dd>
        <dt>Configured</dt>
        <dd>{tool.current_version}</dd>
        <dt>Installed</dt>
        <dd>{tool.installed_version || (tool.available ? 'unknown' : 'missing')}</dd>
        <dt>Candidate</dt>
        <dd>{tool.latest_version}</dd>
        {tool.candidate_release_id ? <><dt>Release</dt><dd>{tool.candidate_release_id}</dd></> : null}
        <dt>Output</dt>
        <dd>{tool.output_format}</dd>
        <dt>Findings</dt>
        <dd>{tool.findings_count}</dd>
        <dt>Artifacts</dt>
        <dd>{tool.artifacts_count || 0}</dd>
      </dl>
      <div className="readiness-head">
        <span>Runtime readiness</span>
        <strong>{readinessLabel}</strong>
      </div>
      <dl className="readiness-grid" aria-label={`${tool.name} runtime readiness`}>
        {readinessFacets.map(({ key, label }) => <ReadinessFacetView facet={tool.readiness?.[key]} key={key} label={label} />)}
      </dl>
      {tool.last_error ? <div className="inline-warning">{tool.last_error}</div> : null}
      {candidateSelected ? (
        <div className="inline-warning">Candidate selected. Host confirmation is required to replace the immutable scanner image; the running binary has not changed.</div>
      ) : tool.update_available && !candidateAttested ? (
        <div className="inline-warning">A catalog candidate exists but has no admitted manifest attestation. Selection remains disabled.</div>
      ) : null}
      <div className="tool-actions">
        <button onClick={() => onToggle(tool)} disabled={busy}>
          {tool.enabled ? <XCircle size={15} /> : <CheckCircle2 size={15} />}
          {tool.enabled ? 'Disable' : 'Enable'}
        </button>
        {tool.source === 'external' ? (
          <button
            onClick={() => onSelectCandidate(tool.id)}
            disabled={Boolean(candidateDisabledReason)}
            title={candidateDisabledReason || 'Record this attested image candidate for later host confirmation.'}
          >
            <PackageCheck size={15} /> {candidateSelected ? 'Candidate selected' : 'Select candidate'}
          </button>
        ) : null}
      </div>
    </article>
  );
}, sameToolCard);

function lifecycleStatusDetail(scope: ScannerLifecycleScope | null, job: Job | null) {
  if (scope?.status === 'failed' && scope.error_code === 'scanner_preparation_commit_uncertain') return 'Preparation failed while the published cache outcome remained uncertain. Open its job in Jobs to queue an explicit read-only outcome check. The failed preparation stays failed.';
  if (job?.kind === 'scanner_cache_reconcile') return jobCacheOutcomeGuidance(job)!;
  if (scope?.receipt.kind === 'reconciliation') return 'Cache outcome check completed. Scanner data is unchanged. The original preparation remains failed.';
  if (!scope) return 'Lifecycle state is unavailable.';
  return {
    idle: 'No command has been queued.',
    queued: 'Persisted and waiting for the durable worker.',
    leased: 'Claimed by a worker; execution is starting.',
    running: 'The source-blind updater is processing this command.',
    cancelling: 'Cancellation is persisted and waiting for updater confirmation.',
    completed: 'The updater receipt was validated and persisted.',
    failed: 'The updater failed without changing the running image or unverified cache state.',
    cancelled: 'Cancellation completed at a safe updater boundary.',
  }[scope.status];
}

function LifecycleScopePanel({
  busy,
  jobs,
  onCancel,
  onRetry,
  onViewJob,
  scope,
  title,
}: {
  busy: boolean;
  jobs: Job[];
  onCancel: (job: Job) => void;
  onRetry: (job: Job) => void;
  onViewJob: (jobId: number) => void;
  scope: ScannerLifecycleScope | null;
  title: string;
}) {
  const jobId = scope?.job_id || null;
  const job = jobId ? jobs.find((item) => item.id === jobId) || null : null;
  return (
    <section className="lifecycle-scope" aria-label={`${title} lifecycle`}>
      <div className="lifecycle-scope-head">
        <strong>{title}</strong>
        <StatusPill value={scope?.status || 'unknown'} />
      </div>
      <p>{lifecycleStatusDetail(scope, job)}</p>
      <dl className="lifecycle-meta">
        <dt>Updated</dt>
        <dd>{formatTime(scope?.updated_at)}</dd>
        {scope?.scope === 'cache' ? (
          <>
            <dt>Updater-managed generation</dt>
            <dd>{scope.active_generation || 'No updater activation recorded'}</dd>
          </>
        ) : null}
        {scope?.scope === 'cache' && scope.previous_generation ? <><dt>Previous good</dt><dd>{scope.previous_generation}</dd></> : null}
      </dl>
      {scope?.error_detail ? <div className="inline-warning lifecycle-error">{scope.error_code ? `${scope.error_code}: ` : ''}{scope.error_detail}</div> : null}
      <div className="lifecycle-actions">
        {jobId ? (
          <button className="secondary-action" onClick={() => onViewJob(jobId)}>
            <ListChecks size={15} /> View job #{jobId}
          </button>
        ) : null}
        {job && canCancelJob(job) ? (
          <button className="secondary-action" onClick={() => onCancel(job)} disabled={busy}>
            <XCircle size={15} /> Cancel
          </button>
        ) : null}
        {job && canRetryJob(job) ? (
          <button className="secondary-action" onClick={() => onRetry(job)} disabled={busy}>
            <RefreshCw size={15} /> Retry
          </button>
        ) : null}
      </div>
    </section>
  );
}

export function ScannerCacheVerificationPanel({ verification, busy, onRetry, onRefresh }: {
  verification: ScannerCacheVerification;
  busy: boolean;
  onRetry: (verification: ScannerCacheVerification) => void;
  onRefresh: () => void;
}) {
  const copy = scannerVerificationCopy(verification);
  const running = verification.state === 'verifying';
  const elapsed = useLiveJobElapsed(verification.started_at, running);
  const activityStale = running && Date.now() - Date.parse(verification.last_activity_at) > 45_000;
  return (
    <div className="inline-warning" role="status" data-testid={`scanner-cache-verification-${verification.target}`}>
      <strong>{copy.title}</strong>
      <p>{copy.detail}</p>
      <p className="helper-text">
        {copy.component ? `${copy.component} · ` : ''}{running ? copy.phase : `Last phase: ${copy.phase}`}
        {elapsed ? ` · elapsed ${elapsed}` : ''}
        {' · '}last activity {formatTime(verification.last_activity_at)}
        {verification.bytes_verified !== null && verification.bytes_total !== null
          ? ` · ${formatBytes(verification.bytes_verified)} of ${formatBytes(verification.bytes_total)} verified`
          : ''}
      </p>
      {activityStale ? <p>No new verification activity has been reported for more than 45 seconds. {verification.target === 'active' ? 'Complete scanning' : 'Rollback'} remains blocked; refresh status to check progress.</p> : null}
      <div className="lifecycle-actions">
        {copy.canRetry ? (
          <button type="button" disabled={busy} title={busy ? 'Another dashboard action is being reconciled.' : undefined} onClick={() => onRetry(verification)}>
            <RefreshCw size={15} /> {verification.target === 'active' ? 'Retry verification' : 'Retry rollback verification'}
          </button>
        ) : null}
        <button type="button" className="secondary-action" disabled={busy} title={busy ? 'Another dashboard action is being reconciled.' : undefined} onClick={onRefresh}>
          <RefreshCw size={15} /> Refresh readiness
        </button>
      </div>
    </div>
  );
}

export function Tools({
  surface,
  tools,
  lifecycle,
  preflight,
  jobs,
  busy,
  prepareScanners,
  checkTools,
  updateScannerCache,
  rollbackScannerCache,
  selectToolCandidate,
  toggleTool,
  cancelJob,
  retryJob,
  viewJob,
  refreshScannerStatus,
  retryScannerVerification,
  dashboardSettled,
}: {
  surface: RouteSurfaceAttributes;
  tools: ScannerTool[];
  lifecycle: ScannerLifecycle | null;
  preflight: ScannerPreflight | null;
  jobs: Job[];
  busy: boolean;
  prepareScanners: () => void;
  checkTools: () => void;
  updateScannerCache: (componentIds: ScannerCacheComponentId[], catalogDigest: string | null) => void;
  rollbackScannerCache: () => void;
  selectToolCandidate: (toolId: string) => void;
  toggleTool: (tool: ScannerTool) => void;
  cancelJob: (job: Job) => void;
  retryJob: (job: Job) => void;
  viewJob: (jobId: number) => void;
  refreshScannerStatus: () => void;
  retryScannerVerification: (verification: ScannerCacheVerification) => void;
  dashboardSettled: boolean;
}) {
  const [selectedComponents, setSelectedComponents] = useState<ScannerCacheComponentId[]>([]);
  const [maintenanceOpen, setMaintenanceOpen] = useState(false);
  const [runtimeRecoveryCopyStatus, setRuntimeRecoveryCopyStatus] = useState('');
  const counts = useMemo(() => ({
    artifacts: tools.reduce((sum, tool) => sum + (tool.artifacts_count || 0), 0),
    enabled: tools.filter((tool) => tool.enabled).length,
    real: tools.filter((tool) => tool.source === 'external').length,
    updates: tools.filter((tool) => tool.update_available).length,
  }), [tools]);
  const stableCheckTools = useEventCallback(checkTools);
  const stablePrepareScanners = useEventCallback(prepareScanners);
  const stableUpdateScannerCache = useEventCallback(updateScannerCache);
  const stableRollbackScannerCache = useEventCallback(rollbackScannerCache);
  const stableSelectToolCandidate = useEventCallback(selectToolCandidate);
  const stableToggleTool = useEventCallback(toggleTool);
  const stableCancelJob = useEventCallback(cancelJob);
  const stableRetryJob = useEventCallback(retryJob);
  const stableViewJob = useEventCallback(viewJob);
  const stableRetryVerification = useEventCallback(retryScannerVerification);
  const componentStates = useMemo(() => new Map(scannerCacheComponents.map((component) => [
    component.id,
    catalogComponentState(lifecycle?.catalog || null, component.id, lifecycle?.cache || null),
  ])), [lifecycle?.catalog, lifecycle?.cache]);
  const catalogNeedsRefresh = catalogNeedsRefreshAfterCache(lifecycle?.catalog || null, lifecycle?.cache || null);
  const catalogSelection = scannerDataCatalogSelection(lifecycle?.catalog || null);
  useEffect(() => { setSelectedComponents([]); }, [lifecycle?.catalog.job_id, catalogSelection?.digest]);
  const eligibleComponents = useMemo(() => scannerCacheComponents
    .filter((component) => componentStates.get(component.id) === 'candidate_available')
    .map((component) => component.id), [componentStates]);
  const actionableSelectedComponents = useMemo(() => selectedComponents
    .filter((componentId) => componentStates.get(componentId) === 'candidate_available'), [componentStates, selectedComponents]);
  const lockRefreshComponents = useMemo(
    () => requiredLockRefreshComponents(preflight, lifecycle?.catalog || null),
    [lifecycle?.catalog, preflight],
  );
  const lockRefreshSummary = lockRefreshComponents.map((component) => component.label).join(', ');
  const eligibleKey = eligibleComponents.join('|');
  useEffect(() => {
    const eligible = new Set(eligibleComponents);
    setSelectedComponents((current) => current.filter((componentId) => eligible.has(componentId)));
  }, [eligibleKey]);
  const cacheBusy = lifecycle ? activeWorkStatuses.has(lifecycle.cache.status) : true;
  const catalogBusy = lifecycle ? activeWorkStatuses.has(lifecycle.catalog.status) : true;
  const rollbackEligibility = preflight?.cache_rollback;
  const rollbackReady = Boolean(
    rollbackEligibility?.eligible
    && rollbackEligibility.target_generation === lifecycle?.cache.previous_generation,
  );
  const rollbackReason = rollbackEligibility?.reason || 'Checking rollback eligibility from the scanner runtime.';
  const preparationBusy = busy || cacheBusy || catalogBusy;
  const verificationReason = scannerVerificationDisabledReason(preflight);
  const activeVerification = preflight?.cache_verification;
  const preparationDisabledReason = verificationReason || scannerPreparationDisabledReason(
    preparationBusy,
  );
  const catalogDisabledReason = busy
    ? 'Catalog check is unavailable while another dashboard action is being reconciled.'
    : catalogBusy
      ? 'A curated catalog check is already in progress.'
      : null;
  const cacheUpdateDisabledReason = verificationReason || (busy
    ? 'Cache update is unavailable while another dashboard action is being reconciled.'
    : cacheBusy
      ? 'A scanner cache command is already in progress.'
      : !catalogSelection
        ? 'Check the reviewed catalog before selecting exact scanner data.'
      : catalogNeedsRefresh
        ? 'Check curated catalog after cache activity before selecting cache candidates.'
        : actionableSelectedComponents.length === 0
          ? 'Select at least one attested cache candidate to update.'
          : null);
  const toolStructure = useMemo(() => JSON.stringify(tools.map((tool) => tool.id)), [tools]);
  // Tool cards are compact and the curated inventory is bounded to nine. Two
  // paint slices keep a full inventory below the Fedora long-task boundary
  // without restoring the three-slice navigation-latency regression.
  const { committedCount, ready } = usePaintedBatch(tools.length, 5, toolStructure, dashboardSettled, 2);
  const blocked = surface.inert || !ready;
  const scannerRuntimeRecoveryCommand = 'python3 scripts/runtime-compose.py "${XDG_STATE_HOME:-$HOME/.local/state}/lomo-kodesec/runtime.env" up -d --no-deps --no-build --force-recreate --wait --wait-timeout 120 scanner';

  async function copyScannerRuntimeRecoveryCommand() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(scannerRuntimeRecoveryCommand);
      setRuntimeRecoveryCopyStatus('Scanner recovery command copied. Run it from the Lomo CodeSecurity checkout, then choose Refresh readiness.');
    } catch {
      setRuntimeRecoveryCopyStatus('Automatic copy is unavailable. Select the bounded command and copy it manually.');
    }
  }

  return (
    <section
      {...surface}
      aria-busy={ready ? undefined : true}
      aria-hidden={blocked ? true : undefined}
      className="stack"
      data-tools-committed-count={committedCount}
      data-tools-render-stage={ready ? 'ready' : 'cards'}
      inert={blocked}
    >
      <div className={`band scanner-preflight ${preflight?.ready ? 'scanner-preflight-ready' : 'scanner-preflight-blocked'}`}>
        <div className="band-head">
          <h2>{preflight?.ready ? 'Ready to Scan' : activeVerification ? 'Scanner readiness' : 'Prepare Scanners'}</h2>
          {preflight?.ready ? <CheckCircle2 size={18} aria-hidden="true" /> : <AlertTriangle size={18} aria-hidden="true" />}
        </div>
        <p className="helper-text">
          {preflight?.ready
            ? `All ${preflight.ready_tool_ids.length} enabled scanners passed their binary, data, rules, and offline-execution checks.`
            : activeVerification
              ? 'The scanner is available. Its retained cache must pass verification before complete scans can start; verification does not read source code.'
            : preflight?.recommended_action === 'enable_scanner'
              ? 'No scanner is enabled. Enable at least one tool below, then CodeSecurity will verify it before scanning.'
              : preflight?.recommended_action === 'repair_scanner_runtime'
                ? 'Complete scanning is blocked by a scanner binary or offline-execution prerequisite that data preparation cannot repair. Review the exact scanner below, restore the shipped runtime, then refresh.'
                : 'Complete scans wait until every enabled scanner has verified binaries, data, rules, and offline execution. Preparation never reads source code.'}
        </p>
        <div className="lifecycle-actions">
          {!preflight?.ready && preflight?.preparation_available ? (
            <button aria-describedby={preparationDisabledReason ? 'scanner-preparation-disabled-reason' : undefined} onClick={stablePrepareScanners} disabled={Boolean(preparationDisabledReason)}>
              {preparationBusy ? <ClockIcon size={16} /> : <PackageCheck size={16} />}
              {preparationBusy
                ? 'Preparation in progress'
                : 'Prepare all scanners'}
            </button>
          ) : null}
          {preflight?.active_generation ? (
            <span className="generation-summary" title={preflight.active_generation}>
              Validated runtime generation {preflight.active_generation.slice(0, 12)}
            </span>
          ) : null}
        </div>
        <DisabledReason id="scanner-preparation-disabled-reason" reason={activeVerification ? null : preparationDisabledReason} />
        {activeVerification ? (
          <ScannerCacheVerificationPanel verification={activeVerification} busy={busy} onRetry={stableRetryVerification} onRefresh={refreshScannerStatus} />
        ) : null}
        <ol className="preparation-steps" aria-label="Scanner preparation steps">
          <li data-complete={lifecycle?.catalog.status === 'completed'}>
            <strong>1. Check available scanner data</strong>
            <span>{catalogBusy ? 'Checking reviewed locks' : lifecycle?.catalog.status === 'completed' ? 'Reviewed locks checked' : 'Not checked yet'}</span>
          </li>
          <li data-complete={preflight?.ready || false}>
            <strong>2. Download and verify required data</strong>
            <span>{activeVerification
              ? activeVerification.state === 'verifying' ? 'Verifying existing data' : 'Verification needs attention'
              : cacheBusy
              ? 'Preparing now'
              : catalogBusy
                ? 'Starts only after the catalog passes'
              : lockRefreshComponents.length
                ? 'Last check requires updated source'
              : preflight?.recommended_action === 'repair_scanner_runtime'
                ? 'Waiting for scanner runtime'
                : preflight?.required_component_ids.length
                  ? `${preflight.required_component_ids.length} required`
                  : 'Complete'}</span>
          </li>
          <li data-complete={preflight?.ready || false}>
            <strong>3. Scan with complete coverage</strong>
            <span>{preflight?.ready ? 'Ready' : activeVerification ? 'Waiting for verification' : 'Waiting for preparation'}</span>
          </li>
        </ol>
        {!activeVerification && preflight?.blocked_tools.length ? (
          <div className="preflight-blocked-tools" role="status">
            <strong>{preflight.blocked_tools.length} blocked {preflight.blocked_tools.length === 1 ? 'scanner' : 'scanners'}</strong>
            <ul>
              {preflight.blocked_tools.map((tool) => (
                <li key={tool.id}>
                  <strong>{tool.name}</strong>
                  <span>{tool.blocking_reasons.join(' ')}</span>
                  {tool.required_component_ids.length ? <small>Requires: {tool.required_component_ids.join(', ')}</small> : null}
                  {tool.preparation_blocking_reasons.length ? (
                    <small>Scanner runtime required: {tool.preparation_blocking_reasons.join(' ')}</small>
                  ) : null}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {!activeVerification && lockRefreshComponents.length ? (
          <div className="inline-warning scanner-lock-refresh" role="status">
            <strong>The last scanner check requires a source update.</strong>{' '}
            That check found scanner data outside its reviewed validity window for {lockRefreshSummary}. Get refreshed reviewed CodeSecurity source and rerun the normal startup command with your existing state and editor options. Startup rebuilds changed inputs and preserves your installation data. After updating, choose <strong>Prepare all scanners</strong> to check the refreshed source. Each attempt checks the catalog before any download. Downloading the same data again will not make it current. Complete scanning remains blocked until preparation succeeds.
          </div>
        ) : null}
        {preflight?.recommended_action === 'repair_scanner_runtime' ? (
          <div className="inline-warning scanner-runtime-recovery" role="alert">
            <strong>Scanner runtime prerequisite required.</strong>{' '}
            Preparing databases and rules cannot repair a missing binary or offline execution path.
            <ol aria-label="Scanner runtime recovery steps">
              <li>Review the affected scanner and exact runtime reason above.</li>
              <li>From the Lomo CodeSecurity checkout, run the bounded command below. It recreates only the scanner from the already installed image; it does not build, pull, delete volumes, or change scanner data.</li>
              <li>Choose <strong>Refresh readiness</strong>. Complete scanning stays blocked until the live binary and offline-execution checks pass.</li>
            </ol>
            <div className="command-box">
              <span>Scanner recovery handoff</span>
              <code>{scannerRuntimeRecoveryCommand}</code>
              <button type="button" className="secondary-action" onClick={() => void copyScannerRuntimeRecoveryCommand()}>
                <Copy size={15} /> Copy recovery command
              </button>
            </div>
            <button type="button" className="secondary-action" onClick={refreshScannerStatus}>
              <RefreshCw size={15} /> Refresh readiness
            </button>
            {runtimeRecoveryCopyStatus ? <p className="status-note" role="status">{runtimeRecoveryCopyStatus}</p> : null}
          </div>
        ) : null}
      </div>

      <WorkbenchSummary label="Scanner summary" items={[
        ['Scanners', tools.length],
        ['Enabled', counts.enabled],
        ['Updates', counts.updates],
        ['Real Tools', counts.real],
        ['Artifacts', counts.artifacts],
      ]} />

      <details
        className="band scanner-maintenance"
        open={maintenanceOpen}
        onToggle={(event) => setMaintenanceOpen(event.currentTarget.open)}
      >
        <summary>
          <ChevronRight className="scanner-maintenance-chevron" size={18} aria-hidden="true" />
          <span>
            <strong>Advanced scanner maintenance</strong>
            <small>Catalog inspection, selected cache updates, and rollback</small>
          </span>
        </summary>
        <div className="scanner-maintenance-content">
        <div className="band-head">
          <h2>Scanner Lifecycle <InfoTip text="Catalog checks and cache updates are explicit durable jobs. The source-blind updater has no source mount, and the control API never contacts upstream services itself." /></h2>
          <button aria-describedby={catalogDisabledReason ? 'scanner-catalog-disabled-reason' : undefined} onClick={stableCheckTools} disabled={Boolean(catalogDisabledReason)}>
            <RefreshCw size={16} /> Check curated catalog
          </button>
        </div>
        <DisabledReason id="scanner-catalog-disabled-reason" reason={catalogDisabledReason} />
        <p className="helper-text">Lifecycle commands return immediately as persisted jobs. Cache activation is serialized with scans; catalog discovery can run alongside them.</p>
        <div className="lifecycle-grid" role="group" aria-label="Scanner lifecycle state">
          <LifecycleScopePanel busy={busy} jobs={jobs} onCancel={stableCancelJob} onRetry={stableRetryJob} onViewJob={stableViewJob} scope={lifecycle?.catalog || null} title="Curated catalog" />
          <LifecycleScopePanel busy={busy} jobs={jobs} onCancel={stableCancelJob} onRetry={stableRetryJob} onViewJob={stableViewJob} scope={lifecycle?.cache || null} title="Offline cache" />
        </div>
        <div className="lifecycle-actions">
          <button
            className="secondary-action"
            aria-describedby="scanner-cache-rollback-reason"
            disabled={busy || cacheBusy || !rollbackReady}
            onClick={stableRollbackScannerCache}
            title={rollbackReason}
          >
            <Undo2 size={16} /> Roll back cache
          </button>
          <span
            className="helper-text"
            id="scanner-cache-rollback-reason"
            role="status"
          >
            {rollbackReady ? rollbackReason : `Rollback unavailable: ${rollbackReason}`}
          </span>
        </div>
        {rollbackEligibility?.verification ? (
          <ScannerCacheVerificationPanel verification={rollbackEligibility.verification} busy={busy} onRetry={stableRetryVerification} onRefresh={refreshScannerStatus} />
        ) : null}
        <form
          className="scanner-cache-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (actionableSelectedComponents.length && !cacheUpdateDisabledReason && catalogSelection) {
              stableUpdateScannerCache([...actionableSelectedComponents].sort() as ScannerCacheComponentId[], catalogSelection.digest);
            }
          }}
        >
          <fieldset>
            <legend>Verified cache candidates</legend>
            <p>Select the exact reviewed data or rule components to stage, validate, and activate atomically.</p>
            {catalogSelection ? <p className="helper-text">{catalogSelection.mode === 'signed'
              ? `Signed scanner-data catalog ${catalogSelection.digest?.slice(0, 12)}. This exact selection is verified again before updating.`
              : 'Source-reviewed data definitions bundled with this build. Expired definitions require an updated reviewed source build; unsigned remote catalogs are never accepted.'}</p> : null}
            {catalogNeedsRefresh ? <p className="helper-text" role="status">Catalog needs refresh after cache activity. Choose <strong>Check curated catalog</strong> to inspect current candidates; this does not download scanner data. Scan readiness above remains independent.</p> : null}
            <div className="cache-component-grid">
              {scannerCacheComponents.map((component) => {
                const state = componentStates.get(component.id) || 'not_checked';
                const selectable = state === 'candidate_available';
                return (
                  <label className={`cache-component cache-component-${state}`} key={component.id}>
                    <input
                      type="checkbox"
                      checked={selectedComponents.includes(component.id)}
                      disabled={busy || cacheBusy || !selectable}
                      title={state === 'catalog_needs_refresh'
                        ? 'Choose Check curated catalog after cache activity before selecting candidates.'
                        : selectable
                        ? `Include ${component.label} in the next verified cache update.`
                        : state === 'current'
                          ? `${component.label} has no newer attested candidate in the current catalog receipt.`
                          : state === 'requires_lock_refresh'
                            ? `${component.label} needs refreshed reviewed CodeSecurity source and a rebuild before preparation.`
                            : `${component.label} is unavailable until a curated catalog check admits a candidate.`}
                      onChange={(event) => setSelectedComponents((current) => event.target.checked
                        ? [...current, component.id]
                        : current.filter((item) => item !== component.id))}
                    />
                    <span>
                      <strong>{component.label}</strong>
                      <small>{component.purpose}</small>
                    </span>
                    <StatusPill value={state === 'catalog_needs_refresh' ? 'not_checked' : state} label={state === 'catalog_needs_refresh' ? 'Catalog needs refresh' : undefined} />
                  </label>
                );
              })}
            </div>
          </fieldset>
          <div className="scanner-cache-submit">
            <span id="scanner-cache-update-summary" role="status">{actionableSelectedComponents.length} selected · only attested catalog candidates can be queued</span>
            <button aria-describedby={cacheUpdateDisabledReason ? 'scanner-cache-update-disabled-reason' : 'scanner-cache-update-summary'} disabled={Boolean(cacheUpdateDisabledReason)}>
              <Database size={16} /> Update selected cache
            </button>
          </div>
          <DisabledReason id="scanner-cache-update-disabled-reason" reason={cacheUpdateDisabledReason} />
        </form>
        </div>
      </details>

      <div className="band">
        <div className="band-head">
          <h2>Tool Readiness <InfoTip text="Binary, data, rules, and offline execution are independent requirements. Missing runtime facets are shown as not reported and never inferred ready." /></h2>
        </div>
        <p className="helper-text">To update scanners or expired definitions, get refreshed reviewed CodeSecurity source and rerun normal startup with your existing state and editor options. Prepare scanners afterward if needed. Candidate selection does not install a scanner. Internal Lite provides optional fallback checks.</p>
        <div className="tool-grid">
          {tools.slice(0, committedCount).map((tool) => (
            <ToolCard
              busy={busy}
              key={tool.id}
              onToggle={stableToggleTool}
              onSelectCandidate={stableSelectToolCandidate}
              tool={tool}
            />
          ))}
        </div>
      </div>
    </section>
  );
}

type SettingsFormSetter = (value: SettingsFormState | ((current: SettingsFormState) => SettingsFormState)) => void;
type SettingsSubmit = (event: FormEvent<HTMLFormElement>) => void;

type SettingsLoadState = 'loading' | 'success' | 'error';

type SettingsSourceBoundaryPanelProps = {
  config: RuntimeConfig | null;
  configLoadState: SettingsLoadState;
  onOpenProjects: () => void;
  routeReady: boolean;
};

const SettingsSourceBoundaryPanel = memo(function SettingsSourceBoundaryPanel({
  config,
  configLoadState,
  onOpenProjects,
  routeReady,
}: SettingsSourceBoundaryPanelProps) {
  const [replacementRoot, setReplacementRoot] = useState('');
  const [sourceOperation, setSourceOperation] = useState<'add' | 'remove'>('add');
  const [copyStatus, setCopyStatus] = useState('');
  const panelRef = useRef<HTMLDivElement>(null);
  const allowedRoots = useMemo(
    () => config ? safeAllowedSourceRoots(config.allowed_roots) : [],
    [config],
  );
  const authorizationCommand = useMemo(
    () => configLoadState !== 'success' || sourceOperation === 'remove' && (allowedRoots.length < 2 || !allowedRoots.includes(replacementRoot))
      ? null : sourceAuthorizationCommand(replacementRoot, config?.installation_id, sourceOperation),
    [replacementRoot, sourceOperation, allowedRoots, configLoadState, config?.installation_id],
  );

  useEffect(() => {
    if (!routeReady || window.location.hash !== '#source-boundary') return undefined;
    const frame = window.requestAnimationFrame(() => {
      panelRef.current?.scrollIntoView({ block: 'start' });
      panelRef.current?.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [routeReady]);

  async function copyAuthorizationCommand() {
    if (!authorizationCommand) return;
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(authorizationCommand);
      setCopyStatus('Guarded host command copied. Run it from the checkout with this installation’s STATE_DIR when using custom runtime state, then reload Settings.');
    } catch {
      setCopyStatus('Automatic copy is unavailable. Select the command and copy it manually.');
    }
  }

  return (
    <div
      className="band span-2 source-boundary-settings"
      id="source-boundary"
      ref={panelRef}
      tabIndex={-1}
    >
      <div className="band-head">
        <div>
          <h2>Source boundary</h2>
          <p className="helper-text">
            CodeSecurity rejects a folder before project or scan admission when it is outside the configured
            read-only source root. It never broadens a host mount automatically.
          </p>
        </div>
        <Shield size={18} aria-hidden="true" />
      </div>
      <div className="source-authorization">
        <div>
          <strong>Configured allowed source {allowedRoots.length === 1 ? 'root' : 'roots'}</strong>
          <p>
            These exact paths come from the authenticated runtime configuration. Source content is not returned
            by this Settings request.
          </p>
        </div>
        {configLoadState === 'loading' ? (
          <p className="status-note" role="status">Loading the configured source boundary.</p>
        ) : configLoadState === 'error' ? (
          <div className="inline-warning" role="alert">
            The source boundary is unavailable because runtime configuration did not load. Use Reload Settings;
            no path is inferred from projects or error text.
          </div>
        ) : allowedRoots.length ? (
          <ul className="source-boundary-roots" aria-label="Configured allowed source roots">
            {allowedRoots.map((root) => <li key={root}><code>{root}</code></li>)}
          </ul>
        ) : (
          <div className="inline-warning" role="alert">
            Runtime configuration returned no safe allowed source root. Scanning remains blocked until the host
            boundary is configured and Settings reloads successfully.
          </div>
        )}
        <ol className="source-boundary-steps" aria-label="Source boundary recovery steps">
          <li>
            If the repository is already inside a listed root, choose or register that exact folder in Projects.
          </li>
          <li>
            If a different source tree is required, enter one narrow absolute POSIX root below and review the
            generated host command.
          </li>
          <li>
            Run the command from the Lomo CodeSecurity checkout. Adding a root preserves all other roots;
            removal revokes only the exact selected root. Neither action deletes stored projects or findings. It
            recreates only scanner, API, and worker from installed images. Database and scanner-cache volumes are
            preserved; no image is rebuilt. Then reload Settings and retry the original IDE action.
          </li>
          <li>
            For custom runtime state, append this installation's exact <code>STATE_DIR="/path/to/your/state"</code>.
            The command checks installation <code>{config?.installation_id || 'unavailable'}</code> and refuses
            a different or missing runtime before creating or changing anything. The browser cannot discover your private state path.
          </li>
        </ol>
        <button type="button" className="secondary-action" onClick={onOpenProjects}>
          <GitBranch size={15} /> Choose or register an approved folder
        </button>
        <label>
          Source authorization action
          <select aria-label="Source authorization action" value={sourceOperation} onChange={(event) => {
            setSourceOperation(event.currentTarget.value as 'add' | 'remove');
            setReplacementRoot('');
            setCopyStatus('');
          }}>
            <option value="add">Add another narrow source root</option>
            <option value="remove">Remove an exact source authorization</option>
          </select>
        </label>
        <label>
          {sourceOperation === 'add' ? 'Additional source root' : 'Exact root to stop authorizing'}
          {sourceOperation === 'remove' ? <select aria-label="Source root to remove" value={replacementRoot} onChange={(event) => {
            setReplacementRoot(event.currentTarget.value);
            setCopyStatus('');
          }} aria-describedby="settings-source-authorization-help">
            <option value="">Choose a currently authorized root</option>
            {allowedRoots.map((root) => <option key={root} value={root}>{root}</option>)}
          </select> :
          <input
            aria-describedby="settings-source-authorization-help"
            value={replacementRoot}
            onChange={(event) => {
              setReplacementRoot(event.currentTarget.value);
              setCopyStatus('');
            }}
            placeholder="/Users/me/dev/team"
          />}
        </label>
        <p className="helper-text" id="settings-source-authorization-help">
          The browser cannot select or mount host folders. Broad roots such as /, /Users, /home, or /Volumes,
          control characters, Compose interpolation, and shell quoting characters remain rejected.
        </p>
        {authorizationCommand ? (
          <div className="source-authorization-command">
            <textarea aria-label="Source authorization host command" readOnly rows={3} value={authorizationCommand} />
            <button type="button" className="secondary-action" onClick={() => void copyAuthorizationCommand()}>
              <Copy size={15} /> Copy host command
            </button>
          </div>
        ) : (
          <div className="inline-warning" role="status">
            {configLoadState !== 'success' || !/^[a-f0-9]{12}$/u.test(config?.installation_id || '')
              ? 'Reload Settings to identify this installation before copying a source command.'
              : sourceOperation === 'remove'
              ? 'Choose an exact current root. To remove the last root, add its replacement first. Stored findings will remain available.'
              : 'Enter one narrow absolute POSIX path. The command remains unavailable for an unsafe or broad root.'}
          </div>
        )}
        {copyStatus ? <p className="status-note" role="status">{copyStatus}</p> : null}
      </div>
    </div>
  );
});

type SettingsRuntimePanelProps = {
  apiOrigin: string;
  configError: string | null;
  configLoadState: SettingsLoadState;
  health: Health | null;
  onReload: () => void;
  onSignOut: () => void;
  providerError: string | null;
  providerLoadState: SettingsLoadState;
  reloadDisabled: boolean;
  reloadStatus: string | null;
  sessionError: string | null;
  signingOut: boolean;
};

const SettingsRuntimePanel = memo(function SettingsRuntimePanel({
  apiOrigin,
  configError,
  configLoadState,
  health,
  onReload,
  onSignOut,
  providerError,
  providerLoadState,
  reloadDisabled,
  reloadStatus,
  sessionError,
  signingOut,
}: SettingsRuntimePanelProps) {
  const loading = configLoadState === 'loading' || providerLoadState === 'loading';
  const failed = configLoadState === 'error' || providerLoadState === 'error';
  return (
    <div className="band">
      <div className="band-head">
        <h2>Runtime</h2>
        <div className="band-head-actions">
          <button
            type="button"
            className="secondary-action"
            disabled={reloadDisabled || loading || signingOut}
            onClick={onReload}
            title={signingOut
              ? 'This browser session is being revoked.'
              : 'Reload runtime configuration and Advisor providers'}
          >
            <RefreshCw size={15} /> {loading ? 'Reloading Settings…' : 'Reload Settings'}
          </button>
          <button
            type="button"
            className="danger"
            disabled={signingOut}
            onClick={onSignOut}
            title="Durably revoke this browser session. Paired IDE clients remain authorized."
          >
            <LogOut size={15} /> {signingOut ? 'Signing out…' : 'Sign out this browser'}
          </button>
        </div>
      </div>
      <p className="helper-text">Reload keeps your unsaved edits and refreshes untouched settings and Advisor provider state.</p>
      <dl className="kv">
        <dt>API</dt>
        <dd title={apiOrigin}>{apiOrigin === window.location.origin ? 'same origin' : 'configured origin'}</dd>
        <dt>Version</dt>
        <dd>{health?.version || '-'}</dd>
        <dt>Database</dt>
        <dd>{health ? health.db ? 'ok' : 'down' : 'unknown'}</dd>
        <dt>Scanner</dt>
        <dd>{health ? health.scanner ? 'ok' : 'down' : 'unknown'}</dd>
      </dl>
      <WorkProcessingStatus health={health} />
      {loading ? <p className="status-note" role="status">Loading runtime configuration and Advisor providers.</p> : null}
      {failed ? (
        <p className="status-note error" role="alert">
          Settings data is incomplete. Controls are disabled; any draft values still displayed are not authoritative.
          {configLoadState === 'error' ? ` Runtime configuration failed: ${configError || 'unknown error'}` : ''}
          {providerLoadState === 'error' ? ` Advisor providers failed: ${providerError || 'unknown error'}` : ''}
          {' '}Use Reload Settings to retry both authoritative resources.
        </p>
      ) : null}
      {!loading && !failed && reloadStatus ? <p className="status-note" role="status">{reloadStatus}</p> : null}
      {sessionError ? <p className="status-note error" role="alert">{sessionError}</p> : null}
    </div>
  );
});

const SettingsBrowserPairingPanel = memo(function SettingsBrowserPairingPanel() {
  const [issue, setIssue] = useState<BrowserPairingTokenIssue | null>(null);
  const [hiddenAfterCopyExpiry, setHiddenAfterCopyExpiry] = useState<string | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState('');
  const [expiryReferenceTime, setExpiryReferenceTime] = useState(() => Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => setExpiryReferenceTime(Date.now()), 60_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const expiresAt = issue?.expires_at || hiddenAfterCopyExpiry;
    if (!expiresAt) return undefined;
    const timer = window.setTimeout(() => {
      setIssue((current) => current?.expires_at === expiresAt ? null : current);
      setHiddenAfterCopyExpiry((current) => current === expiresAt ? null : current);
      setCopyStatus('The one-time browser pairing key expired. Generate a new key to continue.');
      setExpiryReferenceTime(Date.now());
    }, pairingKeyExpiryDelay(expiresAt));
    return () => window.clearTimeout(timer);
  }, [hiddenAfterCopyExpiry, issue?.expires_at]);

  async function generatePairingKey() {
    setIssue(null);
    setCopyStatus('');
    setError(null);
    setIssuing(true);
    try {
      const next = await api.issueBrowserPairingToken();
      setExpiryReferenceTime(Date.now());
      setHiddenAfterCopyExpiry(null);
      setIssue(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIssuing(false);
    }
  }

  async function copyPairingKey() {
    if (!issue) return;
    if (pairingKeyIsExpired(issue.expires_at)) {
      setIssue(null);
      setCopyStatus('The one-time browser pairing key expired. Generate a new key to continue.');
      return;
    }
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API is unavailable.');
      await navigator.clipboard.writeText(issue.bootstrap_token);
      setHiddenAfterCopyExpiry(issue.expires_at);
      setIssue(null);
      setCopyStatus('Hidden after copying. Paste the one-time key only into the CodeSecurity Pair this browser screen.');
    } catch {
      setCopyStatus('Automatic copy is unavailable. Select the browser pairing key and copy it manually.');
    }
  }

  return (
    <div className="band span-2 browser-pairing-panel">
      <div className="band-head">
        <h2>Pair another browser</h2>
        <Shield size={18} />
      </div>
      <p className="helper-text">
        Use this from an already paired browser to authorize one additional local browser profile. Generate a 10-minute
        key, open CodeSecurity in the target browser, and paste the key into <strong>Pair this browser</strong>.
        VS Code's integrated browser is paired by the extension; use <strong>Open Dashboard</strong> or
        <strong> Pair integrated browser again</strong> in VS Code if it needs recovery. Generating another key
        invalidates the prior unused key. The resulting browser member remains authorized until it is individually
        revoked; the browser or operating system can still remove its local cookie.
      </p>
      <button
        type="button"
        onClick={() => void generatePairingKey()}
        disabled={issuing}
        title={issuing
          ? 'A new one-time browser pairing key is being generated.'
          : hiddenAfterCopyExpiry
            ? 'Generate a replacement one-time key. This invalidates the copied key if it has not been consumed.'
            : 'Generate a new one-time key for one other local browser profile.'}
      >
        <RefreshCw size={15} /> {issuing
          ? 'Generating browser pairing key…'
          : hiddenAfterCopyExpiry
            ? 'Generate replacement browser pairing key'
            : 'Generate new browser pairing key'}
      </button>
      {error ? <p className="status-note error" role="alert">{error}</p> : null}
      {issue ? (
        <div className="ide-pairing-result" role="region" aria-label="New browser pairing key">
          <p className="inline-warning" role="status">
            This plaintext key is shown only in the current page state. Refreshing the page or leaving Settings removes it.
          </p>
          <label>
            One-time browser pairing key
            <input aria-label="One-time browser pairing key" readOnly value={issue.bootstrap_token} />
          </label>
          <dl className="kv">
            <dt>Issued</dt>
            <dd><FullLocalTime value={issue.issued_at} /></dd>
            <dt>Expires</dt>
            <dd><ExpiryTime now={expiryReferenceTime} value={issue.expires_at} /></dd>
          </dl>
          <button type="button" onClick={() => void copyPairingKey()} disabled={pairingKeyIsExpired(issue.expires_at, expiryReferenceTime)}>
            <Copy size={15} /> Copy browser pairing key
          </button>
          {copyStatus ? <p className="status-note" role="status">{copyStatus}</p> : null}
          <ol className="pairing-steps">
            <li>Open CodeSecurity in the exact browser profile you want to pair.</li>
            <li>Paste this key into <strong>Pair this browser</strong> and choose <strong>Add this browser</strong>.</li>
          </ol>
          <p className="helper-text">
            If no paired browser remains, the installation owner can recover access with <code>make auth-info</code>.
          </p>
        </div>
      ) : null}
      {hiddenAfterCopyExpiry ? (
        <div className="ide-pairing-result" role="status">
          <p className="inline-warning">
            <strong>Hidden after copying.</strong> The plaintext key is no longer displayed on this page. Copying does not prove that the target browser consumed it; it remains usable once until its expiry unless you generate a replacement.
          </p>
          <dl className="kv">
            <dt>Expires</dt>
            <dd><ExpiryTime now={expiryReferenceTime} value={hiddenAfterCopyExpiry} /></dd>
          </dl>
          <p className="status-note">{copyStatus}</p>
        </div>
      ) : null}
      {!issue && !hiddenAfterCopyExpiry && copyStatus ? (
        <p className="status-note" role="status">{copyStatus}</p>
      ) : null}
    </div>
  );
});

type SettingsIdePairingPanelProps = {
  clients: IdeCapability[];
  clientsLoadState: 'loading' | 'ready' | 'unavailable';
  onClientsChange: (clients: IdeCapability[]) => void;
};

const SettingsIdePairingPanel = memo(function SettingsIdePairingPanel({ clients, clientsLoadState, onClientsChange }: SettingsIdePairingPanelProps) {
  const confirmAction = useConfirmation();
  const panelRef = useRef<HTMLDivElement>(null);
  const deepLinkSubscriptionRef = useRef<SettingsDeepLinkSubscription | null>(null);
  const enrollmentLoadGenerationRef = useRef(0);
  const [enrollments, setEnrollments] = useState<IdeEnrollment[]>([]);
  const [loadingEnrollments, setLoadingEnrollments] = useState(true);
  const [decidingEnrollmentId, setDecidingEnrollmentId] = useState<string | null>(null);
  const [enrollmentError, setEnrollmentError] = useState<string | null>(null);
  const [enrollmentStatus, setEnrollmentStatus] = useState('');
  const [clientError, setClientError] = useState<string | null>(null);
  const [clientStatus, setClientStatus] = useState('');
  const [refreshingClients, setRefreshingClients] = useState(false);
  const [revokingClientId, setRevokingClientId] = useState<string | null>(null);
  const [cancellingPendingClientId, setCancellingPendingClientId] = useState<string | null>(null);
  const [recoveringInvalidClientId, setRecoveringInvalidClientId] = useState<string | null>(null);
  const [expiryReferenceTime, setExpiryReferenceTime] = useState(() => Date.now());
  const clientActionBusy = refreshingClients
    || loadingEnrollments
    || Boolean(decidingEnrollmentId)
    || Boolean(revokingClientId)
    || Boolean(cancellingPendingClientId)
    || Boolean(recoveringInvalidClientId);
  const sortedClients = useMemo(() => [...clients].sort(compareIdeCapabilities), [clients]);

  useEffect(() => {
    const timer = window.setInterval(() => setExpiryReferenceTime(Date.now()), 60_000);
    return () => window.clearInterval(timer);
  }, []);

  const loadEnrollments = useEventCallback(async (signal?: AbortSignal): Promise<IdeEnrollment[]> => {
    const generation = enrollmentLoadGenerationRef.current + 1;
    enrollmentLoadGenerationRef.current = generation;
    setLoadingEnrollments(true);
    try {
      const next = await api.pendingIdeEnrollments(signal);
      if (generation === enrollmentLoadGenerationRef.current) {
        setEnrollments(next);
        setEnrollmentError(null);
        setExpiryReferenceTime(Date.now());
      }
      return next;
    } catch (err) {
      if (generation === enrollmentLoadGenerationRef.current && !isAbortError(err)) {
        setEnrollmentError(err instanceof Error ? err.message : String(err));
      }
      throw err;
    } finally {
      if (generation === enrollmentLoadGenerationRef.current) setLoadingEnrollments(false);
    }
  });

  const nextEnrollmentExpiry = useMemo(() => enrollments
    .map((enrollment) => enrollment.activation_expires_at)
    .filter((value) => !pairingKeyIsExpired(value))
    .sort()[0] || null, [enrollments]);

  useEffect(() => {
    if (!nextEnrollmentExpiry) return undefined;
    const timer = window.setTimeout(() => {
      setExpiryReferenceTime(Date.now());
      void loadEnrollments().catch(() => undefined);
    }, pairingKeyExpiryDelay(nextEnrollmentExpiry));
    return () => window.clearTimeout(timer);
  }, [loadEnrollments, nextEnrollmentExpiry]);

  useEffect(() => {
    const controller = new AbortController();
    void loadEnrollments(controller.signal).catch(() => undefined);
    return () => controller.abort();
  }, [loadEnrollments]);

  useEffect(() => {
    const refreshOnFocus = () => {
      if (document.visibilityState === 'visible') void loadEnrollments().catch(() => undefined);
    };
    const refreshOnExactDeepLink = () => {
      if (window.location.hash === '#ide-access') void loadEnrollments().catch(() => undefined);
    };
    window.addEventListener('focus', refreshOnFocus);
    window.addEventListener('hashchange', refreshOnExactDeepLink);
    const subscription = subscribeToExactSettingsDeepLink(
      window,
      '#ide-access',
      () => panelRef.current,
    );
    deepLinkSubscriptionRef.current = subscription;
    return () => {
      window.removeEventListener('focus', refreshOnFocus);
      window.removeEventListener('hashchange', refreshOnExactDeepLink);
      deepLinkSubscriptionRef.current = null;
      subscription.dispose();
    };
  }, [loadEnrollments]);

  useEffect(() => {
    deepLinkSubscriptionRef.current?.setReady(!loadingEnrollments);
  }, [loadingEnrollments]);

  async function refreshEnrollments(): Promise<IdeEnrollment[]> {
    return loadEnrollments();
  }

  async function decideEnrollment(enrollment: IdeEnrollment, decision: 'approved' | 'rejected') {
    if (decision === 'rejected' && !await confirmAction({
      title: `Reject ${enrollment.client_name}?`,
      message: `Reject IDE access request ${enrollment.verification_code} for "${enrollment.client_name}"? The pending authority cannot activate. The IDE may start a new request later.`,
      confirmLabel: 'Reject request',
      cancelLabel: 'Keep request pending',
      tone: 'danger',
    })) return;
    setDecidingEnrollmentId(enrollment.request_id);
    setEnrollmentError(null);
    setEnrollmentStatus('');
    try {
      await api.decideIdeEnrollment(enrollment, decision);
      setEnrollmentStatus(
        decision === 'approved'
          ? `${enrollment.client_name} was approved. VS Code can now finish activation without a pasted key. Refreshing current IDE access…`
          : `${enrollment.client_name} was rejected. Its pending authority cannot activate.`,
      );
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      try {
        await refreshEnrollments();
        setEnrollmentError(`${detail} Pending requests were refreshed; review the current code before deciding again.`);
      } catch (refreshError) {
        setEnrollmentError(`${detail} Pending requests could not be refreshed: ${refreshError instanceof Error ? refreshError.message : String(refreshError)}`);
      }
      setDecidingEnrollmentId(null);
      return;
    }
    try {
      // The enrollment read also updates its own error state. Let both reads
      // settle before publishing this committed decision's refresh outcome.
      const [enrollmentResult, clientResult] = await Promise.allSettled([
        refreshEnrollments(),
        api.ideCapabilities(),
      ]);
      if (enrollmentResult.status === 'rejected') throw enrollmentResult.reason;
      if (clientResult.status === 'rejected') throw clientResult.reason;
      const nextEnrollments = enrollmentResult.value;
      const nextClients = clientResult.value;
      onClientsChange(nextClients);
      setEnrollmentStatus(
        decision === 'approved'
          ? `${enrollment.client_name} was approved. VS Code can now finish activation without a pasted key. ${nextEnrollments.length} requests remain pending.`
          : `${enrollment.client_name} was rejected. Its pending authority cannot activate. ${nextEnrollments.length} requests remain pending.`,
      );
    } catch (refreshError) {
      setEnrollmentError(
        `${enrollment.client_name} was ${decision}, but current IDE access could not be refreshed: ${refreshError instanceof Error ? refreshError.message : String(refreshError)} Use Refresh IDE access before another decision.`,
      );
    } finally {
      setDecidingEnrollmentId(null);
    }
  }

  async function refreshClients(announce: boolean) {
    setRefreshingClients(true);
    setClientError(null);
    if (announce) setClientStatus('');
    try {
      const [clientsResult, enrollmentsResult] = await Promise.allSettled([
        api.ideCapabilities(),
        refreshEnrollments(),
      ]);
      if (clientsResult.status === 'rejected') throw clientsResult.reason;
      const next = clientsResult.value;
      onClientsChange(next);
      if (enrollmentsResult.status === 'rejected') {
        // The pending-request read owns its visible error. Keep successfully
        // refreshed members even when that separate collection is unavailable.
        setClientStatus('Paired IDE clients refreshed. Pending requests could not be refreshed.');
        return;
      }
      const nextEnrollments = enrollmentsResult.value;
      if (announce) {
        const valid = validIdeCapabilities(next);
        const invalidCount = next.length - valid.length;
        setClientStatus(
          `IDE access refreshed. ${nextEnrollments.length} pending approval. ${valid.filter((client) => client.active).length} active. ${invalidCount} invalid.`,
        );
      }
    } catch (err) {
      setClientError(err instanceof Error ? err.message : String(err));
    } finally {
      setRefreshingClients(false);
    }
  }

  async function reconcileIdeClientsAfterMutationFailure(error: unknown): Promise<boolean> {
    if (!isApiError(error) || !ideCapabilityMutationRequiresAuthoritativeRefresh(error.code)) return false;
    const detail = error.message;
    try {
      const next = await api.ideCapabilities();
      onClientsChange(next);
      setClientError(`${detail} The authoritative IDE client list was refreshed; review the exact profile slot state before acting again.`);
    } catch (refreshError) {
      const refreshDetail = refreshError instanceof Error ? refreshError.message : String(refreshError);
      setClientError(`${detail} The authoritative IDE client list could not be refreshed: ${refreshDetail}`);
    }
    return true;
  }

  async function revokeClient(client: IdeValidCapability) {
    const clientName = ideClientDisplayName(client);
    const activeGeneration = client.active_generation === null ? 'none' : String(client.active_generation);
    const pendingGeneration = client.pending_generation === null ? 'none' : String(client.pending_generation);
    if (!await confirmAction({
      title: `Revoke ${clientName}?`,
      message: `Revoke and allow re-pair for "${clientName}" in profile slot "${client.id}"? This revokes the retained capability, disconnects CodeSecurity in connected VS Code windows if any, cancels unfinished setup, and permits only this exact profile slot to establish a new generation. Current state: latest ${client.latest_generation}, retained active ${activeGeneration}, pending ${pendingGeneration}. Stored scans and findings remain.`,
      confirmLabel: 'Revoke and allow re-pair',
      cancelLabel: 'Keep IDE paired',
      tone: 'danger',
    })) return;
    setRevokingClientId(client.id);
    setClientError(null);
    setClientStatus('');
    let revoked = false;
    try {
      await api.revokeIdeCapability(client);
      revoked = true;
      const next = await api.ideCapabilities();
      onClientsChange(next);
      setClientStatus(`${clientName} was revoked and may now be paired again. The authoritative IDE client list was refreshed.`);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      if (await reconcileIdeClientsAfterMutationFailure(err)) return;
      setClientError(revoked
        ? `${clientName} was revoked and may be paired again, but the current IDE client list could not be refreshed: ${detail}`
        : detail);
    } finally {
      setRevokingClientId(null);
    }
  }

  async function cancelPendingClient(client: IdeValidCapability) {
    const pendingGeneration = client.pending_generation;
    if (pendingGeneration === null) return;
    const clientName = idePendingClientDisplayName(client);
    const retainedAuthority = client.active && client.active_generation !== null
      ? `Active generation ${client.active_generation} remains authorized.`
      : 'No active generation currently remains authorized.';
    if (!await confirmAction({
      title: `Cancel generation ${pendingGeneration} setup?`,
      message: `Cancel unfinished generation ${pendingGeneration} setup for "${clientName}" in profile slot "${client.id}"? This consumes only that exact pending setup and interrupts activation if VS Code is still completing it. ${retainedAuthority}`,
      confirmLabel: 'Cancel unfinished setup',
      cancelLabel: 'Keep setup active',
      tone: 'warning',
    })) return;
    setCancellingPendingClientId(client.id);
    setClientError(null);
    setClientStatus('');
    let cancelled = false;
    try {
      const result = await api.cancelPendingIdeCapability(client.id, pendingGeneration);
      cancelled = result.cancelled;
      const next = await api.ideCapabilities();
      onClientsChange(next);
      setClientStatus(`Unfinished setup for ${clientName} was cancelled. Any previously active generation remains authorized.`);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      if (await reconcileIdeClientsAfterMutationFailure(err)) return;
      setClientError(cancelled
        ? `Unfinished setup for ${clientName} was cancelled, but the current IDE client list could not be refreshed: ${detail}`
        : detail);
    } finally {
      setCancellingPendingClientId(null);
    }
  }

  async function recoverInvalidClient(client: IdeInvalidCapability) {
    if (!await confirmAction({
      title: 'Remove invalid IDE client record?',
      message: `Remove invalid IDE client record for profile slot "${client.id}"? CodeSecurity will delete only the exact invalid server record displayed here if it has not changed. This permits this profile slot to pair from generation 1 again. Stored scans and findings remain.`,
      confirmLabel: 'Remove invalid record',
      cancelLabel: 'Keep record',
      tone: 'danger',
    })) return;
    setRecoveringInvalidClientId(client.id);
    setClientError(null);
    setClientStatus('');
    let recovered = false;
    try {
      await api.recoverInvalidIdeCapability(client);
      recovered = true;
      const next = await api.ideCapabilities();
      onClientsChange(next);
      setClientStatus(`Invalid IDE client record for profile slot ${client.id} was removed. That exact slot may now be paired again.`);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      if (await reconcileIdeClientsAfterMutationFailure(err)) return;
      setClientError(recovered
        ? `The invalid IDE client record for profile slot ${client.id} was removed, but the authoritative IDE client list could not be refreshed: ${detail}`
        : detail);
    } finally {
      setRecoveringInvalidClientId(null);
    }
  }

  return (
    <div
      className="band span-2 ide-pairing-panel"
      id="ide-access"
      ref={panelRef}
      tabIndex={-1}
      aria-busy={clientActionBusy}
    >
      <div className="band-head">
        <h2>IDE access</h2>
        <Code2 size={18} />
      </div>
      <p className="helper-text">
        CodeSecurity asks for access from VS Code automatically. Compare the verification code shown in the editor with
        the request below, then approve only the profile you recognize. No secret is copied or pasted. An approved
        capability stays in that profile&apos;s OS-account-private application storage and works across editor and
        control-stack restarts until you revoke it.
      </p>
      <p className="helper-text">
        A verification code identifies the waiting request; it is not a credential. Approval is bound to the exact
        profile slot, authority generation, requested scopes, and 10-minute deadline shown here.
      </p>
      <div className="ide-client-management">
        <div className="ide-client-management-head">
          <div>
            <h3>Pending requests</h3>
            <p>Approve only when the name and verification code match the visible VS Code request.</p>
          </div>
          <button
            type="button"
            className="secondary-action"
            disabled={clientActionBusy}
            onClick={() => void refreshClients(true)}
            title="Reload pending requests and active IDE clients from durable state"
          >
            <RefreshCw size={15} /> {refreshingClients || loadingEnrollments ? 'Refreshing access…' : 'Refresh IDE access'}
          </button>
        </div>
        {loadingEnrollments ? <p className="status-note" role="status">Loading pending IDE requests…</p> : null}
        {!loadingEnrollments && enrollments.length ? (
          <ul className="ide-client-list" aria-label="Pending IDE access requests">
            {enrollments.map((enrollment) => {
              const deciding = decidingEnrollmentId === enrollment.request_id;
              const presentation = ideEnrollmentPresentation(enrollment, expiryReferenceTime);
              return (
                <li className="ide-client-row ide-enrollment-row" key={enrollment.request_id} aria-busy={deciding}>
                  <div className="ide-client-main">
                    <strong>{enrollment.client_name}</strong>
                    <span className={`pill pill-${presentation.tone}`}>{presentation.label}</span>
                    <span className="visually-hidden">Verification code </span>
                    <code className="ide-enrollment-code">
                      {enrollment.verification_code}
                    </code>
                    <span className="ide-client-detail">
                      Generation {enrollment.generation} · expires <ExpiryTime now={expiryReferenceTime} value={enrollment.activation_expires_at} />
                    </span>
                    <span className="ide-client-detail">
                      Requested scopes: {enrollment.scopes.join(', ')}
                    </span>
                  </div>
                  <div className="ide-client-actions">
                    <button
                      type="button"
                      disabled={clientActionBusy || presentation.expired}
                      onClick={() => void decideEnrollment(enrollment, 'approved')}
                      title={presentation.decisionDisabledReason || `Approve only if ${enrollment.verification_code} matches the visible request in ${enrollment.client_name}`}
                    >
                      <CheckCircle2 size={15} /> {deciding ? 'Applying decision…' : 'Approve'}
                    </button>
                    <button
                      type="button"
                      className="danger"
                      disabled={clientActionBusy || presentation.expired}
                      onClick={() => void decideEnrollment(enrollment, 'rejected')}
                      title={presentation.decisionDisabledReason || `Reject access request ${enrollment.verification_code} for ${enrollment.client_name}`}
                    >
                      <XCircle size={15} /> Reject
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        ) : null}
        {!loadingEnrollments && !enrollmentError && !enrollments.length ? (
          <div className="empty-state">No IDE access requests are waiting. Open CodeSecurity in VS Code to request access automatically.</div>
        ) : null}
        {enrollmentStatus ? <p className="status-note" role="status" aria-live="polite">{enrollmentStatus}</p> : null}
        {enrollmentError ? <p className="status-note error" role="alert">{enrollmentError}</p> : null}
      </div>
      <div className="ide-client-management">
        <div className="ide-client-management-head">
          <div>
            <h3>Paired IDE clients</h3>
            <p>Capabilities remain authorized across editor and control-stack restarts until you explicitly revoke them.</p>
          </div>
        </div>
        {sortedClients.length ? (
          <ul className="ide-client-list" aria-label="Paired IDE clients">
            {sortedClients.map((client) => {
              if (!isValidIdeCapability(client)) {
                const recovering = recoveringInvalidClientId === client.id;
                const descriptionId = `invalid-ide-client-${client.id}-description`;
                return (
                  <li
                    className="ide-client-row ide-client-invalid-row"
                    key={client.id}
                    aria-busy={recovering}
                    aria-describedby={descriptionId}
                  >
                    <div className="ide-client-main">
                      <strong><AlertTriangle aria-hidden="true" size={16} /> Invalid IDE client record</strong>
                      <span className="pill pill-unavailable">Repair required</span>
                      <code title={client.id}>{client.id}</code>
                      <span className="ide-client-detail" id={descriptionId}>
                        CodeSecurity cannot trust or use this record. Source navigation and retained authority are disabled.
                        Remove only this exact invalid record, then let that VS Code profile request access again.
                      </span>
                    </div>
                    <div className="ide-client-actions">
                      <button
                        type="button"
                        className="danger"
                        disabled={clientActionBusy}
                        onClick={() => void recoverInvalidClient(client)}
                        aria-label={`Remove invalid IDE client record for profile slot ${client.id} and allow re-pair`}
                        aria-describedby={descriptionId}
                        title={recovering
                          ? `Invalid IDE client record ${client.id} is being removed before the authoritative list refreshes.`
                          : `Delete only the exact invalid server record for profile slot ${client.id} after confirmation`}
                      >
                        <Trash2 size={15} /> {recovering ? 'Removing invalid record…' : 'Remove invalid record'}
                      </button>
                    </div>
                  </li>
                );
              }
              const status = ideClientStatus(client);
              const name = ideClientTargetLabel(client, sortedClients);
              const revoking = revokingClientId === client.id;
              const cancellingPending = cancellingPendingClientId === client.id;
              const hasPendingSetup = client.pending_generation !== null;
              const canRevokeForRepair = client.active_generation !== null && !client.revoked;
              return (
                <li className="ide-client-row" key={client.id}>
                  <div className="ide-client-main">
                    <strong>{name}</strong>
                    <span className={`pill pill-${status.tone}`}>{status.label}</span>
                    <code title={client.id}>{client.id}</code>
                    <span className="ide-client-detail">
                      Latest generation {client.latest_generation}
                      {client.active_generation !== null
                        ? <> · {client.active ? 'active' : 'retained'} generation {client.active_generation}</>
                        : ' · no active generation'}
                    </span>
                    {hasPendingSetup ? (
                      <span className="ide-client-detail">
                        Generation {client.pending_generation} {client.pending_activation ? 'is waiting for durable activation' : 'did not activate before its deadline'}
                        {client.pending_client_name && client.pending_client_name.trim() !== name
                          ? <> for {client.pending_client_name.trim()}</>
                          : null}
                        {client.pending_activation_expires_at
                          ? <> · activation deadline <ExpiryTime now={expiryReferenceTime} value={client.pending_activation_expires_at} /></>
                          : null}
                      </span>
                    ) : null}
                  </div>
                  <div className="ide-client-actions">
                    {hasPendingSetup ? (
                      <button
                        type="button"
                        className="secondary-action"
                        disabled={clientActionBusy}
                        onClick={() => void cancelPendingClient(client)}
                        aria-label={`Cancel pending setup for ${name} in profile slot ${client.id}`}
                        title={cancellingPending
                          ? `Unfinished setup for ${name} is being cancelled before the list refreshes.`
                          : `Cancel only generation ${client.pending_generation} setup after confirmation; any active generation remains authorized`}
                      >
                        {cancellingPending ? 'Cancelling setup…' : 'Cancel pending setup'}
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="danger"
                      disabled={!canRevokeForRepair || clientActionBusy}
                      onClick={() => void revokeClient(client)}
                      aria-label={`Revoke and allow re-pair for ${name} in profile slot ${client.id}`}
                      title={!canRevokeForRepair
                        ? client.revoked
                          ? 'This client is already revoked and may request access again.'
                          : 'No retained active capability remains to revoke. Cancel unfinished setup separately when shown.'
                        : revoking
                          ? `${name} is being revoked; the client list will refresh before another action is enabled.`
                          : revokingClientId
                            ? 'Wait until the current IDE capability revocation and list refresh finish.'
                            : refreshingClients
                              ? 'Wait until current IDE capability state finishes refreshing.'
                              : `Revoke ${name}, disconnect CodeSecurity in connected VS Code windows, cancel pending setup, and allow this profile slot to request access again`}
                    >
                      <Trash2 size={15} /> {revoking ? 'Revoking…' : 'Revoke and allow re-pair'}
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        ) : clientsLoadState === 'ready' ? (
          <div className="empty-state">No paired IDE clients were returned by the latest workbench refresh. Open CodeSecurity in VS Code to request access.</div>
        ) : (
          <div className="empty-state" role="status">
            {clientsLoadState === 'loading' || refreshingClients
              ? 'Loading paired IDE clients…'
              : 'Paired IDE clients could not be loaded. Use Refresh IDE access to try again.'}
          </div>
        )}
        {clientStatus ? <p className="status-note" role="status" aria-live="polite">{clientStatus}</p> : null}
        {clientError ? <p className="status-note error" role="alert">IDE client action failed. {clientError}</p> : null}
      </div>
    </div>
  );
});

const SettingsAdvisorStatusPanel = memo(function SettingsAdvisorStatusPanel({
  collection,
  config,
  health,
  observationsCurrent,
}: {
  collection: AdvisorProviderCollection | null;
  config: RuntimeConfig | null;
  health: Health | null;
  observationsCurrent: boolean;
}) {
  const resolvedProvider = collection?.providers.find((provider) => provider.id === collection.resolution.provider_id) || null;
  const advisorAvailable = health?.ai.available;
  const advisorMode = config?.ai_mode ?? health?.ai.mode ?? '-';
  const advisorBaseUrl = config?.ollama_base_url ?? health?.ai.base_url ?? '-';
  const advisorModel = config?.ollama_model ?? health?.ai.model ?? '-';
  const advisorThinking = config?.ollama_thinking ?? health?.ai.thinking ?? false;
  const advisorReason = health?.ai.reason;
  const advisorModels = health?.ai.models?.length ? health.ai.models : config?.ollama_models ?? [];
  return (
    <div className="band">
      <div className="band-head">
        <h2>Advisor Route</h2>
        <Bot size={18} />
      </div>
      {!health ? <p className="helper-text" role="status">Current Advisor status is unknown. Provider selection and model values below are last loaded configuration, not a current connection test.</p> : null}
      {health && !observationsCurrent ? <p className="helper-text" role="status">Control-plane health recovered. Reload Settings to verify the retained provider selection; current transport diagnostics alone do not confirm that selection.</p> : null}
      <dl className="kv">
        <dt>Resolved provider</dt>
        <dd>{resolvedProvider?.name || 'none'}</dd>
        <dt>Resolved transport</dt>
        <dd>{collection?.resolution.transport || 'unavailable'}</dd>
        <dt>Resolved target</dt>
        <dd>{resolvedProvider ? advisorProviderDestination(resolvedProvider) : '-'}</dd>
        <dt>Resolved model</dt>
        <dd>{resolvedProvider?.model || '-'}</dd>
        <dt>Resolved model digest</dt>
        <dd>{resolvedProvider?.model_digest || '-'}</dd>
        <dt>Resolution reason</dt>
        <dd>{!observationsCurrent ? 'Unknown; last loaded provider selection is retained.' : advisorReasonText(
          collection?.resolution.reason,
          resolvedProvider ? 'The selected local provider is eligible.' : 'No eligible local provider is available.',
        )}</dd>
        <dt>Policy mode</dt>
        <dd>{advisorMode}</dd>
        <dt>Local transport probe</dt>
        <dd>{advisorAvailable === undefined ? 'unknown' : advisorAvailable ? 'yes' : 'no'}</dd>
        <dt>Local transport URL</dt>
        <dd>{advisorBaseUrl}</dd>
        <dt>Local transport model</dt>
        <dd>{advisorModel}</dd>
        <dt>Local transport thinking</dt>
        <dd>{advisorThinking ? 'on' : 'off'}</dd>
        <dt>Local transport reason</dt>
        <dd>{!health ? 'Unknown; refresh the control-plane health check.' : advisorReasonText(advisorReason, advisorAvailable ? 'The local transport is connected.' : 'The local transport is unavailable.')}</dd>
        <dt>Local transport models</dt>
        <dd>
          {advisorModels.length ? (
            <ul className="advisor-transport-models" aria-label="Detected local transport models">
              {advisorModels.map((model) => <li key={model}>{model}</li>)}
            </ul>
          ) : '-'}
        </dd>
      </dl>
      <p className="helper-text">Local transport values are endpoint diagnostics, not provider-selection truth. Provider selection is the last loaded server resolution; every Advisor action rechecks the exact route before admission.</p>
    </div>
  );
});

type SettingsAdvisorConfigPanelProps = {
  configAvailable: boolean;
  error: string | null;
  form: SettingsFormState;
  onSubmit: SettingsSubmit;
  saving: boolean;
  setForm: SettingsFormSetter;
  status: string | null;
};

const SettingsAdvisorConfigPanel = memo(function SettingsAdvisorConfigPanel({
  configAvailable,
  error,
  form,
  onSubmit,
  saving,
  setForm,
  status,
}: SettingsAdvisorConfigPanelProps) {
  return (
    <div className="band span-2">
      <div className="band-head">
        <h2>Advisor Policy <InfoTip text="Provider endpoints and exact model identities are managed in the ordered provider cards above. These settings control when Advisor runs after a provider is active." /></h2>
        <Bot size={18} />
      </div>
      <p className="helper-text">Choose automatic, required, or disabled Advisor behavior. Saving this policy never tests, activates, or changes a provider.</p>
      <form className="form advisor-policy-form" data-settings-form="advisor" onSubmit={onSubmit}>
        <label>
          Mode
          <select
            value={form.ai_mode}
            onChange={(event) => setForm((current) => ({ ...current, ai_mode: event.target.value as RuntimeConfig['ai_mode'] }))}
            disabled={!configAvailable || saving}
          >
            <option value="auto">Automatic when available</option>
            <option value="on">Required</option>
            <option value="off">Disabled</option>
          </select>
        </label>
        <label>
          Auto Triage Limit
          <input
            type="number"
            min="0"
            max="50"
            value={form.auto_triage_limit}
            onChange={(event) => setForm((current) => ({ ...current, auto_triage_limit: Number(event.target.value) }))}
            disabled={!configAvailable || saving}
            required
          />
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={form.ollama_thinking}
            onChange={(event) => setForm((current) => ({ ...current, ollama_thinking: event.target.checked }))}
            disabled={!configAvailable || saving}
          />
          <span>Thinking mode</span>
        </label>
        <button disabled={!configAvailable || saving}>
          <Save size={16} /> Save Advisor Policy
        </button>
      </form>
      {error ? <p className="status-note error" role="alert">{error}</p> : null}
      {status ? <p className="status-note" role="status">{status}</p> : null}
    </div>
  );
});

type SettingsGatePanelProps = {
  configAvailable: boolean;
  error: string | null;
  form: SettingsFormState;
  onSetCustom: (update: Partial<Pick<SettingsFormState, 'gate_active' | 'gate_max_critical' | 'gate_max_high' | 'gate_block_secrets' | 'gate_apply_to_existing'>>) => void;
  onSetPreset: (value: RuntimeConfig['gate_preset']) => void;
  onSubmit: SettingsSubmit;
  saving: boolean;
  setForm: SettingsFormSetter;
  status: string | null;
};

const SettingsGatePanel = memo(function SettingsGatePanel({
  configAvailable,
  error,
  form,
  onSetCustom,
  onSetPreset,
  onSubmit,
  saving,
  setForm,
  status,
}: SettingsGatePanelProps) {
  const gatePreset = gatePresetDefinitions[form.gate_preset];
  const gateSummary = form.gate_active
    ? `fail when critical > ${gateLimit(form.gate_max_critical)}, high > ${gateLimit(form.gate_max_high)}${form.gate_block_secrets ? ', or secrets are detected' : ''}`
    : 'observe only, never fail scans';
  return (
    <div className="band span-2 gate-policy-panel">
      <div className="band-head">
        <h2>Gate Defaults <InfoTip text="A gate is the local pass/fail policy evaluated after every scan. Settings here become the default for new projects; choose apply to existing projects when you want to rewrite current project policies." /></h2>
        <Shield size={18} />
      </div>
      <p className="helper-text">Use presets for common CI security gate maturity levels, or switch to Custom for team-specific thresholds. `-1` means the severity is recorded but does not block the gate.</p>
      <div className="preset-strip" role="group" aria-label="Gate preset">
        {(['observe', 'baseline', 'strict', 'custom'] as RuntimeConfig['gate_preset'][]).map((presetKey) => {
          const preset = gatePresetDefinitions[presetKey];
          return (
            <button
              type="button"
              key={presetKey}
              className={form.gate_preset === presetKey ? 'active' : ''}
              onClick={() => onSetPreset(presetKey)}
              disabled={!configAvailable || saving}
              title={preset.description}
            >
              <span>{preset.label}</span>
              <small>{preset.description}</small>
            </button>
          );
        })}
      </div>
      <form className="form gate-form" data-settings-form="gate" onSubmit={onSubmit}>
        <label className="check">
          <input
            type="checkbox"
            checked={form.gate_active}
            onChange={(event) => onSetCustom({ gate_active: event.target.checked })}
            disabled={!configAvailable || saving}
          />
          <span>Enable gate evaluation</span>
        </label>
        <label>
          Max critical
          <input
            type="number"
            min="-1"
            max="999"
            value={form.gate_max_critical}
            onChange={(event) => onSetCustom({ gate_max_critical: Number(event.target.value) })}
            disabled={!configAvailable || saving}
            required
          />
        </label>
        <label>
          Max high
          <input
            type="number"
            min="-1"
            max="999"
            value={form.gate_max_high}
            onChange={(event) => onSetCustom({ gate_max_high: Number(event.target.value) })}
            disabled={!configAvailable || saving}
            required
          />
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={form.gate_block_secrets}
            onChange={(event) => onSetCustom({ gate_block_secrets: event.target.checked })}
            disabled={!configAvailable || saving}
          />
          <span>Block secret findings</span>
        </label>
        <label className="check apply-existing">
          <input
            type="checkbox"
            checked={form.gate_apply_to_existing}
            onChange={(event) => setForm((current) => ({ ...current, gate_apply_to_existing: event.target.checked }))}
            disabled={!configAvailable || saving}
          />
          <span>Apply to existing projects on save</span>
        </label>
        <button disabled={!configAvailable || saving}>
          <Save size={16} /> Save Gate
        </button>
      </form>
      {error ? <p className="status-note error" role="alert">{error}</p> : null}
      {status ? <p className="status-note" role="status">{status}</p> : null}
      <div className="gate-summary">
        <strong>{gatePreset.label}</strong>
        <span>{gateSummary}</span>
      </div>
    </div>
  );
});

type SettingsComponentsPanelProps = {
  config: RuntimeConfig | null;
  observationsCurrent: boolean;
  error: string | null;
  form: SettingsFormState;
  onSubmit: SettingsSubmit;
  saving: boolean;
  setForm: SettingsFormSetter;
  status: string | null;
};

type RuntimeComponent = RuntimeConfig['components'][number];

function loopbackComponentUrl(value: string): string | null {
  try {
    const candidate = new URL(value, window.location.origin);
    if (!['http:', 'https:'].includes(candidate.protocol)) return null;
    if (!['127.0.0.1', 'localhost', '[::1]'].includes(candidate.hostname)) return null;
    return candidate.toString();
  } catch {
    return null;
  }
}

function componentPresentation(component: RuntimeComponent, observationsCurrent: boolean) {
  const desiredEnabled = component.desired_state === 'enabled';
  const observed = component.observed_state;
  const reachable = component.reachable;
  const confirmedDesiredOff = observed === 'not_observed' || observed === 'disabled';
  const state = !desiredEnabled
    ? confirmedDesiredOff
      ? 'disabled'
      : 'warning'
    : component.healthy && reachable && observed === 'running'
      ? 'ready'
      : observed === 'unhealthy' || reachable || component.required
        ? 'failure'
        : 'warning';
  const label = component.id;
  const message = component.message;
  const url = loopbackComponentUrl(component.url);
  if (!observationsCurrent) return {
    desiredEnabled,
    label,
    message: `Current status is unknown. Last reported: ${message}`,
    observed: 'unknown',
    state: 'warning',
    url: null,
  };
  return { desiredEnabled, label, message, observed, state, url: reachable ? url : null };
}

const SettingsComponentsPanel = memo(function SettingsComponentsPanel({ config, observationsCurrent, error, form, onSubmit, saving, setForm, status }: SettingsComponentsPanelProps) {
  const [copyStatus, setCopyStatus] = useState('');
  const applyCommand = config?.component_apply_command || 'make apply-components COMPONENTS=core';
  const schemaStatus = config?.schema_init;
  useEffect(() => setCopyStatus(''), [applyCommand]);

  async function copyApplyCommand() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API is unavailable.');
      await navigator.clipboard.writeText(applyCommand);
      setCopyStatus('Apply command copied. Run it from the Lomo CodeSecurity checkout.');
    } catch {
      setCopyStatus('Apply command could not be copied. Select the command and copy it manually.');
    }
  }

  return (
    <div className="band span-2">
      <div className="band-head">
        <h2>Components <InfoTip text="These toggles persist desired local profiles. Apply the shown command on the host because the API container intentionally does not mount the Docker socket." /></h2>
        <ServerCog size={18} />
      </div>
      <p className="helper-text">Choose desired optional services here, then apply the shown command from the host terminal. It stops deselected optional services without deleting their data, then starts core and the selected profiles once. Saving preferences alone does not change containers. Credentials remain in the owner-only runtime file and are never returned to the browser.</p>
      <form className="form component-form" data-settings-form="components" onSubmit={onSubmit}>
        <label className="check">
          <input
            type="checkbox"
            checked={form.component_monitoring_enabled}
            onChange={(event) => setForm((current) => ({ ...current, component_monitoring_enabled: event.target.checked }))}
            disabled={!config || saving}
          />
          <span>Monitoring: Grafana and Prometheus</span>
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={form.component_git_proxy_enabled}
            onChange={(event) => setForm((current) => ({ ...current, component_git_proxy_enabled: event.target.checked }))}
            disabled={!config || saving}
          />
          <span>Git proxy: Gitea</span>
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={form.component_db_admin_enabled}
            onChange={(event) => setForm((current) => ({ ...current, component_db_admin_enabled: event.target.checked }))}
            disabled={!config || saving}
          />
          <span>Database UI: Adminer</span>
        </label>
        <button disabled={!config || saving}>
          <Save size={16} /> Save Desired Components
        </button>
      </form>
      {error ? <p className="status-note error" role="alert">{error}</p> : null}
      {status ? <p className="status-note" role="status">{status}</p> : null}
      <div className="command-box">
        <span>Apply command</span>
        <code>{applyCommand}</code>
        <button
          type="button"
          onClick={() => void copyApplyCommand()}
          title="Copy command"
        >
          <Copy size={15} /> Copy
        </button>
      </div>
      {copyStatus ? <p className="status-note" role="status">{copyStatus}</p> : null}
      {!observationsCurrent ? <p className="helper-text" role="status">Current component observations are unverified. Restore control-plane health, then choose Reload Settings to verify components. Reload preserves your unsaved edits.</p> : null}
      <div className="component-grid">
        {(config?.components || []).map((component) => {
          const presentation = componentPresentation(component, observationsCurrent);
          const content = (
            <>
              <strong>{presentation.label}</strong>
              <span>{component.profile} · desired {presentation.desiredEnabled ? 'on' : 'off'} · observed {presentation.observed.replace(/[-_]/gu, ' ')}</span>
              <small>{presentation.message}</small>
            </>
          );
          return presentation.url ? (
            <a className={`component-card component-${presentation.state}`} href={presentation.url} key={component.id} target="_blank" rel="noreferrer">
              {content}
            </a>
          ) : (
            <div className={`component-card component-${presentation.state}`} key={component.id}>
              {content}
            </div>
          );
        })}
      </div>
      {schemaInitIsVerified(schemaStatus) ? (
        <p className="component-one-shot-note" data-schema-init-state="completed">
          <strong>schema-init</strong> {schemaStatus.message}{' '}
          Initial schema <code>{schemaStatus.schema_id}</code> has fingerprint{' '}
          <code>{schemaStatus.schema_fingerprint}</code>. Initialized{' '}
          <time dateTime={schemaStatus.initialized_at}>{schemaStatus.initialized_at}</time> and verified at API startup.
        </p>
      ) : (
        <p className="component-one-shot-note component-one-shot-unverified" data-schema-init-state="unverified">
          <strong>schema-init status is unverified.</strong> {schemaStatus?.message || 'Runtime configuration has not loaded.'} This one-shot operation is not user-startable from the workbench.
        </p>
      )}
    </div>
  );
});

const SettingsLinksPanel = memo(function SettingsLinksPanel({ config, observationsCurrent }: { config: RuntimeConfig | null; observationsCurrent: boolean }) {
  const links = [
    { id: 'grafana', label: 'Grafana' },
    { id: 'gitea', label: 'Gitea' },
    { id: 'prometheus', label: 'Prometheus' },
  ].map(({ id, label }) => {
    const component = config?.components.find((candidate) => candidate.id === id) || null;
    const presentation = component ? componentPresentation(component, observationsCurrent) : null;
    const available = Boolean(
      component
      && presentation?.desiredEnabled
      && presentation.state === 'ready'
      && presentation.url,
    );
    return { available, component, label, url: presentation?.url || null };
  });
  return (
    <div className="band span-2">
      <div className="band-head">
        <h2>Links</h2>
        <ExternalLink size={18} />
      </div>
      <div className="links">
        <a href={`${API_BASE}/openapi.json`} target="_blank" rel="noreferrer">OpenAPI schema</a>
        {links.map(({ available, component, label, url }) => available && url ? (
          <a href={url} key={label} target="_blank" rel="noreferrer">{label}</a>
        ) : (
          <span
            aria-disabled="true"
            className="disabled-link"
            key={label}
            title={!observationsCurrent ? 'Current component status is unknown. Refresh health and Reload Settings.' : component?.message || 'Component state has not loaded.'}
          >
            {label} · {!observationsCurrent ? 'status unknown' : component?.desired_enabled ? 'not available' : 'disabled'}
          </span>
        ))}
      </div>
    </div>
  );
});

type SettingsProps = {
  surface: RouteSurfaceAttributes;
  health: Health | null;
  healthLossEpoch: number;
  ideCapabilities: IdeCapability[];
  ideCapabilitiesLoadState: 'loading' | 'ready' | 'unavailable';
  onIdeCapabilitiesChange: (clients: IdeCapability[]) => void;
  onOpenProjects: () => void;
  onAdvisorDiscoveryRetry: () => void;
  onSaved: () => Promise<void>;
};

function Settings({ surface, health, healthLossEpoch, ideCapabilities, ideCapabilitiesLoadState, onIdeCapabilitiesChange, onOpenProjects, onAdvisorDiscoveryRetry, onSaved }: SettingsProps) {
  const confirmAction = useConfirmation();
  const apiOrigin = useMemo(() => new URL(API_BASE || '/', window.location.origin).origin, []);
  const [config, setConfig] = useState<RuntimeConfig | null>(null);
  const persistedConfigRef = useRef<RuntimeConfig | null>(null);
  const healthLossEpochRef = useRef(healthLossEpoch);
  healthLossEpochRef.current = healthLossEpoch;
  const [configObservationEpoch, setConfigObservationEpoch] = useState<number | null>(null);
  const [form, setForm] = useState<SettingsFormState>({
    ai_mode: 'auto' as RuntimeConfig['ai_mode'],
    ollama_base_url: 'http://host.docker.internal:11434',
    ollama_model: 'qwen3:8b',
    ollama_thinking: false,
    auto_triage_limit: 5,
    component_monitoring_enabled: false,
    component_git_proxy_enabled: false,
    component_db_admin_enabled: false,
    gate_preset: 'baseline' as RuntimeConfig['gate_preset'],
    gate_active: true,
    gate_max_critical: 0,
    gate_max_high: -1,
    gate_block_secrets: true,
    gate_apply_to_existing: false,
  });
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [statusTarget, setStatusTarget] = useState<SettingsSaveTarget>('advisor');
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [settingsErrorTarget, setSettingsErrorTarget] = useState<SettingsSaveTarget>('advisor');
  const [configLoadError, setConfigLoadError] = useState<string | null>(null);
  const [renderStage, setRenderStage] = useState<SettingsRenderStage>('components');
  const [configLoadState, setConfigLoadState] = useState<SettingsLoadState>('loading');
  const [providerCollection, setProviderCollection] = useState<AdvisorProviderCollection | null>(null);
  const [providerLoadState, setProviderLoadState] = useState<SettingsLoadState>('loading');
  const [providerSaving, setProviderSaving] = useState(false);
  const [providerError, setProviderError] = useState<string | null>(null);
  const [providerStatus, setProviderStatus] = useState<string | null>(null);
  const [providerOperation, setProviderOperation] = useState<AdvisorProviderOperation | null>(null);
  const [localCatalog, setLocalCatalog] = useState<AdvisorLocalCatalog | null>(null);
  const [localDetectionError, setLocalDetectionError] = useState<string | null>(null);
  const [localDetectionLoading, setLocalDetectionLoading] = useState(false);
  const [reloadStatus, setReloadStatus] = useState<string | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [signingOut, setSigningOut] = useState(false);
  const settingsLoadGenerationRef = useRef(0);
  const localDetectionRequestRef = useRef(0);
  const localAutoDetectionKeyRef = useRef('');
  const localProviderMutationRef = useRef(false);
  const settingsAuthoritative = configLoadState === 'success' && providerLoadState === 'success';
  const runtimeObservationsCurrent = health !== null && configLoadState === 'success' && configObservationEpoch === healthLossEpoch;

  const applyLoadedConfig = useCallback((next: RuntimeConfig, observedEpoch: number) => {
    setConfig(next);
    setConfigObservationEpoch(observedEpoch);
    const previous = persistedConfigRef.current;
    persistedConfigRef.current = next;
    setForm(current => previous
      ? mergeScopedSettingsResponse(null, current, previous, next)
      : settingsFormFromConfig(next));
  }, []);

  const reloadSettings = useCallback(async (announce: boolean) => {
    onAdvisorDiscoveryRetry();
    const generation = ++settingsLoadGenerationRef.current;
    const observedEpoch = healthLossEpochRef.current;
    const installationId = persistedConfigRef.current?.installation_id;
    localDetectionRequestRef.current += 1;
    setConfig(null);
    setProviderCollection(null);
    setConfigLoadState('loading');
    setProviderLoadState('loading');
    setConfigLoadError(null);
    setProviderError(null);
    setLocalDetectionLoading(false);
    setLocalCatalog(null);
    setLocalDetectionError(null);
    setSettingsError(null);
    setStatus(null);
    setProviderStatus(null);
    setReloadStatus(null);
    const [configResult, providerResult] = await Promise.allSettled([
      api.config().then(value => requireLoadedSettingsResponse(value, installationId)).catch((error: unknown) => {
        if (error instanceof SyntaxError) throw new Error(invalidSettingsReadMessage);
        throw error;
      }),
      api.advisorProviders(),
    ]);
    if (generation !== settingsLoadGenerationRef.current) return;

    if (configResult.status === 'fulfilled') {
      applyLoadedConfig(configResult.value, observedEpoch);
      setConfigLoadState('success');
    } else {
      setConfigLoadError(configResult.reason instanceof Error ? configResult.reason.message : String(configResult.reason));
      setConfigLoadState('error');
    }
    if (providerResult.status === 'fulfilled') {
      setProviderCollection(providerResult.value);
      setProviderLoadState('success');
    } else {
      setProviderError(providerResult.reason instanceof Error ? providerResult.reason.message : String(providerResult.reason));
      setProviderLoadState('error');
    }
    if (announce && configResult.status === 'fulfilled' && providerResult.status === 'fulfilled') {
      setReloadStatus('Settings reloaded from durable runtime configuration and Advisor provider state.');
    }
  }, [applyLoadedConfig, onAdvisorDiscoveryRetry]);

  const loadProviders = useCallback(async () => {
    const next = await api.advisorProviders();
    setProviderCollection(next);
    setProviderLoadState('success');
    return next;
  }, []);

  async function activateLocalAdvisorProvider(providerId: string, expectedRevision: number): Promise<Job> {
    const idempotencyKey = createCommandIdempotencyKey();
    try {
      return await api.commandAdvisorProvider(
        providerId, expectedRevision, 'activate', false, null, idempotencyKey,
      );
    } catch (err) {
      if (localProviderWriteReconciliationReason(err) !== 'transport_uncertain') throw err;
      return api.commandAdvisorProvider(
        providerId, expectedRevision, 'activate', false, null, idempotencyKey,
      );
    }
  }

  useEffect(() => {
    if (renderStage === 'ready') return undefined;
    if (renderStage === 'components' && (configLoadState === 'loading' || providerLoadState === 'loading')) return undefined;
    // The complete bounded form and both terminal load states have committed.
    // Keep readiness latched across reloads: loading still blocks mutations,
    // without hiding the route or repeating its initial focus handoff.
    setRenderStage((current) => current === 'components' ? 'ready' : current);
  }, [configLoadState, providerLoadState, renderStage]);

  useEffect(() => {
    void reloadSettings(false);
    return () => {
      settingsLoadGenerationRef.current += 1;
    };
  }, [reloadSettings]);

  useEffect(() => {
    const current = providerOperation;
    if (!current || !advisorProviderActiveStatuses.has(current.job.status)) return undefined;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void api.job(current.job.id).then(async (nextJob) => {
        if (cancelled) return;
        if (!advisorProviderActiveStatuses.has(nextJob.status)) {
          await loadProviders();
          if (cancelled) return;
          setProviderOperation({ ...current, job: nextJob });
          setProviderStatus(nextJob.status === 'completed'
            ? `${current.action === 'test' ? 'Connection test' : current.action === 'activate' ? 'Activation' : 'Disconnect'} completed.`
            : `${current.action === 'test' ? 'Connection test' : current.action === 'activate' ? 'Activation' : 'Disconnect'} ended as ${nextJob.status}.`);
          await onSaved();
        } else {
          setProviderOperation({ ...current, job: nextJob });
        }
      }).catch((err) => {
        if (!cancelled) setProviderError(err instanceof Error ? err.message : String(err));
      });
    }, 1_000);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [loadProviders, onSaved, providerOperation]);

  async function saveAdvisorProvider(provider: AdvisorProviderInput, existing: boolean, expectedRevision: number) {
    setProviderSaving(true);
    setProviderError(null);
    setProviderStatus(null);
    try {
      if (!settingsAuthoritative) throw new Error('Settings are not authoritative yet. Reload Settings before changing an Advisor provider.');
      if (!providerCollection) throw new Error('Advisor provider configuration is not available yet.');
      if (providerCollection.revision !== expectedRevision) throw new Error('Advisor provider configuration changed. Review its current settings before saving.');
      if (!existing && providerCollection.providers.length >= 8) throw new Error('The bounded provider chain already contains eight profiles.');
      const next = existing
        ? await api.updateAdvisorProvider(provider.id, expectedRevision, provider)
        : await api.createAdvisorProvider(expectedRevision, provider);
      setProviderCollection(next);
      setProviderStatus(provider.transport === 'local'
        ? `${provider.name} ${existing ? 'updated' : 'added'} at priority ${provider.priority + 1}. Choose a detected model above and use it locally to verify and activate the exact revision.`
        : `${provider.name} ${existing ? 'updated' : 'added'} at priority ${provider.priority + 1}. Test the connection before activation.`);
    } catch (err) {
      setProviderError(err instanceof Error ? err.message : String(err));
      if (isApiError(err) && err.status === 409) {
        try { await loadProviders(); } catch { /* retain the original revision-conflict error */ }
      }
      throw err;
    } finally {
      setProviderSaving(false);
    }
  }

  const detectLocalAdvisorModels = useCallback(async (announce = true) => {
    if (announce) onAdvisorDiscoveryRetry();
    const request = ++localDetectionRequestRef.current;
    setLocalDetectionLoading(true);
    setLocalDetectionError(null);
    if (announce) setProviderStatus(null);
    try {
      if (!settingsAuthoritative) throw new Error('Settings are not authoritative yet. Reload Settings before detecting local Ollama.');
      const catalog = normalizeAdvisorLocalCatalog(await api.localAdvisorModels());
      if (request !== localDetectionRequestRef.current) return;
      setLocalCatalog(catalog);
      const localCount = catalog.models.filter((model) => model.storage === 'local_weights').length;
      const cloudCount = catalog.models.length - localCount;
      if (announce) {
        setProviderStatus(`Local Ollama detection completed: ${localCount} model${localCount === 1 ? '' : 's'} with local weights and ${cloudCount} cloud-only stub${cloudCount === 1 ? '' : 's'}.`);
      }
    } catch (err) {
      if (request !== localDetectionRequestRef.current) return;
      setLocalCatalog(null);
      setLocalDetectionError(err instanceof Error ? err.message : String(err));
    } finally {
      if (request === localDetectionRequestRef.current) setLocalDetectionLoading(false);
    }
  }, [onAdvisorDiscoveryRetry, settingsAuthoritative]);

  useEffect(() => {
    if (!settingsAuthoritative) return;
    const key = localAdvisorAutoDetectionKey(settingsLoadGenerationRef.current, health);
    if (!key || localAutoDetectionKeyRef.current === key) return;
    localAutoDetectionKeyRef.current = key;
    void detectLocalAdvisorModels(false);
  }, [detectLocalAdvisorModels, health, settingsAuthoritative]);

  async function useDetectedLocalAdvisor(model: AdvisorLocalModel) {
    if (localProviderMutationRef.current) return;
    localProviderMutationRef.current = true;
    setProviderSaving(true);
    setProviderError(null);
    setProviderStatus(null);
    try {
      if (!settingsAuthoritative) throw new Error('Settings are not authoritative yet. Reload Settings before configuring local Ollama.');
      if (!providerCollection) throw new Error('Advisor provider configuration is not available yet.');
      const provider = detectedLocalProviderInput(model, providerCollection.providers);
      const existing = providerCollection.providers.find((candidate) => (
        candidate.id === provider.id && candidate.transport === 'local'
      ));
      let next = providerCollection;
      const writeRequired = !existing
        || !existing.enabled
        || existing.model !== provider.model
        || existing.model_digest !== provider.model_digest;
      if (writeRequired) {
        try {
          next = existing
            ? await api.updateAdvisorProvider(provider.id, providerCollection.revision, provider)
            : await api.createAdvisorProvider(providerCollection.revision, provider);
        } catch (err) {
          const reconciliationReason = localProviderWriteReconciliationReason(err);
          if (!reconciliationReason) throw err;
          const authoritative = await loadProviders();
          if (!exactEnabledLocalProvider(provider.id, model, authoritative.providers)) {
            throw new Error(reconciliationReason === 'authority_conflict'
              ? 'Local Advisor provider state changed and does not contain the exact detected model. Review the authoritative provider state before trying again.'
              : 'The local provider write response was uncertain and authoritative state does not confirm the exact detected model. No mutation was repeated.');
          }
          next = authoritative;
        }
      }
      setProviderCollection(next);
      const configured = exactEnabledLocalProvider(provider.id, model, next.providers);
      if (!configured) throw new Error('The detected local model was not preserved in the authoritative provider state. Reload Settings and try again.');
      const job = await activateLocalAdvisorProvider(configured.id, next.revision);
      setProviderOperation({ providerId: configured.id, action: 'activate', job });
      setProviderStatus(`Local Advisor setup queued as job #${job.id}. It verifies and activates ${model.name} without sending source or finding content.`);
      await loadProviders();
      await onSaved();
      setLocalDetectionError(null);
    } catch (err) {
      setProviderError(null);
      setLocalDetectionError(err instanceof Error ? err.message : String(err));
      if (isApiError(err) && err.status === 409) {
        try { await loadProviders(); } catch { /* retain the original revision-conflict error */ }
      }
    } finally {
      setProviderSaving(false);
      localProviderMutationRef.current = false;
    }
  }

  async function toggleAdvisorProvider(provider: AdvisorProvider) {
    if (!settingsAuthoritative || !providerCollection) return;
    setProviderSaving(true);
    setProviderError(null);
    setProviderStatus(null);
    try {
      const next = await api.updateAdvisorProvider(provider.id, providerCollection.revision, {
        ...advisorProviderInputFromProfile(provider),
        enabled: !provider.enabled,
      });
      setProviderCollection(next);
      setProviderStatus(`${provider.name} ${provider.enabled ? 'disabled' : 'enabled'}.`);
    } catch (err) {
      setProviderError(err instanceof Error ? err.message : String(err));
      if (isApiError(err) && err.status === 409) {
        try { await loadProviders(); } catch { /* retain the original revision-conflict error */ }
      }
    } finally {
      setProviderSaving(false);
    }
  }

  async function removeAdvisorProvider(provider: AdvisorProvider) {
    if (!settingsAuthoritative || !providerCollection || !await confirmAction({
      title: `Remove Advisor provider ${provider.name}?`,
      message: `Remove Advisor provider ${provider.name}? Stored scan and Advisor results are unchanged.`,
      confirmLabel: 'Remove provider',
      cancelLabel: 'Keep provider',
      tone: 'danger',
    })) return;
    setProviderSaving(true);
    setProviderError(null);
    setProviderStatus(null);
    try {
      const next = await api.deleteAdvisorProvider(provider.id, providerCollection.revision);
      setProviderCollection(next);
      setProviderStatus(`${provider.name} removed from the provider chain.`);
    } catch (err) {
      setProviderError(err instanceof Error ? err.message : String(err));
      if (isApiError(err) && err.status === 409) {
        try { await loadProviders(); } catch { /* retain the original revision-conflict error */ }
      }
    } finally {
      setProviderSaving(false);
    }
  }

  async function commandAdvisorProvider(provider: AdvisorProvider, action: AdvisorProviderAction) {
    if (!settingsAuthoritative || !providerCollection) return;
    const remoteActivation = action === 'activate' && provider.transport !== 'local';
    const sourceDisclosureApproval = remoteActivation ? remoteProviderActivationApproval(provider) : null;
    if (remoteActivation) {
      const approved = await confirmAction({
        title: `Activate remote Advisor provider ${provider.name}?`,
        message: remoteProviderActivationConfirmation(provider),
        confirmLabel: 'Activate remote provider',
        cancelLabel: 'Keep current provider',
        tone: 'warning',
      });
      if (!approved) return;
    }
    setProviderSaving(true);
    setProviderError(null);
    setProviderStatus(null);
    try {
      const job = action === 'activate' && provider.transport === 'local'
        ? await activateLocalAdvisorProvider(provider.id, providerCollection.revision)
        : await api.commandAdvisorProvider(
          provider.id,
          providerCollection.revision,
          action,
          remoteActivation,
          sourceDisclosureApproval,
        );
      setProviderOperation({ providerId: provider.id, action, job });
      setProviderStatus(`${action === 'test' ? 'Connection test' : action === 'activate' ? 'Activation' : 'Disconnect'} queued as job #${job.id}.`);
      await loadProviders();
      await onSaved();
    } catch (err) {
      setProviderError(err instanceof Error ? err.message : String(err));
      if (isApiError(err) && err.status === 409) {
        try { await loadProviders(); } catch { /* retain the original revision-conflict error */ }
      }
    } finally {
      setProviderSaving(false);
    }
  }

  async function cancelAdvisorProviderOperation() {
    if (!settingsAuthoritative || !providerOperation) return;
    setProviderSaving(true);
    setProviderError(null);
    try {
      const job = await api.cancelJob(providerOperation.job.id);
      setProviderOperation({ ...providerOperation, job });
      setProviderStatus(`Cancellation requested for job #${job.id}. Waiting for connector cleanup.`);
      if (!advisorProviderActiveStatuses.has(job.status)) await loadProviders();
      await onSaved();
    } catch (err) {
      setProviderError(err instanceof Error ? err.message : String(err));
    } finally {
      setProviderSaving(false);
    }
  }

  async function retryAdvisorProviderOperation() {
    if (!settingsAuthoritative || !providerCollection || !providerOperation) return;
    setProviderSaving(true);
    setProviderError(null);
    try {
      const revision = providerOperation.job.revision;
      if (!Number.isSafeInteger(revision) || !revision || revision < 1) throw new Error('The failed operation has no valid retry revision. Refresh Settings.');
      const job = await api.retryJob(providerOperation.job.id, revision);
      setProviderOperation({ ...providerOperation, job });
      const provider = providerCollection.providers.find((candidate) => candidate.id === providerOperation.providerId);
      setProviderStatus(provider?.transport === 'local'
        ? `Original local setup snapshot retry queued as job #${job.id}. After a profile edit, choose the detected model and use it locally to create a command for the new revision.`
        : `Original command snapshot retry queued as job #${job.id}. Profile edits require a new Test connection command.`);
      await onSaved();
    } catch (err) {
      setProviderError(err instanceof Error ? err.message : String(err));
    } finally {
      setProviderSaving(false);
    }
  }

  async function onSaveAdvisor(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const rawTarget = event.currentTarget.dataset.settingsForm;
    const saveTarget: SettingsSaveTarget = rawTarget === 'gate' || rawTarget === 'components' ? rawTarget : 'advisor';
    const applyGateToExisting = form.gate_apply_to_existing;
    const observedEpoch = healthLossEpochRef.current;
    setSaving(true);
    setStatusTarget(saveTarget);
    setStatus(null);
    setSettingsErrorTarget(saveTarget);
    setSettingsError(null);
    try {
      if (!settingsAuthoritative) throw new Error('Settings are not authoritative yet. Reload Settings before saving changes.');
      if (!config) throw new Error('Runtime configuration is not available yet.');
      const payload = buildScopedSettingsPayload(saveTarget, form);
      const next = await api.updateScopedConfig(saveTarget, payload)
        .then(value => requireSavedSettingsResponse(value, payload, config.installation_id))
        .catch((error: unknown) => {
          if (!isApiError(error) || error.status >= 500) throw new Error(unconfirmedSettingsSaveMessage);
          throw error;
        });
      persistedConfigRef.current = next;
      setConfig(next);
      setConfigObservationEpoch(observedEpoch);
      setForm((current) => mergeScopedSettingsResponse(saveTarget, current, config, next));
      setStatus(saveTarget === 'advisor'
        ? 'Advisor policy saved. Provider profiles and the active provider are unchanged.'
        : saveTarget === 'gate'
          ? `Gate defaults saved as ${next.gate_preset}${applyGateToExisting ? ' and applied to existing projects' : ''}.`
          : `Desired components saved. Run ${next.component_apply_command} from the Lomo CodeSecurity checkout to reconcile containers.`);
      await onSaved();
    } catch (err) {
      setSettingsError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }

  const setGatePreset = useCallback((value: RuntimeConfig['gate_preset']) => {
    const preset = gatePresetDefinitions[value];
    setForm((current) => ({
      ...current,
      gate_preset: value,
      gate_active: preset.active,
      gate_max_critical: preset.maxCritical,
      gate_max_high: preset.maxHigh,
      gate_block_secrets: preset.blockSecrets,
    }));
  }, []);

  const setCustomGate = useCallback((update: Partial<Pick<SettingsFormState, 'gate_active' | 'gate_max_critical' | 'gate_max_high' | 'gate_block_secrets' | 'gate_apply_to_existing'>>) => {
    setForm((current) => ({ ...current, gate_preset: 'custom', ...update }));
  }, []);

  const signOutBrowser = useCallback(async () => {
    if (!await confirmAction({
      title: 'Sign out this browser?',
      message: 'Sign out this browser? This durably revokes only this browser session. Paired IDE clients remain authorized until you explicitly revoke them.',
      confirmLabel: 'Sign out browser',
      cancelLabel: 'Stay signed in',
      tone: 'warning',
    })) return;
    setSessionError(null);
    setSigningOut(true);
    try {
      await api.logout();
    } catch (err) {
      setSessionError(err instanceof Error ? err.message : String(err));
      setSigningOut(false);
    }
  }, [confirmAction]);
  const stableSubmit = useEventCallback(onSaveAdvisor);

  const settingsReloading = configLoadState === 'loading' || providerLoadState === 'loading';
  const routeReady = renderStage === 'ready';
  const routeBlocked = surface.inert || !routeReady;
  const advisorDeepLinkReady = settingsDeepLinkReady(routeReady, surface.inert, providerLoadState);

  return (
    <section
      {...surface}
      aria-busy={!routeReady || settingsReloading ? true : undefined}
      aria-hidden={routeBlocked ? true : undefined}
      className="settings-workbench"
      data-settings-config-state={configLoadState}
      data-settings-provider-state={providerLoadState}
      data-settings-render-stage={renderStage}
      inert={routeBlocked}
    >
      <div className="settings-directory">
        <nav aria-label="Settings sections">
          <a href="#settings-protection">Protection</a>
          <a href="#settings-workspaces">Workspace access</a>
          <a href="#settings-advisor">Advisor</a>
          <a href="#settings-access">Trusted access</a>
          <a href="#settings-system">Installation</a>
        </nav>
        <button className="secondary-action" type="button"
          disabled={settingsReloading || saving || providerSaving || Boolean(providerOperation && advisorProviderActiveStatuses.has(providerOperation.job.status))}
          onClick={() => void reloadSettings(true)}>
          <RefreshCw size={14} /> Refresh settings data
        </button>
      </div>
      <SettingsSection id="settings-protection" title="Protection" description="Choose what blocks an outgoing push and the default policy for new projects.">
        <SettingsGitPushProtection routeReady={routeReady && !surface.inert} />
        <SettingsGatePanel
          configAvailable={Boolean(config) && settingsAuthoritative}
          error={settingsErrorTarget === 'gate' ? settingsError : null}
          form={form}
          onSetCustom={setCustomGate}
          onSetPreset={setGatePreset}
          onSubmit={stableSubmit}
          saving={saving || !settingsAuthoritative}
          setForm={setForm}
          status={statusTarget === 'gate' ? status : null}
        />
      </SettingsSection>
      <SettingsSection id="settings-workspaces" title="Workspace access" description="Review the narrow source roots this installation can scan.">
        <SettingsSourceBoundaryPanel
          config={config}
          configLoadState={configLoadState}
          onOpenProjects={onOpenProjects}
          routeReady={routeReady}
        />
      </SettingsSection>
      <SettingsSection id="settings-advisor" title="Advisor" description="Choose an optional provider and its scope. Scanner evidence still owns the gate.">
        <SettingsAdvisorStatusPanel collection={providerCollection} config={config} health={health} observationsCurrent={runtimeObservationsCurrent} />
        <SettingsAdvisorProvidersPanel
          collection={providerCollection}
          deepLinkReady={advisorDeepLinkReady}
          error={providerError}
          localCatalog={localCatalog}
          localDetectionError={localDetectionError}
          localDetectionLoading={localDetectionLoading}
          loadState={providerLoadState}
          mutationsEnabled={settingsAuthoritative}
          operation={providerOperation}
          saving={providerSaving}
          status={providerStatus}
          onCancelOperation={cancelAdvisorProviderOperation}
          onUseDetectedLocal={useDetectedLocalAdvisor}
          onCommand={commandAdvisorProvider}
          onDetectLocal={detectLocalAdvisorModels}
          onRemove={removeAdvisorProvider}
          onRetryOperation={retryAdvisorProviderOperation}
          onSave={saveAdvisorProvider}
          onToggle={toggleAdvisorProvider}
        />
        <SettingsAdvisorConfigPanel
          configAvailable={Boolean(config) && settingsAuthoritative}
          error={settingsErrorTarget === 'advisor' ? settingsError : null}
          form={form}
          onSubmit={stableSubmit}
          saving={saving || !settingsAuthoritative}
          setForm={setForm}
          status={statusTarget === 'advisor' ? status : null}
        />
      </SettingsSection>
      <SettingsSection id="settings-access" title="Trusted access" description="Manage the browsers and editors connected to this installation.">
        <SettingsBrowserPairingPanel />
        <SettingsBrowserMembers />
        <SettingsIdePairingPanel clients={ideCapabilities} clientsLoadState={ideCapabilitiesLoadState} onClientsChange={onIdeCapabilitiesChange} />
      </SettingsSection>
      <SettingsSection id="settings-system" title="Installation" description="Check runtime health, optional services and local integrations.">
        <SettingsRuntimePanel
          apiOrigin={apiOrigin}
          configError={configLoadError}
          configLoadState={configLoadState}
          health={health}
          onReload={() => void reloadSettings(true)}
          onSignOut={() => void signOutBrowser()}
          providerError={providerError}
          providerLoadState={providerLoadState}
          reloadDisabled={saving || providerSaving || Boolean(providerOperation && advisorProviderActiveStatuses.has(providerOperation.job.status))}
          reloadStatus={reloadStatus}
          sessionError={sessionError}
          signingOut={signingOut}
        />
        <SettingsComponentsPanel
          config={config}
          observationsCurrent={runtimeObservationsCurrent}
          error={settingsErrorTarget === 'components' ? settingsError : null}
          form={form}
          onSubmit={stableSubmit}
          saving={saving || !settingsAuthoritative}
          setForm={setForm}
          status={statusTarget === 'components' ? status : null}
        />
        <SettingsLinksPanel config={config} observationsCurrent={runtimeObservationsCurrent} />
      </SettingsSection>
    </section>
  );
}
