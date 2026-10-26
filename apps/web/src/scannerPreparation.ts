import type {
  ScannerCacheComponentId,
  ScannerCacheVerification,
  ScannerCatalogComponentState,
  ScannerPreparationCommandOut,
  ScannerLifecycleStatus,
  ScannerLifecycleScope,
  ScannerPreflight,
} from './api';

export type ScannerCacheComponent = Readonly<{
  id: ScannerCacheComponentId;
  label: string;
  purpose: string;
}>;

export const scannerCacheComponents: ReadonlyArray<ScannerCacheComponent> = [
  { id: 'trivy-db', label: 'Trivy vulnerability DB', purpose: 'Package and operating-system vulnerability metadata.' },
  { id: 'trivy-java-db', label: 'Trivy Java DB', purpose: 'Java ecosystem vulnerability metadata.' },
  { id: 'trivy-checks', label: 'Trivy checks', purpose: 'Reviewed local misconfiguration checks.' },
  { id: 'opengrep-reviewed-rules', label: 'OpenGrep reviewed rules', purpose: 'Pinned offline SAST rules.' },
  { id: 'bearer-rules', label: 'Bearer rules', purpose: 'Pinned security and data-flow rules.' },
  { id: 'grype-db', label: 'Grype vulnerability DB', purpose: 'Offline SBOM vulnerability matching data.' },
];

const verificationFields = new Set([
  'state', 'target', 'generation_id', 'phase', 'component_id',
  'started_at', 'last_activity_at', 'bytes_verified', 'bytes_total',
]);
const verificationUtc = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/u;
const maximumVerificationBytes = 8 * 1024 ** 3;

function scannerUtcTime(value: unknown): number | null {
  if (typeof value !== 'string' || !verificationUtc.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString().slice(0, 19) === value.slice(0, 19)
    ? parsed : null;
}

export function validScannerCacheVerification(value: unknown): value is ScannerCacheVerification {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const entry = value as Record<string, unknown>;
  const validTime = (time: unknown): time is string => scannerUtcTime(time) !== null;
  const validBytes = (bytes: unknown): bytes is number => (
    typeof bytes === 'number' && Number.isSafeInteger(bytes) && bytes >= 0 && bytes <= maximumVerificationBytes
  );
  return Object.keys(entry).length === verificationFields.size
    && Object.keys(entry).every((key) => verificationFields.has(key))
    && typeof entry.state === 'string' && ['verifying', 'timed_out', 'failed'].includes(entry.state)
    && typeof entry.target === 'string' && ['active', 'previous_good'].includes(entry.target)
    && typeof entry.generation_id === 'string' && /^[a-f0-9]{64}$/u.test(entry.generation_id)
    && typeof entry.phase === 'string' && ['queued', 'validating', 'hashing'].includes(entry.phase)
    && (entry.component_id === null || scannerCacheComponents.some(({ id }) => id === entry.component_id))
    && validTime(entry.started_at) && validTime(entry.last_activity_at)
    && Date.parse(entry.last_activity_at) >= Date.parse(entry.started_at)
    && ((entry.bytes_verified === null && entry.bytes_total === null)
      || validBytes(entry.bytes_verified) && validBytes(entry.bytes_total) && entry.bytes_verified <= entry.bytes_total);
}

export function scannerVerificationRecommendedAction(
  verification: ScannerCacheVerification,
): 'wait_for_scanner_verification' | 'retry_scanner_verification' {
  return verification.state === 'verifying' ? 'wait_for_scanner_verification' : 'retry_scanner_verification';
}

export function validScannerVerificationPreflight(preflight: ScannerPreflight): boolean {
  const active = preflight.cache_verification;
  if (active !== undefined && (
    !validScannerCacheVerification(active) || active.target !== 'active'
    || preflight.ready || preflight.preparation_available
    || preflight.recommended_action !== scannerVerificationRecommendedAction(active)
  )) return false;
  if (active === undefined && ['wait_for_scanner_verification', 'retry_scanner_verification'].includes(preflight.recommended_action)) return false;
  const previous = preflight.cache_rollback?.verification;
  if (previous === undefined && [
    'previous_generation_verifying', 'previous_generation_verification_timeout', 'previous_generation_verification_failed',
  ].includes(preflight.cache_rollback?.reason_code)) return false;
  if (previous !== undefined && (
    !validScannerCacheVerification(previous) || previous.target !== 'previous_good'
    || previous.generation_id !== preflight.cache_rollback.target_generation
    || preflight.cache_rollback.eligible
    || preflight.cache_rollback.reason_code !== {
      verifying: 'previous_generation_verifying',
      timed_out: 'previous_generation_verification_timeout',
      failed: 'previous_generation_verification_failed',
    }[previous.state]
  )) return false;
  return true;
}

export function scannerVerificationPollRequired(preflight: ScannerPreflight | null): boolean {
  return preflight?.cache_verification?.state === 'verifying'
    || preflight?.cache_rollback?.verification?.state === 'verifying';
}

export function applyAcceptedScannerVerification(
  preflight: ScannerPreflight | null,
  requested: ScannerCacheVerification,
  accepted: ScannerCacheVerification,
): ScannerPreflight | null {
  if (!preflight || !validScannerCacheVerification(accepted)
    || accepted.state !== 'verifying' || accepted.target !== requested.target
    || accepted.generation_id !== requested.generation_id
    || !['timed_out', 'failed'].includes(requested.state)) return preflight;
  const current = requested.target === 'active'
    ? preflight.cache_verification : preflight.cache_rollback.verification;
  if (!current || current.target !== requested.target
    || current.generation_id !== requested.generation_id || current.state !== requested.state
    || current.started_at !== requested.started_at
    || current.last_activity_at !== requested.last_activity_at
    || (requested.target === 'previous_good'
      && preflight.cache_rollback.target_generation !== requested.generation_id)) return preflight;

  // This accepted command receipt updates display/polling, not admission.
  // Preserve the server's revision until a fresh preflight supplies its proof.
  return requested.target === 'active'
    ? { ...preflight, cache_verification: accepted, ready: false, preparation_available: false,
      recommended_action: 'wait_for_scanner_verification' }
    : { ...preflight, cache_rollback: { ...preflight.cache_rollback, eligible: false,
      reason_code: 'previous_generation_verifying',
      reason: 'The previous scanner cache generation is being verified. Rollback stays unavailable until verification finishes.',
      verification: accepted } };
}

export function scannerVerificationDisabledReason(preflight: ScannerPreflight | null): string | null {
  const active = preflight?.cache_verification;
  if (!active) return null;
  return active.state === 'verifying'
    ? 'Existing scanner data is being verified. Wait for verification before complete scanning or preparing more data; no new download is needed.'
    : 'Scanner cache verification did not finish. Retry verification from Tools before complete scanning or preparing more data.';
}

export function scannerVerificationCopy(verification: ScannerCacheVerification) {
  const target = verification.target === 'active' ? 'scanner cache' : 'rollback cache';
  return {
    title: verification.state === 'verifying'
      ? `Verifying ${target}`
      : verification.state === 'timed_out'
        ? `${verification.target === 'active' ? 'Scanner' : 'Rollback'} cache verification timed out`
        : `${verification.target === 'active' ? 'Scanner' : 'Rollback'} cache verification could not complete`,
    detail: verification.target === 'active'
      ? 'Checking existing data locally. Complete scanning and new preparation wait for verified results; nothing is downloaded. Explicit limited coverage remains available when another enabled scanner is ready.'
      : 'Checking the exact previous-good generation locally. An already-verified active cache remains available for scanning.',
    phase: { queued: 'Waiting for verification', validating: 'Checking database integrity and contents', hashing: 'Verifying file bytes' }[verification.phase],
    component: scannerCacheComponents.find(({ id }) => id === verification.component_id)?.label || null,
    canRetry: verification.state === 'timed_out' || verification.state === 'failed',
  };
}

export type CatalogComponentState = ScannerCatalogComponentState | 'not_checked' | 'catalog_needs_refresh';

export function catalogNeedsRefreshAfterCache(
  catalog: ScannerLifecycleScope | null,
  cache: ScannerLifecycleScope | null,
): boolean {
  if (catalog?.status !== 'completed' || !cache || cache.status === 'idle') return false;
  if (!['completed', 'failed', 'cancelled'].includes(cache.status)) return true;
  const result = catalog.receipt.result;
  const cacheActivityEndedAt = scannerUtcTime(cache.completed_at);
  const startedAt = scannerUtcTime(catalog.started_at);
  const checkedAt = scannerUtcTime(result && typeof result === 'object' && !Array.isArray(result)
    ? (result as Record<string, unknown>).checked_at : null);
  // A failed/cancelled attempt retains the previously activated generation but
  // replaces this scope's receipt. It cannot make an older catalog current.
  // Without a catalog generation binding, conservatively require a check that
  // began after the latest cache activity; completion time alone is not proof.
  return cacheActivityEndedAt === null || startedAt === null || checkedAt === null
    || startedAt <= cacheActivityEndedAt || checkedAt <= cacheActivityEndedAt || checkedAt < startedAt;
}

const catalogComponentStates = new Set<ScannerCatalogComponentState>([
  'current',
  'candidate_available',
  'requires_lock_refresh',
  'unavailable',
  'unattested',
]);

export function scannerDataCatalogSelection(scope: ScannerLifecycleScope | null): Readonly<{
  mode: 'signed' | 'source-reviewed/bundled'; digest: string | null;
}> | null {
  if (scope?.status !== 'completed') return null;
  const result = scope.receipt.result;
  if (!result || typeof result !== 'object' || Array.isArray(result)) return null;
  const fields = result as Record<string, unknown>;
  const mode = fields.catalog_mode ?? 'source-reviewed/bundled';
  const digest = fields.catalog_digest ?? null;
  if (mode === 'source-reviewed/bundled' && digest === null) return { mode, digest };
  if (mode === 'signed' && typeof digest === 'string' && /^[0-9a-f]{64}$/u.test(digest)) return { mode, digest };
  return null;
}

export function catalogComponentState(
  scope: ScannerLifecycleScope | null,
  componentId: ScannerCacheComponentId,
  cache: ScannerLifecycleScope | null = null,
): CatalogComponentState {
  if (scope?.status !== 'completed') return 'not_checked';
  if (catalogNeedsRefreshAfterCache(scope, cache)) return 'catalog_needs_refresh';
  const result = scope.receipt.result;
  if (!result || typeof result !== 'object' || Array.isArray(result)) return 'not_checked';
  const components = (result as Record<string, unknown>).components;
  if (!Array.isArray(components) || components.length > scannerCacheComponents.length) return 'not_checked';
  const matches = components.filter((item) => (
    item
    && typeof item === 'object'
    && !Array.isArray(item)
    && (item as Record<string, unknown>).component_id === componentId
  ));
  if (matches.length !== 1) return 'not_checked';
  const state = (matches[0] as Record<string, unknown>).state;
  return typeof state === 'string' && catalogComponentStates.has(state as ScannerCatalogComponentState)
    ? state as ScannerCatalogComponentState
    : 'not_checked';
}

export function requiredLockRefreshComponents(
  preflight: ScannerPreflight | null,
  catalog: ScannerLifecycleScope | null,
): ScannerCacheComponent[] {
  if (!preflight || catalog?.status !== 'completed') return [];
  const required = new Set(preflight.required_component_ids);
  return scannerCacheComponents.filter((component) => (
    required.has(component.id)
    && catalogComponentState(catalog, component.id) === 'requires_lock_refresh'
  ));
}

export function scannerPreparationDisabledReason(
  busy: boolean,
): string | null {
  // Historical catalog expiry must not trap a refreshed source installation.
  // The primary command starts a fresh catalog check, not a cache download.
  return busy ? 'Scanner preparation is already processing or reconciling durable work.' : null;
}

export function scannerPreparationCommandCopy(
  command: ScannerPreparationCommandOut,
): Readonly<{ title: string; detail: string }> {
  const catalogId = command.catalog.job.id;
  const catalogStatus = exactScannerJobStatus(command.catalog.job.status);
  if (command.cache) {
    const cacheStatus = exactScannerJobStatus(command.cache.job.status);
    if (!catalogStatus || !cacheStatus) {
      return Object.freeze({
        title: `Scanner preparation jobs #${catalogId} and #${command.cache.job.id} recorded`,
        detail: 'The exact durable job state is not recognized. Review these jobs or refresh readiness before taking another action.',
      });
    }
    return Object.freeze({
      title: `Scanner cache job #${command.cache.job.id} ${scannerLifecycleStatusLabel(cacheStatus)}`,
      detail: `Catalog job #${catalogId} is ${scannerLifecycleStatusLabel(catalogStatus)}; verified cache job #${command.cache.job.id} is ${scannerLifecycleStatusLabel(cacheStatus)}. Track the exact durable stages from Tools or Jobs.`,
    });
  }

  if (catalogStatus === 'completed') {
    return Object.freeze({
      title: `Scanner catalog job #${catalogId} completed`,
      detail: 'The reviewed-lock check completed without creating cache work. Refreshed readiness will show whether preparation is complete or an exact lock/runtime blocker needs attention.',
    });
  }
  if (catalogStatus === 'failed' || catalogStatus === 'cancelled') {
    return Object.freeze({
      title: `Scanner catalog job #${catalogId} ${catalogStatus}`,
      detail: `The reviewed-lock check ${catalogStatus}; no verified cache job was created. Review the exact catalog job before retrying.`,
    });
  }
  if (!catalogStatus || catalogStatus === 'idle') {
    return Object.freeze({
      title: `Scanner catalog job #${catalogId} recorded`,
      detail: catalogStatus === 'idle'
        ? 'The catalog command has no active lifecycle yet. Refresh readiness before taking another action.'
        : 'The exact durable job state is not recognized. Review this job or refresh readiness before taking another action.',
    });
  }
  return Object.freeze({
    title: `Scanner catalog job #${catalogId} ${scannerLifecycleStatusLabel(catalogStatus)}`,
    detail: catalogStatus === 'cancelling'
      ? 'Catalog cancellation is in progress; no verified cache job has been created.'
      : 'CodeSecurity is checking the reviewed scanner locks. Verified cache work will be created only if that catalog check passes.',
  });
}

function exactScannerJobStatus(status: string): ScannerLifecycleStatus | null {
  switch (status) {
    case 'idle':
    case 'queued':
    case 'leased':
    case 'running':
    case 'cancelling':
    case 'completed':
    case 'failed':
    case 'cancelled':
      return status;
    default:
      return null;
  }
}

function scannerLifecycleStatusLabel(status: ScannerLifecycleStatus): string {
  switch (status) {
    case 'idle': return 'idle';
    case 'queued': return 'queued';
    case 'leased':
    case 'running': return 'in progress';
    case 'cancelling': return 'cancellation requested';
    case 'completed': return 'completed';
    case 'failed': return 'failed';
    case 'cancelled': return 'cancelled';
  }
}
