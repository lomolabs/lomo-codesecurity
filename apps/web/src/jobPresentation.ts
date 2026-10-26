import type { Job } from './api';

export function jobWaitingGuidance(job: Pick<Job, 'status'>): string | null {
  // A queued retry can retain the previous attempt's heartbeat/activity. Only
  // the current status establishes whether a worker has claimed this attempt.
  return job.status === 'queued' ? 'Waiting for a worker to start this job. It is safely queued.' : null;
}

export function jobRetryGuidance(job: Pick<Job, 'status' | 'can_retry' | 'retry_blocked_reason'>): string | null {
  return job.status === 'failed' && job.can_retry === false
    ? job.retry_blocked_reason || null
    : null;
}

export function jobRetryTimingNote(job: Pick<Job, 'status' | 'attempt' | 'started_at'>): string | null {
  return job.started_at && (job.status === 'queued' || (job.attempt ?? 0) > 1)
    ? 'Time since first start includes earlier attempts and time waiting to retry, not just this attempt.'
    : null;
}

function hasUncertainCacheOutcome(job: Pick<Job, 'kind' | 'status' | 'error_code' | 'can_reconcile_cache'>): boolean {
  return job.kind === 'scanner_cache_update' && job.status === 'failed'
    && (job.error_code === 'scanner_preparation_commit_uncertain'
      || (job.error_code === 'scanner_preparation_deadline' && job.can_reconcile_cache === true));
}

export function canReconcileScannerCacheJob(job: Pick<Job, 'kind' | 'status' | 'error_code' | 'revision' | 'attempt' | 'can_reconcile_cache'>): boolean {
  // The API additionally proves the persisted budget and exact publication
  // target. A failed preparation is never retried by this separate command.
  return hasUncertainCacheOutcome(job)
    && Number.isSafeInteger(job.revision) && (job.revision ?? 0) > 0
    && Number.isSafeInteger(job.attempt) && (job.attempt ?? 0) > 0;
}

export function jobCacheOutcomeGuidance(job: Pick<Job, 'kind' | 'status' | 'error_code' | 'can_reconcile_cache'>, outcomeStatus?: string): string | null {
  if (job.kind === 'scanner_cache_reconcile') {
    const preserved = ' Scanner data is unchanged. The original preparation remains failed.';
    if (job.status === 'completed') return 'Cache outcome verified.' + preserved;
    if (job.status === 'failed') return 'The check could not confirm the cache outcome.' + preserved;
    if (job.status === 'cancelled') return 'The check was cancelled; cache outcome may still be uncertain.' + preserved;
    if (job.status === 'cancelling') return 'Stopping the cache outcome check.' + preserved;
    return (job.status === 'queued' ? 'Waiting to check cache outcome.' : 'Checking cache outcome.')
      + ' This read-only check has a separate 15-minute limit.' + preserved;
  }
  if (!hasUncertainCacheOutcome(job)) return null;
  if (outcomeStatus === 'completed') return 'The linked check verified the cache outcome. This preparation remains failed.';
  if (['queued', 'leased', 'running', 'cancelling'].includes(outcomeStatus || '')) return 'A separate cache outcome check is in progress. This preparation remains failed.';
  return 'Cache outcome is uncertain. Check it without changing scanner data, using a separate 15-minute limit. This preparation remains failed.';
}

const JOB_KIND_LABELS: Readonly<Record<string, string>> = Object.freeze({
  scan: 'Scan',
  advisor: 'Advisor review',
  advisor_provider: 'Advisor provider',
  scanner_catalog_check: 'Scanner catalog check',
  scanner_cache_update: 'Scanner data preparation',
  scanner_cache_reconcile: 'Cache outcome check',
  scanner_cache_rollback: 'Scanner data rollback',
  maintenance: 'Maintenance',
});

export function jobKindLabel(kind: string): string {
  return JOB_KIND_LABELS[kind] || 'Background task';
}

const JOB_STATUS_LABELS: Readonly<Record<string, string>> = Object.freeze({
  queued: 'Waiting',
  leased: 'Assigned',
  running: 'Running',
  cancelling: 'Cancelling',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
});

export function jobStatusLabel(status: string): string {
  return JOB_STATUS_LABELS[status] || 'Status unavailable';
}

const JOB_STAGE_LABELS: Readonly<Record<string, string>> = Object.freeze({
  queued: 'Waiting for a worker',
  leased: 'Assigned to a worker',
  starting: 'Starting',
  running: 'Running',
  resolving_lock: 'Checking scanner data lock',
  discovering: 'Checking scanner catalog',
  validating_active: 'Checking current scanner data',
  downloading: 'Downloading scanner data',
  validating_source: 'Verifying downloaded data',
  retaining: 'Retaining verified data',
  staging: 'Preparing candidate data',
  validating_generation: 'Verifying candidate data',
  activating: 'Activating scanner data',
  committing: 'Saving scanner data receipt',
  rolling_back: 'Restoring previous scanner data',
  source_blind_updater: 'Preparing scanner data',
  scanner_cleanup_wait: 'Finishing scanner cleanup',
  scanner: 'Running scanners',
  scanner_evidence: 'Saving scanner evidence',
  advisor_disclosure_reserved: 'Submitting approved Advisor request',
  advisor: 'Running Advisor review',
  provider_readiness: 'Checking Advisor provider',
  gate: 'Evaluating scan policy',
  recovery: 'Recovering job state',
  recovery_wait: 'Waiting to reconcile job state',
  recovery_exhausted: 'Recovery attempts exhausted',
  cancelling: 'Cancelling',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
});

export function jobStageLabel(stage: string | null | undefined): string {
  if (!stage) return 'Waiting for a worker';
  return JOB_STAGE_LABELS[stage] || 'Working';
}
