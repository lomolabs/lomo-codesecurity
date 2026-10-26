import { CodeSecurityRequestError, PairingRequiredError } from './client';


export type JobStatus =
  | 'queued'
  | 'leased'
  | 'running'
  | 'cancelling'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type Job = {
  id: number;
  kind: string;
  title: string;
  status: JobStatus;
  stage?: string | null;
  detail?: string | null;
  progress?: number | null;
  scan_id?: number | null;
  finding_id?: number | null;
  error_code?: string | null;
  error_detail?: string | null;
  attempt: number;
  max_attempts: number;
  revision: number;
  can_cancel: boolean;
  can_retry: boolean;
};

export type JobRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export type ObserveJobOptions = {
  request: JobRequest;
  jobId: number;
  scanId: number;
  signal: AbortSignal;
  cancellationRequested: () => boolean;
  onUpdate: (job: Job) => void;
  onConnectionIssue?: (attempt: number) => void;
  waitForChange: (revision: number, signal: AbortSignal) => Promise<void>;
  wait?: (milliseconds: number, signal: AbortSignal) => Promise<void>;
  now?: () => number;
  timeoutMs?: number;
  maxConsecutiveFailures?: number;
};

const ACTIVE_STATUSES = new Set<JobStatus>(['queued', 'leased', 'running', 'cancelling']);
const TERMINAL_STATUSES = new Set<JobStatus>(['completed', 'failed', 'cancelled']);
const DEFAULT_TIMEOUT_MS = 30 * 60 * 1000;

class JobStateContractError extends CodeSecurityRequestError {}


function abortError(): DOMException {
  return new DOMException('The CodeSecurity operation was stopped.', 'AbortError');
}


function observationTimeoutError(jobId: number): CodeSecurityRequestError {
  return new CodeSecurityRequestError(
    `Job #${jobId} is still persisted but exceeded the 30-minute foreground observation window. `
    + 'Open Jobs to continue monitoring it.',
  );
}


function abortableRequest<T>(request: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(abortError());
  }
  return new Promise((resolve, reject) => {
    const stop = () => {
      signal.removeEventListener('abort', stop);
      reject(abortError());
    };
    signal.addEventListener('abort', stop, { once: true });
    request.then(
      (value) => {
        signal.removeEventListener('abort', stop);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener('abort', stop);
        reject(error);
      },
    );
  });
}


export function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}


export function abortableDelay(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    return Promise.reject(abortError());
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', stop);
      resolve();
    }, milliseconds);
    const stop = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', stop);
      reject(abortError());
    };
    signal.addEventListener('abort', stop, { once: true });
  });
}


export function jobProgressMessage(job: Job): string {
  const stage = (job.stage || job.status)
    .replace(/[\p{Cc}\p{Cf}]+/gu, ' ')
    .replaceAll('_', ' ')
    .replaceAll('-', ' ')
    .trim()
    .slice(0, 80) || job.status;
  const attempt = job.max_attempts > 1
    ? ` · attempt ${Math.max(job.attempt, 0)}/${Math.max(job.max_attempts, 1)}`
    : '';
  const progress = Number.isFinite(job.progress)
    ? ` · ${Math.min(Math.max(Math.round(job.progress as number), 0), 100)}%`
    : '';
  return `job #${job.id} · ${job.status} · ${stage}${progress}${attempt}`;
}


function validateJob(value: Job, jobId: number, scanId: number): Job {
  if (
    !value
    || value.id !== jobId
    || value.kind !== 'scan'
    || value.scan_id !== scanId
    || !TERMINAL_STATUSES.has(value.status) && !ACTIVE_STATUSES.has(value.status)
    || !Number.isSafeInteger(value.revision)
    || value.revision < 1
  ) {
    throw new JobStateContractError('CodeSecurity returned job state outside the requested workspace scan.');
  }
  return value;
}


function isRetryableObservationFailure(error: unknown): boolean {
  return error instanceof CodeSecurityRequestError
    && !(error instanceof JobStateContractError)
    && (error.retryable || error.status !== undefined && error.status >= 500)
    && !(error instanceof PairingRequiredError);
}


async function readObservedJob(
  options: ObserveJobOptions,
  signal: AbortSignal,
): Promise<Job> {
  return validateJob(
    await abortableRequest(
      options.request<Job>(`/v1/jobs/${options.jobId}`, { signal }),
      signal,
    ),
    options.jobId,
    options.scanId,
  );
}


export async function observeJob(options: ObserveJobOptions): Promise<Job> {
  const wait = options.wait || abortableDelay;
  const now = options.now || Date.now;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxFailures = options.maxConsecutiveFailures ?? 3;
  const startedAt = now();
  let failures = 0;
  let cancellationSubmitted = false;
  const operation = new AbortController();
  let deadlineExceeded = false;
  const stop = () => operation.abort();
  if (options.signal.aborted) {
    stop();
  } else {
    options.signal.addEventListener('abort', stop, { once: true });
  }
  const deadline = setTimeout(() => {
    deadlineExceeded = true;
    operation.abort();
  }, Math.max(timeoutMs, 0));

  try {
    while (now() - startedAt < timeoutMs) {
      if (operation.signal.aborted) {
        if (deadlineExceeded && !options.signal.aborted) {
          throw observationTimeoutError(options.jobId);
        }
        throw abortError();
      }

      let job: Job;
      try {
        job = await readObservedJob(options, operation.signal);
        failures = 0;
      } catch (error) {
        if (isAbortError(error) && deadlineExceeded && !options.signal.aborted) {
          throw observationTimeoutError(options.jobId);
        }
        if (isAbortError(error) || error instanceof PairingRequiredError || !isRetryableObservationFailure(error)) {
          throw error;
        }
        failures += 1;
        if (failures > maxFailures) {
          throw new CodeSecurityRequestError(
            'The local control plane stayed unavailable while observing this durable job. '
            + 'The job remains persisted; reconnect and refresh Jobs.',
          );
        }
        options.onConnectionIssue?.(failures);
        await wait(Math.min(1000 * failures, 3000), operation.signal);
        continue;
      }

      options.onUpdate(job);
      if (TERMINAL_STATUSES.has(job.status)) {
        return job;
      }

      if (options.cancellationRequested() && !cancellationSubmitted && job.can_cancel) {
        cancellationSubmitted = true;
        job = validateJob(
          await abortableRequest(
            options.request<Job>(`/v1/jobs/${job.id}/cancel`, {
              method: 'POST',
              signal: operation.signal,
            }),
            operation.signal,
          ),
          options.jobId,
          options.scanId,
        );
        options.onUpdate(job);
        if (TERMINAL_STATUSES.has(job.status)) {
          return job;
        }
      }

      // Durable state changes wake this observer through the authenticated
      // event stream. There is no fixed status polling while the job is idle.
      try {
        await options.waitForChange(job.revision, operation.signal);
      } catch (error) {
        if (isAbortError(error) && deadlineExceeded && !options.signal.aborted) {
          throw observationTimeoutError(options.jobId);
        }
        if (
          isAbortError(error)
          || error instanceof PairingRequiredError
          || !(error instanceof CodeSecurityRequestError)
        ) throw error;

        // The stream is a wake channel, never the durable job authority. If it
        // exhausts its own bounded reconnect/reconciliation policy, perform one
        // exact REST read before failing the foreground observer. This is not a
        // polling fallback: a terminal revision is surfaced once, while an
        // active revision remains persisted and returns an actionable error.
        const recovered = await readObservedJob(options, operation.signal);
        options.onUpdate(recovered);
        if (TERMINAL_STATUSES.has(recovered.status)) return recovered;
        throw new CodeSecurityRequestError(
          `The local event stream stayed unavailable while job #${recovered.id} remained `
          + `${recovered.status} at revision ${recovered.revision}. The job remains persisted; open Jobs to continue monitoring it.`,
          error.status,
          error.retryable,
          {
            code: error.code,
            action: error.action,
            correlationId: error.correlationId,
            sourceBoundary: error.sourceBoundary,
          },
        );
      }
    }

    throw observationTimeoutError(options.jobId);
  } finally {
    clearTimeout(deadline);
    options.signal.removeEventListener('abort', stop);
    operation.abort();
  }
}
