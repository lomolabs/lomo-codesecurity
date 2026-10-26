import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

import type { Job } from '../src/api.ts';
import { jobKindLabel, jobRetryGuidance, jobRetryTimingNote, jobStageLabel, jobStatusLabel, jobWaitingGuidance } from '../src/jobPresentation.ts';

test('queued jobs wait without stale execution warnings while claimed and terminal semantics remain intact', async (context) => {
  const now = '2026-09-08T06:41:32Z';
  const old = '2026-09-08T06:38:08Z';
  context.mock.method(Date, 'now', () => Date.parse(now));
  const vite = await createServer({
    root: fileURLToPath(new URL('..', import.meta.url)), configFile: false,
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { JobRow } = await vite.ssrLoadModule('/src/App.tsx') as typeof import('../src/App.tsx');
  const { AdvisorProviderOperationStatus } = await vite.ssrLoadModule('/src/AdvisorProviders.tsx') as typeof import('../src/AdvisorProviders.tsx');
  const queued: Job = { id: 3, kind: 'advisor_provider', title: 'Activate local Advisor', status: 'queued',
    stage: 'queued', attempt: 0, max_attempts: 3, progress: 0, created_at: old, updated_at: old };
  const retry: Job = { ...queued, attempt: 1, started_at: old, heartbeat_at: old, updated_at: '2026-09-08T06:40:40Z',
    activity: { component_id: 'qwen3:8b', component_index: 1, component_total: 1, updated_at: old } };
  const before = structuredClone([queued, retry]);
  const renderJob = (job: Job) => renderToStaticMarkup(createElement(JobRow, {
    job, busy: false, targeted: false, onCancel() {}, onRetry() {}, onOpenFindings() {},
  }));
  const renderProvider = (job: Job) => renderToStaticMarkup(createElement(AdvisorProviderOperationStatus, {
    operation: { job, action: 'activate', providerId: 'provider-synthetic' },
  }));
  const waiting = 'Waiting for a worker to start this job. It is safely queued.';
  for (const job of [queued, retry]) {
    assert.equal(jobWaitingGuidance(job), waiting);
    for (const html of [renderJob(job), renderProvider(job)]) {
      assert.ok(html.includes(waiting));
      assert.doesNotMatch(html, /job-stale-warning|advisor-provider-stalled|Worker heartbeat|Check worker health|qwen3:8b/u);
    }
  }
  assert.match(renderProvider(queued), /Since queued 3m 24s/u);
  assert.match(renderProvider(retry), /Last job update/u);
  assert.equal(renderProvider(retry), renderProvider({ ...retry, heartbeat_at: undefined }),
    'a queued retry displays its newer job update, not the previous attempt heartbeat');
  assert.match(renderJob(retry), /Since first start 3m 24s/u);
  for (const status of ['leased', 'running', 'cancelling']) {
    const job = { ...retry, status, stage: status };
    assert.equal(jobWaitingGuidance(job), null);
    assert.match(renderJob(job), /job-stale-warning/u);
    assert.match(renderProvider(job), /advisor-provider-stalled/u);
    for (const html of [renderJob(job), renderProvider(job)]) assert.ok(!html.includes(waiting));
  }
  const healthy = { ...retry, status: 'running', stage: 'provider_readiness', heartbeat_at: now, activity: undefined };
  assert.match(renderJob(healthy), /Worker heartbeat is active/u);
  for (const html of [renderJob(healthy), renderProvider(healthy)]) assert.doesNotMatch(html, /job-stale-warning|advisor-provider-stalled/u);
  for (const status of ['completed', 'failed', 'cancelled']) {
    const job = { ...retry, status, stage: status };
    assert.equal(jobWaitingGuidance(job), null);
    for (const html of [renderJob(job), renderProvider(job)]) {
      assert.ok(!html.includes(waiting));
      assert.doesNotMatch(html, /job-stale-warning|advisor-provider-stalled/u);
    }
  }
  assert.deepEqual([queued, retry], before, 'waiting presentation must preserve persisted timing, attempts and activity');
});

test('retry timing names the first start without inventing an attempt duration', async (context) => {
  context.mock.method(Date, 'now', () => Date.parse('2026-09-07T17:59:19Z'));
  const vite = await createServer({
    root: fileURLToPath(new URL('..', import.meta.url)), configFile: false,
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  context.after(async () => { await vite.close(); });
  const { JobRow } = await vite.ssrLoadModule('/src/App.tsx') as typeof import('../src/App.tsx');
  const { AdvisorProviderOperationStatus } = await vite.ssrLoadModule('/src/AdvisorProviders.tsx') as typeof import('../src/AdvisorProviders.tsx');
  const queuedRetry: Job = {
    id: 9, kind: 'advisor', title: 'Synthetic Advisor review', status: 'queued',
    stage: 'queued', attempt: 1, max_attempts: 3, progress: 0,
    created_at: '2026-09-07T16:40:00Z', started_at: '2026-09-07T16:41:09Z',
    updated_at: '2026-09-07T17:59:19Z', heartbeat_at: '2026-09-07T17:59:19Z',
  };
  const before = structuredClone(queuedRetry);
  const renderJob = (job: Job) => renderToStaticMarkup(createElement(JobRow, {
    job, busy: false, targeted: false, onCancel() {}, onRetry() {}, onOpenFindings() {},
  }));
  const renderProvider = (job: Job) => renderToStaticMarkup(createElement(AdvisorProviderOperationStatus, {
    operation: { job, action: 'activate', providerId: 'provider-synthetic' },
  }));
  const note = 'Time since first start includes earlier attempts and time waiting to retry, not just this attempt.';
  for (const job of [queuedRetry, { ...queuedRetry, status: 'running', stage: 'advisor', attempt: 2, progress: 50 }]) {
    assert.equal(jobRetryTimingNote(job), note);
    for (const html of [renderJob(job), renderProvider(job)]) {
      assert.match(html, /First started /u);
      assert.match(html, /Since first start 1h 18m 10s/u);
      assert.ok(html.includes(note));
      assert.doesNotMatch(html, / · elapsed |Since queued|attempt duration/u);
    }
  }
  const running = renderJob({ ...queuedRetry, status: 'running', stage: 'advisor', attempt: 2, progress: 50 });
  assert.match(running, /aria-valuenow="50"/u);
  assert.match(running, /Worker heartbeat active/u);
  const completed = { ...queuedRetry, status: 'completed', stage: 'completed', attempt: 2, progress: 100 };
  for (const html of [renderJob(completed), renderProvider(completed)]) {
    assert.match(html, /First started /u);
    assert.doesNotMatch(html, /Since first start \d|Since queued/u);
  }
  const firstQueue = { ...queuedRetry, started_at: undefined, attempt: 0 };
  assert.equal(jobRetryTimingNote(firstQueue), null);
  assert.doesNotMatch(renderJob(firstQueue), /First started|Since first start|Since queued/u);
  assert.match(renderProvider(firstQueue), /Since queued 1h 19m 19s/u);
  assert.doesNotMatch(renderProvider(firstQueue), /First started|Since first start/u);
  assert.equal(jobRetryTimingNote({ ...queuedRetry, status: 'running' }), null);
  assert.deepEqual(queuedRetry, before, 'presentation must not alter persisted timing or progress');
});

test('obsolete Advisor retry guidance uses the server refusal beside existing finding navigation', async () => {
  const reason = 'This selection changed. Open the findings and submit a new Advisor review.';
  assert.equal(jobRetryGuidance({ status: 'failed', can_retry: false, retry_blocked_reason: reason }), reason);
  assert.equal(jobRetryGuidance({ status: 'failed', can_retry: true, retry_blocked_reason: reason }), null);
  assert.equal(jobRetryGuidance({ status: 'queued', can_retry: false, retry_blocked_reason: reason }), null);
  assert.equal(jobRetryGuidance({ status: 'failed', can_retry: false }), null);
  const appSource = await readFile(fileURLToPath(new URL('../src/App.tsx', import.meta.url)), 'utf8');
  assert.match(appSource, /<p className="inline-warning">\{jobRetryGuidance\(job\)\}<\/p>/u);
  assert.match(appSource, /previous\.retry_blocked_reason === next\.retry_blocked_reason/u);
  assert.match(appSource, /onOpenFindings\(scan\.id, job\.finding_scan_number\)/u);
});

test('job kinds use concise user-facing labels without exposing wire identifiers', () => {
  assert.equal(jobKindLabel('scan'), 'Scan');
  assert.equal(jobKindLabel('advisor'), 'Advisor review');
  assert.equal(jobKindLabel('advisor_provider'), 'Advisor provider');
  assert.equal(jobKindLabel('scanner_catalog_check'), 'Scanner catalog check');
  assert.equal(jobKindLabel('scanner_cache_update'), 'Scanner data preparation');
  assert.equal(jobKindLabel('scanner_cache_rollback'), 'Scanner data rollback');
  assert.equal(jobKindLabel('unexpected_future_kind'), 'Background task');
});

test('job statuses and phases use truthful product language without wire tokens', async () => {
  assert.deepEqual(
    ['queued', 'leased', 'running', 'cancelling', 'completed', 'failed', 'cancelled']
      .map(jobStatusLabel),
    ['Waiting', 'Assigned', 'Running', 'Cancelling', 'Completed', 'Failed', 'Cancelled'],
  );
  assert.equal(jobStatusLabel('future_status'), 'Status unavailable');

  const expectedStages = new Map([
    ['source_blind_updater', 'Preparing scanner data'],
    ['scanner_cleanup_wait', 'Finishing scanner cleanup'],
    ['advisor_disclosure_reserved', 'Submitting approved Advisor request'],
    ['provider_readiness', 'Checking Advisor provider'],
    ['recovery_exhausted', 'Recovery attempts exhausted'],
    ['recovery_wait', 'Waiting to reconcile job state'],
    ['validating_generation', 'Verifying candidate data'],
    ['downloading', 'Downloading scanner data'],
  ]);
  for (const [stage, label] of expectedStages) assert.equal(jobStageLabel(stage), label);
  assert.equal(jobStageLabel('future_stage'), 'Working');
  assert.equal(jobStageLabel(undefined), 'Waiting for a worker');

  const appSource = await readFile(fileURLToPath(new URL('../src/App.tsx', import.meta.url)), 'utf8');
  assert.doesNotMatch(appSource, /job\.stage[^\n]*replace\(\/_\/gu/u);
  assert.doesNotMatch(appSource, /job\.status\.replace\(\/_\/gu/u);
  assert.match(appSource, /<StatusPill value=\{job\.status\} label=\{jobStatusLabel\(job\.status\)\} \/>/u);
});

test('uncertain preparation offers a distinct read-only check and preserves failed and terminal history', async (context) => {
  const { canReconcileScannerCacheJob, jobCacheOutcomeGuidance } = await import('../src/jobPresentation.ts');
  const original: Job = { id: 42, kind: 'scanner_cache_update', title: 'Prepare scanner data', status: 'failed',
    error_code: 'scanner_preparation_commit_uncertain', attempt: 1, max_attempts: 1, revision: 7, can_retry: false,
    created_at: '2026-09-30T00:00:00Z', updated_at: '2026-09-30T00:15:00Z' };
  const before = structuredClone(original);
  assert.equal(canReconcileScannerCacheJob(original), true);
  for (const patch of [{ kind: 'scan' }, { status: 'running' }, { status: 'completed' }, { error_code: 'scanner_preparation_deadline' },
    { revision: undefined }, { revision: 0 }, { attempt: 0 }, { kind: 'scanner_cache_reconcile' }]) {
    assert.equal(canReconcileScannerCacheJob({ ...original, ...patch }), false);
  }
  const vite = await createServer({ root: fileURLToPath(new URL('..', import.meta.url)), configFile: false,
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  context.after(async () => { await vite.close(); });
  const { JobRow } = await vite.ssrLoadModule('/src/App.tsx') as typeof import('../src/App.tsx');
  const render = (job: Job, cacheRecoveryBusy = false, cacheOutcomeJob: Pick<Job, 'id' | 'status'> | null = null) => renderToStaticMarkup(createElement(JobRow, {
    job, busy: false, targeted: false, scan: null, cacheRecoveryBusy, cacheOutcomeJob, onOpenJob() {},
    onCancel() {}, onRetry() {}, onReconcileCache() {}, onOpenFindings() {},
  }));
  const failed = render(original);
  assert.match(failed, /Check cache outcome/u);
  const historical = { ...original, error_code: 'scanner_preparation_deadline', can_reconcile_cache: true, can_retry: true };
  assert.equal(canReconcileScannerCacheJob(historical), true);
  assert.match(render(historical), /Check cache outcome/u);
  assert.match(render(historical), /This preparation remains failed/u);
  assert.doesNotMatch(render(historical), /> Retry<|>Retry</u);
  assert.equal(canReconcileScannerCacheJob({ ...historical, can_reconcile_cache: false }), false);
  assert.equal(canReconcileScannerCacheJob({ ...historical, error_code: 'unrelated' }), false);

  assert.match(failed, /aria-describedby="job-42-cache-outcome"/u);
  assert.match(failed, /Cache outcome is uncertain/u);
  assert.match(failed, /This preparation remains failed/u);
  assert.doesNotMatch(failed, /> Retry<|>Retry</u);
  assert.match(render(original, true), /disabled=""[^>]*aria-describedby="job-42-cache-outcome"/u);
  for (const status of ['queued', 'running', 'completed', 'failed', 'cancelled']) {
    const check = { ...original, id: 43, kind: 'scanner_cache_reconcile', title: 'Reconcile cache outcome', status,
      error_code: undefined, can_retry: true };
    const html = render(check);
    assert.match(html, /Cache outcome check/u);
    assert.match(html, /Scanner data is unchanged/u);
    assert.match(html, status === 'completed' ? /class="helper-text" id="job-43-cache-outcome"/u : /id="job-43-cache-outcome"/u);
    assert.match(html, /original preparation remains failed/u);
    assert.doesNotMatch(html, /Check cache outcome|> Retry<|>Retry</u);
    assert.ok(jobCacheOutcomeGuidance(check));
    if (status === 'completed') assert.match(html, /Cache outcome verified/u);
    if (status === 'failed') assert.match(html, /could not confirm the cache outcome/u);
    if (status === 'cancelled') assert.match(html, /check was cancelled/u);
  }
  for (const status of ['queued', 'completed']) {
    const linked = render(original, false, { id: 43, status });
    assert.match(linked, /View outcome check #43/u);
    assert.doesNotMatch(linked, /Check cache outcome<|>Check cache outcome/u);
    assert.match(linked, /preparation remains failed/u);
  }
  assert.match(render({ ...original, id: 43, kind: 'scanner_cache_reconcile', original_job_id: 42 }), /Preparation #42/u);
  assert.equal(jobKindLabel('scanner_cache_reconcile'), 'Cache outcome check');
  assert.deepEqual(original, before, 'presentation must not alter the original failed preparation');
});
