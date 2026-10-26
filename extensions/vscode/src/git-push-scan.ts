import { createHash } from 'node:crypto';
import { workspaceScanCommand } from './client';
import { readGitPushCheck } from './git-push-cli';
import { GitPushBoundaryError, GitRepository, exportGitTree, inspectGitRepository, planGitPush,
  readGitLocalRefs, readGitRemoteAdvertisement } from './git-push-objects';
import { GitPushRepository, GitPushUiAdapters, validateGitPushPolicy } from './git-push-ui';
import { Job } from './jobs';
import { Scan } from './workspace';

export type GitPushSelection = Readonly<{ destination: string; localRef: string; localOid: string; remoteRef: string }>;
type Progress = Readonly<{
  signal: AbortSignal;
  cancellationRequested(): boolean;
  report(message: string): void;
  observe(jobId: number, scanId: number): Promise<Job>;
}>;
export type GitPushScanAdapters = Pick<GitPushUiAdapters, 'chooseRepository' | 'assertCurrent' | 'request' | 'confirm' | 'showStatus'> & Readonly<{
  selectTarget(repository: GitRepository): Promise<GitPushSelection | undefined>;
  withProgress(task: (progress: Progress) => Promise<void>): Promise<void>;
  showRecovery(message: string): Promise<void>;
  showBlocked(message: string, scanIds: readonly number[]): Promise<void>;
}>;
const SHA = /^[0-9a-f]{64}$/u;
const positive = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) > 0;
function fail(message: string): never { throw new GitPushBoundaryError('push_check_required', message); }

/** User-triggered evidence collection. Only the server's final /check can pass a push. */
export async function runGitPushScan(adapter: GitPushScanAdapters): Promise<void> {
  let repository = await adapter.chooseRepository();
  if (!repository) return;
  const guard = () => adapter.assertCurrent(repository!);
  const route = `/v1/git/push-protection/${repository.repositoryId}`;
  guard();
  const policy = validateGitPushPolicy(await adapter.request(route), repository); guard();
  repository = Object.freeze({ ...repository, projectId: policy.project_id });
  const approved = (value: typeof policy) => value.enabled && value.members.some((member) =>
    member.client_slot === repository!.clientSlot && member.generation === repository!.generation && member.state === 'approved');
  if (!approved(policy)) fail('Turn on repository push protection and approve this exact IDE in Settings before checking outgoing commits.');
  const git = await inspectGitRepository(repository.root); guard();
  if (git.repositoryId !== repository.repositoryId) fail('The selected repository changed.');
  const selected = await adapter.selectTarget(git); guard();
  if (!selected) return;
  const currentPlan = async () => {
    guard();
    const refs = await readGitLocalRefs(git); guard();
    if (!refs.some((ref) => ref.ref === selected.localRef && ref.oid === selected.localOid)) {
      fail('The selected local reference changed. Preview its current outgoing commits again.');
    }
    const remote = await readGitRemoteAdvertisement(git, selected.destination); guard();
    const old = remote.refs[selected.remoteRef] ?? '0'.repeat(git.format === 'sha1' ? 40 : 64);
    const plan = await planGitPush(git, `${selected.localRef} ${selected.localOid} ${selected.remoteRef} ${old}\n`, remote); guard();
    return plan;
  };
  const plan = await currentPlan();
  const detail = `${repository.root}\nDestination: ${selected.destination}\n${selected.localRef} → ${selected.remoteRef}`
    + `\nLocal object: ${selected.localOid}\nRemote object: ${plan.refs[0].remote_oid}`
    + `\n\n${plan.commits.length} outgoing commits · ${plan.trees.length} distinct committed trees.`
    + '\nOnly immutable committed regular files are copied into local scanner snapshots. Unsaved/uncommitted changes are excluded. '
    + 'No push, checkout, dependency installation or Advisor request occurs. Cancel during work cancels only its current job; earlier completed evidence remains.';
  if (!await adapter.confirm('Check these exact outgoing commits?', detail, 'Check committed files')) return;
  guard();
  if ((await currentPlan()).digest !== plan.digest) fail('The remote or outgoing plan changed during preview. No scan was submitted.');
  const latest = validateGitPushPolicy(await adapter.request(route), repository); guard();
  if (!approved(latest) || latest.revision !== policy.revision) fail('Repository policy or IDE approval changed during preview. No scan was submitted.');
  const initial = readGitPushCheck(await adapter.request(`${route}/check`, { method: 'POST', body: JSON.stringify(plan) }), plan, policy.revision); guard();
  if (!initial) fail('The local service returned an invalid outgoing-check response. No scan was submitted.');
  if (initial.decision === 'pass') {
    await adapter.showStatus('These exact outgoing commits already pass the current repository gate. Git rechecks their evidence and current policy at push time.'); return;
  }
  if (initial.decision !== 'blocked' || !initial.preflight_revision
    || !['push_evidence_missing_or_stale', 'push_gate_failed_or_incomplete'].includes(initial.reason_code || '')) {
    fail('Outgoing checks are not ready. Review the repository gate, IDE approval and scanner preparation in Settings before retrying.');
  }
  const interrupted = initial.scans.find((scan) => ['failed', 'partial'].includes(scan.status));
  if (interrupted) {
    await adapter.showRecovery(`Outgoing scan #${interrupted.scan_id} · job #${interrupted.job_id} is ${interrupted.status}. `
      + 'Check Outgoing does not create a duplicate or automatically retry this execution. Open Jobs, review its exact result and use Retry if offered, then check again. No push was approved.');
    return;
  }
  const cancelledScans = initial.scans.filter((scan) => scan.status === 'cancelled');
  if (cancelledScans.length) {
    const cancelledDetail = cancelledScans.map((scan) => `Cancelled scan #${scan.scan_id} · job #${scan.job_id}`).join('\n');
    if (!await adapter.confirm('Start a new check for cancelled commits?', `${detail}\n\n${cancelledDetail}\n`
      + 'Cancelled jobs remain in history. This starts new scans only for the cancelled committed trees and any missing evidence. '
      + 'Completed evidence is reused. No push occurs.', 'Start new check')) {
      guard();
      await adapter.showRecovery(`Outgoing scan #${cancelledScans[0].scan_id} · job #${cancelledScans[0].job_id} is cancelled. `
        + 'Check Outgoing does not create a duplicate or automatically retry this execution. '
        + 'Open Jobs to review it. To start new work, choose Check Outgoing again and confirm Start new check. No push was approved.');
      return;
    }
    guard();
    if ((await currentPlan()).digest !== plan.digest) fail('The outgoing plan changed during restart review. No new scan was submitted.');
    const restartPolicy = validateGitPushPolicy(await adapter.request(route), repository); guard();
    if (!approved(restartPolicy) || restartPolicy.revision !== policy.revision) {
      fail('Repository policy or IDE approval changed during restart review. No new scan was submitted.');
    }
    const refreshed = readGitPushCheck(await adapter.request(`${route}/check`, {
      method: 'POST', body: JSON.stringify(plan),
    }), plan, policy.revision); guard();
    if (!refreshed || refreshed.decision !== initial.decision || refreshed.reason_code !== initial.reason_code
      || refreshed.preflight_revision !== initial.preflight_revision
      || JSON.stringify(refreshed.missing_trees) !== JSON.stringify(initial.missing_trees)
      || JSON.stringify(refreshed.scans) !== JSON.stringify(initial.scans)) {
      fail('Outgoing evidence changed during restart review. Check again before starting new work.');
    }
  }
  let companionProject: number | undefined;
  let cancelled = false;
  let completedBeforeCancellation: { scanId: number; jobId: number } | undefined;
  let interruptedJob: { scanId: number; jobId: number; status: string } | undefined;
  const admitted: number[] = [];
  await adapter.withProgress(async (progress) => {
    for (let index = 0; index < plan.trees.length; index++) {
      guard();
      if (progress.cancellationRequested()) { cancelled = true; break; }
      const tree = plan.trees[index];
      const existing = initial.scans.find((scan) => scan.tree_oid === tree);
      const restart = cancelledScans.find((scan) => scan.tree_oid === tree);
      progress.report(`Committed tree ${index + 1}/${plan.trees.length}`);
      let scanId: number;
      let jobId: number;
      if (existing && !restart) {
        if (!['queued', 'running'].includes(existing.status)) continue;
        scanId = existing.scan_id; jobId = existing.job_id;
      } else {
        if (!restart && !initial.missing_trees.includes(tree)) fail('The service did not account for every outgoing tree. No additional scan was submitted.');
        const files = await exportGitTree(git, tree); guard();
        if (progress.cancellationRequested()) { cancelled = true; break; }
        const value = await adapter.request(`${route}/trees`, { method: 'POST', signal: progress.signal,
          body: JSON.stringify({ object_format: git.format, tree_oid: tree, files }) }); guard();
        const snapshot = value as Record<string, unknown>;
        if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)
          || Object.keys(snapshot).sort().join(',') !== 'file_count,object_format,project_id,repository_id,schema,snapshot_digest,source_id,total_bytes,tree_oid'
          || snapshot.schema !== 'lomo-git-tree-evidence/v1' || snapshot.repository_id !== repository.repositoryId
          || snapshot.source_id !== repository.repositoryId || snapshot.tree_oid !== tree || snapshot.object_format !== git.format
          || !positive(snapshot.project_id) || companionProject !== undefined && snapshot.project_id !== companionProject
          || typeof snapshot.snapshot_digest !== 'string' || !SHA.test(snapshot.snapshot_digest)
          || snapshot.file_count !== files.length || snapshot.total_bytes !== files.reduce((sum, file) => sum + file.size_bytes, 0)) {
          fail('The local snapshot receipt does not match the exact committed tree. No scan was submitted for it.');
        }
        companionProject = snapshot.project_id;
        if (progress.cancellationRequested()) { cancelled = true; break; }
        const command = workspaceScanCommand(snapshot.project_id, undefined, undefined, snapshot.snapshot_digest);
        // The cancelled scan is a stable, explicit restart generation. Replaying
        // this admission cannot create another job, while a later cancellation
        // can be reviewed as a separate new check without rewriting history.
        const identity = createHash('sha256').update(`${plan.digest}\0${tree}\0${policy.revision}\0${initial.preflight_revision}`
          + (restart ? `\0cancelled:${restart.scan_id}` : '')).digest('hex');
        const scan = await adapter.request(command.path, { ...command.init, signal: progress.signal,
          headers: { 'Idempotency-Key': `git-push-${identity}` },
          body: JSON.stringify({ ...JSON.parse(command.init.body as string), coverage: 'complete', preflight_revision: initial.preflight_revision }) }) as Scan;
        guard();
        if (!scan || scan.project_id !== snapshot.project_id || !positive(scan.id) || !positive(scan.job_id)
          || !positive(scan.revision) || !positive(scan.job_revision)) fail('Scan admission was not confirmed. Open Jobs before submitting another outgoing check.');
        scanId = scan.id; jobId = scan.job_id; admitted.push(scan.id);
      }
      const job = await progress.observe(jobId, scanId); guard();
      if (job.id !== jobId || job.scan_id !== scanId || job.kind !== 'scan' || !positive(job.revision)) fail('The observed job belongs to different outgoing work.');
      if (job.status === 'cancelled') { cancelled = true; break; }
      if (job.status !== 'completed') { interruptedJob = { scanId, jobId, status: job.status }; break; }
      if (progress.cancellationRequested()) { completedBeforeCancellation = { scanId, jobId }; break; }
    }
  });
  guard();
  if (completedBeforeCancellation) {
    await adapter.showStatus(`Outgoing check stopped, but scan #${completedBeforeCancellation.scanId} · job #${completedBeforeCancellation.jobId} already completed. `
      + 'That result remains available and may satisfy push protection. Later trees were not submitted; no push was performed.');
    return;
  }
  if (interruptedJob) {
    await adapter.showRecovery(`Outgoing scan #${interruptedJob.scanId} · job #${interruptedJob.jobId} is ${interruptedJob.status}. `
      + 'Review this exact job and use Retry if offered. Later trees were not submitted; no push was approved.');
    return;
  }
  if (cancelled) {
    await adapter.showStatus(`Outgoing check cancelled. ${admitted.length} scan(s) were admitted; review Jobs for retained results. No push was approved.`); return;
  }
  if ((await currentPlan()).digest !== plan.digest) fail('The outgoing references changed while scanning. Evidence was retained, but preview the new push before retrying.');
  const final = readGitPushCheck(await adapter.request(`${route}/check`, {
    method: 'POST', body: JSON.stringify(plan),
  }), plan, policy.revision); guard();
  if (!final || final.decision !== 'pass') {
    const message = 'The exact outgoing commits are blocked or their evidence changed. Review their scan findings and the repository gate; no push was approved.';
    const blockedScans = final?.decision === 'blocked' && final.reason_code === 'push_gate_failed_or_incomplete'
      ? [...new Set(final.scans.filter(scan => scan.status === 'completed' && scan.gate_decision === 'fail')
        .map(scan => scan.scan_id))] : [];
    if (blockedScans.length) { await adapter.showBlocked(message, blockedScans); return; }
    fail(message);
  }
  await adapter.showStatus(`${plan.commits.length} outgoing commit(s) pass the current repository gate. Git rechecks this exact evidence and current policy at push time; no push was performed.`);
}
