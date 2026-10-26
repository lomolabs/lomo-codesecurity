const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { mkdtemp, mkdir, writeFile, rm, realpath } = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { inspectGitRepository, readGitLocalRefs, readGitPushDestinations } = require('../../dist/git-push-objects.js');
const { runGitPushScan } = require('../../dist/git-push-scan.js');
const contract = require('../../../../apps/api/tests/fixtures/git-push-check-pass.json');

async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'lomo-outgoing-check-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = path.join(root, 'source'); const remote = path.join(root, 'remote.git');
  await mkdir(source);
  const git = (...args) => execFileSync('git', ['-C', source, ...args], { encoding: 'utf8' }).trim();
  git('init', '--quiet', '--initial-branch=main');
  execFileSync('git', ['init', '--bare', '--quiet', '--initial-branch=main', remote]);
  git('remote', 'add', 'origin', remote);
  for (const text of ['first committed\n', 'second committed\n']) {
    await writeFile(path.join(source, 'fixture.txt'), text); git('add', 'fixture.txt');
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'fixture');
  }
  await writeFile(path.join(source, 'fixture.txt'), 'uncommitted excluded\n');
  await writeFile(path.join(source, 'untracked.txt'), 'never uploaded\n');
  const observed = await inspectGitRepository(source);
  const repository = { repositoryId: observed.repositoryId, root: source, gitDirectory: observed.gitDirectory,
    projectId: 7, name: 'synthetic fixture', clientSlot: `ks1_${'s'.repeat(43)}`, generation: 1 };
  const policy = { repository_id: repository.repositoryId, project_id: 7, root_path: source, git_directory: observed.gitDirectory,
    name: repository.name, revision: 4, enabled: true, observed_state: 'not_installed', observed_revision: null,
    observed_at: null, hook_digest: null, reason_code: 'host_setup_required',
    members: [{ client_slot: repository.clientSlot, generation: 1, name: 'Synthetic IDE', state: 'approved',
      requested_at: '2026-09-12T20:00:00Z', approved_at: '2026-09-12T20:01:00Z' }] };
  const selected = { destination: remote, localRef: 'refs/heads/main', localOid: git('rev-parse', 'HEAD'), remoteRef: 'refs/heads/main' };
  const calls = []; const messages = []; const scans = []; const uploads = [];
  let removed = false; let cancelled = false; let checks = 0;
  const adapters = {
    chooseRepository: async () => repository,
    assertCurrent: () => { if (removed) throw Error('source removed'); },
    selectTarget: async () => selected,
    confirm: async (_title, detail) => { assert.match(detail, /2 outgoing commits · 2 distinct committed trees/); return true; },
    showStatus: async (message) => messages.push(message),
    showRecovery: async (message) => messages.push(message),
    showBlocked: async (message, scanIds) => { messages.push(message); messages.push({ blockingScanIds: [...scanIds] }); },
    request: async (url, init = {}) => {
      calls.push({ url, init });
      if (url.endsWith(repository.repositoryId)) return policy;
      const payload = JSON.parse(init.body);
      if (url.endsWith('/check')) {
        checks++;
        return { ...contract.response, repository_id: repository.repositoryId, policy_revision: 4,
          plan_digest: payload.digest, decision: checks === 1 ? 'blocked' : 'pass',
          reason_code: checks === 1 ? 'push_evidence_missing_or_stale' : null,
          missing_trees: checks === 1 ? payload.trees : [],
          scans: checks === 1 ? [] : payload.trees.map((tree, index) => ({ ...contract.response.scans[0], tree_oid: tree, scan_id: 20 + index, job_id: 30 + index })),
          ...(checks === 1 ? { evidence_digest: undefined } : {}) };
      }
      if (url.endsWith('/trees')) {
        uploads.push(payload);
        return { schema: 'lomo-git-tree-evidence/v1', repository_id: repository.repositoryId,
          object_format: 'sha1', tree_oid: payload.tree_oid, source_id: repository.repositoryId, project_id: 8,
          snapshot_digest: payload.tree_oid.padEnd(64, '0'), file_count: payload.files.length,
          total_bytes: payload.files.reduce((sum, file) => sum + file.size_bytes, 0) };
      }
      assert.equal(url, '/v1/scans'); scans.push(payload);
      return { id: scans.length + 19, job_id: scans.length + 29, project_id: 8, revision: 1, job_revision: 1, status: 'queued' };
    },
    withProgress: async (task) => task({ signal: new AbortController().signal, cancellationRequested: () => cancelled,
      report: () => {}, observe: async (jobId, scanId) => ({ id: jobId, scan_id: scanId, kind: 'scan', revision: 2, status: 'completed' }) }),
  };
  return { adapters, repository, observed, calls, messages, uploads, scans, git,
    remove: () => { removed = true; }, cancel: () => { cancelled = true; } };
}

test('outgoing check requires exact preview and protects cancellation, changed refs and removed roots before writes', async (t) => {
  for (const outcome of ['cancel', 'remove', 'change']) await t.test(outcome, async (t) => {
    const f = await fixture(t);
    f.adapters.confirm = async () => {
      if (outcome === 'remove') f.remove();
      if (outcome === 'change') f.git('update-ref', 'refs/heads/main', f.git('rev-parse', 'HEAD~1'));
      return outcome !== 'cancel';
    };
    if (outcome === 'cancel') await runGitPushScan(f.adapters);
    else await assert.rejects(runGitPushScan(f.adapters), /source removed|local reference changed/);
    assert.equal(f.calls.filter((call) => call.init.method === 'POST').length, 0);
  });
});

test('outgoing check directs retained cancelled or partial execution to exact Jobs recovery without duplicate scans', async (t) => {
  for (const status of ['cancelled', 'partial']) await t.test(status, async (t) => {
    const f = await fixture(t); const original = f.adapters.request;
    f.adapters.confirm = async title => title === 'Check these exact outgoing commits?';
    f.adapters.request = async (url, init) => {
      const value = await original(url, init);
      if (!url.endsWith('/check')) return value;
      const plan = JSON.parse(init.body);
      return { ...value, reason_code: 'push_gate_failed_or_incomplete', missing_trees: [],
        scans: plan.trees.map((tree) => ({ ...contract.response.scans[0], tree_oid: tree, scan_id: 20, job_id: 30,
          status, gate_decision: 'incomplete' })) };
    };
    await runGitPushScan(f.adapters);
    assert.equal(f.uploads.length, 0); assert.equal(f.scans.length, 0);
    assert.match(f.messages[0], /scan #20 · job #30/);
    assert.match(f.messages[0], /does not create a duplicate or automatically retry/);
    assert.match(f.messages[0], status === 'cancelled' ? /confirm Start new check/ : /Retry if offered/);
  });
});

test('outgoing check uploads exact committed trees through shared scan admission and only final API evidence permits pass', async (t) => {
  const f = await fixture(t);
  assert.deepEqual(await readGitLocalRefs(f.observed), [{ ref: 'refs/heads/main', oid: f.git('rev-parse', 'HEAD') }]);
  assert.equal((await readGitPushDestinations(f.observed))[0].name, 'origin');
  await runGitPushScan(f.adapters);
  assert.equal(f.uploads.length, 2); assert.equal(f.scans.length, 2);
  assert.deepEqual(f.uploads.map((upload) => Buffer.from(upload.files[0].content_base64, 'base64').toString()).sort(), ['first committed\n', 'second committed\n']);
  assert(f.uploads.every((upload) => upload.files.length === 1 && upload.files[0].path === 'fixture.txt'));
  assert(f.scans.every((scan) => scan.project_id === 8 && scan.use_ai === false && scan.mode === 'full' && scan.coverage === 'complete'
    && scan.preflight_revision === contract.response.preflight_revision && !Object.hasOwn(scan, 'target_path')));
  const keys = f.calls.filter((call) => call.url === '/v1/scans').map((call) => call.init.headers['Idempotency-Key']);
  assert.equal(new Set(keys).size, 2); assert(keys.every((key) => /^git-push-[a-f0-9]{64}$/.test(key)));
  assert.match(f.messages.at(-1), /pass the current repository gate/);
});

test('outgoing check refuses mismatched snapshot, failed final gate and stops later tree admission on cancellation', async (t) => {
  for (const outcome of ['snapshot', 'gate', 'cancel']) await t.test(outcome, async (t) => {
    const f = await fixture(t); const request = f.adapters.request;
    f.adapters.request = async (url, init) => {
      const value = await request(url, init);
      if (outcome === 'snapshot' && url.endsWith('/trees')) return { ...value, tree_oid: 'f'.repeat(40) };
      if (outcome === 'gate' && url.endsWith('/check') && value.decision === 'pass') return { ...value, decision: 'blocked', reason_code: 'push_gate_failed_or_incomplete' };
      return value;
    };
    if (outcome === 'cancel') {
      f.adapters.withProgress = async (task) => task({ signal: new AbortController().signal, cancellationRequested: () => f.scans.length > 0,
        report: () => {}, observe: async (jobId, scanId) => ({ id: jobId, scan_id: scanId, kind: 'scan', revision: 2, status: 'cancelled' }) });
      await runGitPushScan(f.adapters);
      assert.equal(f.scans.length, 1); assert.equal(f.uploads.length, 1); assert.match(f.messages.at(-1), /cancelled/);
    } else await assert.rejects(runGitPushScan(f.adapters), outcome === 'snapshot' ? /snapshot receipt/ : /blocked or their evidence changed/);
    if (outcome === 'snapshot') assert.equal(f.scans.length, 0);
    assert(!f.messages.some((message) => message.includes('pass the current repository gate')));
  });
});


test('blocked history offers only validated failed scan IDs, never the later clean tip', async (t) => {
  const f = await fixture(t); const request = f.adapters.request;
  f.adapters.request = async (url, init) => {
    const value = await request(url, init);
    if (!url.endsWith('/check') || value.decision !== 'pass') return value;
    return { ...value, decision: 'blocked', reason_code: 'push_gate_failed_or_incomplete',
      scans: value.scans.map((scan, index) => ({ ...scan, gate_decision: index === 0 ? 'fail' : 'pass' })) };
  };
  await runGitPushScan(f.adapters);
  assert.deepEqual(f.messages.at(-1), { blockingScanIds: [20] });
  assert(!f.messages.some(message => typeof message === 'string' && message.includes('pass the current repository gate')));
});

test('a malformed final proof cannot supply actionable scan IDs', async (t) => {
  const f = await fixture(t); const request = f.adapters.request;
  f.adapters.request = async (url, init) => {
    const value = await request(url, init);
    if (!url.endsWith('/check') || value.decision !== 'pass') return value;
    return { ...value, decision: 'blocked', reason_code: 'push_gate_failed_or_incomplete', policy_revision: 999,
      scans: value.scans.map(scan => ({ ...scan, gate_decision: 'fail' })) };
  };
  await assert.rejects(runGitPushScan(f.adapters), /blocked or their evidence changed/);
  assert(!f.messages.some(message => typeof message === 'object'));
});

test('outgoing check reports completion that wins a cancellation race truthfully', async (t) => {
  const f = await fixture(t);
  f.adapters.withProgress = async (task) => task({ signal: new AbortController().signal,
    cancellationRequested: () => f.scans.length > 0, report: () => {},
    observe: async (jobId, scanId) => ({ id: jobId, scan_id: scanId, kind: 'scan', revision: 2, status: 'completed' }) });
  await runGitPushScan(f.adapters);
  assert.equal(f.scans.length, 1);
  assert.match(f.messages.at(-1), /already completed/);
  assert.match(f.messages.at(-1), /may satisfy push protection/);
  assert.doesNotMatch(f.messages.at(-1), /check cancelled/);
});

test('native outgoing Cancel wakes the persisted observer and retains cleanup observation', async () => {
  const { readFileSync } = require('node:fs');
  const { runInNewContext } = require('node:vm');
  const { observeJob } = require('../../dist/jobs.js');
  const source = readFileSync(path.join(__dirname, '../../src/extension.ts'), 'utf8');
  const start = source.indexOf('withProgress: async (task) => vscode.window.withProgress');
  const end = source.indexOf('\n      });\n    } else await runGitPushProtection', start);
  assert(start > 0 && end > start);
  const expression = source.slice(start + 'withProgress: '.length, end).trim().replace(/,$/, '');
  let listener, cancelled = false, disposed = 0, wake, waiting, posted = 0, reads = 0;
  const ready = new Promise(resolve => { waiting = resolve; });
  const signal = new AbortController().signal;
  const token = { get isCancellationRequested() { return cancelled; },
    onCancellationRequested(callback) { listener = callback; return { dispose() { disposed++; listener = undefined; } }; } };
  const observe = async (jobId, scanId, passedSignal, cancellationRequested) => observeJob({
    jobId, scanId, signal: passedSignal, cancellationRequested, onUpdate: () => {},
    request: async (url, init) => {
      assert.equal(init.signal.aborted, false, 'Cancel must retain the durable cleanup observer');
      if (url.endsWith('/cancel')) { posted++; assert.equal(init.method, 'POST'); }
      else reads++;
      return { id: jobId, scan_id: scanId, kind: 'scan', revision: posted ? 3 : 2,
        status: posted ? 'cancelled' : 'running', can_cancel: !posted };
    },
    waitForChange: async () => { await new Promise(resolve => { wake = resolve; waiting(); }); },
    timeoutMs: 1000,
  });
  const adapter = runInNewContext(`(${expression})`, {
    vscode: { ProgressLocation: { Notification: 15 }, window: {
      withProgress: async (options, task) => { assert.equal(options.cancellable, true); return task({ report() {} }, token); },
    } },
    sourceAbort: { signal }, observePersistedJob: observe,
    realtime: { wakeAllJobs: () => { assert(wake); wake(); } },
  });
  const run = adapter(progress => progress.observe(79, 65));
  await ready; cancelled = true; listener();
  const result = await run;
  assert.equal(result.status, 'cancelled'); assert.equal(posted, 1); assert.equal(reads, 2);
  assert.equal(signal.aborted, false); assert.equal(disposed, 1); assert.equal(listener, undefined);
  await assert.rejects(adapter(async () => { throw Error('owned task failed'); }), /owned task failed/);
  assert.equal(disposed, 2);
});

test('cancelled outgoing checks require explicit restart, preserve completed trees and fence stale review', async (t) => {
  for (const outcome of ['restart', 'decline', 'changed-evidence', 'changed-policy', 'changed-ref']) await t.test(outcome, async (t) => {
    const f = await fixture(t), original = f.adapters.request;
    let restartApproved = false, checks = 0, restartPrompts = 0;
    f.adapters.confirm = async (title, detail, action) => {
      if (title === 'Check these exact outgoing commits?') return true;
      assert.equal(title, 'Start a new check for cancelled commits?');
      assert.equal(action, 'Start new check'); assert.match(detail, /Cancelled scan #10 · job #12/);
      assert.match(detail, /Cancelled jobs remain in history/); restartPrompts++;
      if (outcome === 'changed-ref') f.git('update-ref', 'refs/heads/main', f.git('rev-parse', 'HEAD~1'));
      restartApproved = outcome !== 'decline'; return restartApproved;
    };
    f.adapters.request = async (url, init) => {
      const value = await original(url, init);
      if (url.endsWith(f.repository.repositoryId) && restartApproved && outcome === 'changed-policy') {
        return { ...value, revision: value.revision + 1 };
      }
      if (!url.endsWith('/check')) return value;
      checks++; const plan = JSON.parse(init.body);
      if (checks % 3 === 0) return value;
      return { ...value, decision: 'blocked', reason_code: 'push_gate_failed_or_incomplete', evidence_digest: undefined,
        missing_trees: [], scans: plan.trees.map((tree, index) => ({ ...contract.response.scans[0], tree_oid: tree,
          scan_id: index === 0 ? 10 : 11, job_id: index === 0 ? 12 : 13,
          status: index === 0 ? 'cancelled' : 'completed', gate_decision: index === 0 ? 'incomplete' : 'pass',
          revision: restartApproved && outcome === 'changed-evidence' ? 99 : 2 })) };
    };
    if (outcome.startsWith('changed-')) {
      await assert.rejects(runGitPushScan(f.adapters), /changed/);
    } else await runGitPushScan(f.adapters);
    assert.equal(restartPrompts, 1);
    assert.equal(f.scans.length, outcome === 'restart' ? 1 : 0);
    assert.equal(f.uploads.length, outcome === 'restart' ? 1 : 0);
    if (outcome === 'restart') {
      const key = f.calls.find(call => call.url === '/v1/scans').init.headers['Idempotency-Key'];
      await runGitPushScan(f.adapters);
      const keys = f.calls.filter(call => call.url === '/v1/scans').map(call => call.init.headers['Idempotency-Key']);
      assert.deepEqual(keys, [key, key], 'one cancelled generation must reuse its admission key');
      assert.match(f.messages.at(-1), /pass the current repository gate/);
    }
  });
});
