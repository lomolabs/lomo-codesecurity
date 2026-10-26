const assert = require('node:assert/strict');
const test = require('node:test');
const { CodeSecurityRequestError } = require('../../dist/request-error.js');
const { runGitPushProtection, validateGitPushPolicy, pushProtectionStatus } = require('../../dist/git-push-ui.js');

const repository = Object.freeze({ repositoryId: 'a'.repeat(64), projectId: 7, name: 'fixture', root: '/fixture', gitDirectory: '/fixture/.git', clientSlot: `ks1_${'s'.repeat(43)}`, generation: 3 });
const digest = 'b'.repeat(64);
const stamp = '2026-09-12T21:00:00Z';
const policy = (overrides = {}) => ({
  repository_id: repository.repositoryId, project_id: repository.projectId, name: repository.name,
  root_path: repository.root, git_directory: repository.gitDirectory,
  revision: 4, enabled: true, observed_state: 'installed', observed_revision: 4,
  observed_at: stamp, hook_digest: digest, reason_code: null,
  members: [{ client_slot: repository.clientSlot, generation: repository.generation, name: 'QA profile', state: 'approved', requested_at: stamp, approved_at: stamp }],
  ...overrides,
});
function fixture(options = {}) {
  let saved = options.policy === null ? null : policy(options.policy);
  let host = options.host || { state: 'installed', enabled: true, revision: 4, hookDigest: digest };
  const effects = [];
  let open = true;
  let reads = 0;
  const adapters = {
    chooseRepository: async () => options.cancelRepository ? undefined : repository,
    assertCurrent() { if (!open) throw new Error('workspace or profile changed'); },
    request: async (path, init = {}) => {
      if (!init.method) {
        reads++;
        if (options.beforeRead) options.beforeRead(reads, saved);
        if (!saved) throw new CodeSecurityRequestError('setup required', 404, false, { code: 'push_setup_required' });
        return structuredClone(saved);
      }
      const body = JSON.parse(init.body);
      effects.push({ path, method: init.method, body });
      if (path.endsWith('/observation')) {
        assert.equal(body.expected_revision, saved.revision);
        saved = { ...saved, observed_state: body.state, observed_revision: saved.revision, hook_digest: body.hook_digest, observed_at: stamp, reason_code: null };
      } else if (init.method === 'PATCH') {
        assert.equal(body.expected_revision, saved.revision);
        saved = { ...saved, enabled: body.enabled, revision: saved.revision + 1, reason_code: 'policy_changed' };
      } else {
        saved = policy({ enabled: false, revision: 1, observed_state: 'not_installed', observed_revision: null, observed_at: null, hook_digest: null, reason_code: 'host_setup_required',
          members: [{ ...policy().members[0], state: 'requested', approved_at: null }] });
      }
      return structuredClone(saved);
    },
    inspectPolicy: async () => host,
    applyPolicy: async (_repository, next) => {
      effects.push({ kind: 'apply', revision: next.revision, enabled: next.enabled });
      host = options.badApply || { state: 'installed', enabled: next.enabled, revision: next.revision, hookDigest: digest };
      return host;
    },
    removePolicy: async (selected, retained) => {
      effects.push({ kind: 'remove', projectId: selected.projectId, policyRevision: retained?.revision });
      return options.removal || { localRemoved: true, registrationRemoved: true, cleanup: 'complete', reasonCode: null };
    },
    choose: async (choices, title, description) => {
      effects.push({ kind: 'menu', choices: choices.map((item) => item.id), title, description });
      return options.choice;
    },
    confirm: async (title, detail, action) => {
      effects.push({ kind: 'confirm', title, detail, action });
      if (options.closeDuringConfirm) open = false;
      return options.confirm !== false;
    },
    showStatus: async (message) => { effects.push({ kind: 'status', message }); },
    openSettings: async () => { effects.push({ kind: 'settings' }); },
  };
  return { adapters, effects, writes: () => effects.filter((item) => item.method || item.kind === 'apply' || item.kind === 'remove') };
}

test('push-protection UI cancellation and removed-root confirmation make no policy or hook writes', async () => {
  for (const options of [{ cancelRepository: true }, { choice: undefined }, { choice: 'toggle', confirm: false }]) {
    const run = fixture(options); await runGitPushProtection(run.adapters); assert.deepEqual(run.writes(), []);
  }
  const changed = fixture({ choice: 'toggle', closeDuringConfirm: true });
  await assert.rejects(runGitPushProtection(changed.adapters), /workspace or profile changed/);
  assert.deepEqual(changed.writes(), []);
});

test('push-protection UI setup requests exact member approval without enabling or installing', async () => {
  const run = fixture({ policy: null, host: { state: 'not_installed', enabled: null, revision: null, hookDigest: null }, choice: 'setup' });
  await runGitPushProtection(run.adapters);
  assert.equal(run.writes().length, 1);
  assert.deepEqual(run.writes()[0].body, { repository_id: repository.repositoryId, name: 'fixture', project_id: 7,
    root_path: '/fixture', git_directory: '/fixture/.git' });
  assert.equal(run.effects.filter((item) => item.kind === 'settings').length, 1);
  assert.equal(run.effects.filter((item) => item.kind === 'status').length, 0);
  assert.equal(run.effects.at(-1).kind, 'settings');
});

test('push-protection UI never mistakes another generation approval for current membership', async () => {
  const run = fixture({ policy: { members: [{ ...policy().members[0], generation: 2 }] }, choice: undefined });
  await runGitPushProtection(run.adapters);
  assert.deepEqual(run.effects.find((item) => item.kind === 'menu').choices, ['setup', 'settings', 'remove']);
  assert.deepEqual(run.writes(), []);
});

test('push-protection UI Off requires explicit bypass confirmation and exact applied observation', async () => {
  const run = fixture({ choice: 'toggle' });
  await runGitPushProtection(run.adapters);
  const confirm = run.effects.find((item) => item.kind === 'confirm');
  assert.match(confirm.detail, /failed or unscanned commits/);
  assert.match(confirm.detail, /--no-verify/);
  assert.equal(confirm.action, 'Apply protection off');
  assert.deepEqual(run.writes().map((item) => item.method || item.kind), ['PATCH', 'apply', 'POST']);
  assert.deepEqual(run.writes()[0].body, { expected_revision: 4, enabled: false, confirm_bypass: true });
  assert.deepEqual(run.writes()[2].body, { expected_revision: 5, state: 'installed', hook_digest: digest });
  assert.match(run.effects.at(-1).message, /Requested: Off · Local hook: Off · current setting applied/);
  assert.match(run.effects.at(-1).message, /Lomo will not check or block pushes/);
  assert.doesNotMatch(run.effects.at(-1).message, /still needs an exact outgoing-commit check/);
});

test('push-protection UI refresh reports requested Off versus still-applied On without mutation', async () => {
  const run = fixture({ policy: { enabled: false, revision: 5, reason_code: 'policy_changed' }, choice: 'refresh' });
  await runGitPushProtection(run.adapters);
  assert.match(run.effects.at(-1).message, /Requested: Off · Local hook: On · review\/apply required/);
  assert.deepEqual(run.writes(), []);
});

test('push-protection UI concurrent policy edit and bad host result never record installed success', async () => {
  const changed = fixture({ choice: 'apply', beforeRead: (count, item) => { if (count === 2) item.revision++; } });
  await assert.rejects(runGitPushProtection(changed.adapters), /changed before host setup/);
  assert.deepEqual(changed.writes(), []);
  const unconfirmed = fixture({ choice: 'apply', badApply: { state: 'installed', enabled: true, revision: 3, hookDigest: digest } });
  await assert.rejects(runGitPushProtection(unconfirmed.adapters), /local hook was not confirmed/);
  assert.equal(unconfirmed.writes().length, 1);
  assert.equal(unconfirmed.writes()[0].kind, 'apply');
});

test('push-protection UI validates exact policy, member uniqueness, revision and local observation', async () => {
  assert.equal(validateGitPushPolicy(policy(), repository).revision, 4);
  for (const value of [policy({ project_id: 8 }), policy({ repository_id: 'c'.repeat(64) }), policy({ surprise: true }),
    policy({ revision: true }), policy({ observed_revision: 5 }), policy({ members: [policy().members[0], policy().members[0]] })]) {
    assert.throws(() => validateGitPushPolicy(value, repository), /invalid or different/);
  }
  const invalid = fixture({ host: { state: 'installed', enabled: true, revision: 4, hookDigest: null } });
  await assert.rejects(runGitPushProtection(invalid.adapters), /local hook state/);
  assert.deepEqual(invalid.writes(), []);
  assert.match(pushProtectionStatus(policy({ enabled: false, revision: 5 }), { state: 'installed', enabled: true, revision: 4, hookDigest: digest }), /review\/apply required/);
});

test('push-protection removal confirms bypass, preserves old project binding and distinguishes retry from owner review', async () => {
  for (const options of [{ choice: 'remove', confirm: false }, { choice: 'remove', closeDuringConfirm: true }]) {
    const f = fixture(options);
    if (options.closeDuringConfirm) await assert.rejects(runGitPushProtection(f.adapters), /workspace or profile changed/);
    else await runGitPushProtection(f.adapters);
    assert.deepEqual(f.writes(), []);
  }
  for (const cleanup of ['complete', 'retryable', 'review_required']) {
    const f = fixture({ choice: 'remove', policy: { project_id: 6 }, removal: {
      localRemoved: true, registrationRemoved: cleanup === 'complete', cleanup,
      reasonCode: cleanup === 'review_required' ? 'push_policy_changed' : null,
    } });
    await runGitPushProtection(f.adapters);
    assert.deepEqual(f.effects.find((item) => item.kind === 'menu').choices, ['remove', 'settings']);
    assert.match(f.effects.find((item) => item.kind === 'menu').description, /project #6.*project is #7/);
    assert.deepEqual(f.writes(), [{ kind: 'remove', projectId: 6, policyRevision: 4 }]);
    const confirmation = f.effects.find((item) => item.kind === 'confirm');
    assert.match(confirmation.detail, /failed or unscanned commits/);
    assert.match(confirmation.detail, /repository-specific editor grants/);
    assert.match(confirmation.detail, /No scans, projects, findings, credentials/);
    assert.match(f.effects.at(-1).message, cleanup === 'complete' ? /were removed/ : cleanup === 'retryable' ? /retry the same retained request/ : /needs owner review/);
  }
  const pending = fixture({ choice: 'remove', policy: null, host: { state: 'needs_repair', enabled: null, revision: 4, hookDigest: digest } });
  await runGitPushProtection(pending.adapters);
  assert.deepEqual(pending.effects.find((item) => item.kind === 'menu').choices, ['remove', 'settings']);
});
