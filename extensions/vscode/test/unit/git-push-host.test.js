const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { execFileSync, spawnSync } = require('node:child_process');
const { mkdtemp, mkdir, writeFile, readFile, rm, symlink, realpath, chmod } = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { ProfileCredentialStore } = require('../../dist/credentials.js');
const { inspectGitRepository } = require('../../dist/git-push-objects.js');
const { applyGitPushPolicy, inspectGitPushPolicy, readGitPushConfiguration, gitPushClient, removeGitPushPolicy } = require('../../dist/git-push-host.js');
const { decodeGitPushInput, runGitPushHook, validateGitPushCheck, normalizeGitHookConfigurationArgument } = require('../../dist/git-push-cli.js');

test('Windows hook CLI normalizes only the generated separator spelling before private reads', () => {
  const native=String.raw`c:\Users\QA\globalStorage\git-push-v1\fixture.json`;
  assert.equal(normalizeGitHookConfigurationArgument(native,'win32'),native);
  assert.equal(normalizeGitHookConfigurationArgument(native.replaceAll('\\','/'),'win32'),native);
  for(const invalid of ['c:/Users/QA/../fixture.json','c:/Users/QA/./fixture.json',
    'c:/Users//QA/fixture.json','c:/Users/QA/fixture.json/','c:/Users/QA /fixture.json',
    'c:/Users/CON/file.json',String.raw`c:/Users\QA/fixture.json`,
    String.raw`c:\Users/QA/fixture.json`,'//server/share/fixture.json',
    '//?/c:/Users/QA/fixture.json','c:Users/QA/fixture.json','/c/Users/QA/fixture.json',
    'c:/Users/QA/fixture.json:stream','c:/Users/QA/fixture\u0000.json']) {
    assert.throws(()=>normalizeGitHookConfigurationArgument(invalid,'win32'),{code:'git_push_host_unverified'},invalid);
  }
  assert.equal(normalizeGitHookConfigurationArgument('c:/users/QA/fixture.json','win32'),String.raw`c:\users\QA\fixture.json`);
  for(const platform of ['darwin','linux']) {
    for(const exact of ['/tmp/owned/fixture.json','C:/Users/QA/fixture.json','/tmp/owned/../fixture.json']) {
      assert.equal(normalizeGitHookConfigurationArgument(exact,platform),exact);
    }
  }
});

async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'lomo-push-host-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = path.join(root, 'source');
  const storage = path.join(root, 'profile');
  const extension = path.join(root, 'extension');
  await mkdir(source); await mkdir(storage, { mode: 0o700 }); await mkdir(extension); await mkdir(path.join(extension, 'dist'));
  await writeFile(path.join(extension, 'dist', 'git-push-cli.js'), '// synthetic installed helper identity\n');
  execFileSync('git', ['init', '--quiet', '--initial-branch=main', source]);
  const observed = await inspectGitRepository(source);
  const context = { endpoint: 'http://127.0.0.1:8080', globalStoragePath: storage,
    globalStorageIdentity: `vscode-userdata:${storage}`, extensionPath: extension, nodePath: process.execPath };
  const credentials = new ProfileCredentialStore(storage, context.globalStorageIdentity);
  const active = { v: 1, endpoint: context.endpoint, client_slot: credentials.clientSlot, generation: 1,
    capability: `kc1.${credentials.clientSlot}.1.${createHash('sha256').update('synthetic-hook-authority').digest('base64url')}` };
  const pending = { ...active, enrollment_request_id: `ker1_${'r'.repeat(24)}`, enrollment_revision: 1,
    enrollment_verification_code: 'ABCD-EF23', activation_expires_at: '2026-09-12T23:59:59Z' };
  await credentials.writePending(context.endpoint, pending);
  await credentials.promotePending(context.endpoint, pending, active);
  const repository = { repositoryId: observed.repositoryId, root: source, gitDirectory: observed.gitDirectory,
    projectId: 7, name: 'fixture', clientSlot: credentials.clientSlot, generation: 1 };
  let policy = { repository_id: repository.repositoryId, root_path: source, git_directory: observed.gitDirectory,
    name: 'fixture', project_id: 7, revision: 2, enabled: true,
    observed_state: 'not_installed', observed_revision: null, observed_at: null, hook_digest: null, reason_code: 'host_setup_required',
    members: [{ client_slot: credentials.clientSlot, generation: 1, name: 'Synthetic IDE', state: 'approved', requested_at: '2026-09-12T20:00:00Z', approved_at: '2026-09-12T20:01:00Z' }] };
  const priorFetch = global.fetch;
  let requests = 0;
  global.fetch = async (url, init) => {
    requests++;
    assert.equal(url, `${context.endpoint}/v1/git/push-protection/${repository.repositoryId}`);
    assert.equal(new Headers(init.headers).get('Authorization'), `Bearer ${active.capability}`);
    return new Response(JSON.stringify(policy), { headers: { 'Content-Type': 'application/json' } });
  };
  t.after(() => { global.fetch = priorFetch; });
  return { root, repository, context, credentials, active, policy, setPolicy(value) { policy = value; }, requests: () => requests,
    configPath: path.join(storage, 'git-push-v1', `${repository.repositoryId}.json`), hookPath: path.join(observed.gitDirectory, 'hooks', 'pre-push') };
}

test('push host applies verified On then Off, retains credentials only in the existing store and runs Off offline', async (t) => {
  const f = await fixture(t);
  assert.equal((await inspectGitPushPolicy(f.repository, f.policy, f.context)).state, 'not_installed');
  const on = await applyGitPushPolicy(f.repository, f.policy, f.context);
  assert.deepEqual({ state: on.state, enabled: on.enabled, revision: on.revision }, { state: 'installed', enabled: true, revision: 2 });
  const raw = await readFile(f.configPath, 'utf8');
  const hook = await readFile(f.hookPath, 'utf8');
  assert(!raw.includes(f.active.capability)); assert(!hook.includes(f.active.capability));
  const offPolicy = { ...f.policy, enabled: false, revision: 3 };
  f.setPolicy(offPolicy);
  const off = await applyGitPushPolicy(f.repository, offPolicy, f.context);
  assert.equal(off.enabled, false); assert.equal(off.revision, 3);
  global.fetch = async () => assert.fail('applied Off must work without API or enrollment');
  await writeFile(path.join(f.repository.gitDirectory, 'info', 'grafts'), '# unsupported while On\n');
  assert.equal(await runGitPushHook(f.configPath, '', '/does-not-need-a-remote'), 0);
  const cli = spawnSync(process.execPath, [path.resolve(__dirname, '../../dist/git-push-cli.js'), '--hook', f.configPath, 'origin', '/offline'],
    { encoding: 'utf8', input: 'x'.repeat(40 * 1024) });
  assert.equal(cli.status, 0); assert.equal(cli.stderr, ''); assert.equal(cli.stdout, '');
});

test('SCM filesystem witness accepts protection files written by the production host', async (t) => {
  const { inspectGitPushScmFiles } = await import('../support/git-push-host-files.mjs');
  const { scmWindowsAclReader } = await import('../support/git-push-windows-acl.mjs');
  const aclDependencies = { createWindowsAclReader: process.platform === 'win32' ? scmWindowsAclReader : undefined };
  const f = await fixture(t);
  await applyGitPushPolicy(f.repository, f.policy, f.context);
  const neighborRoot = path.join(f.root, 'neighbor');
  await mkdir(neighborRoot);
  execFileSync('git', ['init', '--quiet', '--initial-branch=main', neighborRoot]);
  const observed = await inspectGitRepository(neighborRoot);
  const neighbor = { ...f.repository, repositoryId: observed.repositoryId,
    root: observed.root, gitDirectory: observed.gitDirectory, name: 'neighbor', projectId: 8 };
  const neighborPolicy = { ...f.policy, repository_id: neighbor.repositoryId,
    root_path: neighbor.root, git_directory: neighbor.gitDirectory, name: neighbor.name, project_id: 8 };
  f.setPolicy(neighborPolicy);
  const originalFetch = global.fetch;
  global.fetch = async url => {
    assert.equal(url, `${f.context.endpoint}/v1/git/push-protection/${neighbor.repositoryId}`);
    return new Response(JSON.stringify(neighborPolicy), { headers: { 'Content-Type': 'application/json' } });
  };
  try { await applyGitPushPolicy(neighbor, neighborPolicy, f.context); }
  finally { global.fetch = originalFetch; }
  const options = { globalStoragePath: f.context.globalStoragePath,
    globalStorageIdentity: f.context.globalStorageIdentity, extensionPath: f.context.extensionPath,
    controlOrigin: f.context.endpoint,
    expected_helper_sha256: createHash('sha256').update(await readFile(path.join(f.context.extensionPath, 'dist', 'git-push-cli.js'))).digest('hex'),
    repositories: [f.repository, neighbor].map(repo => ({ repository_id: repo.repositoryId,
      root: repo.root, git_directory: repo.gitDirectory })) };
  const witness = await inspectGitPushScmFiles(options, aclDependencies);
  assert.equal(witness.length, 2);
  for (const row of witness) {
    const actual = await readGitPushConfiguration(path.join(f.context.globalStoragePath, 'git-push-v1', `${row.repository_id}.json`));
    assert.equal(row.root, actual.repository.root);
    assert.equal(row.revision, actual.revision);
    assert.equal(row.enabled, actual.enabled);
    assert.equal(row.hook_digest, actual.hookDigest);
  }
  await assert.rejects(inspectGitPushScmFiles({ ...options,
    globalStorageIdentity: `${f.context.globalStorageIdentity}/wrong-profile` }, aclDependencies), /SCM/);
});

test('push host refuses changed hooks, member revocation and insecure configuration without replacing them', async (t) => {
  const f = await fixture(t);
  await applyGitPushPolicy(f.repository, f.policy, f.context);
  const configuration = await readFile(f.configPath, 'utf8');
  const revoked = { ...f.policy, revision: 3, members: [{ ...f.policy.members[0], state: 'revoked' }] };
  f.setPolicy(revoked);
  await assert.rejects(applyGitPushPolicy(f.repository, revoked, f.context), /approval changed/);
  assert.equal(await readFile(f.configPath, 'utf8'), configuration);
  f.setPolicy(f.policy);
  await writeFile(f.hookPath, '#!/bin/sh\n# unrelated replacement\n', { mode: 0o700 });
  assert.equal((await inspectGitPushPolicy(f.repository, f.policy, f.context)).state, 'needs_repair');
  await assert.rejects(applyGitPushPolicy(f.repository, f.policy, f.context), /hook or profile binding changed/);
  assert.match(await readFile(f.hookPath, 'utf8'), /unrelated replacement/);
  await chmod(f.configPath, 0o644);
  await assert.rejects(readGitPushConfiguration(f.configPath), /private file\/directory permissions/);
});

test('explicit Apply recovers an unchanged hook after same-profile re-enrollment and fresh repository approval', async (t) => {
  const f = await fixture(t);
  await applyGitPushPolicy(f.repository, f.policy, f.context);
  const before = await readGitPushConfiguration(f.configPath);
  const hook = await readFile(f.hookPath, 'utf8');
  const active = { ...f.active, generation: 2, capability: `kc1.${f.active.client_slot}.2.${'q'.repeat(43)}` };
  const pending = { ...active, enrollment_request_id: `ker1_${'n'.repeat(24)}`, enrollment_revision: 1,
    enrollment_verification_code: 'ABCD-EF23', activation_expires_at: '2026-09-12T23:59:59Z' };
  const repository = { ...f.repository, generation: 2 };
  const approved = { ...f.policy, revision: 3,
    members: [...f.policy.members, { ...f.policy.members[0], generation: 2 }] };
  await f.credentials.writePending(f.context.endpoint, pending);
  f.setPolicy(approved);
  await assert.rejects(applyGitPushPolicy(repository, approved, f.context), /finish IDE access/);
  await f.credentials.promotePending(f.context.endpoint, pending, active);
  Object.assign(f.active, active); // The mock server now expects only the new bearer.
  await assert.rejects(gitPushClient(before).request('/v1/git/push-protection'), /finish IDE access/);
  assert.equal((await inspectGitPushPolicy(repository, approved, f.context)).state, 'needs_repair');
  for (const state of ['requested', 'revoked']) {
    const denied = { ...approved, members: [approved.members[0], { ...approved.members[1], state }] };
    f.setPolicy(denied);
    await assert.rejects(applyGitPushPolicy(repository, denied, f.context), /approval changed/);
    assert.deepEqual(await readGitPushConfiguration(f.configPath), before);
  }
  f.setPolicy(approved);
  await writeFile(f.hookPath, '#!/bin/sh\n# unrelated hook\n');
  await assert.rejects(applyGitPushPolicy(repository, approved, f.context), /hook or profile binding changed/);
  assert.deepEqual(await readGitPushConfiguration(f.configPath), before);
  await writeFile(f.hookPath, hook);
  // A new generation cannot take another slot, downgrade a newer hook, or
  // change the original profile, endpoint, source project or helper location.
  for (const changed of [
    { ...before, repository: { ...before.repository, clientSlot: `ks1_${'x'.repeat(43)}` } },
    { ...before, repository: { ...before.repository, generation: 3 } },
    { ...before, repository: { ...before.repository, projectId: 8 } },
    { ...before, context: { ...before.context, globalStorageIdentity: 'other-profile' } },
    { ...before, context: { ...before.context, endpoint: 'http://127.0.0.1:8081' } },
    { ...before, context: { ...before.context, extensionPath: path.join(f.root, 'other-extension') } },
  ]) {
    await writeFile(f.configPath, JSON.stringify(changed) + '\n');
    await assert.rejects(applyGitPushPolicy(repository, approved, f.context), /hook or profile binding changed/);
    assert.deepEqual(await readGitPushConfiguration(f.configPath), changed);
  }
  await writeFile(f.configPath, JSON.stringify(before) + '\n');
  assert.equal((await applyGitPushPolicy(repository, approved, f.context)).state, 'installed');
  assert.deepEqual(await readGitPushConfiguration(f.configPath), {
    ...before, repository: { ...before.repository, generation: 2 }, revision: 3,
  });
  assert.equal(await readFile(f.hookPath, 'utf8'), hook);
  assert.equal((await inspectGitPushPolicy(repository, approved, f.context)).state, 'installed');
});

test('push host never follows linked configuration or activates a pending IDE generation', async (t) => {
  const f = await fixture(t);
  await applyGitPushPolicy(f.repository, f.policy, f.context);
  const configuration = await readGitPushConfiguration(f.configPath);
  const copied = path.join(f.root, 'copied.json');
  await writeFile(copied, await readFile(f.configPath), { mode: 0o600 });
  await rm(f.configPath); await symlink(copied, f.configPath);
  await assert.rejects(readGitPushConfiguration(f.configPath), /unlinked owner-private/);
  const pending = { ...f.active, generation: 2, capability: `kc1.${f.active.client_slot}.2.${'p'.repeat(43)}`,
    enrollment_request_id: `ker1_${'q'.repeat(24)}`, enrollment_revision: 1,
    enrollment_verification_code: 'ABCD-EF23', activation_expires_at: '2026-09-12T23:59:59Z' };
  await f.credentials.writePending(f.context.endpoint, pending);
  const before = f.requests();
  await assert.rejects(gitPushClient(configuration).request('/v1/git/push-protection'), /finish IDE access/);
  assert.equal(f.requests(), before);
  assert.equal((await f.credentials.readPending(f.context.endpoint)).generation, 2);
});

test('push CLI no-argument contract is inert and exact check refuses missing, duplicate or failed tree evidence', () => {
  const result = spawnSync(process.execPath, [path.resolve(__dirname, '../../dist/git-push-cli.js')], { encoding: 'utf8' });
  assert.equal(result.status, 2); assert.match(result.stderr, /^Usage:/); assert.equal(result.stdout, '');
  // The API's test_api_cli_positive_contract compares its actual route output
  // to this same body-free fixture. Do not invent a separate client protocol.
  const { plan, policy_revision: revision, response: value } = require('../../../../apps/api/tests/fixtures/git-push-check-pass.json');
  const tree = plan.trees[0]; const scan = value.scans[0];
  assert.equal(validateGitPushCheck(value, plan, revision), true);
  for (const changed of [{ scans: [] }, { scans: [scan, scan] }, { scans: [{ ...scan, gate_decision: 'fail' }] },
    { scans: [{ ...scan, revision: undefined }] }, { policy_revision: revision + 1 }, { plan_digest: 'e'.repeat(64) },
    { missing_trees: [tree] }, { decision: 'off' }, { evidence_digest: null }, { preflight_revision: undefined },
    { preflight_revision: 8 }, { reason_code: 'invented_success' }]) {
    assert.equal(validateGitPushCheck({ ...value, ...changed }, plan, revision), false);
  }
});

test('push host preserves exact profile ownership and On refuses configuration or Git changes during the final check', async (t) => {
  for (const change of ['history', 'configuration', 'helper']) await t.test(change, async (t) => {
    const f = await fixture(t);
    const git = (...args) => execFileSync('git', ['-C', f.repository.root, ...args], { encoding: 'utf8' }).trim();
    await writeFile(path.join(f.repository.root, 'fixture.txt'), 'committed fixture\n');
    git('add', 'fixture.txt');
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'fixture');
    const remote = path.join(f.root, 'remote.git');
    execFileSync('git', ['init', '--bare', '--quiet', '--initial-branch=main', remote]);
    await applyGitPushPolicy(f.repository, f.policy, f.context);
    const reversedContext = Object.fromEntries(Object.entries(f.context).reverse());
    assert.equal((await inspectGitPushPolicy(f.repository, f.policy, reversedContext)).state, 'installed');
    assert.equal((await inspectGitPushPolicy({ ...f.repository, projectId: 8 }, f.policy, f.context)).state, 'needs_repair');
    assert.equal((await inspectGitPushPolicy({ ...f.repository, generation: 2 }, f.policy, f.context)).state, 'needs_repair');
    assert.equal((await inspectGitPushPolicy({ ...f.repository, clientSlot: `ks1_${'z'.repeat(43)}` }, f.policy, f.context)).state, 'needs_repair');
    const policyRequest = global.fetch;
    let mutate = false;
    global.fetch = async (url, init) => {
      if (!url.endsWith('/check')) return policyRequest(url, init);
      const plan = JSON.parse(init.body);
      const contract = require('../../../../apps/api/tests/fixtures/git-push-check-pass.json');
      if (mutate) {
        if (change === 'history') await writeFile(path.join(f.repository.gitDirectory, 'info', 'grafts'), '# changed during check\n');
        if (change === 'helper') await writeFile(path.join(f.context.extensionPath, 'dist', 'git-push-cli.js'), '// changed helper\n');
        if (change === 'configuration') {
          const config = JSON.parse(await readFile(f.configPath, 'utf8'));
          await writeFile(f.configPath, JSON.stringify({ ...config, revision: config.revision + 1 }) + '\n');
        }
      }
      return new Response(JSON.stringify({ ...contract.response, repository_id: f.repository.repositoryId,
        policy_revision: f.policy.revision, plan_digest: plan.digest,
        scans: plan.trees.map((tree) => ({ ...contract.response.scans[0], tree_oid: tree })) }),
      { headers: { 'Content-Type': 'application/json' } });
    };
    const input = `refs/heads/main ${git('rev-parse', 'HEAD')} refs/heads/main ${'0'.repeat(40)}\n`;
    assert.equal(await runGitPushHook(f.configPath, input, remote), 0);
    mutate = true;
    await assert.rejects(runGitPushHook(f.configPath, input, remote), /Grafts|setting changed|installed helper changed/);
  });
});

test('push host explicit same-owner Apply repairs only a helper update while preserving the exact hook', async (t) => {
  const f = await fixture(t);
  await applyGitPushPolicy(f.repository, f.policy, f.context);
  const hook = await readFile(f.hookPath, 'utf8');
  const before = await readGitPushConfiguration(f.configPath);
  const helper = path.join(f.context.extensionPath, 'dist', 'git-push-cli.js');
  await writeFile(helper, '// newly installed helper at the same reviewed path\n');
  assert.equal((await inspectGitPushPolicy(f.repository, f.policy, f.context)).state, 'needs_repair');
  await assert.rejects(runGitPushHook(f.configPath, '', '/not-contacted'), /installed push helper changed/);
  assert.equal((await applyGitPushPolicy(f.repository, f.policy, f.context)).state, 'installed');
  const after = await readGitPushConfiguration(f.configPath);
  assert.notEqual(after.helperDigest, before.helperDigest);
  assert.equal(after.helperDigest, createHash('sha256').update(await readFile(helper)).digest('hex'));
  assert.deepEqual(after.repository, before.repository); assert.deepEqual(after.context, before.context);
  assert.equal(after.revision, before.revision); assert.equal(after.hookDigest, before.hookDigest);
  assert.equal(await readFile(f.hookPath, 'utf8'), hook);
  assert.equal((await inspectGitPushPolicy(f.repository, f.policy, f.context)).state, 'installed');
  const updated = await readFile(f.configPath, 'utf8');
  await writeFile(helper, '// another helper update\n');
  await writeFile(f.hookPath, '#!/bin/sh\n# unrelated hook change\n');
  await assert.rejects(applyGitPushPolicy(f.repository, f.policy, f.context), /hook or profile binding changed/);
  assert.equal(await readFile(f.hookPath, 'utf8'), '#!/bin/sh\n# unrelated hook change\n');
  assert.equal(await readFile(f.configPath, 'utf8'), updated);
});

test('push CLI On preserves exact UTF-8 reference bytes and refuses replacement decoding', () => {
  const input = `refs/heads/修正 ${'a'.repeat(40)} refs/heads/修正 ${'0'.repeat(40)}\n`;
  assert.equal(decodeGitPushInput(Buffer.from(input)), input);
  for (const bytes of [Buffer.from([0xff]), Buffer.from([0xc3]), Buffer.from([0xe2, 0x28, 0xa1])]) {
    assert.throws(() => decodeGitPushInput(bytes), (error) => error.code === 'push_input_invalid');
  }
});

async function removalFixture(t, applied = true) {
  const f = await fixture(t);
  if (applied) await applyGitPushPolicy(f.repository, f.policy, f.context);
  const before = applied ? await readFile(f.configPath, 'utf8') : undefined;
  const policyFetch = global.fetch;
  const requests = [];
  let mode = 'ack';
  global.fetch = async (url, init) => {
    if (!url.endsWith('/remove')) return policyFetch(url, init);
    const body = JSON.parse(init.body); requests.push(body);
    if (mode === 'outage') throw new TypeError('synthetic unavailable');
    if (mode === 'conflict') return new Response(JSON.stringify({ detail: { code: 'push_policy_changed', message: 'Review the changed policy.' } }), { status: 409 });
    return new Response(JSON.stringify({ repository_id: f.repository.repositoryId, removed: true,
      revision: body.expected_revision, tree_bindings_deleted: 2, already_removed: requests.length > 1 }));
  };
  return { ...f, before, requests, setMode: (value) => { mode = value; },
    removalPath: f.configPath.replace(/\.json$/, '.removal.json') };
}

test('push removal preserves credentials and unrelated hooks, and manages an old project without rebinding', async (t) => {
  for (const applied of [true, false]) await t.test(applied ? 'owned hook' : 'registration only', async (t) => {
    const f = await removalFixture(t, applied);
    const other = path.join(f.repository.gitDirectory, 'hooks', 'pre-commit');
    await writeFile(other, '# unrelated check\n');
    const result = await removeGitPushPolicy({ ...f.repository, projectId: 99 }, f.policy, f.context);
    assert.deepEqual(result, { localRemoved: true, registrationRemoved: true, cleanup: 'complete', reasonCode: null });
    for (const removed of [f.hookPath, f.configPath, f.removalPath]) await assert.rejects(readFile(removed), { code: 'ENOENT' });
    assert.equal(await readFile(other, 'utf8'), '# unrelated check\n');
    assert.deepEqual(await f.credentials.readAuthority(f.context.endpoint), f.active);
    assert.deepEqual(f.requests, [{ expected_revision: 2, confirm_removal: true,
      hook_digest: applied ? JSON.parse(f.before).hookDigest : null }]);
  });
});

test('push removal retains exact retry state through outage/conflict and completes interrupted final cleanup', async (t) => {
  const f = await removalFixture(t); f.setMode('outage');
  const first = await removeGitPushPolicy(f.repository, f.policy, f.context);
  assert.equal(first.cleanup, 'retryable'); assert.equal(first.registrationRemoved, false);
  await assert.rejects(readFile(f.hookPath), { code: 'ENOENT' });
  assert.equal(await readFile(f.configPath, 'utf8'), f.before);
  assert.equal(JSON.parse(await readFile(f.removalPath, 'utf8')).hookRemoved, true);
  await assert.rejects(applyGitPushPolicy(f.repository, f.policy, f.context), /Removal is pending/);
  f.setMode('conflict');
  const second = await removeGitPushPolicy(f.repository, { ...f.policy, revision: 30 }, f.context);
  assert.equal(second.cleanup, 'review_required'); assert.equal(second.reasonCode, 'push_policy_changed');
  assert(f.requests.every((item) => item.expected_revision === 2));
  // Model interruption after config deletion but before receipt removal.
  await rm(f.configPath);
  assert.equal((await inspectGitPushPolicy(f.repository, null, f.context)).state, 'needs_repair');
  f.setMode('ack');
  assert.equal((await removeGitPushPolicy(f.repository, null, f.context)).registrationRemoved, true);
  await assert.rejects(readFile(f.removalPath), { code: 'ENOENT' });
  assert.deepEqual(await f.credentials.readAuthority(f.context.endpoint), f.active);
});

test('push removal refuses changed hooks, other profiles, stale confirmation and any present hook on retry', async (t) => {
  for (const scenario of ['other profile', 'changed hook', 'policy changed', 'resumed hook']) await t.test(scenario, async (t) => {
    const f = await removalFixture(t);
    const hook = await readFile(f.hookPath, 'utf8');
    if (scenario === 'other profile') {
      await assert.rejects(removeGitPushPolicy({ ...f.repository, generation: 2 }, f.policy, f.context), /another profile or generation/);
    } else if (scenario === 'changed hook') {
      await writeFile(f.hookPath, '# other hook\n');
      await assert.rejects(removeGitPushPolicy(f.repository, f.policy, f.context), /installed hook changed/);
      assert.equal(await readFile(f.hookPath, 'utf8'), '# other hook\n');
    } else if (scenario === 'policy changed') {
      f.setPolicy({ ...f.policy, revision: 3 });
      await assert.rejects(removeGitPushPolicy(f.repository, f.policy, f.context), /changed after removal confirmation/);
    } else {
      f.setMode('outage'); await removeGitPushPolicy(f.repository, f.policy, f.context);
      await writeFile(f.hookPath, hook, { mode: 0o700 });
      const pending = JSON.parse(await readFile(f.removalPath, 'utf8'));
      // Even the pre-confirmation crash window cannot delete a new identical hook.
      await writeFile(f.removalPath, JSON.stringify({ ...pending, hookRemoved: false }) + '\n');
      await assert.rejects(removeGitPushPolicy(f.repository, f.policy, f.context), /hook is present while resuming/);
      assert.equal(f.requests.length, 1); assert.equal(await readFile(f.hookPath, 'utf8'), hook);
    }
    assert.equal(await readFile(f.configPath, 'utf8'), f.before);
    if (!['changed hook', 'resumed hook'].includes(scenario)) assert.equal(await readFile(f.hookPath, 'utf8'), hook);
  });
});
