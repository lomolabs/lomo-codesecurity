const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const {
  chmod,
  link,
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  symlink,
  unlink,
  utimes,
  writeFile,
} = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const Module = require('node:module');

const {
  CodeSecurityClient,
  CodeSecurityRequestError,
  IDE_CAPABILITY_SCOPES,
} = require('../../dist/client.js');
const {
  PROFILE_AUTHORITY_FILE_NAME,
  PROFILE_AUTHORITY_LOCK_FILE_NAME,
  PROFILE_CREDENTIAL_DIRECTORY_NAME,
  PROFILE_PENDING_AUTHORITY_FILE_NAME,
  ProfileCredentialStore,
  ProfileCredentialStoreError,
} = require('../../dist/credentials.js');

const ENDPOINT = 'http://127.0.0.1:8080';
const ACTIVATION_EXPIRES_AT = '2099-01-01T00:10:00Z';

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function capability(slot, generation, fill = 'A') {
  return `kc1.${slot}.${generation}.${fill.repeat(43)}`;
}

function authority(store, generation, fill = 'A') {
  return Object.freeze({
    v: 1,
    endpoint: ENDPOINT,
    client_slot: store.clientSlot,
    generation,
    capability: capability(store.clientSlot, generation, fill),
    activation_expires_at: ACTIVATION_EXPIRES_AT,
    enrollment_request_id: `ker1_${'r'.repeat(24)}`,
    enrollment_revision: 1,
    enrollment_verification_code: 'ABCD-EF23',
  });
}

function activeAuthority(store, generation, fill = 'A') {
  return Object.freeze({
    v: 1,
    endpoint: ENDPOINT,
    client_slot: store.clientSlot,
    generation,
    capability: capability(store.clientSlot, generation, fill),
  });
}

function enrollmentResponse(record) {
  return {
    request_id: record.enrollment_request_id,
    state: 'awaiting_approval',
    revision: record.enrollment_revision,
    verification_code: record.enrollment_verification_code,
    capability: record.capability,
    scopes: [...IDE_CAPABILITY_SCOPES],
    client_slot: record.client_slot,
    generation: record.generation,
    requested_at: '2099-01-01T00:00:00Z',
    activation_expires_at: record.activation_expires_at,
  };
}

function approvedEnrollment(record) {
  return {
    request_id: record.enrollment_request_id,
    state: 'approved',
    revision: 2,
    decision_at: '2099-01-01T00:01:00Z',
    activation_expires_at: record.activation_expires_at,
  };
}

function activationResponse(record) {
  return {
    client_slot: record.client_slot,
    generation: record.generation,
    scopes: [...IDE_CAPABILITY_SCOPES],
  };
}

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'lomo-credentials-'));
  const identity = `file://${root}/named-profile/globalStorage/lomo.kodesec`;
  return { root, identity, store: new ProfileCredentialStore(root, identity) };
}

function namespacePath(root) {
  const digest = createHash('sha256').update(ENDPOINT, 'utf8').digest('hex');
  return path.join(root, PROFILE_CREDENTIAL_DIRECTORY_NAME, digest);
}

function mutationLockRaw(store, createdAt = new Date().toISOString()) {
  return JSON.stringify({
    client_slot: store.clientSlot,
    created_at: createdAt,
    endpoint_hash: createHash('sha256').update(ENDPOINT, 'utf8').digest('hex'),
    nonce: '11111111-1111-4111-8111-111111111111',
    pid: process.pid,
    v: 1,
  });
}

function canonicalPending(record) {
  return JSON.stringify({
    activation_expires_at: record.activation_expires_at,
    capability: record.capability,
    client_slot: record.client_slot,
    endpoint: record.endpoint,
    enrollment_request_id: record.enrollment_request_id,
    enrollment_revision: record.enrollment_revision,
    enrollment_verification_code: record.enrollment_verification_code,
    generation: record.generation,
    v: 1,
  });
}

test('Windows credential consumer protects only newly created empty paths and rechecks existing ACL before read', async () => {
  const { root, identity } = await fixture();
  const modulePath = require.resolve('../../dist/credentials.js');
  const priorModule = require.cache[modulePath];
  const priorLoad = Module._load;
  const priorPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
  const native = require('../../dist/windows-private-path.js');
  const checks = [];
  let rejectPending = false;
  Module._load = function (request, parent, isMain) {
    if (request === './windows-private-path' && parent?.filename === modulePath) return {
      ...native,
      verifyWindowsPrivatePath: async (target, kind, protectNew) => {
        checks.push({ target, kind, protectNew });
        if (protectNew && kind === 'file') assert.equal((await lstat(target)).size, 0, 'permissions before secret write');
        if (protectNew && kind === 'directory') assert.deepEqual(await readdir(target), [], 'no repair of populated paths');
        if (rejectPending && target.endsWith(PROFILE_PENDING_AUTHORITY_FILE_NAME)) {
          throw new native.WindowsPrivatePathError('windows_private_path_insecure');
        }
      },
    };
    return priorLoad.call(this, request, parent, isMain);
  };
  delete require.cache[modulePath];
  try {
    Object.defineProperty(process, 'platform', { ...priorPlatform, value: 'win32' });
    const NativeStore = require(modulePath).ProfileCredentialStore;
    const store = new NativeStore(root, identity);
    const pending = authority(store, 1);
    await store.writePending(ENDPOINT, pending);
    assert.deepEqual(await store.readPending(ENDPOINT), pending);
    const createdDirectories = checks.filter((entry) => entry.kind === 'directory' && entry.protectNew).map((entry) => entry.target);
    assert.deepEqual(createdDirectories, [path.join(root, PROFILE_CREDENTIAL_DIRECTORY_NAME), namespacePath(root)]);
    assert.equal(checks.some((entry) => entry.target === root && entry.protectNew), false, 'existing profile parent is never repaired');
    const priorChecks = checks.length;
    rejectPending = true;
    await assert.rejects(store.readPending(ENDPOINT), (error) => error.code === 'profile_credential_store_insecure');
    assert(checks.slice(priorChecks).some((entry) => entry.target.endsWith(PROFILE_PENDING_AUTHORITY_FILE_NAME)));
    assert(checks.slice(priorChecks).every((entry) => !entry.protectNew));
  } finally {
    Object.defineProperty(process, 'platform', priorPlatform);
    Module._load = priorLoad;
    delete require.cache[modulePath];
    require.cache[modulePath] = priorModule;
  }
});

test('owner-approved IDE enrollment persists a canonical authority before activation and survives recreation', async () => {
  const { root, identity, store } = await fixture();
  const candidate = authority(store, 1);
  const active = activeAuthority(store, 1);
  const calls = [];
  const fetchImplementation = async (url, init) => {
    const pathname = new URL(String(url)).pathname;
    calls.push({ pathname, init });
    if (pathname === '/v1/auth/ide/enrollments') return jsonResponse(enrollmentResponse(candidate));
    if (pathname === '/v1/auth/ide/enrollments/current/wait') return jsonResponse(approvedEnrollment(candidate));
    if (pathname === '/v1/auth/ide/activate') {
      assert.deepEqual(await store.readPending(ENDPOINT), candidate);
      return jsonResponse(activationResponse(candidate));
    }
    assert.equal(pathname, '/v1/projects');
    return jsonResponse({ ok: true });
  };
  const client = new CodeSecurityClient(store, () => ENDPOINT, fetchImplementation);
  await client.connectIde('Fedora QA profile');

  assert.deepEqual(JSON.parse(calls[0].init.body), {
    client_name: 'Fedora QA profile',
    client_slot: store.clientSlot,
    expected_active_generation: 0,
  });
  assert.equal(calls[2].pathname, '/v1/auth/ide/activate');
  assert.equal(new Headers(calls[2].init.headers).get('Authorization'), `Bearer ${candidate.capability}`);
  assert.equal(await store.readPending(ENDPOINT), undefined);
  assert.deepEqual(await store.readAuthority(ENDPOINT), active);

  const recreatedStore = new ProfileCredentialStore(root, identity);
  const recreated = new CodeSecurityClient(recreatedStore, () => ENDPOINT, fetchImplementation);
  assert.deepEqual(await recreated.request('/v1/projects'), { ok: true });
  assert.equal(calls.at(-1).pathname, '/v1/projects');
  assert.equal(new Headers(calls.at(-1).init.headers).get('Authorization'), `Bearer ${candidate.capability}`);
});

test('a lost activation response leaves a recoverable candidate that a fresh client promotes', async () => {
  const { root, identity, store } = await fixture();
  const candidate = authority(store, 1);
  const active = activeAuthority(store, 1);
  let activationAttempts = 0;
  const first = new CodeSecurityClient(store, () => ENDPOINT, async (url) => {
    const pathname = new URL(String(url)).pathname;
    if (pathname === '/v1/auth/ide/enrollments') return jsonResponse(enrollmentResponse(candidate));
    if (pathname === '/v1/auth/ide/enrollments/current/wait') return jsonResponse(approvedEnrollment(candidate));
    activationAttempts += 1;
    throw new Error('simulated lost activation response');
  });
  await assert.rejects(first.connectIde('Crash fixture'), (error) => {
    assert(error instanceof CodeSecurityRequestError);
    assert.equal(error.message.includes(candidate.capability), false);
    return true;
  });
  assert.deepEqual(await store.readPending(ENDPOINT), candidate);
  assert.equal(await store.readAuthority(ENDPOINT), undefined);

  const recreatedStore = new ProfileCredentialStore(root, identity);
  const calls = [];
  const recreated = new CodeSecurityClient(recreatedStore, () => ENDPOINT, async (url, init) => {
    const pathname = new URL(String(url)).pathname;
    calls.push({ pathname, init });
    if (pathname === '/v1/auth/ide/enrollments/current/wait') return jsonResponse(approvedEnrollment(candidate));
    if (pathname === '/v1/auth/ide/activate') return jsonResponse(activationResponse(candidate));
    return jsonResponse({ recovered: true });
  });
  assert.deepEqual(await recreated.request('/v1/projects'), { recovered: true });
  assert.deepEqual(calls.map(({ pathname }) => pathname), [
    '/v1/auth/ide/enrollments/current/wait', '/v1/auth/ide/activate', '/v1/projects',
  ]);
  assert.equal(activationAttempts, 1);
  assert.deepEqual(await recreatedStore.readAuthority(ENDPOINT), active);
  assert.equal(await recreatedStore.readPending(ENDPOINT), undefined);
});

test('fresh recoverers converge through one durable activation and exact active reuse', async () => {
  const { root, identity, store } = await fixture();
  const candidate = authority(store, 1);
  const active = activeAuthority(store, 1);
  await store.writePending(ENDPOINT, candidate);
  let activations = 0;
  const fetchImplementation = async (url) => {
    const pathname = new URL(String(url)).pathname;
    if (pathname === '/v1/auth/ide/enrollments/current/wait') {
      return jsonResponse(approvedEnrollment(candidate));
    }
    if (pathname === '/v1/auth/ide/activate') {
      activations += 1;
      return jsonResponse(activationResponse(candidate));
    }
    assert.equal(pathname, '/v1/projects');
    return jsonResponse({ recovered: true });
  };
  const firstStore = new ProfileCredentialStore(root, identity);
  const secondStore = new ProfileCredentialStore(root, identity);
  const results = [
    await new CodeSecurityClient(firstStore, () => ENDPOINT, fetchImplementation).request('/v1/projects'),
    await new CodeSecurityClient(secondStore, () => ENDPOINT, fetchImplementation).request('/v1/projects'),
  ];
  assert.equal(activations, 1);
  assert.deepEqual(results, [{ recovered: true }, { recovered: true }]);
  assert.deepEqual(await firstStore.readAuthority(ENDPOINT), active);
  assert.equal(await firstStore.readPending(ENDPOINT), undefined);
});

test('a late 401 marks only its exact generation and cannot clobber a successor authority', async () => {
  const { root, identity, store } = await fixture();
  const firstPending = authority(store, 1, 'A');
  const first = activeAuthority(store, 1, 'A');
  const successorPending = authority(store, 2, 'B');
  const successor = activeAuthority(store, 2, 'B');
  await store.writePending(ENDPOINT, firstPending);
  await store.promotePending(ENDPOINT, firstPending, first);
  let releaseUnauthorized;
  const unauthorized = new Promise((resolve) => { releaseUnauthorized = resolve; });
  let markStarted;
  const started = new Promise((resolve) => { markStarted = resolve; });
  const client = new CodeSecurityClient(store, () => ENDPOINT, async () => {
    markStarted();
    await unauthorized;
    return jsonResponse({}, 401);
  });
  const lateRequest = client.request('/v1/projects');
  await started;
  const successorStore = new ProfileCredentialStore(root, identity);
  await successorStore.writePending(ENDPOINT, successorPending);
  await successorStore.promotePending(ENDPOINT, successorPending, successor);
  releaseUnauthorized();
  await assert.rejects(lateRequest, /authority changed while this request was in flight/u);

  assert.deepEqual(await successorStore.readAuthority(ENDPOINT), successor);
  assert.equal(await successorStore.isRejected(ENDPOINT, successor), false);
});

test('cross-process mutation lock prevents a held writer from being followed by a stale downgrade', async () => {
  const { root, identity, store } = await fixture();
  const firstPending = authority(store, 1, 'A');
  const firstActive = activeAuthority(store, 1, 'A');
  await store.writePending(ENDPOINT, firstPending);
  await store.promotePending(ENDPOINT, firstPending, firstActive);
  const namespace = namespacePath(root);
  const lockPath = path.join(namespace, PROFILE_AUTHORITY_LOCK_FILE_NAME);
  await writeFile(lockPath, mutationLockRaw(store), { mode: 0o600, flag: 'wx' });

  const staleStore = new ProfileCredentialStore(root, identity);
  const stalePending = authority(staleStore, 2, 'B');
  await assert.rejects(
    staleStore.writePending(ENDPOINT, stalePending),
    (error) => error.code === 'profile_credential_store_busy',
  );
  await unlink(lockPath);

  const winnerPending = authority(store, 3, 'C');
  const winnerActive = activeAuthority(store, 3, 'C');
  await store.writePending(ENDPOINT, winnerPending);
  await store.promotePending(ENDPOINT, winnerPending, winnerActive);
  await assert.rejects(
    staleStore.writePending(ENDPOINT, stalePending),
    (error) => error.code === 'profile_credential_store_write_unconfirmed',
  );
  assert.deepEqual(await staleStore.readAuthority(ENDPOINT), winnerActive);
});

test('active authority generations refuse lower and same-different replacement while exact same and higher converge', async () => {
  const { root, store } = await fixture();
  const retainedPending = authority(store, 2, 'A');
  const retainedActive = activeAuthority(store, 2, 'A');
  await store.writePending(ENDPOINT, retainedPending);
  await store.promotePending(ENDPOINT, retainedPending, retainedActive);

  const lowerPending = authority(store, 1, 'B');
  const lowerActive = activeAuthority(store, 1, 'B');
  await assert.rejects(
    store.writePending(ENDPOINT, lowerPending),
    (error) => error.code === 'profile_credential_store_write_unconfirmed',
  );
  const pendingPath = path.join(namespacePath(root), PROFILE_PENDING_AUTHORITY_FILE_NAME);
  await writeFile(pendingPath, canonicalPending(lowerPending), { mode: 0o600 });
  await chmod(pendingPath, 0o600);
  await assert.rejects(
    store.promotePending(ENDPOINT, lowerPending, lowerActive),
    (error) => error.code === 'profile_credential_store_write_unconfirmed',
  );
  await unlink(pendingPath);

  await store.promotePending(ENDPOINT, retainedPending, retainedActive);
  const sameDifferentPending = authority(store, 2, 'C');
  const sameDifferentActive = activeAuthority(store, 2, 'C');
  await assert.rejects(
    store.promotePending(ENDPOINT, sameDifferentPending, sameDifferentActive),
    (error) => error.code === 'profile_credential_store_write_unconfirmed',
  );

  const successorPending = authority(store, 3, 'D');
  const successorActive = activeAuthority(store, 3, 'D');
  await store.writePending(ENDPOINT, successorPending);
  await store.promotePending(ENDPOINT, successorPending, successorActive);
  assert.deepEqual(await store.readAuthority(ENDPOINT), successorActive);
});

test('explicit reset removes only an exact rejected authority and refuses active or pending state', async () => {
  const { store } = await fixture();
  const pending = authority(store, 1, 'A');
  const active = activeAuthority(store, 1, 'A');
  await store.writePending(ENDPOINT, pending);
  await store.promotePending(ENDPOINT, pending, active);

  await assert.rejects(
    store.discardRejectedAuthority(ENDPOINT, active),
    (error) => error.code === 'profile_credential_store_write_unconfirmed'
      && /not proven rejected/u.test(error.message),
  );
  assert.deepEqual(await store.readAuthority(ENDPOINT), active);

  await store.markRejected(ENDPOINT, active);
  const successorPending = authority(store, 2, 'B');
  await store.writePending(ENDPOINT, successorPending);
  await assert.rejects(
    store.discardRejectedAuthority(ENDPOINT, active),
    (error) => error.code === 'profile_credential_store_write_unconfirmed'
      && /pending IDE access request/u.test(error.message),
  );
  assert.deepEqual(await store.readAuthority(ENDPOINT), active);
  await store.discardPending(ENDPOINT, successorPending);

  await store.discardRejectedAuthority(ENDPOINT, active);
  assert.equal(await store.readAuthority(ENDPOINT), undefined);
  assert.equal(await store.isRejected(ENDPOINT, active), false);
});

test('explicit repair refuses a current mutation lock and replaces only an exact abandoned lock', { skip: process.platform === 'win32' }, async () => {
  const { root, store } = await fixture();
  const pending = authority(store, 1);
  await store.writePending(ENDPOINT, pending);
  const namespace = namespacePath(root);
  const lockPath = path.join(namespace, PROFILE_AUTHORITY_LOCK_FILE_NAME);
  await writeFile(lockPath, mutationLockRaw(store), { mode: 0o600, flag: 'wx' });

  await assert.rejects(
    store.repairCorruptRecords(ENDPOINT),
    (error) => error.code === 'profile_credential_store_busy',
  );
  assert.equal((await lstat(lockPath)).isFile(), true);

  const abandoned = new Date(Date.now() - 20 * 60 * 1_000);
  await writeFile(lockPath, mutationLockRaw(store, '2099-01-01T00:00:00Z'), { mode: 0o600 });
  await chmod(lockPath, 0o600);
  await utimes(lockPath, abandoned, abandoned);
  const result = await store.repairCorruptRecords(ENDPOINT);
  assert.deepEqual(result, { removed: [PROFILE_AUTHORITY_LOCK_FILE_NAME] });
  await assert.rejects(lstat(lockPath), (error) => error.code === 'ENOENT');
  assert.deepEqual(await store.readPending(ENDPOINT), pending);
});

test('pair cancellation is confirmed when the local pending write fails', async () => {
  const { store } = await fixture();
  const candidate = authority(store, 1);
  const failingStore = {
    ...store,
    clientSlot: store.clientSlot,
    readAuthority: store.readAuthority.bind(store),
    readPending: store.readPending.bind(store),
    writePending: async () => { throw new ProfileCredentialStoreError('profile_credential_store_write_unconfirmed', 'write refused'); },
    promotePending: store.promotePending.bind(store),
    discardPending: store.discardPending.bind(store),
    discardRejectedAuthority: store.discardRejectedAuthority.bind(store),
    markRejected: store.markRejected.bind(store),
    isRejected: store.isRejected.bind(store),
    rejectionReason: store.rejectionReason.bind(store),
  };
  const calls = [];
  const client = new CodeSecurityClient(failingStore, () => ENDPOINT, async (url, init) => {
    const pathname = new URL(String(url)).pathname;
    calls.push({ pathname, init });
    if (pathname === '/v1/auth/ide/enrollments') return jsonResponse(enrollmentResponse(candidate));
    assert.equal(pathname, '/v1/auth/ide/pending');
    return jsonResponse({ cancelled: true });
  });
  await assert.rejects(client.connectIde('Write failure'), (error) => {
    assert.equal(error.code, 'profile_credential_store_write_unconfirmed');
    assert.equal(error.message.includes(candidate.capability), false);
    return true;
  });
  assert.deepEqual(calls.map(({ pathname }) => pathname), ['/v1/auth/ide/enrollments', '/v1/auth/ide/pending']);
});

test('a rejected authority starts a clean enrollment generation', async () => {
  const { store } = await fixture();
  const firstPending = authority(store, 1, 'A');
  const first = activeAuthority(store, 1, 'A');
  const second = authority(store, 2, 'B');
  await store.writePending(ENDPOINT, firstPending);
  await store.promotePending(ENDPOINT, firstPending, first);
  await store.markRejected(ENDPOINT, first);
  let enrollmentBody;
  const client = new CodeSecurityClient(store, () => ENDPOINT, async (url, init) => {
    const pathname = new URL(String(url)).pathname;
    if (pathname === '/v1/auth/ide/enrollments') {
      enrollmentBody = JSON.parse(init.body);
      return jsonResponse(enrollmentResponse(second));
    }
    if (pathname === '/v1/auth/ide/enrollments/current/wait') {
      return jsonResponse(approvedEnrollment(second));
    }
    assert.equal(pathname, '/v1/auth/ide/activate');
    return jsonResponse(activationResponse(second));
  });
  await client.connectIde('Rotated profile');
  assert.equal(enrollmentBody.expected_active_generation, 0);
});

test('authority files fail closed on malformed, permissive, symlink, and hardlink storage', { skip: process.platform === 'win32' }, async (t) => {
  await t.test('malformed canonical bytes', async () => {
    const { root, store } = await fixture();
    const candidate = authority(store, 1);
    await store.writePending(ENDPOINT, candidate);
    await writeFile(path.join(namespacePath(root), PROFILE_PENDING_AUTHORITY_FILE_NAME), '{"v":1}\n', { mode: 0o600 });
    await assert.rejects(store.readPending(ENDPOINT), ProfileCredentialStoreError);
  });
  await t.test('permissive file mode', async () => {
    const { root, store } = await fixture();
    const candidate = authority(store, 1);
    await store.writePending(ENDPOINT, candidate);
    await chmod(path.join(namespacePath(root), PROFILE_PENDING_AUTHORITY_FILE_NAME), 0o644);
    await assert.rejects(store.readPending(ENDPOINT), (error) => error.code === 'profile_credential_store_insecure');
  });
  await t.test('symbolic link', async () => {
    const { root, store } = await fixture();
    const namespace = namespacePath(root);
    await mkdir(namespace, { recursive: true, mode: 0o700 });
    const outside = path.join(root, 'outside.json');
    await writeFile(outside, '{}', { mode: 0o600 });
    await symlink(outside, path.join(namespace, PROFILE_AUTHORITY_FILE_NAME));
    await assert.rejects(store.readAuthority(ENDPOINT), (error) => error.code === 'profile_credential_store_insecure');
  });
  await t.test('hard link', async () => {
    const { root, store } = await fixture();
    const candidate = authority(store, 1);
    await store.writePending(ENDPOINT, candidate);
    const pendingPath = path.join(namespacePath(root), PROFILE_PENDING_AUTHORITY_FILE_NAME);
    await link(pendingPath, path.join(root, 'second-link.json'));
    assert.equal((await lstat(pendingPath)).nlink, 2);
    await assert.rejects(store.readPending(ENDPOINT), (error) => error.code === 'profile_credential_store_insecure');
  });
});

test('explicit repair removes only corrupt allowlisted regular records and preserves valid siblings', { skip: process.platform === 'win32' }, async (t) => {
  await t.test('corrupt active authority is removed while a valid pending candidate remains', async () => {
    const { root, store } = await fixture();
    const firstPending = authority(store, 1, 'A');
    const firstActive = activeAuthority(store, 1, 'A');
    const successorPending = authority(store, 2, 'B');
    await store.writePending(ENDPOINT, firstPending);
    await store.promotePending(ENDPOINT, firstPending, firstActive);
    await store.writePending(ENDPOINT, successorPending);
    const activePath = path.join(namespacePath(root), PROFILE_AUTHORITY_FILE_NAME);
    await writeFile(activePath, '{"v":1}', { mode: 0o600 });
    await chmod(activePath, 0o600);

    const result = await store.repairCorruptRecords(ENDPOINT);

    assert.deepEqual(result, { removed: [PROFILE_AUTHORITY_FILE_NAME] });
    assert.equal(await store.readAuthority(ENDPOINT), undefined);
    assert.deepEqual(await store.readPending(ENDPOINT), successorPending);
  });

  await t.test('corrupt rejection marker is removed while active authority remains', async () => {
    const { root, store } = await fixture();
    const pending = authority(store, 1);
    const active = activeAuthority(store, 1);
    await store.writePending(ENDPOINT, pending);
    await store.promotePending(ENDPOINT, pending, active);
    await store.markRejected(ENDPOINT, active);
    const namespace = namespacePath(root);
    const marker = (await readdir(namespace)).find((name) => name.startsWith('rejected-'));
    assert(marker);
    await writeFile(path.join(namespace, marker), '{"v":1}', { mode: 0o600 });
    await chmod(path.join(namespace, marker), 0o600);

    const result = await store.repairCorruptRecords(ENDPOINT);

    assert.deepEqual(result, { removed: [marker] });
    assert.deepEqual(await store.readAuthority(ENDPOINT), active);
    assert.equal((await readdir(namespace)).includes(marker), false);
  });

  await t.test('unsafe later sibling refuses the whole repair plan before removing a corrupt candidate', async () => {
    const { root, store } = await fixture();
    const pending = authority(store, 1);
    const active = activeAuthority(store, 1);
    await store.writePending(ENDPOINT, pending);
    await store.promotePending(ENDPOINT, pending, active);
    const namespace = namespacePath(root);
    const activePath = path.join(namespace, PROFILE_AUTHORITY_FILE_NAME);
    const corruptBytes = '{"v":1}';
    await writeFile(activePath, corruptBytes, { mode: 0o600 });
    await chmod(activePath, 0o600);
    await writeFile(path.join(namespace, 'zz-unexpected.json'), '{}', { mode: 0o600 });

    await assert.rejects(
      store.repairCorruptRecords(ENDPOINT),
      (error) => error.code === 'profile_credential_store_insecure',
    );
    assert.equal(await readFile(activePath, 'utf8'), corruptBytes);
  });

  await t.test('recent temporary is retained and the exact abandoned temporary is removable', async () => {
    const { root, store } = await fixture();
    const pending = authority(store, 1);
    await store.writePending(ENDPOINT, pending);
    const namespace = namespacePath(root);
    const temporaryName = `.pending.write-${process.pid}-11111111-1111-4111-8111-111111111111`;
    const temporaryPath = path.join(namespace, temporaryName);
    await writeFile(temporaryPath, '{}', { mode: 0o600 });

    await assert.rejects(
      store.repairCorruptRecords(ENDPOINT),
      (error) => error.code === 'profile_credential_store_write_unconfirmed',
    );
    assert.equal((await lstat(temporaryPath)).isFile(), true);

    const abandoned = new Date(Date.now() - 20 * 60 * 1_000);
    await utimes(temporaryPath, abandoned, abandoned);
    const result = await store.repairCorruptRecords(ENDPOINT);
    assert.deepEqual(result, { removed: [temporaryName] });
    await assert.rejects(lstat(temporaryPath), (error) => error.code === 'ENOENT');
    assert.deepEqual(await store.readPending(ENDPOINT), pending);
  });
});

test('explicit repair refuses links, non-regular entries, and insecure modes without deleting them', { skip: process.platform === 'win32' }, async (t) => {
  await t.test('symbolic link', async () => {
    const { root, store } = await fixture();
    const namespace = namespacePath(root);
    await mkdir(namespace, { recursive: true, mode: 0o700 });
    const outside = path.join(root, 'outside-corrupt.json');
    await writeFile(outside, '{"v":1}', { mode: 0o600 });
    const authorityPath = path.join(namespace, PROFILE_AUTHORITY_FILE_NAME);
    await symlink(outside, authorityPath);

    await assert.rejects(
      store.repairCorruptRecords(ENDPOINT),
      (error) => error.code === 'profile_credential_store_insecure',
    );
    assert.equal(await readFile(outside, 'utf8'), '{"v":1}');
    assert.equal((await lstat(authorityPath)).isSymbolicLink(), true);
  });

  await t.test('hard link', async () => {
    const { root, store } = await fixture();
    const pending = authority(store, 1);
    await store.writePending(ENDPOINT, pending);
    const pendingPath = path.join(namespacePath(root), PROFILE_PENDING_AUTHORITY_FILE_NAME);
    const secondLink = path.join(root, 'second-repair-link.json');
    await link(pendingPath, secondLink);

    await assert.rejects(
      store.repairCorruptRecords(ENDPOINT),
      (error) => error.code === 'profile_credential_store_insecure',
    );
    assert.equal((await lstat(pendingPath)).nlink, 2);
    assert.equal((await lstat(secondLink)).nlink, 2);
  });

  await t.test('directory at an allowlisted record name', async () => {
    const { root, store } = await fixture();
    const pending = authority(store, 1);
    await store.writePending(ENDPOINT, pending);
    const authorityPath = path.join(namespacePath(root), PROFILE_AUTHORITY_FILE_NAME);
    await mkdir(authorityPath, { mode: 0o700 });

    await assert.rejects(
      store.repairCorruptRecords(ENDPOINT),
      (error) => error.code === 'profile_credential_store_insecure',
    );
    assert.equal((await lstat(authorityPath)).isDirectory(), true);
  });

  await t.test('permissive record', async () => {
    const { root, store } = await fixture();
    const pending = authority(store, 1);
    await store.writePending(ENDPOINT, pending);
    const pendingPath = path.join(namespacePath(root), PROFILE_PENDING_AUTHORITY_FILE_NAME);
    await chmod(pendingPath, 0o644);

    await assert.rejects(
      store.repairCorruptRecords(ENDPOINT),
      (error) => error.code === 'profile_credential_store_insecure',
    );
    assert.equal((await lstat(pendingPath)).mode & 0o777, 0o644);
  });
});

test('authority parsing is bounded, fatal UTF-8, and endpoint-namespaced', async () => {
  const { root, identity, store } = await fixture();
  const candidate = authority(store, 1);
  await store.writePending(ENDPOINT, candidate);
  const raw = await readFile(path.join(namespacePath(root), PROFILE_PENDING_AUTHORITY_FILE_NAME), 'utf8');
  assert.equal(raw.endsWith('\n'), false);
  const other = new ProfileCredentialStore(root, `${identity}/remote-wsl`);
  assert.notEqual(store.clientSlot, other.clientSlot);
  assert.equal(await other.readAuthority('http://127.0.0.1:8081'), undefined);
});

test('terminal enrollment reasons survive offline store and client recreation', async () => {
  for (const reason of ['rejected', 'expired', 'unavailable']) {
    const { root, identity, store } = await fixture();
    const pending = { ...authority(store, 1), activation_expires_at: '2020-01-01T00:10:00Z' };
    await store.writePending(ENDPOINT, pending);
    await store.markRejected(ENDPOINT, pending, reason);
    await store.markRejected(ENDPOINT, pending, reason);
    const reopened = new ProfileCredentialStore(root, identity);
    assert.equal(await reopened.isRejected(ENDPOINT, pending), true);
    assert.equal(await reopened.rejectionReason(ENDPOINT, pending), reason);
    const client = new CodeSecurityClient(reopened, () => ENDPOINT, async () => assert.fail('terminal review must remain offline'));
    assert.equal((await client.pendingIdeEnrollment()).state, reason);
    await assert.rejects(client.connectIde('Retained'), error => error.code === `ide_enrollment_${reason}`);
    assert.deepEqual(await reopened.readPending(ENDPOINT), pending);
    assert.equal(await reopened.readAuthority(ENDPOINT), undefined);
    await assert.rejects(reopened.markRejected(ENDPOINT, pending, reason === 'expired' ? 'rejected' : 'expired'),
      error => error.code === 'profile_credential_store_write_unconfirmed');
    assert.equal(await reopened.rejectionReason(ENDPOINT, pending), reason);
  }
});

test('legacy rejection remains a neutral denial and malformed terminal markers fail closed', async () => {
  const { root, identity, store } = await fixture();
  const pending = authority(store, 1);
  await store.writePending(ENDPOINT, pending);
  await store.markRejected(ENDPOINT, pending, 'expired');
  const namespace = namespacePath(root);
  const names = (await readdir(namespace)).filter(name => name.startsWith('rejected-'));
  assert.equal(names.length, 1);
  const markerPath = path.join(namespace, names[0]);
  const marker = JSON.parse(await readFile(markerPath, 'utf8'));
  assert.equal(marker.v, 2);
  assert.equal(marker.reason, 'expired');
  for (const patch of [{ reason: 'approved' }, { reason: ['expired'] }, { extra: true }, { v: 3 },
    { raw_sha256: [marker.raw_sha256] }, { endpoint_hash: [marker.endpoint_hash] },
    { raw_sha256: '0'.repeat(64) }, { generation: 2 }, { client_slot: `ks1_${'z'.repeat(43)}` },
    { endpoint_hash: '0'.repeat(64) }]) {
    await writeFile(markerPath, JSON.stringify({ ...marker, ...patch }));
    await assert.rejects(store.rejectionReason(ENDPOINT, pending), error => error.code === 'profile_credential_store_corrupt');
  }
  await writeFile(markerPath, JSON.stringify(Object.fromEntries(Object.entries(marker).reverse())));
  await assert.rejects(store.rejectionReason(ENDPOINT, pending), error => error.code === 'profile_credential_store_corrupt');
  const { reason, ...legacy } = marker;
  legacy.v = 1;
  await writeFile(markerPath, JSON.stringify(legacy));
  const reopened = new ProfileCredentialStore(root, identity);
  assert.equal(await reopened.isRejected(ENDPOINT, pending), true);
  assert.equal(await reopened.rejectionReason(ENDPOINT, pending), 'unavailable');
  const client = new CodeSecurityClient(reopened, () => ENDPOINT, async () => assert.fail('legacy denial must remain offline'));
  assert.equal((await client.pendingIdeEnrollment()).state, 'unavailable');
  await assert.rejects(client.connectIde('Legacy'), error => error.code === 'ide_enrollment_unavailable');
  assert.equal(await reopened.readAuthority(ENDPOINT), undefined);
});
