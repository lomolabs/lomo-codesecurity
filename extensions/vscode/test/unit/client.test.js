const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const {
  CodeSecurityClient,
  CodeSecurityRequestError,
  IDE_CAPABILITY_SCOPES,
  PairingRequiredError,
  durableCommandHeaders,
  normalizeEndpoint,
  workspaceScanCommand,
} = require('../../dist/client.js');
const { ProfileCredentialStoreError } = require('../../dist/credentials.js');

const ENDPOINT = 'http://127.0.0.1:8080';
const SLOT = `ks1_${'s'.repeat(43)}`;

test('public health is credential-free, fixed-path, and refuses redirects and oversized bodies', async () => {
  let credentialReads = 0;
  const credentials = new Proxy({}, { get() { credentialReads++; throw new Error('public health must not touch credentials'); } });
  for (const [response, refusal] of [
    [jsonResponse({ ok: true }), null],
    [new Response('', { status: 302, headers: { Location: 'http://example.invalid/healthz' } }), /redirect/],
    [new Response('x', { headers: { 'Content-Length': '16385' } }), /oversized public health/],
    [new Response('x'.repeat(16385)), /oversized public health/],
  ]) {
    const client = new CodeSecurityClient(credentials, () => ENDPOINT, async (url, init) => {
      assert.equal(url, `${ENDPOINT}/healthz`);
      assert.equal(init.credentials, 'omit');
      assert.equal(init.redirect, 'error');
      assert.equal(new Headers(init.headers).has('Authorization'), false);
      return response;
    });
    if (refusal) await assert.rejects(client.publicHealth(), refusal);
    else assert.deepEqual(await client.publicHealth(), { ok: true });
  }
  assert.equal(credentialReads, 0);
});

test('public health refuses endpoint changes during fetch and body consumption without reading authority', async () => {
  for (const duringBody of [false, true]) {
    let endpoint = ENDPOINT;
    let ready;
    const started = new Promise(resolve => { ready = resolve; });
    let release;
    const held = new Promise(resolve => { release = resolve; });
    const client = new CodeSecurityClient({}, () => endpoint, async () => {
      if (!duringBody) { ready(); await held; return jsonResponse({ ok: true }); }
      return new Response(new ReadableStream({ async pull(controller) {
        ready(); await held; controller.enqueue(new TextEncoder().encode('{"ok":true}')); controller.close();
      } }));
    });
    const health = client.publicHealth();
    await started;
    endpoint = 'http://127.0.0.1:8090';
    release();
    await assert.rejects(health, error => error.code === 'ide_endpoint_changed');
  }
});

function capability(generation, label = `generation-${generation}`) {
  const secret = createHash('sha256').update(label).digest('base64url');
  return `kc1.${SLOT}.${generation}.${secret}`;
}

function authority(generation = 1, endpoint = ENDPOINT, label) {
  return Object.freeze({
    v: 1,
    endpoint,
    client_slot: SLOT,
    generation,
    capability: capability(generation, label),
    activation_expires_at: '2026-08-29T23:59:59Z',
    enrollment_request_id: `ker1_${'r'.repeat(24)}`,
    enrollment_revision: 1,
    enrollment_verification_code: 'ABCD-EF23',
  });
}

function activeAuthority(generation = 1, endpoint = ENDPOINT, label) {
  return Object.freeze({
    v: 1,
    endpoint,
    client_slot: SLOT,
    generation,
    capability: capability(generation, label),
  });
}

function enrollmentResponse(record, scopes = IDE_CAPABILITY_SCOPES) {
  return {
    request_id: record.enrollment_request_id,
    state: 'awaiting_approval',
    revision: record.enrollment_revision,
    verification_code: record.enrollment_verification_code,
    capability: record.capability,
    scopes: [...scopes],
    client_slot: record.client_slot,
    generation: record.generation,
    requested_at: '2026-08-29T23:49:59Z',
    activation_expires_at: record.activation_expires_at,
  };
}

function approvedEnrollment(record) {
  return {
    request_id: record.enrollment_request_id,
    state: 'approved',
    revision: 2,
    decision_at: '2026-08-29T23:50:00Z',
    activation_expires_at: record.activation_expires_at,
  };
}

function enrollmentStatus(record, state, revision = 2) {
  return {
    request_id: record.enrollment_request_id,
    state,
    revision,
    decision_at: ['awaiting_approval', 'expired'].includes(state)
      ? null
      : '2026-08-29T23:50:00Z',
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

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

class FakeProfileCredentialStore {
  constructor(authorities = []) {
    this.clientSlot = SLOT;
    this.authorities = new Map(authorities.map((record) => [record.endpoint, record]));
    this.pending = new Map();
    this.rejected = new Set();
    this.rejectionReasons = new Map();
    this.operations = [];
    this.writePendingError = undefined;
    this.discardPendingError = undefined;
  }

  async readAuthority(endpoint) {
    this.operations.push({ operation: 'readAuthority', endpoint });
    return this.authorities.get(endpoint);
  }

  async readPending(endpoint) {
    this.operations.push({ operation: 'readPending', endpoint });
    return this.pending.get(endpoint);
  }

  async writePending(endpoint, record) {
    this.operations.push({ operation: 'writePending', endpoint, record });
    if (this.writePendingError) throw this.writePendingError;
    this.pending.set(endpoint, record);
  }

  async promotePending(endpoint, record, active) {
    this.operations.push({ operation: 'promotePending', endpoint, record, active });
    assert.deepEqual(this.pending.get(endpoint), record);
    this.authorities.set(endpoint, active);
    this.pending.delete(endpoint);
  }

  async discardPending(endpoint, record) {
    this.operations.push({ operation: 'discardPending', endpoint, record });
    if (this.discardPendingError) throw this.discardPendingError;
    if (this.pending.get(endpoint)?.capability === record.capability) this.pending.delete(endpoint);
  }

  async discardRejectedAuthority(endpoint, record) {
    this.operations.push({ operation: 'discardRejectedAuthority', endpoint, record });
    assert.equal(this.rejected.has(record.capability), true);
    if (this.authorities.get(endpoint)?.capability === record.capability) {
      this.authorities.delete(endpoint);
    }
    this.rejected.delete(record.capability);
  }

  async markRejected(endpoint, record, reason = 'rejected') {
    this.operations.push({ operation: 'markRejected', endpoint, record });
    this.rejected.add(record.capability);
    this.rejectionReasons.set(record.capability, reason);
  }

  async rejectionReason(endpoint, record) {
    return this.rejected.has(record.capability) ? this.rejectionReasons.get(record.capability) ?? 'unavailable' : undefined;
  }

  async isRejected(endpoint, record) {
    this.operations.push({ operation: 'isRejected', endpoint, record });
    return this.rejected.has(record.capability);
  }
}

test('repository consent identity exposes only the exact retained non-secret profile namespace', async () => {
  const store = new FakeProfileCredentialStore([activeAuthority(3)]);
  const client = new CodeSecurityClient(store, () => ENDPOINT, async () => assert.fail('retained identity needs no HTTP request'));
  assert.deepEqual(await client.activeIdeIdentity(), { endpoint: ENDPOINT, clientSlot: SLOT, generation: 3 });
  assert.equal(IDE_CAPABILITY_SCOPES.some((scope) => scope.startsWith('push:')), false,
    'repository consent must not silently enlarge the base IDE capability');
  assert.equal(store.operations.some((item) => /write|promote|discard|markRejected/.test(item.operation)), false);
});

test('repository consent identity refuses an endpoint switch without changing the retained authority', async () => {
  const original = activeAuthority(3);
  const store = new FakeProfileCredentialStore([original]);
  let endpoint = ENDPOINT;
  const readAuthority = store.readAuthority.bind(store);
  store.readAuthority = async (selected) => {
    const result = await readAuthority(selected);
    endpoint = 'http://127.0.0.1:8090';
    return result;
  };
  const client = new CodeSecurityClient(store, () => endpoint, async () => assert.fail('identity refuses before HTTP'));
  await assert.rejects(client.activeIdeIdentity(), /endpoint changed/i);
  assert.equal(store.authorities.get(ENDPOINT), original);
  assert.equal(store.rejected.size, 0);
});

async function assertHeldPendingRecoveryEndpointSwitch(invoke) {
  const nextEndpoint = 'http://127.0.0.1:8090';
  const original = activeAuthority(1, ENDPOINT, 'pending-recovery-original');
  const pending = authority(2, ENDPOINT, 'pending-recovery-pending');
  const successor = activeAuthority(3, nextEndpoint, 'pending-recovery-successor');
  const store = new FakeProfileCredentialStore([original, successor]);
  store.pending.set(ENDPOINT, pending);

  let releasePendingRead;
  let markPendingRead;
  const heldPendingRead = new Promise((resolve) => { releasePendingRead = resolve; });
  const pendingReadStarted = new Promise((resolve) => { markPendingRead = resolve; });
  const readPending = store.readPending.bind(store);
  store.readPending = async (endpoint) => {
    const value = await readPending(endpoint);
    markPendingRead();
    await heldPendingRead;
    return value;
  };

  let endpoint = ENDPOINT;
  let requests = 0;
  const client = new CodeSecurityClient(
    store,
    () => endpoint,
    async () => { requests += 1; return jsonResponse({}); },
  );
  const operation = invoke(client);
  await pendingReadStarted;
  endpoint = nextEndpoint;
  releasePendingRead();

  await assert.rejects(operation, (error) => {
    assert.ok(error instanceof CodeSecurityRequestError);
    assert.match(error.message, /endpoint changed before pending enrollment recovery.*no request was sent/iu);
    assert.equal(error.retryable, true);
    assert.equal(error.code, 'ide_endpoint_changed');
    assert.equal(error.action, 'retry_against_selected_endpoint');
    return true;
  });
  assert.equal(requests, 0);
  assert.equal(store.rejected.size, 0);
  assert.deepEqual(store.pending.get(ENDPOINT), pending);
  assert.deepEqual(store.authorities.get(ENDPOINT), original);
  assert.deepEqual(store.authorities.get(nextEndpoint), successor);
  assert.deepEqual(
    store.operations.filter(({ operation: name }) => (
      name === 'writePending'
      || name === 'discardPending'
      || name === 'promotePending'
      || name === 'markRejected'
    )),
    [],
  );
  assert.deepEqual(store.operations.filter(({ endpoint: accessed }) => accessed === nextEndpoint), []);
}

class FakeEnrollmentProtocol {
  constructor(record, route) {
    this.record = record;
    this.route = route;
    this.calls = [];
  }

  fetch = async (url, init = {}) => {
    const parsed = new URL(String(url));
    const call = {
      path: parsed.pathname,
      method: init.method || 'GET',
      authorization: new Headers(init.headers).get('Authorization'),
      body: init.body === undefined ? undefined : JSON.parse(String(init.body)),
    };
    this.calls.push(call);
    if (parsed.pathname === '/v1/auth/ide/enrollments') return jsonResponse(enrollmentResponse(this.record), 201);
    if (parsed.pathname === '/v1/auth/ide/enrollments/current/wait') {
      assert.equal(call.authorization, `Bearer ${this.record.capability}`);
      return jsonResponse(approvedEnrollment(this.record));
    }
    if (parsed.pathname === '/v1/auth/ide/activate') {
      assert.equal(call.authorization, `Bearer ${this.record.capability}`);
      return jsonResponse(activationResponse(this.record));
    }
    if (parsed.pathname === '/v1/auth/ide/pending' && call.method === 'DELETE') {
      assert.equal(call.authorization, `Bearer ${this.record.capability}`);
      return jsonResponse({ cancelled: true });
    }
    if (this.route) return this.route(parsed, init, call);
    throw new Error(`unexpected request ${call.method} ${parsed.pathname}`);
  };
}

test('durable command helpers carry unique identities and bounded source targets', () => {
  const first = durableCommandHeaders()['Idempotency-Key'];
  const second = durableCommandHeaders()['Idempotency-Key'];
  assert.match(first, /^vscode-[0-9a-f-]{36}$/u);
  assert.match(second, /^vscode-[0-9a-f-]{36}$/u);
  assert.notEqual(first, second);

  assert.deepEqual(JSON.parse(workspaceScanCommand(17).init.body), {
    project_id: 17, mode: 'full', use_ai: false,
  });
  assert.deepEqual(JSON.parse(workspaceScanCommand(17, 'k8s/deployment.yaml', 'file').init.body), {
    project_id: 17,
    mode: 'full',
    use_ai: false,
    target_path: 'k8s/deployment.yaml',
    target_kind: 'file',
  });
  assert.deepEqual(
    JSON.parse(workspaceScanCommand(17, 'k8s/deployment.yaml', 'file', 'a'.repeat(64)).init.body),
    {
      project_id: 17,
      mode: 'full',
      use_ai: false,
      target_path: 'k8s/deployment.yaml',
      target_kind: 'file',
      source_snapshot_digest: 'a'.repeat(64),
    },
  );
  assert.throws(() => workspaceScanCommand(0), CodeSecurityRequestError);
  assert.throws(() => workspaceScanCommand(17, '../outside.py', 'file'), CodeSecurityRequestError);
  assert.throws(() => workspaceScanCommand(17, 'src', undefined), CodeSecurityRequestError);
  assert.throws(() => workspaceScanCommand(17, undefined, undefined, 'bad'), CodeSecurityRequestError);
});

test('constructing the client performs no network or authority-store access', () => {
  const store = new FakeProfileCredentialStore();
  let requests = 0;
  const client = new CodeSecurityClient(store, () => ENDPOINT, async () => {
    requests += 1;
    return jsonResponse({});
  });
  assert(client);
  assert.equal(requests, 0);
  assert.deepEqual(store.operations, []);
});

test('IDE enrollment durably stages, waits for owner approval, activates, promotes, and authenticates', async () => {
  const next = authority(1);
  const active = activeAuthority(1);
  const store = new FakeProfileCredentialStore();
  const protocol = new FakeEnrollmentProtocol(next, async (url, _init, call) => {
    assert.equal(url.pathname, '/v1/projects');
    assert.equal(call.authorization, `Bearer ${next.capability}`);
    return jsonResponse({ ok: true });
  });
  const client = new CodeSecurityClient(store, () => `${ENDPOINT}/`, protocol.fetch);

  const reviews = [];
  await client.connectIde(' VS Code (Test) ', (review) => reviews.push(review));
  assert.deepEqual(await client.request('/v1/projects'), { ok: true });
  assert.deepEqual(protocol.calls.map(({ path }) => path), [
    '/v1/auth/ide/enrollments',
    '/v1/auth/ide/enrollments/current/wait',
    '/v1/auth/ide/activate',
    '/v1/projects',
  ]);
  assert.deepEqual(protocol.calls[0].body, {
    client_name: 'VS Code (Test)',
    client_slot: SLOT,
    expected_active_generation: 0,
  });
  assert.equal(protocol.calls[0].authorization, null);
  assert.deepEqual(store.authorities.get(ENDPOINT), active);
  assert.deepEqual(store.pending, new Map());
  assert.deepEqual(reviews.map(({ state }) => state), ['awaiting_approval', 'approved']);
});

test('one-use installer bootstrap claims only the first pending IDE before ordinary activation', async () => {
  const next = authority(1);
  const store = new FakeProfileCredentialStore();
  const bootstrap = 'z'.repeat(43);
  const protocol = new FakeEnrollmentProtocol(next, async (url, _init, call) => {
    assert.equal(url.pathname, '/v1/auth/ide/enrollments/current/claim-first-owner');
    assert.equal(call.authorization, `Bearer ${next.capability}`);
    assert.deepEqual(call.body, {
      bootstrap_token: bootstrap,
      expected_request_id: next.enrollment_request_id,
      expected_revision: 1,
      expected_generation: 1,
    });
    return jsonResponse(approvedEnrollment(next));
  });
  const client = new CodeSecurityClient(store, () => ENDPOINT, protocol.fetch);

  assert.deepEqual(await client.connectIde('First Mac profile', undefined, undefined, bootstrap), {
    finishFirstOwnerSetup: true,
    authority: 'activated_now',
  });
  assert.deepEqual(protocol.calls.map(({ path }) => path), [
    '/v1/auth/ide/enrollments',
    '/v1/auth/ide/enrollments/current/claim-first-owner',
    '/v1/auth/ide/enrollments/current/wait',
    '/v1/auth/ide/activate',
  ]);

  const later = authority(1, ENDPOINT, 'later-profile');
  const laterStore = new FakeProfileCredentialStore();
  const laterProtocol = new FakeEnrollmentProtocol(later, async (url) => {
    assert.equal(url.pathname, '/v1/auth/ide/enrollments/current/claim-first-owner');
    return jsonResponse({ detail: {
      code: 'first_owner_claim_not_pristine',
      message: 'This installation already has an owner.',
      action: 'review_pending_enrollments',
    } }, 409);
  });
  const laterClient = new CodeSecurityClient(laterStore, () => ENDPOINT, laterProtocol.fetch);
  assert.deepEqual(await laterClient.connectIde('Later profile', undefined, undefined, bootstrap), {
    finishFirstOwnerSetup: false,
    authority: 'activated_now',
  });
  assert.deepEqual(laterProtocol.calls.map(({ path }) => path), [
    '/v1/auth/ide/enrollments',
    '/v1/auth/ide/enrollments/current/claim-first-owner',
    '/v1/auth/ide/enrollments/current/wait',
    '/v1/auth/ide/activate',
  ]);
});

test('retained first-owner pending recovers a committed claim whose response was lost', async () => {
  const pending = authority(1, ENDPOINT, 'lost-first-owner-claim');
  const store = new FakeProfileCredentialStore();
  store.pending.set(ENDPOINT, pending);
  const bootstrap = 'z'.repeat(43);
  let serverState = 'awaiting_approval';
  const calls = [];
  const fetch = async (url, init = {}) => {
    const path = new URL(String(url)).pathname;
    calls.push(path);
    if (path === '/v1/auth/ide/enrollments/current/wait') {
      return jsonResponse(serverState === 'approved'
        ? approvedEnrollment(pending)
        : enrollmentStatus(pending, 'awaiting_approval', 1));
    }
    if (path === '/v1/auth/ide/enrollments/current/claim-first-owner') {
      serverState = 'approved';
      throw new TypeError('fixture lost the committed claim response');
    }
    if (path === '/v1/auth/ide/activate') return jsonResponse(activationResponse(pending));
    throw new Error(`unexpected request ${init.method || 'GET'} ${path}`);
  };

  await assert.rejects(
    new CodeSecurityClient(store, () => ENDPOINT, fetch).connectIde(
      'First Mac profile', undefined, undefined, bootstrap,
    ),
    /Could not reach the local CodeSecurity first-owner claim endpoint/u,
  );
  assert.deepEqual(store.pending.get(ENDPOINT), pending);

  const recovered = new CodeSecurityClient(store, () => ENDPOINT, fetch);
  assert.deepEqual(await recovered.connectIde('First Mac profile', undefined, undefined, bootstrap), {
    finishFirstOwnerSetup: true,
    authority: 'activated_now',
  });
  assert.deepEqual(calls, [
    '/v1/auth/ide/enrollments/current/wait',
    '/v1/auth/ide/enrollments/current/claim-first-owner',
    '/v1/auth/ide/enrollments/current/wait',
    '/v1/auth/ide/activate',
  ]);
  assert.equal(store.pending.size, 0);
  assert.deepEqual(store.authorities.get(ENDPOINT), activeAuthority(1, ENDPOINT, 'lost-first-owner-claim'));
});

test('retained first-owner pending promotes locally after server activation committed before its response', async () => {
  const pending = authority(1, ENDPOINT, 'lost-first-owner-activation');
  const store = new FakeProfileCredentialStore();
  store.pending.set(ENDPOINT, pending);
  const bootstrap = 'y'.repeat(43);
  let activationCommitted = false;
  let activationAttempts = 0;
  const calls = [];
  const fetch = async (url, init = {}) => {
    const path = new URL(String(url)).pathname;
    calls.push(path);
    if (path === '/v1/auth/ide/enrollments/current/wait') {
      return jsonResponse(enrollmentStatus(pending, 'approved', activationCommitted ? 3 : 2));
    }
    if (path === '/v1/auth/ide/activate') {
      activationAttempts += 1;
      if (activationAttempts === 1) {
        activationCommitted = true;
        throw new TypeError('fixture lost the committed activation response');
      }
      return jsonResponse(activationResponse(pending));
    }
    throw new Error(`unexpected request ${init.method || 'GET'} ${path}`);
  };

  await assert.rejects(
    new CodeSecurityClient(store, () => ENDPOINT, fetch).connectIde(
      'First Mac profile', undefined, undefined, bootstrap,
    ),
    /Could not reach the local CodeSecurity authority-activation endpoint/u,
  );
  assert.deepEqual(store.pending.get(ENDPOINT), pending);

  const recovered = new CodeSecurityClient(store, () => ENDPOINT, fetch);
  assert.deepEqual(await recovered.connectIde('First Mac profile', undefined, undefined, bootstrap), {
    finishFirstOwnerSetup: true,
    authority: 'activated_now',
  });
  assert.deepEqual(calls, [
    '/v1/auth/ide/enrollments/current/wait',
    '/v1/auth/ide/activate',
    '/v1/auth/ide/enrollments/current/wait',
    '/v1/auth/ide/activate',
  ]);
  assert.equal(store.pending.size, 0);
  assert.deepEqual(
    store.authorities.get(ENDPOINT),
    activeAuthority(1, ENDPOINT, 'lost-first-owner-activation'),
  );
});

test('rejected and expired retained first-owner enrollments never claim or activate', async () => {
  for (const state of ['rejected', 'expired']) {
    const pending = authority(1, ENDPOINT, `terminal-first-owner-${state}`);
    const store = new FakeProfileCredentialStore();
    store.pending.set(ENDPOINT, pending);
    const calls = [];
    const client = new CodeSecurityClient(store, () => ENDPOINT, async (url) => {
      const path = new URL(String(url)).pathname;
      calls.push(path);
      assert.equal(path, '/v1/auth/ide/enrollments/current/wait');
      return jsonResponse(enrollmentStatus(pending, state));
    });
    await assert.rejects(
      client.connectIde('First Mac profile', undefined, undefined, 'x'.repeat(43)),
      (error) => error instanceof CodeSecurityRequestError
        && error.code === `ide_enrollment_${state}`,
    );
    assert.deepEqual(calls, ['/v1/auth/ide/enrollments/current/wait']);
    assert.equal(store.rejected.has(pending.capability), true);
    assert.deepEqual(store.pending.get(ENDPOINT), pending);
    const recreated = new CodeSecurityClient(store, () => ENDPOINT, async () =>
      jsonResponse(enrollmentStatus(pending, state)));
    assert.equal((await recreated.pendingIdeEnrollment()).state, state,
      'restarting must preserve the distinction between owner rejection and expiry');
  }
});

test('a recreated client reuses the exact durable authority without pairing', async () => {
  const active = activeAuthority(3);
  const store = new FakeProfileCredentialStore([active]);
  const calls = [];
  const client = new CodeSecurityClient(store, () => ENDPOINT, async (url, init) => {
    calls.push({
      path: new URL(String(url)).pathname,
      authorization: new Headers(init.headers).get('Authorization'),
    });
    return jsonResponse({ ok: true });
  });
  assert.deepEqual(await client.request('/v1/projects'), { ok: true });
  assert.deepEqual(calls, [{ path: '/v1/projects', authorization: `Bearer ${active.capability}` }]);
});

test('active exact authority preserves unfinished first-owner browser cleanup without network enrollment', async () => {
  const active = activeAuthority(3, ENDPOINT, 'promoted-first-owner');
  const store = new FakeProfileCredentialStore([active]);
  let requests = 0;
  const client = new CodeSecurityClient(store, () => ENDPOINT, async () => {
    requests += 1;
    throw new Error('active first-owner cleanup must not enroll or claim again');
  });

  assert.deepEqual(
    await client.connectIde('First Mac profile', undefined, undefined, 'f'.repeat(43)),
    { authority: 'retained', finishFirstOwnerSetup: true },
  );
  assert.equal(requests, 0);
  assert.deepEqual(store.authorities.get(ENDPOINT), active);
  assert.equal(store.pending.size, 0);
});

test('browser invitation uses retained IDE authority and accepts only the exact ten-minute envelope', async () => {
  const active = activeAuthority();
  const store = new FakeProfileCredentialStore([active]);
  const token = `kbi1.${'i'.repeat(24)}.${'s'.repeat(43)}`;
  const calls = [];
  const client = new CodeSecurityClient(store, () => ENDPOINT, async (url, init) => {
    calls.push({ url: String(url), init });
    return jsonResponse({
      bootstrap_token: token,
      invitation_id: 'i'.repeat(24),
      purpose: 'integrated_dashboard',
      issued_at: '2026-08-30T12:00:00Z',
      expires_at: '2026-08-30T12:10:00Z',
      expires_in: 600,
    });
  });

  assert.deepEqual(await client.issueBrowserInvitation('integrated_dashboard'), {
    bootstrapToken: token,
    invitationId: 'i'.repeat(24),
    purpose: 'integrated_dashboard',
    issuedAt: '2026-08-30T12:00:00Z',
    expiresAt: '2026-08-30T12:10:00Z',
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${ENDPOINT}/v1/auth/ide/browser-invitations`);
  assert.equal(calls[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(String(calls[0].init.body)), { purpose: 'integrated_dashboard' });
  assert.equal(new Headers(calls[0].init.headers).get('authorization'), `Bearer ${active.capability}`);
  assert.doesNotMatch(calls[0].url, /[?#]bootstrap|kbi1/u);

  const malformed = new CodeSecurityClient(store, () => ENDPOINT, async () => jsonResponse({
    bootstrap_token: token,
    invitation_id: 'i'.repeat(24),
    purpose: 'integrated_dashboard',
    issued_at: '2026-08-30T12:00:00Z',
    expires_at: '2026-08-30T12:09:59Z',
    expires_in: 600,
  }));
  await assert.rejects(
    malformed.issueBrowserInvitation('integrated_dashboard'),
    /invalid browser invitation/u,
  );
});

test('browser membership acknowledgement accepts only exact pending active and revoked unions', async () => {
  const active = activeAuthority();
  const store = new FakeProfileCredentialStore([active]);
  const invitationId = 'i'.repeat(24);
  const memberId = `kbm1_${'m'.repeat(32)}`;
  const responses = [
    {
      invitation_id: invitationId,
      status: 'pending',
      purpose: 'integrated_dashboard',
      expires_at: '2026-08-30T12:10:00Z',
    },
    {
      invitation_id: invitationId,
      status: 'active',
      purpose: 'integrated_dashboard',
      member_id: memberId,
      created_at: '2026-08-30T12:00:01Z',
    },
    { invitation_id: invitationId, status: 'missing_or_revoked' },
  ];
  const paths = [];
  const client = new CodeSecurityClient(store, () => ENDPOINT, async (url) => {
    paths.push(new URL(String(url)).pathname);
    return jsonResponse(responses.shift());
  });

  assert.deepEqual(await client.waitForBrowserInvitationMembership(invitationId), {
    invitationId,
    status: 'pending',
    purpose: 'integrated_dashboard',
    expiresAt: '2026-08-30T12:10:00Z',
  });
  assert.deepEqual(await client.waitForBrowserInvitationMembership(invitationId), {
    invitationId,
    status: 'active',
    purpose: 'integrated_dashboard',
    memberId,
    createdAt: '2026-08-30T12:00:01Z',
  });
  assert.deepEqual(await client.waitForBrowserInvitationMembership(invitationId), {
    invitationId,
    status: 'missing_or_revoked',
  });
  assert.deepEqual(paths, Array(3).fill(
    `/v1/auth/ide/browser-invitations/${invitationId}/membership`,
  ));

  const malformed = new CodeSecurityClient(store, () => ENDPOINT, async () => jsonResponse({
    invitation_id: invitationId,
    status: 'active',
    purpose: 'integrated_dashboard',
    member_id: memberId,
    created_at: '2026-08-30T12:00:01Z',
    verifier: 'must-not-be-returned',
  }));
  await assert.rejects(
    malformed.waitForBrowserInvitationMembership(invitationId),
    /invalid active browser membership acknowledgement/u,
  );
});

test('a recoverable pending authority activates before the first ordinary request', async () => {
  const pending = authority(4);
  const active = activeAuthority(4);
  const store = new FakeProfileCredentialStore();
  store.pending.set(ENDPOINT, pending);
  const protocol = new FakeEnrollmentProtocol(pending, async (_url, _init, call) => {
    assert.equal(call.authorization, `Bearer ${pending.capability}`);
    return jsonResponse({ resumed: true });
  });
  const client = new CodeSecurityClient(store, () => ENDPOINT, protocol.fetch);
  assert.deepEqual(await client.request('/v1/projects'), { resumed: true });
  assert.deepEqual(protocol.calls.map(({ path }) => path), [
    '/v1/auth/ide/enrollments/current/wait', '/v1/auth/ide/activate', '/v1/projects',
  ]);
  assert.deepEqual(store.authorities.get(ENDPOINT), active);
});

test('typed enrollment generation conflict preserves local authority storage unchanged', async () => {
  const store = new FakeProfileCredentialStore();
  const calls = [];
  const client = new CodeSecurityClient(store, () => ENDPOINT, async (url, init) => {
    calls.push({ path: new URL(String(url)).pathname, body: JSON.parse(String(init.body)) });
    return jsonResponse({
      detail: {
        code: 'ide_enrollment_generation_conflict',
        message: 'This profile slot already has an active authority.',
        action: 'revoke_or_restore_profile_authority',
      },
    }, 409);
  });
  await assert.rejects(client.connectIde('Fedora QA'), (error) => {
    assert.equal(error.status, 409);
    assert.equal(error.code, 'ide_enrollment_generation_conflict');
    assert.equal(error.action, 'revoke_or_restore_profile_authority');
    return true;
  });
  assert.deepEqual(calls[0].body, {
    client_name: 'Fedora QA',
    client_slot: SLOT,
    expected_active_generation: 0,
  });
  assert.deepEqual(store.authorities, new Map());
  assert.deepEqual(store.pending, new Map());
});

test('reinstalled local service offers an exact rejected-profile reset after cleaning its pending request', async () => {
  const retained = activeAuthority(1, ENDPOINT, 'previous-installation');
  const replacement = authority(1, ENDPOINT, 'replacement-installation');
  const store = new FakeProfileCredentialStore([retained]);
  store.rejected.add(retained.capability);
  store.writePendingError = new ProfileCredentialStoreError(
    'profile_credential_store_write_unconfirmed',
    'same generation from another installation',
  );
  const calls = [];
  const client = new CodeSecurityClient(store, () => ENDPOINT, async (url, init) => {
    const pathname = new URL(String(url)).pathname;
    calls.push({ pathname, authorization: new Headers(init.headers).get('Authorization') });
    if (pathname === '/v1/auth/ide/enrollments') return jsonResponse(enrollmentResponse(replacement));
    if (pathname === '/v1/auth/ide/pending') return jsonResponse({ cancelled: true });
    throw new Error(`unexpected request ${pathname}`);
  });

  await assert.rejects(client.connectIde('Mac QA A'), (error) => {
    assert.equal(error.code, 'rejected_profile_authority_generation_conflict');
    assert.equal(error.action, 'reset_rejected_profile_authority');
    assert.equal(error.message.includes(retained.capability), false);
    assert.equal(error.message.includes(replacement.capability), false);
    return true;
  });
  assert.deepEqual(calls, [
    { pathname: '/v1/auth/ide/enrollments', authorization: null },
    { pathname: '/v1/auth/ide/pending', authorization: `Bearer ${replacement.capability}` },
  ]);
  assert.deepEqual(store.authorities.get(ENDPOINT), retained);

  await client.resetRejectedIdeAuthority();
  assert.equal(store.authorities.has(ENDPOINT), false);
  assert.equal(store.rejected.has(retained.capability), false);
  assert.deepEqual(
    store.operations.filter(({ operation }) => operation === 'discardRejectedAuthority'),
    [{ operation: 'discardRejectedAuthority', endpoint: ENDPOINT, record: retained }],
  );
});

test('invalid pairing scopes cancel only the trustworthy exact pending identity', async () => {
  const pending = authority(1);
  const store = new FakeProfileCredentialStore();
  const calls = [];
  const client = new CodeSecurityClient(store, () => ENDPOINT, async (url, init) => {
    const path = new URL(String(url)).pathname;
    calls.push({ path, authorization: new Headers(init.headers).get('Authorization') });
    if (path === '/v1/auth/ide/enrollments') {
      return jsonResponse(enrollmentResponse(pending, IDE_CAPABILITY_SCOPES.slice(1)));
    }
    if (path === '/v1/auth/ide/pending') return jsonResponse({ cancelled: true });
    throw new Error(`unexpected request ${path}`);
  });
  await assert.rejects(client.connectIde('VS Code'), (error) => {
    assert(error instanceof CodeSecurityRequestError);
    assert.match(error.message, /invalid IDE enrollment response.*cancelled/u);
    return true;
  });
  assert.deepEqual(calls, [
    { path: '/v1/auth/ide/enrollments', authorization: null },
    { path: '/v1/auth/ide/pending', authorization: `Bearer ${pending.capability}` },
  ]);
  assert.deepEqual(store.authorities, new Map());
});

test('untrusted pair identity fails typed before field use and never sends its bearer', async (t) => {
  for (const candidate of [
    { name: 'null', body: null },
    { name: 'number', body: 7 },
    { name: 'string', body: 'not-an-authority' },
    { name: 'array', body: [] },
    { name: 'mismatched capability tuple', body: { ...enrollmentResponse(authority(1)), capability: 'not-kc1' } },
  ]) {
    await t.test(candidate.name, async () => {
      const store = new FakeProfileCredentialStore();
      const calls = [];
      const client = new CodeSecurityClient(store, () => ENDPOINT, async (url, init) => {
        const path = new URL(String(url)).pathname;
        calls.push({ path, authorization: new Headers(init.headers).get('Authorization') });
        if (path === '/v1/auth/ide/enrollments') return jsonResponse(candidate.body);
        throw new Error(`unexpected request ${path}`);
      });

      await assert.rejects(client.connectIde('VS Code'), (error) => {
        assert(error instanceof CodeSecurityRequestError);
        assert.equal(error instanceof TypeError, false);
        assert.equal(error.code, 'ide_enrollment_response_identity_untrusted');
        assert.equal(error.action, 'review_paired_ide_clients');
        assert.match(error.message, /No returned bearer was used/u);
        return true;
      });
      assert.deepEqual(calls, [{ path: '/v1/auth/ide/enrollments', authorization: null }]);
      assert.deepEqual(store.pending, new Map());
      assert.deepEqual(store.authorities, new Map());
    });
  }
});

test('malformed and oversized successful enrollment bodies require Settings review without bearer use', async (t) => {
  for (const candidate of [
    {
      name: 'malformed JSON',
      response: () => new Response('{', { status: 200, headers: { 'Content-Type': 'application/json' } }),
      reason: /invalid authentication response/u,
    },
    {
      name: 'oversized body',
      response: () => new Response('{}', {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Content-Length': '16385' },
      }),
      reason: /oversized authentication response/u,
    },
  ]) {
    await t.test(candidate.name, async () => {
      const calls = [];
      const client = new CodeSecurityClient(new FakeProfileCredentialStore(), () => ENDPOINT, async (url) => {
        const requestPath = new URL(String(url)).pathname;
        calls.push(requestPath);
        assert.equal(requestPath, '/v1/auth/ide/enrollments');
        return candidate.response();
      });

      await assert.rejects(client.connectIde('VS Code'), (error) => {
        assert(error instanceof CodeSecurityRequestError);
        assert.equal(error.code, 'ide_enrollment_response_identity_untrusted');
        assert.equal(error.action, 'review_paired_ide_clients');
        assert.match(error.message, candidate.reason);
        assert.match(error.message, /No returned bearer was used/u);
        return true;
      });
      assert.deepEqual(calls, ['/v1/auth/ide/enrollments']);
    });
  }
});

test('trusted extra-key enrollment envelope is cancelled with its exact bearer', async () => {
  const pending = authority(1);
  const calls = [];
  const client = new CodeSecurityClient(new FakeProfileCredentialStore(), () => ENDPOINT, async (url, init) => {
    const path = new URL(String(url)).pathname;
    calls.push({ path, authorization: new Headers(init.headers).get('Authorization') });
    if (path === '/v1/auth/ide/enrollments') return jsonResponse({ ...enrollmentResponse(pending), extra: true });
    if (path === '/v1/auth/ide/pending') return jsonResponse({ cancelled: true });
    throw new Error(`unexpected request ${path}`);
  });

  await assert.rejects(client.connectIde('VS Code'), /exact pending authority was cancelled/u);
  assert.deepEqual(calls, [
    { path: '/v1/auth/ide/enrollments', authorization: null },
    { path: '/v1/auth/ide/pending', authorization: `Bearer ${pending.capability}` },
  ]);
});

test('parent abort after server issuance still uses a fresh cleanup deadline', async () => {
  const pending = authority(1);
  const controller = new AbortController();
  const calls = [];
  const client = new CodeSecurityClient(new FakeProfileCredentialStore(), () => ENDPOINT, async (url, init) => {
    const path = new URL(String(url)).pathname;
    calls.push({ path, signalAborted: init.signal?.aborted === true });
    if (path === '/v1/auth/ide/enrollments') {
      controller.abort();
      return jsonResponse(enrollmentResponse(pending, IDE_CAPABILITY_SCOPES.slice(1)));
    }
    if (path === '/v1/auth/ide/pending') return jsonResponse({ cancelled: true });
    throw new Error(`unexpected request ${path}`);
  });

  await assert.rejects(
    client.connectIde('VS Code', undefined, controller.signal),
    (error) => error.name === 'AbortError',
  );
  assert.deepEqual(calls, [
    { path: '/v1/auth/ide/enrollments', signalAborted: false },
    { path: '/v1/auth/ide/pending', signalAborted: false },
  ]);
});

test('unconfirmed exact pending cleanup returns the recovery action without exposing bearer', async () => {
  const pending = authority(1, ENDPOINT, 'cleanup-secret');
  const client = new CodeSecurityClient(new FakeProfileCredentialStore(), () => ENDPOINT, async (url) => {
    const path = new URL(String(url)).pathname;
    if (path === '/v1/auth/ide/enrollments') return jsonResponse(enrollmentResponse(pending, IDE_CAPABILITY_SCOPES.slice(1)));
    assert.equal(path, '/v1/auth/ide/pending');
    return jsonResponse({ message: 'unavailable' }, 503);
  });

  await assert.rejects(client.connectIde('VS Code'), (error) => {
    assert(error instanceof CodeSecurityRequestError);
    assert.equal(error.code, 'ide_enrollment_pending_cleanup_unconfirmed');
    assert.equal(error.action, 'review_paired_ide_clients');
    assert.equal(error.message.includes(pending.capability), false);
    return true;
  });
});

test('pending-write failure cancels exact server pending without exposing it', async () => {
  const pending = authority(1, ENDPOINT, 'never-expose-this-authority');
  const store = new FakeProfileCredentialStore();
  store.writePendingError = new ProfileCredentialStoreError(
    'profile_credential_store_write_unconfirmed',
    'The dedicated profile authority file write could not be confirmed.',
  );
  const protocol = new FakeEnrollmentProtocol(pending);
  const client = new CodeSecurityClient(store, () => ENDPOINT, protocol.fetch);
  await assert.rejects(client.connectIde('VS Code'), (error) => {
    assert.equal(error.code, 'profile_credential_store_write_unconfirmed');
    assert.equal(error.message.includes(pending.capability), false);
    return true;
  });
  assert.deepEqual(protocol.calls.map(({ path }) => path), [
    '/v1/auth/ide/enrollments', '/v1/auth/ide/pending',
  ]);
});

test('unexpected local discard failure after exact server cancellation is rethrown', async () => {
  const pending = authority(1);
  const store = new FakeProfileCredentialStore();
  store.writePendingError = new ProfileCredentialStoreError(
    'profile_credential_store_write_unconfirmed',
    'fixture pending write refused',
  );
  const unexpected = new Error('fixture discard programmer error');
  store.discardPendingError = unexpected;
  const protocol = new FakeEnrollmentProtocol(pending);
  const client = new CodeSecurityClient(store, () => ENDPOINT, protocol.fetch);

  await assert.rejects(client.connectIde('VS Code'), (error) => error === unexpected);
  assert.deepEqual(protocol.calls.map(({ path }) => path), [
    '/v1/auth/ide/enrollments', '/v1/auth/ide/pending',
  ]);
});

test('selected endpoint change cancels pending before local persistence', async () => {
  const pending = authority(1);
  const store = new FakeProfileCredentialStore();
  let endpoint = ENDPOINT;
  let releaseEnrollment;
  let markEnrollmentStarted;
  const heldEnrollment = new Promise((resolve) => { releaseEnrollment = resolve; });
  const enrollmentStarted = new Promise((resolve) => { markEnrollmentStarted = resolve; });
  const calls = [];
  const client = new CodeSecurityClient(store, () => endpoint, async (url, init) => {
    const path = new URL(String(url)).pathname;
    calls.push({ path, authorization: new Headers(init.headers).get('Authorization') });
    if (path === '/v1/auth/ide/enrollments') {
      markEnrollmentStarted();
      return heldEnrollment;
    }
    return jsonResponse({ cancelled: true });
  });
  const pairing = client.connectIde('VS Code');
  await enrollmentStarted;
  endpoint = 'http://127.0.0.1:8090';
  releaseEnrollment(jsonResponse(enrollmentResponse(pending)));
  await assert.rejects(pairing, /endpoint changed while IDE enrollment/u);
  assert.deepEqual(calls, [
    { path: '/v1/auth/ide/enrollments', authorization: null },
    { path: '/v1/auth/ide/pending', authorization: `Bearer ${pending.capability}` },
  ]);
  assert.deepEqual(store.operations.map(({ operation }) => operation), ['readPending', 'readAuthority']);
});

test('approval-needed callback runs only after exact pending authority is durable', async () => {
  const pending = authority(1);
  const store = new FakeProfileCredentialStore();
  const controller = new AbortController();
  const calls = [];
  const client = new CodeSecurityClient(store, () => ENDPOINT, async (url) => {
    calls.push(new URL(String(url)).pathname);
    return jsonResponse(enrollmentResponse(pending), 201);
  });
  await assert.rejects(
    client.connectIde('Mac QA', (review) => {
      assert.deepEqual(store.pending.get(ENDPOINT), pending);
      assert.equal(review.verificationCode, pending.enrollment_verification_code);
      controller.abort();
    }, controller.signal),
    (error) => error.name === 'AbortError',
  );
  assert.deepEqual(calls, ['/v1/auth/ide/enrollments']);
  assert.deepEqual(store.pending.get(ENDPOINT), pending);
  assert.equal(store.authorities.size, 0);
});

test('explicit cancel reconciles already-inactive server state and discards only exact local pending', async () => {
  const pending = authority(3);
  const store = new FakeProfileCredentialStore();
  store.pending.set(ENDPOINT, pending);
  const calls = [];
  const client = new CodeSecurityClient(store, () => ENDPOINT, async (url, init) => {
    calls.push({
      path: new URL(String(url)).pathname,
      authorization: new Headers(init.headers).get('Authorization'),
    });
    return jsonResponse({ detail: 'already inactive' }, 410);
  });
  await client.cancelIdeEnrollment();
  assert.deepEqual(calls, [{
    path: '/v1/auth/ide/pending',
    authorization: `Bearer ${pending.capability}`,
  }]);
  assert.equal(store.pending.size, 0);
});

test('event stream uses exact authority and explicit cursor headers', async () => {
  const active = activeAuthority(2);
  const store = new FakeProfileCredentialStore([active]);
  let call;
  const client = new CodeSecurityClient(store, () => ENDPOINT, async (url, init) => {
    call = { url: String(url), init };
    return new Response('event: stream.ready\ndata: {}\n\n', {
      headers: { 'Content-Type': 'text/event-stream; charset=utf-8' },
    });
  });
  const response = await client.openEventStream(37, new AbortController().signal);
  const headers = new Headers(call.init.headers);
  assert.equal(call.url, `${ENDPOINT}/v1/events`);
  assert.equal(headers.get('Authorization'), `Bearer ${active.capability}`);
  assert.equal(headers.get('Last-Event-ID'), '37');
  assert.equal(headers.get('Cache-Control'), 'no-cache');
  assert.equal(await response.text(), 'event: stream.ready\ndata: {}\n\n');
});

test('event stream rejects invalid cursors and non-SSE responses without exposing capability data', async () => {
  const active = activeAuthority(1, ENDPOINT, 'never-expose-stream-capability');
  let calls = 0;
  const client = new CodeSecurityClient(
    new FakeProfileCredentialStore([active]),
    () => ENDPOINT,
    async () => {
      calls += 1;
      return jsonResponse({ detail: active.capability });
    },
  );

  await assert.rejects(client.openEventStream(-1, new AbortController().signal), /non-negative/u);
  await assert.rejects(client.openEventStream(0, new AbortController().signal), (error) => {
    assert(error instanceof CodeSecurityRequestError);
    assert.match(error.message, /invalid event-stream response/u);
    assert.equal(error.message.includes(active.capability), false);
    return true;
  });
  assert.equal(calls, 1);
});

test('missing authority and exact endpoint namespaces fail closed before fetch', async () => {
  const old = activeAuthority(1);
  const store = new FakeProfileCredentialStore([old]);
  let endpoint = 'http://127.0.0.1:8090';
  let requests = 0;
  const invalidations = [];
  const client = new CodeSecurityClient(
    store,
    () => endpoint,
    async () => { requests += 1; return jsonResponse({}); },
    (value) => invalidations.push(value),
  );
  await assert.rejects(client.request('/v1/projects'), PairingRequiredError);
  assert.equal(requests, 0);
  assert.deepEqual(store.authorities.get(ENDPOINT), old);
  assert.deepEqual(invalidations, [{ endpoint, reason: 'missing_or_invalid' }]);
});

test('ordinary request pending recovery endpoint switch preserves both namespaces and sends nothing', async () => {
  await assertHeldPendingRecoveryEndpointSwitch((client) => client.request('/v1/projects'));
});

test('event stream pending recovery endpoint switch preserves both namespaces and sends nothing', async () => {
  await assertHeldPendingRecoveryEndpointSwitch(
    (client) => client.openEventStream(0, new AbortController().signal),
  );
});

test('ordinary request endpoint change preserves both authority namespaces and sends nothing', async () => {
  const nextEndpoint = 'http://127.0.0.1:8090';
  const original = activeAuthority(1, ENDPOINT, 'original-endpoint');
  const successor = activeAuthority(2, nextEndpoint, 'successor-endpoint');
  const store = new FakeProfileCredentialStore([original, successor]);
  let endpointRead = 0;
  let requests = 0;
  const client = new CodeSecurityClient(
    store,
    () => (endpointRead++ === 0 ? ENDPOINT : nextEndpoint),
    async () => { requests += 1; return jsonResponse({}); },
  );

  await assert.rejects(
    client.request('/v1/projects'),
    /endpoint changed before this request was sent.*No authority was rejected/u,
  );
  assert.equal(requests, 0);
  assert.equal(store.rejected.size, 0);
  assert.deepEqual(store.authorities.get(ENDPOINT), original);
  assert.deepEqual(store.authorities.get(nextEndpoint), successor);
  assert.deepEqual(
    store.operations.filter(({ operation }) => operation === 'readAuthority').map(({ endpoint }) => endpoint),
    [ENDPOINT],
  );
});

test('event stream endpoint change preserves both authority namespaces and sends nothing', async () => {
  const nextEndpoint = 'http://127.0.0.1:8090';
  const original = activeAuthority(1, ENDPOINT, 'original-stream-endpoint');
  const successor = activeAuthority(2, nextEndpoint, 'successor-stream-endpoint');
  const store = new FakeProfileCredentialStore([original, successor]);
  let endpointRead = 0;
  let requests = 0;
  const client = new CodeSecurityClient(
    store,
    () => (endpointRead++ === 0 ? ENDPOINT : nextEndpoint),
    async () => {
      requests += 1;
      return new Response('', { headers: { 'Content-Type': 'text/event-stream' } });
    },
  );

  await assert.rejects(
    client.openEventStream(0, new AbortController().signal),
    /endpoint changed before the event stream was opened.*No authority was rejected/u,
  );
  assert.equal(requests, 0);
  assert.equal(store.rejected.size, 0);
  assert.deepEqual(store.authorities.get(ENDPOINT), original);
  assert.deepEqual(store.authorities.get(nextEndpoint), successor);
  assert.deepEqual(
    store.operations.filter(({ operation }) => operation === 'readAuthority').map(({ endpoint }) => endpoint),
    [ENDPOINT],
  );
});

test('late 401 cannot reject a successor authority', async () => {
  const old = activeAuthority(1, ENDPOINT, 'old');
  const successor = activeAuthority(2, ENDPOINT, 'successor');
  const store = new FakeProfileCredentialStore([old]);
  let releaseResponse;
  let markStarted;
  const held = new Promise((resolve) => { releaseResponse = resolve; });
  const started = new Promise((resolve) => { markStarted = resolve; });
  const client = new CodeSecurityClient(store, () => ENDPOINT, async () => {
    markStarted();
    return held;
  });
  const request = client.request('/v1/projects');
  await started;
  store.authorities.set(ENDPOINT, successor);
  releaseResponse(jsonResponse({ detail: 'old rejected' }, 401));
  await assert.rejects(request, /authority changed while this request was in flight/u);
  assert.equal(store.rejected.size, 0);
  assert.deepEqual(store.authorities.get(ENDPOINT), successor);
});

test('late event-stream 401 cannot reject a successor authority', async () => {
  const old = activeAuthority(1, ENDPOINT, 'old-stream');
  const successor = activeAuthority(2, ENDPOINT, 'successor-stream');
  const store = new FakeProfileCredentialStore([old]);
  let releaseResponse;
  let markStarted;
  const held = new Promise((resolve) => { releaseResponse = resolve; });
  const started = new Promise((resolve) => { markStarted = resolve; });
  const client = new CodeSecurityClient(store, () => ENDPOINT, async () => {
    markStarted();
    return held;
  });
  const stream = client.openEventStream(0, new AbortController().signal);
  await started;
  store.authorities.set(ENDPOINT, successor);
  releaseResponse(jsonResponse({ detail: 'old stream rejected' }, 401));
  await assert.rejects(stream, /authority changed while the event stream was opening/u);
  assert.equal(store.rejected.size, 0);
  assert.deepEqual(store.authorities.get(ENDPOINT), successor);
});

test('exact 401 marks only current authority and emits typed invalidation', async () => {
  const active = activeAuthority(5);
  const store = new FakeProfileCredentialStore([active]);
  const invalidations = [];
  const client = new CodeSecurityClient(
    store,
    () => ENDPOINT,
    async () => jsonResponse({ detail: 'revoked' }, 401),
    (value) => invalidations.push(value),
  );
  await assert.rejects(client.request('/v1/projects'), PairingRequiredError);
  assert.equal(store.rejected.has(active.capability), true);
  assert.deepEqual(store.authorities.get(ENDPOINT), active);
  assert.deepEqual(invalidations, [{ endpoint: ENDPOINT, reason: 'unauthorized' }]);
});

test('request failures preserve only bounded structured public guidance', async () => {
  const active = activeAuthority();
  const client = new CodeSecurityClient(
    new FakeProfileCredentialStore([active]),
    () => ENDPOINT,
    async () => jsonResponse({
      detail: {
        code: 'source_outside_allowed_root',
        message: 'The selected folder is outside the authorized source boundary.',
        action: 'authorize_source',
        correlation_id: 'source-boundary-7',
        context: {
          source_target: {
            kind: 'mounted_directory',
            display_path: '/workspace/current/nested',
            private_mount_identity: 'must-not-surface-context',
          },
          authorization_boundary: {
            kind: 'allowed_roots',
            display_paths: ['/workspace/approved'],
            private_host_root: 'must-not-surface-root',
          },
          selected_path: '/workspace/current/nested',
          allowed_roots: ['/workspace/approved'],
          private_debug: active.capability,
        },
        safe_details: {
          selected_source: '/workspace/current/nested',
          configured_source_boundary: '/workspace/approved',
          ignored_secret: 'must-not-surface-safe-details',
        },
      },
    }, 422),
  );
  await assert.rejects(client.request('/v1/scans'), (error) => {
    assert.equal(error.code, 'source_outside_allowed_root');
    assert.equal(error.action, 'authorize_source');
    assert.equal(error.correlationId, 'source-boundary-7');
    assert.deepEqual(error.sourceBoundary, {
      selectedTarget: '/workspace/current/nested',
      authorizedRoots: ['/workspace/approved'],
    });
    const serialized = JSON.stringify(error);
    assert.equal(serialized.includes(active.capability), false);
    assert.equal(serialized.includes('must-not-surface-context'), false);
    assert.equal(serialized.includes('must-not-surface-root'), false);
    assert.equal(serialized.includes('must-not-surface-safe-details'), false);
    return true;
  });
});

test('workspace batch refusal retains all 32 bounded configured source roots', async () => {
  const roots = Array.from({ length: 32 }, (_, index) => `/workspace/root${index}`);
  const client = new CodeSecurityClient(new FakeProfileCredentialStore([activeAuthority()]), () => ENDPOINT,
    async () => jsonResponse({ detail: { code: 'source_outside_allowed_root', message: 'Source outside boundary.',
      action: 'authorize_source', context: { allowed_roots: roots } } }, 422));
  await assert.rejects(client.request('/v1/scans'), (error) => {
    assert.deepEqual(error.sourceBoundary.authorizedRoots, roots);
    return true;
  });
});

test('scanner verification admission preserves typed guidance without retaining cache context', async () => {
  for (const [reason, action, message] of [
    ['verifying', 'wait_for_scanner_verification', 'Scanner cache verification is in progress.'],
    ['timed_out', 'retry_scanner_verification', 'Scanner cache verification timed out.'],
    ['failed', 'retry_scanner_verification', 'Scanner cache verification could not complete.'],
  ]) {
    const client = new CodeSecurityClient(
      new FakeProfileCredentialStore([activeAuthority()]),
      () => ENDPOINT,
      async () => jsonResponse({ detail: {
        code: 'scanner_cache_verification_required',
        message,
        action,
        context: { target: 'active', generation_id: 'a'.repeat(64) },
        safe_details: { reason_code: reason },
        correlation_id: 'scanner-verification-7',
      } }, 409),
    );
    await assert.rejects(client.request('/v1/scans', { method: 'POST' }), (error) => {
      assert(error instanceof CodeSecurityRequestError);
      assert.equal(error.code, 'scanner_cache_verification_required');
      assert.equal(error.action, action);
      assert.equal(error.message, message);
      assert.equal(error.status, 409);
      assert.equal(error.retryable, false, 'readiness is not an automatically replayable transport failure');
      assert.equal(error.correlationId, 'scanner-verification-7');
      assert.equal(error.sourceBoundary, undefined);
      assert.doesNotMatch(JSON.stringify(error), /generation_id|reason_code/);
      return true;
    });
  }
});

test('provider remediation preserves typed guidance without retaining provider context', async () => {
  const active = activeAuthority();
  const client = new CodeSecurityClient(
    new FakeProfileCredentialStore([active]),
    () => ENDPOINT,
    async () => jsonResponse({
      detail: {
        code: 'advisor_provider_not_executable',
        message: 'No tested and currently executable Advisor provider is available.',
        action: 'test_advisor_provider',
        correlation_id: 'req.advisor-409:7',
        context: {
          provider_id: 'private-provider-id',
          destination: 'private-provider.internal:11434',
        },
        safe_details: {
          provider_id: 'private-provider-id',
          reason_code: 'private-provider-reason',
        },
      },
    }, 409),
  );

  await assert.rejects(client.request('/v1/findings/501/triage'), (error) => {
    assert(error instanceof CodeSecurityRequestError);
    assert.equal(error.status, 409);
    assert.equal(error.code, 'advisor_provider_not_executable');
    assert.equal(error.action, 'test_advisor_provider');
    assert.equal(error.correlationId, 'req.advisor-409:7');
    const serialized = JSON.stringify(error);
    assert.equal(serialized.includes('private-provider-id'), false);
    assert.equal(serialized.includes('private-provider.internal'), false);
    assert.equal(serialized.includes('private-provider-reason'), false);
    return true;
  });
});

test('sanitized validation errors show only bounded field and rule text, never raw input or context', async () => {
  const request = (detail) => new CodeSecurityClient(new FakeProfileCredentialStore([activeAuthority()]), () => ENDPOINT,
    async () => jsonResponse({ detail }, 422)).request('/v1/git/push-protection');
  await assert.rejects(request([{ type: 'value_error', loc: ['body', 'root_path'], msg: 'Value error, Use one canonical local repository path.' }]), (error) => {
    assert.equal(error.code, 'request_validation_failed');
    assert.equal(error.message, 'Check the request: body.root_path: Value error, Use one canonical local repository path.');
    assert.equal(error.status, 422); assert.equal(error.retryable, false); return true;
  });
  const entry = { type: 'value_error', loc: ['body'], msg: 'Invalid request.' };
  for (const detail of [[{ ...entry, input: 'private raw source or credential' }], [{ ...entry, ctx: { secret: 'private' } }],
    [{ ...entry, loc: ['body', '/private/source/path'] }], [{ ...entry, msg: 'private\nvalue' }],
    [{ ...entry, msg: 'x'.repeat(241) }], Array.from({ length: 9 }, () => entry)]) {
    await assert.rejects(request(detail), (error) => {
      assert.equal(error.message, 'CodeSecurity request failed with status 422.');
      assert.equal(JSON.stringify(error).includes('private'), false); return true;
    });
  }
});

test('hostile detail, cancellation, and invalid deadlines remain bounded', async (t) => {
  for (const detail of ['private body', { message: 'line one\nline two', code: 'bad code' }]) {
    await t.test(`detail ${JSON.stringify(detail)}`, async () => {
      const client = new CodeSecurityClient(
        new FakeProfileCredentialStore([activeAuthority()]),
        () => ENDPOINT,
        async () => jsonResponse({ detail }, 422),
      );
      await assert.rejects(client.request('/v1/scans'), (error) => {
        assert.equal(error.message, 'CodeSecurity request failed with status 422.');
        return true;
      });
    });
  }

  const store = new FakeProfileCredentialStore([activeAuthority()]);
  let requests = 0;
  const client = new CodeSecurityClient(store, () => ENDPOINT, async () => {
    requests += 1;
    return jsonResponse({});
  });
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(client.request('/v1/projects', { signal: controller.signal }), {
    name: 'AbortError',
  });
  for (const deadlineMs of [0, -1, 1.5, Number.MAX_SAFE_INTEGER]) {
    await assert.rejects(client.request('/v1/projects', undefined, { deadlineMs }), /integers/u);
  }
  assert.equal(requests, 0);
});

test('REST header and JSON-body stalls fail as bounded retryable 408 requests', async (t) => {
  for (const stall of ['headers', 'body']) {
    await t.test(stall, async () => {
      const active = activeAuthority();
      let observedSignal;
      const client = new CodeSecurityClient(
        new FakeProfileCredentialStore([active]),
        () => ENDPOINT,
        async (_url, init) => {
          observedSignal = init.signal;
          if (stall === 'body') {
            return {
              ok: true,
              status: 200,
              json: () => new Promise((_resolve, reject) => init.signal.addEventListener(
                'abort',
                () => reject(new DOMException('body deadline', 'AbortError')),
                { once: true },
              )),
            };
          }
          return new Promise((_resolve, reject) => init.signal.addEventListener(
            'abort',
            () => reject(new DOMException('header deadline', 'AbortError')),
            { once: true },
          ));
        },
        undefined,
        { requestTimeoutMs: 5 },
      );

      await assert.rejects(client.request('/v1/projects'), (error) => (
        error instanceof CodeSecurityRequestError
        && error.status === 408
        && error.retryable === true
        && /timed out/iu.test(error.message)
      ));
      assert.equal(observedSignal.aborted, true);
    });
  }
});

test('one slow admission request can select its own bounded deadline', async () => {
  const active = activeAuthority();
  let observedSignal;
  const client = new CodeSecurityClient(
    new FakeProfileCredentialStore([active]),
    () => ENDPOINT,
    async (_url, init) => {
      observedSignal = init.signal;
      return new Promise((_resolve, reject) => init.signal.addEventListener(
        'abort',
        () => reject(new DOMException('admission deadline', 'AbortError')),
        { once: true },
      ));
    },
    undefined,
    { requestTimeoutMs: 1_000 },
  );

  await assert.rejects(
    client.request('/v1/scans', { method: 'POST' }, { deadlineMs: 5 }),
    (error) => (
      error instanceof CodeSecurityRequestError
      && error.status === 408
      && error.retryable === true
    ),
  );
  assert.equal(observedSignal.aborted, true);
});

test('caller cancellation wins over the internal REST deadline', async () => {
  const active = activeAuthority();
  let markRequestStarted;
  const requestStarted = new Promise((resolve) => { markRequestStarted = resolve; });
  const client = new CodeSecurityClient(
    new FakeProfileCredentialStore([active]),
    () => ENDPOINT,
    async (_url, init) => {
      markRequestStarted();
      return new Promise((_resolve, reject) => init.signal.addEventListener(
        'abort',
        () => reject(new DOMException('caller stopped', 'AbortError')),
        { once: true },
      ));
    },
    undefined,
    { requestTimeoutMs: 50 },
  );
  const controller = new AbortController();
  const request = client.request('/v1/projects', { signal: controller.signal });
  await requestStarted;
  controller.abort();
  await assert.rejects(request, (error) => error.name === 'AbortError');
});

test('sequential page-shaped REST calls receive independent deadlines', async () => {
  const active = activeAuthority();
  const originalDateNow = Date.now;
  const originalSetTimeout = globalThis.setTimeout;
  const originalClearTimeout = globalThis.clearTimeout;
  let fakeNow = 0;
  let timerId = 0;
  const scheduled = [];
  const pendingTimers = new Map();
  const signals = [];
  const responses = [];
  const starts = [];
  Date.now = () => fakeNow;
  globalThis.setTimeout = (callback, delay, ...arguments_) => {
    const id = ++timerId;
    const timer = {
      id,
      delay,
      due: fakeNow + Number(delay),
      run: () => callback(...arguments_),
    };
    scheduled.push(timer);
    pendingTimers.set(id, timer);
    return id;
  };
  globalThis.clearTimeout = (id) => { pendingTimers.delete(id); };
  try {
    const client = new CodeSecurityClient(
      new FakeProfileCredentialStore([active]),
      () => ENDPOINT,
      async (_url, init) => {
        signals.push(init.signal);
        let release;
        const response = new Promise((resolve) => { release = resolve; });
        responses.push(release);
        let markStarted;
        const started = new Promise((resolve) => { markStarted = resolve; });
        starts.push(started);
        markStarted();
        return response;
      },
      undefined,
      { requestTimeoutMs: 80 },
    );

    const first = client.request('/v1/page/1');
    while (starts.length < 1) await Promise.resolve();
    await starts[0];
    assert.deepEqual(scheduled.map(({ delay }) => delay), [80]);
    const firstTimer = scheduled[0];
    fakeNow = 60;
    responses[0](jsonResponse({ page: 1 }));
    assert.deepEqual(await first, { page: 1 });
    assert.equal(pendingTimers.has(firstTimer.id), false);

    const second = client.request('/v1/page/2');
    while (starts.length < 2) await Promise.resolve();
    await starts[1];
    assert.deepEqual(
      scheduled.map(({ delay }) => delay),
      [80, 80],
      'each sequential request receives the full configured policy after fake time advances',
    );
    assert.deepEqual(scheduled.map(({ due }) => due), [80, 140]);
    assert.notEqual(signals[0], signals[1]);
    firstTimer.run();
    assert.equal(
      signals[1].aborted,
      false,
      'a cleared first-request deadline cannot abort the second request',
    );
    responses[1](jsonResponse({ page: 2 }));
    assert.deepEqual(await second, { page: 2 });
    assert.equal(pendingTimers.size, 0);
  } finally {
    Date.now = originalDateNow;
    globalThis.setTimeout = originalSetTimeout;
    globalThis.clearTimeout = originalClearTimeout;
  }
});

test('request headers and loopback endpoint validation fail closed', async () => {
  const active = activeAuthority();
  const calls = [];
  const client = new CodeSecurityClient(
    new FakeProfileCredentialStore([active]),
    () => ENDPOINT,
    async (url, init) => { calls.push({ url: String(url), init }); return jsonResponse({ ok: true }); },
  );
  await assert.rejects(client.request('v1/projects'), /paths must be absolute/u);
  assert.deepEqual(await client.request('/v1/projects', {
    method: 'POST',
    headers: { Authorization: 'Bearer caller-value' },
    body: JSON.stringify({ value: 1 }),
  }), { ok: true });
  const headers = new Headers(calls[0].init.headers);
  assert.equal(headers.get('Authorization'), `Bearer ${active.capability}`);
  assert.equal(headers.get('Content-Type'), 'application/json');

  for (const endpoint of [
    'https://127.0.0.1:8080', 'http://localhost', 'http://127.0.0.1:0',
    'http://127.0.0.1:65536', 'http://0.0.0.0:8080', 'http://127.0.0.1:8080/path',
  ]) assert.throws(() => normalizeEndpoint(endpoint), CodeSecurityRequestError);
  assert.equal(normalizeEndpoint('http://LOCALHOST:8080/'), 'http://localhost:8080');
  assert.equal(normalizeEndpoint('http://[::1]:8080'), 'http://[::1]:8080');
});

test('malformed pair and activation envelopes are never promoted', async (t) => {
  const record = authority();
  for (const candidate of [
    { name: 'malformed capability', pair: { ...enrollmentResponse(record), capability: 'not-kc1' } },
    {
      name: 'expanded scopes',
      pair: { ...enrollmentResponse(record), scopes: [...IDE_CAPABILITY_SCOPES, 'project:delete'] },
    },
    {
      name: 'wrong activation generation',
      pair: enrollmentResponse(record),
      activation: { ...activationResponse(record), generation: 2 },
    },
  ]) {
    await t.test(candidate.name, async () => {
      const store = new FakeProfileCredentialStore();
      const client = new CodeSecurityClient(store, () => ENDPOINT, async (url) => {
        const path = new URL(String(url)).pathname;
        if (path === '/v1/auth/ide/enrollments') return jsonResponse(candidate.pair);
        if (path === '/v1/auth/ide/activate') return jsonResponse(candidate.activation);
        return jsonResponse({ cancelled: true });
      });
      await assert.rejects(client.connectIde('VS Code'), CodeSecurityRequestError);
      assert.equal(store.authorities.size, 0);
    });
  }
});

test('pending activation persists exact 410 expiry but never invents expiry from 401', async () => {
  for (const [status, expected] of [[401, 'unavailable'], [410, 'expired']]) {
    const pending = authority(1, ENDPOINT, `activation-${status}`);
    const store = new FakeProfileCredentialStore();
    store.pending.set(ENDPOINT, pending);
    const paths = [];
    const client = new CodeSecurityClient(store, () => ENDPOINT, async url => {
      const pathname = new URL(url).pathname;
      paths.push(pathname);
      if (pathname === '/v1/auth/ide/enrollments/current/wait') return jsonResponse(approvedEnrollment(pending));
      assert.equal(pathname, '/v1/auth/ide/activate');
      return jsonResponse({ detail: 'No active authority' }, status);
    });
    await assert.rejects(client.request('/v1/projects'), error => error.review?.state === expected);
    assert.deepEqual(paths, ['/v1/auth/ide/enrollments/current/wait', '/v1/auth/ide/activate']);
    assert.equal(await store.rejectionReason(ENDPOINT, pending), expected);
    assert.equal(store.authorities.size, 0);
    const recreated = new CodeSecurityClient(store, () => ENDPOINT, async () => assert.fail('terminal denial must not retry'));
    assert.equal((await recreated.pendingIdeEnrollment()).state, expected);
    await assert.rejects(recreated.request('/v1/projects'), error => error.review?.state === expected);
  }
});
