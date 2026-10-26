const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');
const { runInNewContext } = require('node:vm');

const { fakeApi } = require('../suite/support/fake-api.js');

const semanticFixture = Object.freeze({
  findings: [
    {
      repository: 'primary',
      number: 1,
      file_path: 'generated.ts',
      scanner: 'semgrep',
      severity: 'high',
      start_line: 1,
      start_column: 8,
      end_line: 1,
      end_column: 13,
      message: 'Primary fixture finding',
      lifecycle_status: 'open',
    },
    {
      repository: 'primary',
      number: 4,
      file_path: 'generated.ts',
      scanner: 'semgrep',
      severity: 'critical',
      start_line: 1,
      start_column: 1,
      end_line: 1,
      end_column: 7,
      message: 'Secondary primary fixture finding',
      lifecycle_status: 'open',
    },
    {
      repository: 'secondary',
      number: 8,
      file_path: 'secondary.ts',
      scanner: 'semgrep',
      severity: 'low',
      start_line: 1,
      start_column: 1,
      end_line: 1,
      end_column: 7,
      message: 'Secondary repository fixture finding',
      lifecycle_status: 'open',
    },
  ],
  large_set: {
    count: 0,
    first_number: 100,
    file_path: 'large.ts',
    message_prefix: 'Large fixture finding',
    scanner: 'semgrep',
    severity: 'low',
  },
});

async function postScan(
  origin,
  idempotencyKey,
  projectId = 17,
  targetPath = undefined,
  targetKind = 'file',
  snapshotDigest = undefined,
) {
  const response = await fetch(`${origin}/v1/scans`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Idempotency-Key': idempotencyKey,
    },
    body: JSON.stringify({
      project_id: projectId,
      mode: 'full',
      use_ai: false,
      ...(targetPath === undefined ? {} : { target_path: targetPath }),
      ...(targetPath === undefined ? {} : { target_kind: targetKind }),
      ...(snapshotDigest === undefined ? {} : { source_snapshot_digest: snapshotDigest }),
    }),
  });
  return Object.freeze({ response, body: await response.json() });
}

test('fake event stream matches production keepalive cadence and releases each response timer', { timeout: 10000 }, async (t) => {
  for (const ending of ['client disconnect', 'fixture close', 'capability revoked']) {
    await t.test(ending, async (t) => {
      t.mock.timers.enable({ apis: ['setInterval'] });
      const schedule = global.setInterval;
      const clear = global.clearInterval;
      let timer;
      let heartbeatCalls = 0;
      let resolveCleared;
      const cleared = new Promise((resolve) => { resolveCleared = resolve; });
      t.mock.method(global, 'setInterval', (callback, milliseconds) => {
        assert.equal(milliseconds, 15_000);
        assert.equal(timer, undefined, 'one exact response owns one heartbeat timer');
        timer = schedule(() => { heartbeatCalls += 1; callback(); }, milliseconds);
        return timer;
      });
      t.mock.method(global, 'clearInterval', (value) => {
        assert.equal(value, timer, 'response teardown clears its own heartbeat timer');
        clear(value);
        resolveCleared();
      });
      const fixture = await fakeApi({
        primaryRepoPath: '/fixture/primary', secondaryRepoPath: '/fixture/secondary', semanticFixture,
      });
      let closed = false;
      try {
        const response = await fetch(`${fixture.origin}/v1/events`, {
          headers: { Accept: 'text/event-stream', 'Last-Event-ID': '0' },
        });
        assert.equal(response.status, 200);
        const reader = response.body.getReader();
        const ready = await reader.read();
        assert.equal(new TextDecoder().decode(ready.value),
          'event: stream.ready\ndata: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n');
        t.mock.timers.tick(14_999);
        assert.equal(heartbeatCalls, 0);
        t.mock.timers.tick(1);
        assert.equal(new TextDecoder().decode((await reader.read()).value), ': keepalive\n\n');
        t.mock.timers.tick(15_000);
        assert.equal(new TextDecoder().decode((await reader.read()).value), ': keepalive\n\n');
        assert.equal(heartbeatCalls, 2);
        if (ending === 'client disconnect') await reader.cancel();
        else if (ending === 'fixture close') {
          await fixture.close();
          closed = true;
        } else {
          fixture.revokeCapability();
          t.mock.timers.tick(15_000);
          assert.deepEqual(await reader.read(), { value: undefined, done: true },
            'revocation ends the stream instead of sending another keepalive');
        }
        await cleared;
        const callsAtClose = heartbeatCalls;
        t.mock.timers.tick(45_000);
        assert.equal(heartbeatCalls, callsAtClose, 'closed response cannot retain background heartbeats');
        assert.equal(fixture.requests.filter(({ pathname }) => pathname === '/v1/events').length, 1);
      } finally {
        if (!closed) await fixture.close();
      }
    });
  }
});

test('fake IDE enrollment preserves the exact submitted client name for foreground review', async () => {
  const fixture = await fakeApi({
    primaryRepoPath: '/fixture/primary',
    secondaryRepoPath: '/fixture/secondary',
    semanticFixture,
  });
  try {
    const clientName = 'Visual Studio Code · fixture · local';
    const response = await fetch(`${fixture.origin}/v1/auth/ide/enrollments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: clientName,
        client_slot: `ks1_${'A'.repeat(43)}`,
        expected_active_generation: 0,
      }),
    });
    assert.equal(response.status, 201);
    const pending = fixture.currentIdeEnrollment();
    assert.equal(pending.client_name, clientName);
    assert.equal(pending.state, 'awaiting_approval');
    assert(Object.isFrozen(pending));
    fixture.approveIdeEnrollment(pending.request_id, pending.verification_code);
    const approved = fixture.currentIdeEnrollment();
    assert.equal(approved.client_name, clientName);
    assert.equal(approved.state, 'approved');
  } finally {
    await fixture.close();
  }
});

test('fake browser invitation requires exact consumption and preserves purpose without credential witnesses', { timeout: 15000 }, async () => {
  let observedMembershipRequest;
  const membershipRequested = new Promise((resolve) => { observedMembershipRequest = resolve; });
  const fixture = await fakeApi({
    primaryRepoPath: '/fixture/primary', secondaryRepoPath: '/fixture/secondary', semanticFixture,
    onRequest(request) {
      if (request.pathname.endsWith('/membership')) observedMembershipRequest();
    },
  });
  const post = async (path, body, headers = {}) => {
    const response = await fetch(`${fixture.origin}${path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body),
    });
    return { response, payload: await response.json() };
  };
  try {
    const enrolled = await post('/v1/auth/ide/enrollments', {
      client_name: 'Synthetic browser fixture', client_slot: `ks1_${'A'.repeat(43)}`, expected_active_generation: 0,
    });
    assert.equal(enrolled.response.status, 201);
    const authority = { Authorization: `Bearer ${enrolled.payload.capability}` };
    fixture.approveIdeEnrollment(enrolled.payload.request_id, enrolled.payload.verification_code);
    assert.equal((await post('/v1/auth/ide/activate', {}, authority)).response.status, 200);
    const issue = async (purpose) => {
      const result = await post('/v1/auth/ide/browser-invitations', { purpose }, authority);
      assert.equal(result.response.status, 201);
      assert.equal(result.payload.purpose, purpose);
      return result.payload;
    };
    const integrated = await issue('integrated_dashboard');
    const pending = fixture.currentBrowserMemberships();
    assert.deepEqual(pending, [{ invitation_id: integrated.invitation_id, purpose: 'integrated_dashboard',
      status: 'pending', expires_at: integrated.expires_at }]);
    assert(Object.isFrozen(pending) && Object.isFrozen(pending[0]));
    let membershipSettled = false;
    const membershipResponse = fetch(
      `${fixture.origin}/v1/auth/ide/browser-invitations/${integrated.invitation_id}/membership`,
      { headers: authority },
    ).then(async (response) => {
      membershipSettled = true;
      assert.equal(response.status, 200);
      return response.json();
    });
    await membershipRequested;
    assert.equal(membershipSettled, false, 'opening the membership wait must not pair a browser');
    for (const [token, status] of [
      [integrated.bootstrap_token.replace(integrated.invitation_id, 'z'.repeat(24)), 409],
      [integrated.bootstrap_token.slice(0, -1) + 'd', 401],
    ]) {
      assert.equal((await post('/v1/auth/bootstrap', { bootstrap_token: token })).response.status, status);
    }
    assert.deepEqual(fixture.currentBrowserMemberships(), pending);
    const missing = await fetch(`${fixture.origin}/v1/auth/ide/browser-invitations/${'z'.repeat(24)}/membership`,
      { headers: authority });
    assert.deepEqual(await missing.json(), { invitation_id: 'z'.repeat(24), status: 'missing_or_revoked' });
    assert.equal((await fetch(`${fixture.origin}/v1/auth/ide/browser-invitations/${integrated.invitation_id}/membership`)).status, 401);

    const page = await fetch(`${fixture.origin}/?lomo_browser=vscode`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type'), /^text\/html/u);
    const script = (await page.text()).match(/<script>([\s\S]+)<\/script>/u)[1];
    // Execute the served page's actual script with a minimal browser surface;
    // HTTP still crosses the public routes. This is not foreground UI proof.
    const runPage = async (token, retainedCookie, routeHash = '') => {
      const location = new URL(`${fixture.origin}/?lomo_browser=vscode${token ? `#bootstrap=${token}` : routeHash}`);
      const status = { textContent: '' };
      let cookie = retainedCookie;
      await runInNewContext(script, {
        location, URLSearchParams,
        history: { replaceState(_state, _unused, path) {
          assert.equal(path, '/?lomo_browser=vscode');
          location.href = new URL(path, fixture.origin).href;
        } },
        document: { getElementById(id) { assert.equal(id, 'status'); return status; } },
        fetch: async (path, options) => {
          assert.equal(location.hash, token ? '' : routeHash,
            'remove only the invitation fragment before the exchange, preserving ordinary routes');
          const response = await fetch(`${fixture.origin}${path}`, {
            ...options, headers: { ...options?.headers, ...(cookie ? { Cookie: cookie } : {}) },
          });
          const returnedCookie = response.headers.get('set-cookie');
          if (returnedCookie) {
            assert.match(returnedCookie, /; Path=\/; HttpOnly; SameSite=Strict$/u);
            cookie = returnedCookie.split(';')[0];
          }
          return response;
        },
      });
      return { cookie, message: status.textContent, hash: location.hash };
    };
    assert.equal((await runPage()).message, 'Browser is not paired.');
    assert.equal(fixture.requests.at(-1).responseAuthenticated, false);
    const beforePairing = fixture.requests.length;
    const paired = await runPage(integrated.bootstrap_token);
    assert.equal(paired.message, 'Browser paired. Synthetic fixture only.');
    assert.deepEqual(fixture.requests.slice(beforePairing).map(({ method, pathname, responseAuthenticated }) => (
      { method, pathname, responseAuthenticated }
    )), [
      { method: 'POST', pathname: '/v1/auth/bootstrap', responseAuthenticated: undefined },
      { method: 'GET', pathname: '/v1/auth/session', responseAuthenticated: true },
    ], 'the page must prove its browser cookie was accepted before rendering paired');
    const active = await membershipResponse;
    assert.deepEqual(active, fixture.currentBrowserMemberships()[0]);
    assert.equal(active.status, 'active');
    assert.match(active.member_id, /^kbm1_[A-Za-z0-9_-]{32}$/u);
    assert.equal(active.purpose, 'integrated_dashboard');
    assert.equal((await runPage(integrated.bootstrap_token, paired.cookie)).message, 'Browser is not paired.');
    assert.deepEqual(fixture.currentBrowserMemberships(), [active], 'replay must not create another member');
    assert.equal((await runPage(undefined, paired.cookie)).message, paired.message, 'reload reuses the exact session');
    const sourceBoundary = await runPage(undefined, paired.cookie, '#source-boundary');
    assert.equal(sourceBoundary.message, paired.message);
    assert.equal(sourceBoundary.hash, '#source-boundary', 'settings navigation must retain its exact fragment');

    const extra = await issue('extra_browser');
    assert.notEqual(extra.invitation_id, integrated.invitation_id);
    const alreadyPaired = await post('/v1/auth/bootstrap', { bootstrap_token: extra.bootstrap_token }, { Cookie: paired.cookie });
    assert.equal(alreadyPaired.response.status, 409);
    assert.equal(alreadyPaired.payload.detail.code, 'browser_already_paired');
    assert.equal(fixture.currentBrowserMemberships()[1].status, 'pending');
    assert.equal((await runPage(extra.bootstrap_token)).message, paired.message);
    const memberships = fixture.currentBrowserMemberships();
    assert.deepEqual(memberships[0], active);
    assert.equal(memberships[1].purpose, 'extra_browser');
    assert.equal(memberships[1].status, 'active');
    assert.notEqual(memberships[1].member_id, active.member_id);
    assert.equal((await post('/v1/auth/bootstrap', { bootstrap_token: extra.bootstrap_token })).response.status, 409);
    assert.deepEqual(fixture.currentBrowserMemberships(), memberships);
    const bootstraps = fixture.requests.filter(({ pathname }) => pathname === '/v1/auth/bootstrap');
    assert(bootstraps.length > 0 && bootstraps.every(({ body }) => body === undefined));
    const witnesses = JSON.stringify(fixture.requests);
    for (const credential of [integrated.bootstrap_token, extra.bootstrap_token, paired.cookie, 'fixture-browser-csrf']) {
      assert(!witnesses.includes(credential), 'request witnesses must not expose browser credentials');
    }
  } finally {
    await fixture.close();
  }
});

test('native snapshot route witnesses exact workspace folder and file admission without qualification claims', async () => {
  const { sourceTargetForUri, sourceTargetForFileUri } = require('../../dist/source.js');
  const { collectNativeWindowsSourceSnapshot, admittedNativeWindowsSourceSnapshot } = require('../../dist/snapshot.js');
  const uri = (fsPath) => {
    const uriPath = `/${fsPath.replaceAll('\\', '/')}`;
    return { scheme: 'file', authority: '', path: uriPath, fsPath, toString: () => `file://${uriPath}` };
  };
  const root = { name: 'native-fixture', uri: uri(String.raw`C:\qa\native-fixture`) };
  const workspace = sourceTargetForUri(root.uri, [root], 'win32');
  const directory = sourceTargetForUri(uri(String.raw`C:\qa\native-fixture\infra`), [root], 'win32');
  const file = sourceTargetForFileUri(uri(String.raw`C:\qa\native-fixture\infra\main.tf`), [root], 'win32');
  const entries = [
    ['generated.ts', 'export const generatedFixture = true;\n'],
    ['infra/main.tf', '# synthetic selected terraform source\n'],
    ['infra/sibling.tf', '# synthetic neighboring terraform source\n'],
  ].map(([path, text]) => ({ path, content_base64: Buffer.from(text).toString('base64'),
    sha256: createHash('sha256').update(text).digest('hex'), size_bytes: Buffer.byteLength(text) }));
  const fixture = await fakeApi({
    primaryRepoPath: workspace.repoPath, secondaryRepoPath: '/fixture/secondary',
    nativeSnapshotSource: { source_id: workspace.sourceId,
      files: entries.map(({ content_base64, ...metadata }) => metadata) },
    semanticFixture: { ...semanticFixture, findings: [...semanticFixture.findings,
      { ...semanticFixture.findings[0], number: 5, file_path: 'infra/main.tf' },
      { ...semanticFixture.findings[0], number: 6, file_path: 'infra/sibling.tf' },
    ] },
  });
  const key = (number) => `vscode-00000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
  const read = async (route) => {
    const response = await fetch(`${fixture.origin}${route}`);
    assert.equal(response.status, 200);
    return response.json();
  };
  const admit = async (upload) => {
    const response = await fetch(`${fixture.origin}/v1/source-snapshots`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(upload),
    });
    return { status: response.status, payload: await response.json() };
  };
  try {
    const siblingBefore = await read('/v1/projects/18/scans/latest');
    const previous = [];
    const admitted = [];
    for (const [index, target] of [workspace, directory, file].entries()) {
      const selected = entries.filter(({ path }) => target.kind === 'workspace'
        || target.kind === 'directory' && path.startsWith(`${target.targetPath}/`)
        || target.kind === 'file' && path === target.targetPath);
      const upload = await collectNativeWindowsSourceSnapshot(target, undefined,
        async () => ({ directory_scope: target.kind === 'directory' ? target.targetPath : null, files: selected }));
      const receipt = await admit(upload);
      assert.equal(receipt.status, 201);
      const admission = admittedNativeWindowsSourceSnapshot(receipt.payload, target, upload);
      const expectedManifest = { directory_scope: upload.directory_scope, file_count: selected.length,
        files: selected.map(({ path, sha256, size_bytes }) => ({ path, sha256, size_bytes })),
        schema: 'lomo-source-snapshot/v1', source_id: workspace.sourceId,
        total_bytes: selected.reduce((total, item) => total + item.size_bytes, 0) };
      assert.equal(admission.snapshotDigest, createHash('sha256').update(JSON.stringify(expectedManifest)).digest('hex'));
      const scan = await postScan(fixture.origin, key(index + 1), admission.project.id,
        target.targetPath, target.kind === 'workspace' ? undefined : target.kind, admission.snapshotDigest);
      assert.equal(scan.response.status, 202);
      const terminal = await read(`/v1/scans/${scan.body.id}`);
      const job = await read(`/v1/jobs/${scan.body.job_id}`);
      const manifest = await read(`/v1/scans/${scan.body.id}/finding-files`);
      assert.equal(terminal.status, 'completed');
      assert.equal(job.scan_id, terminal.id);
      assert.equal(job.status, 'completed');
      assert.deepEqual(manifest.items.map(({ file_path }) => file_path).sort(), selected.map(({ path }) => path));
      assert.equal(Object.hasOwn(terminal, 'source_snapshot_digest'), false,
        'do not invent a public ScanOut field for the admission witness');
      const witness = fixture.requests.find(({ responseScanId }) => responseScanId === terminal.id);
      assert.deepEqual(witness.sourceSnapshotAdmission, receipt.payload);
      for (const [oldScan, oldManifest] of previous) {
        assert.deepEqual(await read(`/v1/scans/${oldScan.id}/finding-files`), oldManifest,
          'later scopes must preserve earlier exact scan findings');
      }
      previous.push([terminal, manifest]);
      admitted.push({ upload, receipt: receipt.payload, target, scan: scan.body });
    }
    assert.equal(new Set(admitted.map(({ receipt }) => receipt.snapshot_digest)).size, 3);
    assert.equal(new Set(admitted.map(({ scan }) => scan.id)).size, 3);
    assert.equal(new Set(admitted.map(({ scan }) => scan.job_id)).size, 3);
    assert.deepEqual(await read('/v1/projects/18/scans/latest'), siblingBefore);
    const replay = await postScan(fixture.origin, key(1), 17, undefined, undefined, admitted[0].receipt.snapshot_digest);
    assert.deepEqual(replay.body, admitted[0].scan);
    const mismatches = [
      [undefined, undefined, undefined],
      [undefined, undefined, 'f'.repeat(64)],
      ['infra', 'directory', admitted[0].receipt.snapshot_digest],
      ['generated.ts', 'file', admitted[2].receipt.snapshot_digest],
      [undefined, undefined, admitted[2].receipt.snapshot_digest],
    ];
    for (const [index, args] of mismatches.entries()) {
      assert.equal((await postScan(fixture.origin, key(20 + index), 17, ...args)).response.status, 422);
    }
    assert.equal((await postScan(fixture.origin, key(30), 18, undefined, undefined,
      admitted[0].receipt.snapshot_digest)).response.status, 422);
    assert.equal((await postScan(fixture.origin, key(1), 17, 'infra', 'directory',
      admitted[1].receipt.snapshot_digest)).response.status, 409);
    for (const mutate of [
      (upload) => { upload.source_id = 'f'.repeat(64); },
      (upload) => { upload.files[0].content_base64 = Buffer.from('altered').toString('base64'); },
      (upload) => { upload.files[0].path = '../outside.ts'; },
      (upload) => { upload.files.reverse(); },
      (upload) => { upload.directory_scope = 'infra'; },
    ]) {
      const altered = structuredClone(admitted[0].upload);
      mutate(altered);
      assert.equal((await admit(altered)).status, 422);
    }
    assert.equal((await read('/v1/projects/17/scans/latest')).id, admitted[2].scan.id,
      'rejected requests must not create another scan');
    const snapshotRequests = fixture.requests.filter(({ pathname }) => pathname === '/v1/source-snapshots');
    assert(snapshotRequests.every(({ body }) => body === undefined));
    assert(!JSON.stringify(snapshotRequests).includes('content_base64'));
    assert(!JSON.stringify(snapshotRequests).includes('synthetic selected terraform'));
  } finally {
    await fixture.close();
  }
});

async function getFindings(origin, scanId, findingsRevision) {
  const response = await fetch(
    `${origin}/v1/scans/${scanId}/findings?expected_revision=${findingsRevision}`
      + '&file_path=generated.ts&limit=200',
  );
  assert.equal(response.status, 200);
  return (await response.json()).items;
}

async function patchLifecycle(origin, findingId, expectedRevision) {
  const response = await fetch(`${origin}/v1/findings/${findingId}/lifecycle`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'gate_exempt',
      expected_revision: expectedRevision,
      reason: 'Per-scan snapshot test',
    }),
  });
  assert.equal(response.status, 200);
  return response.json();
}

async function deleteFinding(origin, findingId, expectedRevision) {
  const response = await fetch(
    `${origin}/v1/findings/${findingId}?expected_revision=${expectedRevision}`,
    { method: 'DELETE' },
  );
  assert.equal(response.status, 200);
  return response.json();
}

test('fake scans replay exact commands and isolate fresh finding snapshots by global identity', async () => {
  const observedRequests = [];
  const fixture = await fakeApi({
    primaryRepoPath: '/fixture/primary',
    secondaryRepoPath: '/fixture/secondary',
    semanticFixture,
    onRequest(request) {
      observedRequests.push(JSON.parse(JSON.stringify(request)));
    },
  });
  const firstKey = 'vscode-00000000-0000-4000-8000-000000000001';
  const secondKey = 'vscode-00000000-0000-4000-8000-000000000002';
  try {
    const first = await postScan(fixture.origin, firstKey);
    assert.equal(first.response.status, 202);
    assert.equal(first.body.id, 73);
    assert.equal(first.body.job_id, 91);
    const firstFindings = await getFindings(fixture.origin, first.body.id, 2);
    const firstFindingOne = firstFindings.find(({ scan_finding_number: number }) => number === 1);
    assert(firstFindingOne);
    assert.equal(firstFindingOne.revision, 1);

    const lifecycle = await patchLifecycle(fixture.origin, firstFindingOne.id, 1);
    assert.equal(lifecycle.id, firstFindingOne.id);
    assert.equal(lifecycle.revision, 2);
    assert.equal(lifecycle.findings_revision, 3);

    const replay = await postScan(fixture.origin, firstKey);
    assert.equal(replay.response.status, 202);
    assert.deepEqual(replay.body, first.body);

    const second = await postScan(fixture.origin, secondKey);
    assert.equal(second.response.status, 202);
    assert.equal(second.body.id, 74);
    assert.equal(second.body.job_id, 92);
    const secondFindings = await getFindings(fixture.origin, second.body.id, 2);
    const secondFindingOne = secondFindings.find(({ scan_finding_number: number }) => number === 1);
    assert(secondFindingOne);
    assert.equal(secondFindingOne.revision, 1);
    assert.equal(secondFindingOne.lifecycle_status, 'open');
    assert.equal(new Set([
      ...firstFindings.map(({ id }) => id),
      ...secondFindings.map(({ id }) => id),
    ]).size, firstFindings.length + secondFindings.length);

    const deletion = await deleteFinding(fixture.origin, secondFindingOne.id, 1);
    assert.equal(deletion.finding_id, secondFindingOne.id);
    assert.equal(deletion.scan_id, second.body.id);
    const secondAfterDelete = await getFindings(fixture.origin, second.body.id, 3);
    assert.equal(secondAfterDelete.some(({ id }) => id === secondFindingOne.id), false);

    const thirdKey = 'vscode-00000000-0000-4000-8000-000000000003';
    const third = await postScan(fixture.origin, thirdKey);
    assert.equal(third.response.status, 202);
    assert.equal(third.body.id, 75);
    assert.equal(third.body.job_id, 93);
    const thirdFindings = await getFindings(fixture.origin, third.body.id, 2);
    const thirdFindingOne = thirdFindings.find(({ scan_finding_number: number }) => number === 1);
    assert(thirdFindingOne);
    assert.equal(thirdFindingOne.lifecycle_status, 'open');
    assert.equal(thirdFindingOne.revision, 1);
    assert.notEqual(thirdFindingOne.id, firstFindingOne.id);
    assert.notEqual(thirdFindingOne.id, secondFindingOne.id);

    const firstAfterLaterMutations = await getFindings(fixture.origin, first.body.id, 3);
    const retainedFirst = firstAfterLaterMutations.find(({ scan_finding_number: number }) => number === 1);
    assert.equal(retainedFirst.id, firstFindingOne.id);
    assert.equal(retainedFirst.lifecycle_status, 'gate_exempt');
    assert.equal(retainedFirst.revision, 2);

    const latestResponse = await fetch(`${fixture.origin}/v1/projects/17/scans/latest`);
    assert.equal(latestResponse.status, 200);
    assert.equal((await latestResponse.json()).id, third.body.id);

    const manifestResponse = await fetch(`${fixture.origin}/v1/scans/${third.body.id}/finding-files`);
    assert.equal(manifestResponse.status, 200);
    const manifest = await manifestResponse.json();
    assert.equal(manifest.scan.id, third.body.id);
    assert.equal(manifest.total_findings, 2);
    assert.equal(manifest.items[0].first_scan_finding_number, 1);

    const conflictingReplay = await postScan(fixture.origin, firstKey, 18);
    assert.equal(conflictingReplay.response.status, 409);
    assert.match(conflictingReplay.body.detail, /different scan command/u);

    const scanRequests = fixture.requests.filter(({ method, pathname }) => (
      method === 'POST' && pathname === '/v1/scans'
    ));
    assert.deepEqual(
      scanRequests.map(({ idempotentReplay, responseScanId, responseJobId }) => ({
        idempotentReplay,
        responseScanId,
        responseJobId,
      })),
      [
        { idempotentReplay: false, responseScanId: 73, responseJobId: 91 },
        { idempotentReplay: true, responseScanId: 73, responseJobId: 91 },
        { idempotentReplay: false, responseScanId: 74, responseJobId: 92 },
        { idempotentReplay: false, responseScanId: 75, responseJobId: 93 },
        { idempotentReplay: undefined, responseScanId: undefined, responseJobId: undefined },
      ],
    );
    const observedManifest = observedRequests.find(({ pathname }) => (
      pathname === `/v1/scans/${third.body.id}/finding-files`
    ));
    assert.deepEqual(observedManifest.responseScan, {
      file_paths: ['generated.ts'],
      findings_revision: 2,
      gate_decision: 'fail',
      id: third.body.id,
      revision: 4,
      total_files: 1,
      total_findings: 2,
    });
    const observedThirdFindings = observedRequests.find(({ pathname, search }) => (
      pathname === `/v1/scans/${third.body.id}/findings`
      && search.includes('expected_revision=2')
    ));
    assert.deepEqual(
      observedThirdFindings.responseFindings,
      thirdFindings.map(({ id, revision, scan_finding_number: scanFindingNumber }) => ({
        id,
        revision,
        scan_finding_number: scanFindingNumber,
      })),
      'request observers must receive completed response identity metadata for the Remote WSL ledger',
    );
  } finally {
    await fixture.close();
  }
});

test('fake API exact-file scan preserves its source scan and exposes one target-path manifest', async () => {
  const fixture = await fakeApi({
    primaryRepoPath: '/fixture/primary',
    secondaryRepoPath: '/fixture/secondary',
    semanticFixture,
  });
  try {
    const sourceBeforeResponse = await fetch(`${fixture.origin}/v1/scans/71/finding-files`);
    assert.equal(sourceBeforeResponse.status, 200);
    const sourceBefore = await sourceBeforeResponse.json();

    const exact = await postScan(
      fixture.origin,
      'vscode-00000000-0000-4000-8000-000000000090',
      17,
      'generated.ts',
    );
    assert.equal(exact.response.status, 202);
    const exactManifestResponse = await fetch(
      `${fixture.origin}/v1/scans/${exact.body.id}/finding-files`,
    );
    assert.equal(exactManifestResponse.status, 200);
    const exactManifest = await exactManifestResponse.json();
    assert.equal(exactManifest.total_files, 1);
    assert.equal(exactManifest.total_findings, 2);
    assert.deepEqual(
      exactManifest.items.map(({ file_path: filePath, total }) => ({ filePath, total })),
      [{ filePath: 'generated.ts', total: 2 }],
    );

    const sourceAfterResponse = await fetch(`${fixture.origin}/v1/scans/71/finding-files`);
    assert.equal(sourceAfterResponse.status, 200);
    assert.deepEqual(await sourceAfterResponse.json(), sourceBefore);

    const command = fixture.requests.find(({ method, pathname, responseScanId }) => (
      method === 'POST' && pathname === '/v1/scans' && responseScanId === exact.body.id
    ));
    assert.deepEqual(command.body, {
      mode: 'full',
      project_id: 17,
      target_path: 'generated.ts',
      target_kind: 'file',
      use_ai: false,
    });
    assert.deepEqual(command.sourceScanAfter, command.sourceScanBefore);
    assert.equal(command.sourceScanBefore.id, 71);
    assert.deepEqual(command.registeredSourceBoundaryBefore, {
      project_id: 17,
      repo_path: '/fixture/primary',
    });
    assert.deepEqual(
      command.registeredSourceBoundaryAfter,
      command.registeredSourceBoundaryBefore,
    );
  } finally {
    await fixture.close();
  }
});

test('fake API can expose one bounded rich-limit manifest without materializing excess findings', async () => {
  const fixture = await fakeApi({
    primaryRepoPath: '/fixture/primary',
    secondaryRepoPath: '/fixture/secondary',
    semanticFixture: {
      ...semanticFixture,
      large_set: { ...semanticFixture.large_set, count: 2 },
    },
  });
  try {
    const control = fixture.enableRichLimitManifest();
    assert.deepEqual(control, {
      actual_findings: 2,
      file_path: 'large.ts',
      findings_revision: 10,
      rich_findings: 5_001,
      scan_id: 71,
      total_findings: 5_003,
    });
    const response = await fetch(`${fixture.origin}/v1/scans/71/finding-files`);
    assert.equal(response.status, 200);
    const manifest = await response.json();
    assert.equal(manifest.total_findings, 5_003);
    assert.equal(manifest.scan.findings_revision, 10);
    const rich = manifest.items.find(({ file_path: filePath }) => filePath === 'large.ts');
    assert.equal(rich.total, 5_001);
    assert.equal(rich.active, 5_001);
    assert.equal(rich.blocking, 5_001);
    assert.equal(rich.severity_counts.low, 5_001);
    assert.equal(rich.lifecycle_counts.open, 5_001);
  } finally {
    await fixture.close();
  }
});

test('fake API qualification fixture keeps a nested Explorer folder under its owner project', async () => {
  const fixture = await fakeApi({
    primaryRepoPath: '/fixture/primary',
    secondaryRepoPath: '/fixture/secondary',
    semanticFixture: {
      ...semanticFixture,
      findings: [
        ...semanticFixture.findings,
        {
          repository: 'primary',
          number: 2,
          file_path: 'src/other.ts',
          scanner: 'semgrep',
          severity: 'medium',
          start_line: 1,
          start_column: 1,
          end_line: 1,
          end_column: 7,
          message: 'Nested folder fixture finding',
          lifecycle_status: 'open',
        },
      ],
    },
  });
  try {
    const resolution = await fetch(`${fixture.origin}/v1/projects/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo_path: '/fixture/primary' }),
    });
    assert.equal(resolution.status, 200);
    assert.deepEqual(await resolution.json(), {
      id: 17,
      name: 'fixture',
      repo_path: '/fixture/primary',
      revision: 2,
    });

    const scan = await postScan(
      fixture.origin,
      'vscode-00000000-0000-4000-8000-000000000019',
      17,
      'src',
      'directory',
    );
    assert.equal(scan.response.status, 202);
    const manifestResponse = await fetch(`${fixture.origin}/v1/scans/${scan.body.id}/finding-files`);
    assert.equal(manifestResponse.status, 200);
    const manifest = await manifestResponse.json();
    assert.equal(manifest.total_findings, 1);
    assert.deepEqual(manifest.items.map(({ file_path: filePath, total }) => ({ filePath, total })), [
      { filePath: 'src/other.ts', total: 1 },
    ]);
  } finally {
    await fixture.close();
  }
});

test('UI fake API exposes credential-free exact health and authenticated source previews without project mutation', async () => {
  const { CodeSecurityClient } = require('../../dist/client.js');
  const { admittedSourceSnapshotLimits, SOURCE_SNAPSHOT_LIMITS } = require('../../dist/snapshot.js');
  const { validateMountedSourcePreview } = require('../../dist/source.js');
  const fixture = await fakeApi({ primaryRepoPath: '/fixture/primary', secondaryRepoPath: '/fixture/secondary', semanticFixture });
  const post = async (path, body, headers = {}) => {
    const response = await fetch(`${fixture.origin}${path}`, { method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
    return { response, payload: await response.json() };
  };
  try {
    const noCredentials = new Proxy({}, { get() { throw new Error('public health must not read credentials'); } });
    const client = new CodeSecurityClient(noCredentials, () => fixture.origin);
    assert.deepEqual(admittedSourceSnapshotLimits((await client.publicHealth()).source_snapshot_limits), SOURCE_SNAPSHOT_LIMITS);
    assert.equal((await post('/v1/sources/preview', { repo_path: '/fixture/primary' })).response.status, 401);
    const enrolled = await post('/v1/auth/ide/enrollments', { client_name: 'Synthetic preview fixture',
      client_slot: `ks1_${'A'.repeat(43)}`, expected_active_generation: 0 });
    fixture.approveIdeEnrollment(enrolled.payload.request_id, enrolled.payload.verification_code);
    const headers = { Authorization: `Bearer ${enrolled.payload.capability}` };
    assert.equal((await post('/v1/auth/ide/activate', {}, headers)).response.status, 200);
    for (const [root, authorized] of [['/fixture/primary', true], ['/fixture/secondary/nested', true], ['/fixture', false], ['/fixture/primary-other', false]]) {
      const preview = await post('/v1/sources/preview', { repo_path: root }, headers);
      assert.equal(preview.response.status, 200);
      assert.deepEqual(validateMountedSourcePreview(preview.payload, root), {
        installation_id: '012345abcdef', repo_path: root, authorization_mode: 'mounted', authorized,
        configured_roots: ['/fixture/primary', '/fixture/secondary'], reason_code: authorized ? null : 'source_outside_allowed_root',
      });
    }
    fixture.revokeCapability();
    assert.equal((await client.publicHealth()).ok, true, 'public health remains readable after authority revocation');
    assert.equal((await post('/v1/sources/preview', { repo_path: '/fixture/primary' }, headers)).response.status, 401);
    assert.equal(fixture.requests.filter(({ method, pathname }) => method === 'POST'
      && ['/v1/projects', '/v1/projects/resolve', '/v1/scans', '/v1/source-snapshots'].includes(pathname)).length, 0);
  } finally { await fixture.close(); }
});

test('native UI fixture admits exact large asset transport and rejects oversized fixture bounds', async () => {
  const sourceId = 'd'.repeat(64);
  const content = Buffer.alloc(1_997_816, 23);
  const file = { path: 'docs/image.png', size_bytes: content.length,
    sha256: createHash('sha256').update(content).digest('hex') };
  const options = { primaryRepoPath: `/source-snapshots/native-windows/${sourceId}`,
    secondaryRepoPath: '/fixture/secondary', semanticFixture, nativeSnapshotSource: { source_id: sourceId, files: [file] } };
  const fixture = await fakeApi(options);
  try {
    const response = await fetch(`${fixture.origin}/v1/source-snapshots`, { method: 'POST',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ source_id: sourceId,
        name: 'native-large', directory_scope: null, files: [{ ...file, content_base64: content.toString('base64') }] }) });
    assert.equal(response.status, 201);
    const receipt = await response.json();
    assert.equal(receipt.total_bytes, content.length);
    const witness = fixture.requests.at(-1).responseSnapshot;
    assert.deepEqual(witness.files, [file]);
    assert.equal(Object.hasOwn(witness.files[0], 'content_base64'), false);
  } finally { await fixture.close(); }
  await assert.rejects(fakeApi({ ...options, nativeSnapshotSource: { source_id: sourceId,
    files: [{ ...file, size_bytes: 8_388_609 }] } }));
  await assert.rejects(fakeApi({ ...options, nativeSnapshotSource: { source_id: sourceId,
    files: Array.from({ length: 9 }, (_, i) => ({ ...file, path: `docs/asset${i}.png`, size_bytes: 8_388_608 })) } }));
});
