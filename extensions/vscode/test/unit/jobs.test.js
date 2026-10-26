const assert = require('node:assert/strict');
const test = require('node:test');

const { CodeSecurityRequestError, PairingRequiredError } = require('../../dist/client.js');
const {
  abortableDelay,
  jobProgressMessage,
  observeJob,
} = require('../../dist/jobs.js');


function job(overrides = {}) {
  return {
    id: 71,
    kind: 'scan',
    title: 'Scan #41',
    status: 'running',
    stage: 'scanner_run',
    detail: 'Running a stable scanner operation.',
    progress: 35,
    scan_id: 41,
    attempt: 1,
    max_attempts: 3,
    revision: 2,
    can_cancel: true,
    can_retry: false,
    ...overrides,
  };
}


function observation(request, overrides = {}) {
  let clock = 0;
  const waits = [];
  const changes = [];
  return {
    waits,
    changes,
    promise: observeJob({
      request,
      jobId: 71,
      scanId: 41,
      signal: new AbortController().signal,
      cancellationRequested: () => false,
      onUpdate: () => {},
      wait: async (milliseconds) => {
        waits.push(milliseconds);
        clock += milliseconds;
      },
      waitForChange: async (revision) => {
        changes.push(revision);
        clock += 1;
      },
      now: () => clock,
      ...overrides,
    }),
  };
}


test('foreground observation exposes every durable state and stops at the terminal revision', async () => {
  const states = [
    job({ status: 'queued', stage: 'queued', progress: 0, attempt: 0, revision: 1 }),
    job({ status: 'running', stage: 'normalizing', progress: 46, revision: 2 }),
    job({ status: 'completed', stage: 'completed', progress: 100, revision: 3, can_cancel: false }),
  ];
  const paths = [];
  const updates = [];
  const run = observation(async (path, init) => {
    paths.push({ path, init });
    return states.shift();
  }, { onUpdate: (value) => updates.push(value.status) });

  const terminal = await run.promise;

  assert.equal(terminal.status, 'completed');
  assert.deepEqual(updates, ['queued', 'running', 'completed']);
  assert.deepEqual(paths.map(({ path }) => path), ['/v1/jobs/71', '/v1/jobs/71', '/v1/jobs/71']);
  assert(paths.every(({ init }) => init.signal instanceof AbortSignal));
  assert.deepEqual(run.waits, []);
  assert.deepEqual(run.changes, [1, 2]);
});


test('a failed event wait performs one exact durable read and surfaces the terminal job', async () => {
  let reads = 0;
  let changeWaits = 0;
  const updates = [];
  const run = observation(async (path, init) => {
    reads += 1;
    assert.equal(path, '/v1/jobs/71');
    assert(init.signal instanceof AbortSignal);
    return reads === 1
      ? job({ status: 'running', stage: 'scanner_run', progress: 82, revision: 7 })
      : job({ status: 'completed', stage: 'completed', progress: 100, revision: 8, can_cancel: false });
  }, {
    onUpdate: (value) => updates.push([value.status, value.progress, value.revision]),
    waitForChange: async (revision) => {
      changeWaits += 1;
      assert.equal(revision, 7);
      throw new CodeSecurityRequestError(
        'The local event stream stayed unavailable.',
        503,
        true,
      );
    },
  });

  const terminal = await run.promise;

  assert.equal(terminal.status, 'completed');
  assert.equal(reads, 2, 'stream failure permits one recovery read, not polling');
  assert.equal(changeWaits, 1);
  assert.deepEqual(updates, [
    ['running', 82, 7],
    ['completed', 100, 8],
  ]);
  assert.deepEqual(run.waits, []);
});


test('user cancellation is persisted once only when the server advertises support', async () => {
  const calls = [];
  let reads = 0;
  const run = observation(async (path, init) => {
    calls.push({ path, method: init?.method || 'GET' });
    if (init?.method === 'POST') {
      return job({ status: 'cancelling', stage: 'cancelling', revision: 3, can_cancel: false });
    }
    reads += 1;
    return reads === 1
      ? job({ status: 'running', revision: 2, can_cancel: true })
      : job({ status: 'cancelled', stage: 'cancelled', revision: 4, can_cancel: false });
  }, { cancellationRequested: () => true });

  assert.equal((await run.promise).status, 'cancelled');
  assert.deepEqual(calls, [
    { path: '/v1/jobs/71', method: 'GET' },
    { path: '/v1/jobs/71/cancel', method: 'POST' },
    { path: '/v1/jobs/71', method: 'GET' },
  ]);
});


test('observation rejects a cross-scan job before presenting or acting on it', async () => {
  let updates = 0;
  const run = observation(async () => job({ scan_id: 99 }), { onUpdate: () => { updates += 1; } });

  await assert.rejects(run.promise, /outside the requested workspace scan/);
  assert.equal(updates, 0);
  assert.deepEqual(run.waits, []);
});


test('temporary local outages retry within a small bound without hiding capability revocation', async () => {
  let requests = 0;
  const issues = [];
  const run = observation(async () => {
    requests += 1;
    if (requests <= 3) {
      throw new CodeSecurityRequestError('unreachable', undefined, true);
    }
    return job({ status: 'completed', revision: 5, progress: 100, can_cancel: false });
  }, { onConnectionIssue: (attempt) => issues.push(attempt) });

  assert.equal((await run.promise).status, 'completed');
  assert.equal(requests, 4);
  assert.deepEqual(issues, [1, 2, 3]);
  assert.deepEqual(run.waits, [1000, 2000, 3000]);

  const unauthorized = observation(async () => { throw new PairingRequiredError(); });
  await assert.rejects(unauthorized.promise, PairingRequiredError);
  assert.deepEqual(unauthorized.waits, []);
});


test('persistent outage ends with an actionable persisted-work message', async () => {
  const run = observation(async () => { throw new CodeSecurityRequestError('unreachable', undefined, true); });
  await assert.rejects(run.promise, /job remains persisted; reconnect and refresh Jobs/i);
  assert.deepEqual(run.waits, [1000, 2000, 3000]);
});


test('a protocol failure is surfaced immediately rather than retried as an outage', async () => {
  const run = observation(async () => { throw new CodeSecurityRequestError('invalid JSON response'); });
  await assert.rejects(run.promise, /invalid JSON response/);
  assert.deepEqual(run.waits, []);
});


test('an abort releases an outstanding observation delay promptly', async () => {
  const controller = new AbortController();
  const pending = abortableDelay(60_000, controller.signal);
  controller.abort();
  await assert.rejects(pending, (error) => error.name === 'AbortError');
});


test('the foreground deadline aborts and releases a hung job request', async () => {
  let observedSignal;
  const pending = observeJob({
    request: async (_path, init) => {
      observedSignal = init.signal;
      return new Promise(() => {});
    },
    jobId: 71,
    scanId: 41,
    signal: new AbortController().signal,
    cancellationRequested: () => false,
    onUpdate: () => {},
    waitForChange: async () => {},
    timeoutMs: 10,
  });

  await assert.rejects(pending, /exceeded the 30-minute foreground observation window/);
  assert.equal(observedSignal.aborted, true);
});


test('external disposal aborts and releases a hung job request', async () => {
  const controller = new AbortController();
  let observedSignal;
  const pending = observeJob({
    request: async (_path, init) => {
      observedSignal = init.signal;
      return new Promise(() => {});
    },
    jobId: 71,
    scanId: 41,
    signal: controller.signal,
    cancellationRequested: () => false,
    onUpdate: () => {},
    waitForChange: async () => {},
  });

  controller.abort();
  await assert.rejects(pending, (error) => error.name === 'AbortError');
  assert.equal(observedSignal.aborted, true);
});


test('progress text includes status, normalized stage, bounded progress, and attempts', () => {
  assert.equal(
    jobProgressMessage(job({ status: 'running', stage: 'persisting_findings', progress: 140 })),
    'job #71 · running · persisting findings · 100% · attempt 1/3',
  );
});
