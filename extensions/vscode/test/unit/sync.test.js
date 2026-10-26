const assert = require('node:assert/strict');
const test = require('node:test');

const { RefreshProofSupersededError, WorkspaceRefreshCoordinator } = require('../../dist/sync.js');


function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}


function turn() {
  return new Promise((resolve) => setImmediate(resolve));
}


test('manual refresh bursts share one workspace reconciliation', async () => {
  const coordinator = new WorkspaceRefreshCoordinator();
  const work = deferred();
  let starts = 0;
  const operation = async () => {
    starts += 1;
    return work.promise;
  };
  const refreshes = Array.from({ length: 1_000 }, () => coordinator.run(
    'file:///workspace',
    { key: 'manual', proof: 'workspace', supersedes: false },
    operation,
  ));
  await turn();

  assert.equal(starts, 1);
  assert.equal(coordinator.activeCount, 1);
  work.resolve({ revision: 7 });
  const results = await Promise.all(refreshes);
  assert(results.every(({ revision }) => revision === 7));
  assert.equal(coordinator.activeCount, 0);
});


test('a newer event cancels transport work but transfers older cursor waiters to its proof', async () => {
  const coordinator = new WorkspaceRefreshCoordinator();
  const operations = [];
  const operation = (name) => (signal) => {
    const work = deferred();
    const record = { name, signal, work };
    operations.push(record);
    signal.addEventListener('abort', () => work.reject(
      new DOMException(`${name} superseded`, 'AbortError'),
    ), { once: true });
    return work.promise;
  };
  let olderSettled = false;
  const acknowledgedCursors = [];
  const older = coordinator.run(
    'file:///workspace',
    { key: 'event:10', proof: 'workspace', supersedes: true },
    operation('older'),
  ).then((value) => {
    acknowledgedCursors.push(10);
    return value;
  }).finally(() => { olderSettled = true; });
  await turn();
  const newer = coordinator.run(
    'file:///workspace',
    { key: 'event:11', proof: 'workspace', supersedes: true },
    operation('newer'),
  ).then((value) => {
    acknowledgedCursors.push(11);
    return value;
  });
  await turn();

  assert.equal(operations.length, 2);
  assert.equal(operations[0].signal.aborted, true);
  assert.equal(olderSettled, false, 'the older SSE callback must not acknowledge its cursor yet');
  assert.deepEqual(acknowledgedCursors, []);
  operations[1].work.resolve({ revision: 11 });
  assert.deepEqual(await Promise.all([older, newer]), [{ revision: 11 }, { revision: 11 }]);
  assert.deepEqual(acknowledgedCursors.sort((left, right) => left - right), [10, 11]);
  assert.equal(coordinator.activeCount, 0);
});


test('an incompatible exact refresh cannot substitute for an event cursor proof', async () => {
  const coordinator = new WorkspaceRefreshCoordinator();
  const eventWork = deferred();
  const exactWork = deferred();
  let eventSignal;
  const eventWaiter = coordinator.run(
    'file:///workspace',
    { key: 'event:10', proof: 'workspace', supersedes: true },
    (signal) => {
      eventSignal = signal;
      signal.addEventListener('abort', () => eventWork.reject(
        new DOMException('event transport superseded', 'AbortError'),
      ), { once: true });
      return eventWork.promise;
    },
  );
  const eventRejected = assert.rejects(
    eventWaiter,
    (error) => error instanceof RefreshProofSupersededError
      && error.status === 409
      && error.retryable === true,
  );
  await turn();
  const exactWaiter = coordinator.run(
    'file:///workspace',
    { key: 'exact:41:1', proof: 'exact:41', supersedes: true },
    () => exactWork.promise,
  );
  await turn();

  await eventRejected;
  assert.equal(eventSignal.aborted, true);
  exactWork.resolve({ revision: 4 });
  assert.deepEqual(await exactWaiter, { revision: 4 });
});


test('a manual workspace proof never joins an active exact-scan proof', async () => {
  const coordinator = new WorkspaceRefreshCoordinator();
  const exactWork = deferred();
  const manualWork = deferred();
  const exact = coordinator.run(
    'file:///workspace',
    { key: 'exact:41:1', proof: 'exact:41', supersedes: true },
    (signal) => {
      signal.addEventListener('abort', () => exactWork.reject(
        new DOMException('exact transport superseded', 'AbortError'),
      ), { once: true });
      return exactWork.promise;
    },
  );
  const exactRejected = assert.rejects(exact, (error) => error.status === 409 && error.retryable);
  await turn();
  const manual = coordinator.run(
    'file:///workspace',
    { key: 'manual', proof: 'workspace', supersedes: false },
    () => manualWork.promise,
  );
  await exactRejected;
  manualWork.resolve({ revision: 42 });
  assert.deepEqual(await manual, { revision: 42 });
});


test('one cancelled caller detaches without aborting reconciliation needed by another caller', async () => {
  const coordinator = new WorkspaceRefreshCoordinator();
  const work = deferred();
  let operationSignal;
  const firstCaller = new AbortController();
  const first = coordinator.run(
    'file:///workspace',
    { key: 'manual', proof: 'workspace', supersedes: false },
    async (signal) => {
      operationSignal = signal;
      return work.promise;
    },
    firstCaller.signal,
  );
  const second = coordinator.run(
    'file:///workspace',
    { key: 'manual', proof: 'workspace', supersedes: false },
    () => { throw new Error('joined work must not start twice'); },
  );
  await turn();
  firstCaller.abort();

  await assert.rejects(first, (error) => error.name === 'AbortError');
  assert.equal(operationSignal.aborted, false);
  work.resolve({ revision: 3 });
  assert.deepEqual(await second, { revision: 3 });
});


test('workspace and authority teardown reject waiters and abort every active operation', async () => {
  const coordinator = new WorkspaceRefreshCoordinator();
  const signals = [];
  const pending = ['file:///one', 'file:///two'].map((workspaceKey) => coordinator.run(
    workspaceKey,
    { key: 'manual', proof: 'workspace', supersedes: false },
    (signal) => {
      signals.push(signal);
      return new Promise(() => {});
    },
  ));
  await turn();
  coordinator.cancelAll();

  await Promise.all(pending.map((promise) => assert.rejects(
    promise,
    (error) => error.name === 'AbortError',
  )));
  assert.equal(signals.length, 2);
  assert(signals.every((signal) => signal.aborted));
  assert.equal(coordinator.activeCount, 0);
});


test('supersede and teardown consume internal AbortErrors without unhandled rejections', async () => {
  const coordinator = new WorkspaceRefreshCoordinator();
  const unhandled = [];
  const onUnhandled = (error) => { unhandled.push(error); };
  process.on('unhandledRejection', onUnhandled);
  try {
    const first = coordinator.run(
      'file:///workspace',
      { key: 'event:1', proof: 'workspace', supersedes: true },
      (signal) => new Promise((_resolve, reject) => signal.addEventListener('abort', () => {
        reject(new DOMException('superseded', 'AbortError'));
      }, { once: true })),
    );
    await turn();
    const replacementWork = deferred();
    const replacement = coordinator.run(
      'file:///workspace',
      { key: 'event:2', proof: 'workspace', supersedes: true },
      () => replacementWork.promise,
    );
    await turn();
    coordinator.cancelAll();
    await Promise.all([first, replacement].map((promise) => assert.rejects(
      promise,
      (error) => error.name === 'AbortError',
    )));
    await turn();
    await turn();
    assert.deepEqual(unhandled, []);
  } finally {
    process.removeListener('unhandledRejection', onUnhandled);
  }
});
