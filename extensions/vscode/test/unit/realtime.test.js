const assert = require('node:assert/strict');
const test = require('node:test');

const { CodeSecurityRequestError } = require('../../dist/client.js');
const {
  RealtimeSync,
  consumeEventStream,
  validateAuthoritativeScanJob,
  validateDomainEvent,
  validateSourceOpenCommand,
} = require('../../dist/realtime.js');


const ready = 'event: stream.ready\ndata: {"v":1,"highwater_event_id":8,"earliest_event_id":1}\n\n';
const readyAtZero = 'event: stream.ready\ndata: {"v":1,"highwater_event_id":0,"earliest_event_id":0}\n\n';

function event(id, kind = 'job.changed', aggregate = 'job') {
  const scope = kind === 'job.changed'
    ? { project_id: 7, scan_id: 41, job_id: 71 }
    : kind === 'project.changed'
      ? { project_id: 7 }
      : { project_id: 7, scan_id: 41 };
  const aggregateId = kind === 'job.changed' ? '71' : kind === 'project.changed' ? '7' : '41';
  return `id: ${id}\nevent: ${kind}\ndata: ${JSON.stringify({
    v: 1,
    event_id: id,
    kind,
    aggregate: { type: aggregate, id: aggregateId, revision: 3 },
    occurred_at: '2026-08-13T12:00:00Z',
    scope,
    change: 'updated',
    hint: { status: 'running', progress: 35 },
  })}\n\n`;
}

function responseFromChunks(chunks, { hold = false, signal } = {}) {
  const encoder = new TextEncoder();
  let ended = false;
  return new Response(new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      if (!hold) {
        ended = true;
        controller.close();
      } else {
        signal?.addEventListener('abort', () => {
          if (ended) return;
          ended = true;
          controller.error(new DOMException('stopped', 'AbortError'));
        }, { once: true });
      }
    },
    cancel() { ended = true; },
  }), { headers: { 'Content-Type': 'text/event-stream' } });
}

class MemoryState {
  constructor() { this.values = new Map(); this.updates = []; }
  get(key) { return this.values.get(key); }
  async update(key, value) { this.updates.push(value); this.values.set(key, value); }
}

async function eventually(predicate, message) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.fail(message);
}


test('fragmented SSE is bounded, handshaken, and wire IDs match validated domain events', async () => {
  const source = ready + event(8);
  const chunks = [];
  for (let offset = 0; offset < source.length; offset += 7) chunks.push(source.slice(offset, offset + 7));
  const controls = [];
  const events = [];
  const result = await consumeEventStream(
    responseFromChunks(chunks),
    new AbortController().signal,
    {
      ready: async (value) => controls.push(value),
      reset: async () => assert.fail('unexpected reset'),
      event: async (value) => events.push(value),
    },
  );

  assert.equal(result, 'closed');
  assert.deepEqual(controls, [{ v: 1, highwater_event_id: 8, earliest_event_id: 1 }]);
  assert.equal(events[0].event_id, 8);
  assert.equal(events[0].aggregate.revision, 3);
});


test('hostile or expanded event payloads fail closed before reaching reconciliation', () => {
  const base = {
    v: 1,
    event_id: 4,
    kind: 'findings.changed',
    aggregate: { type: 'findings', id: '41', revision: 9 },
    occurred_at: '2026-08-13T12:00:00.123456Z',
    scope: { project_id: 7, scan_id: 41 },
    change: 'updated',
    hint: { count: 9 },
  };
  assert.equal(validateDomainEvent(base, '4', 'findings.changed').event_id, 4);
  assert.throws(
    () => validateDomainEvent({ ...base, scope: { ...base.scope, file_path: '/private/source' } }, '4', 'findings.changed'),
    CodeSecurityRequestError,
  );
  assert.throws(
    () => validateDomainEvent({ ...base, hint: { snippet: 'secret source' } }, '4', 'findings.changed'),
    CodeSecurityRequestError,
  );
  assert.throws(
    () => validateDomainEvent({ ...base, scope: {} }, '4', 'findings.changed'),
    /misdirected event scope/,
  );
  assert.throws(
    () => validateDomainEvent({ ...base, scope: { project_id: 7, scan_id: 99 } }, '4', 'findings.changed'),
    /misdirected event scope/,
  );
  assert.throws(() => validateDomainEvent(base, '5', 'findings.changed'), CodeSecurityRequestError);
  assert.throws(
    () => validateDomainEvent({ ...base, occurred_at: '2026-02-31T12:00:00Z' }, '4', 'findings.changed'),
    CodeSecurityRequestError,
  );

  const job = {
    ...base,
    kind: 'job.changed',
    aggregate: { type: 'job', id: '71', revision: 9 },
    scope: { project_id: 7, scan_id: 41, job_id: 71 },
  };
  assert.equal(validateDomainEvent(job, '4', 'job.changed').scope.scan_id, 41);
  for (const scope of [
    { scan_id: 41, job_id: 71 },
    { project_id: 7, job_id: 71 },
    { project_id: 7, scan_id: 41 },
  ]) {
    assert.throws(
      () => validateDomainEvent({ ...job, scope }, '4', 'job.changed'),
      /misdirected event scope/,
    );
  }
});

test('installation jobs require their own ID and either both repository coordinates or neither', () => {
  const job = JSON.parse(event(9).split('data: ')[1]);
  const installationJob = { ...job, scope: { job_id: 71 } };
  assert.deepEqual(validateDomainEvent(installationJob, '9', 'job.changed'), installationJob);
  for (const scope of [{}, { job_id: 72 }, { job_id: 71, scan_id: 41 },
    { job_id: 71, project_id: 7 }, { job_id: 71, scan_id: null }, { job_id: 71, kind: 'scan' }]) {
    assert.throws(() => validateDomainEvent({ ...job, scope }), CodeSecurityRequestError);
  }
});

test('preparation updates keep one live connection without waking or reading scan jobs', async (t) => {
  const storage = new MemoryState();
  const states = [];
  const cursors = [];
  let controller;
  let jobReads = 0;
  const encoder = new TextEncoder();
  const sync = new RealtimeSync({
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      cursors.push(cursor);
      return new Response(new ReadableStream({
        start(stream) {
          controller = stream;
          stream.enqueue(encoder.encode(readyAtZero));
          signal.addEventListener('abort', () => stream.error(new DOMException('stopped', 'AbortError')), { once: true });
        },
      }), { headers: { 'Content-Type': 'text/event-stream' } });
    },
    request: async () => {
      jobReads += 1;
      return { id: 71, kind: 'scan', scan_id: 41, revision: 3 };
    },
  }, storage, { onState: state => states.push(state) });
  t.after(() => sync.dispose());
  const outer = new AbortController();
  await sync.reconnectPairedCapability(outer.signal);
  let scanResolved = false;
  const waiting = sync.waitForJob(71, 41, 2, outer.signal).then(() => { scanResolved = true; });
  void waiting.catch(() => {}); // Disposal also settles a failed test's waiter.
  for (let id = 1; id <= 68; id += 1) {
    const document = JSON.parse(event(id).split('data: ')[1]);
    document.aggregate.id = id < 6 ? '1' : '2';
    document.scope = { job_id: Number(document.aggregate.id) };
    controller.enqueue(encoder.encode(`id: ${id}\nevent: job.changed\ndata: ${JSON.stringify(document)}\n\n`));
  }
  await eventually(() => storage.updates.at(-1)?.event_id === 68, 'preparation cursor did not advance');
  assert.deepEqual(cursors, [0]);
  assert.deepEqual(states, ['connecting', 'connected']);
  assert.equal(jobReads, 0);
  assert.equal(scanResolved, false);
  controller.enqueue(encoder.encode(event(69)));
  await waiting;
  assert.equal(jobReads, 1);
  assert.equal(storage.updates.at(-1).event_id, 69);
});

test('targeted source-open events are body-free, ID-less, and separately validated', async () => {
  const command = {
    v: 1,
    command_id: 'a'.repeat(32),
    project_id: 7,
    scan_id: 41,
    finding_id: 501,
    scan_finding_number: 3,
    expected_finding_revision: 2,
    expected_findings_revision: 9,
    expires_at: '2026-08-26T12:00:00Z',
  };
  assert.deepEqual(validateSourceOpenCommand(command), command);
  assert.throws(
    () => validateSourceOpenCommand({ ...command, file_path: 'private/source.ts' }),
    /invalid targeted source-open command/,
  );
  const commands = [];
  await consumeEventStream(
    responseFromChunks([
      ready,
      `event: ide.source.open\ndata: ${JSON.stringify(command)}\n\n`,
    ]),
    new AbortController().signal,
    {
      ready: async () => {},
      reset: async () => assert.fail('unexpected reset'),
      event: async () => assert.fail('unexpected domain event'),
      sourceOpen: async (value) => commands.push(value),
    },
  );
  assert.deepEqual(commands, [command]);
  await assert.rejects(
    consumeEventStream(
      responseFromChunks([
        ready,
        `id: 9\nevent: ide.source.open\ndata: ${JSON.stringify(command)}\n\n`,
      ]),
      new AbortController().signal,
      {
        ready: async () => {},
        reset: async () => {},
        event: async () => {},
        sourceOpen: async () => {},
      },
    ),
    /invalid targeted source-open event/,
  );
});


test('oversized event frames are rejected before JSON parsing or callback delivery', async () => {
  let delivered = false;
  await assert.rejects(
    consumeEventStream(
      responseFromChunks([ready, `event: job.changed\ndata: ${'x'.repeat(16_385)}\n\n`]),
      new AbortController().signal,
      {
        ready: async () => {},
        reset: async () => {},
        event: async () => { delivered = true; },
      },
    ),
    /oversized event frame/,
  );
  assert.equal(delivered, false);
});


test('multibyte hostile frames are bounded by UTF-8 bytes, not JavaScript characters', async () => {
  const hostile = '💥'.repeat(4_097);
  await assert.rejects(
    consumeEventStream(
      responseFromChunks([ready, `event: job.changed\ndata: ${hostile}\n\n`]),
      new AbortController().signal,
      { ready: async () => {}, reset: async () => {}, event: async () => {} },
    ),
    /oversized event frame/,
  );
});


test('cursor advances only after project reconciliation and job events wake revision waits', async () => {
  const state = new MemoryState();
  const opened = [];
  const order = [];
  const update = state.update.bind(state);
  state.update = async (key, value) => {
    order.push(`cursor:${value.event_id}`);
    await update(key, value);
  };
  const controller = new AbortController();
  let streamController;
  const encoder = new TextEncoder();
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      opened.push(cursor);
      return new Response(new ReadableStream({
        start(controller) {
          streamController = controller;
          controller.enqueue(encoder.encode(readyAtZero));
          signal.addEventListener('abort', () => controller.error(new DOMException('stopped', 'AbortError')), { once: true });
        },
      }), { headers: { 'Content-Type': 'text/event-stream' } });
    },
    request: async (path, init) => {
      order.push(`get:${path}`);
      assert(init.signal instanceof AbortSignal);
      return { id: 71, kind: 'scan', scan_id: 41, revision: 3 };
    },
  };
  const reconciled = [];
  const sync = new RealtimeSync(client, state, { random: () => 0.5 });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    scanId: 41,
    onEvent: async (value, signal) => { assert.equal(signal.aborted, false); reconciled.push(value.event_id); },
    onReset: async (signal) => { assert.equal(signal.aborted, false); reconciled.push(0); },
  });
  await sync.ensureConnected(controller.signal);
  const jobWait = sync.waitForJob(71, 41, 2, controller.signal);
  await new Promise((resolve) => setImmediate(resolve));
  streamController.enqueue(encoder.encode(event(7, 'scan.changed', 'scan') + event(8)));
  await jobWait;
  for (let attempt = 0; attempt < 100 && !state.updates.some(({ event_id }) => event_id === 8); attempt += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.equal(
    state.updates.some(({ event_id }) => event_id === 8),
    true,
    `event cursor should be persisted: ${JSON.stringify({ updates: state.updates, order, reconciled, opened })}`,
  );

  assert.deepEqual(opened, [0]);
  assert.deepEqual(reconciled, [0, 7]);
  assert.deepEqual(state.updates.map(({ event_id }) => event_id), [0, 7, 8]);
  assert(order.indexOf('get:/v1/jobs/71') < order.indexOf('cursor:8'));
  sync.dispose();
});

test('a job event received before waiter registration wakes only after its cursor is durable', async () => {
  const state = new MemoryState();
  let releaseEventCursor;
  const eventCursorGate = new Promise((resolve) => { releaseEventCursor = resolve; });
  let markEventCursorStarted;
  const eventCursorStarted = new Promise((resolve) => { markEventCursorStarted = resolve; });
  const update = state.update.bind(state);
  state.update = async (key, value) => {
    if (value.event_id === 8) {
      markEventCursorStarted();
      await eventCursorGate;
    }
    await update(key, value);
  };
  let streamController;
  const encoder = new TextEncoder();
  let jobReads = 0;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (_cursor, signal) => new Response(new ReadableStream({
      start(controller) {
        streamController = controller;
        controller.enqueue(encoder.encode(readyAtZero));
        signal.addEventListener(
          'abort',
          () => controller.error(new DOMException('stopped', 'AbortError')),
          { once: true },
        );
      },
    }), { headers: { 'Content-Type': 'text/event-stream' } }),
    request: async () => {
      jobReads += 1;
      return { id: 71, kind: 'scan', scan_id: 41, revision: 3 };
    },
  };
  const sync = new RealtimeSync(client, state);
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    scanId: 41,
    onEvent: async () => {},
    onReset: async () => {},
  });
  const outer = new AbortController();
  await sync.ensureConnected(outer.signal);
  streamController.enqueue(encoder.encode(event(8)));
  await eventCursorStarted;

  let resolved = false;
  const waiting = sync.waitForJob(71, 41, 2, outer.signal).then(() => { resolved = true; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(resolved, false, 'an unpersisted event revision cannot wake a later waiter');
  releaseEventCursor();
  await waiting;

  assert.equal(state.updates.at(-1).event_id, 8);
  assert.equal(jobReads, 0, 'the no-waiter event is only a wake hint; the observer performs its next exact GET');
  sync.dispose();
});


test('a durable pre-wait job hint cannot wake a waiter for a different scan', async () => {
  const state = new MemoryState();
  let streamController;
  const encoder = new TextEncoder();
  let jobReads = 0;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (_cursor, signal) => new Response(new ReadableStream({
      start(controller) {
        streamController = controller;
        controller.enqueue(encoder.encode(readyAtZero));
        signal.addEventListener(
          'abort',
          () => controller.error(new DOMException('stopped', 'AbortError')),
          { once: true },
        );
      },
    }), { headers: { 'Content-Type': 'text/event-stream' } }),
    request: async () => {
      jobReads += 1;
      return { id: 71, kind: 'scan', scan_id: 41, revision: 3 };
    },
  };
  const sync = new RealtimeSync(client, state);
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    scanId: 41,
    onEvent: async () => {},
    onReset: async () => {},
  });
  const outer = new AbortController();
  await sync.ensureConnected(outer.signal);
  streamController.enqueue(encoder.encode(event(8).replace('"scan_id":41', '"scan_id":99')));
  await eventually(() => state.updates.at(-1)?.event_id === 8, 'wrong-scan hint cursor should persist');

  let resolved = false;
  const waiting = sync.waitForJob(71, 41, 2, outer.signal).then(() => { resolved = true; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(resolved, false, 'job IDs alone cannot cross scan authority');
  assert.equal(jobReads, 0);

  streamController.enqueue(encoder.encode(event(9)));
  await waiting;
  assert.equal(jobReads, 1);
  assert.equal(state.updates.at(-1).event_id, 9);
  sync.dispose();
});


test('job cursor replays after a failed exact GET and hostile scoped job resources fail closed', async () => {
  const state = new MemoryState();
  const cursors = [];
  let requests = 0;
  let firstStreamController;
  const firstStream = new Response(new ReadableStream({
    start(controller) { firstStreamController = controller; },
  }), { headers: { 'Content-Type': 'text/event-stream' } });
  const encoder = new TextEncoder();
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      cursors.push(cursor);
      if (cursors.length === 1) return firstStream;
      return responseFromChunks([readyAtZero, event(8)], { hold: true, signal });
    },
    request: async (path) => {
      assert.equal(path, '/v1/jobs/71');
      requests += 1;
      if (requests === 1) throw new Error('simulated crash before authoritative job read');
      return { id: 71, kind: 'scan', scan_id: 41, revision: 3 };
    },
  };
  const sync = new RealtimeSync(client, state, { wait: async () => {}, random: () => 0.5 });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    scanId: 41,
    onEvent: async () => {},
    onReset: async () => {},
  });
  firstStreamController.enqueue(encoder.encode(readyAtZero));
  const connected = new AbortController();
  await sync.ensureConnected(connected.signal);
  const waiting = sync.waitForJob(71, 41, 2, connected.signal);
  await new Promise((resolve) => setImmediate(resolve));
  firstStreamController.enqueue(encoder.encode(event(8)));
  await waiting;
  await eventually(() => state.updates.at(-1)?.event_id === 8, 'replayed job event should advance after exact GET');

  assert.deepEqual(cursors.slice(0, 2), [0, 0]);
  assert.equal(requests, 2);
  assert.equal(state.updates.filter(({ event_id }) => event_id === 8).length, 1);
  sync.dispose();

  for (const hostile of [
    { id: 72, kind: 'scan', scan_id: 41, revision: 3 },
    { id: 71, kind: 'advisor', scan_id: 41, revision: 3 },
    { id: 71, kind: 'scan', scan_id: 99, revision: 3 },
    { id: 71, kind: 'scan', scan_id: 41, revision: 2 },
  ]) {
    assert.throws(
      () => validateAuthoritativeScanJob(hostile, 71, 41, 3),
      /outside the active scan event revision/,
    );
  }
});


test('reset highwater waits for active job REST and then releases its waiter after cursor persistence', async () => {
  const state = new MemoryState();
  const cursors = [];
  const order = [];
  let streamController;
  let retryController;
  const encoder = new TextEncoder();
  let reads = 0;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      cursors.push(cursor);
      return new Response(new ReadableStream({
        start(controller) {
          streamController = controller;
          if (cursors.length === 1) controller.enqueue(encoder.encode(readyAtZero));
          else retryController = controller;
          signal.addEventListener('abort', () => controller.error(new DOMException('stopped', 'AbortError')), { once: true });
        },
      }), { headers: { 'Content-Type': 'text/event-stream' } });
    },
    request: async () => {
      reads += 1;
      order.push('job:get');
      if (reads === 1) throw new Error('reset job read failed');
      return { id: 71, kind: 'scan', scan_id: 41, revision: 4 };
    },
  };
  const update = state.update.bind(state);
  state.update = async (key, value) => { order.push(`cursor:${value.event_id}`); await update(key, value); };
  const sync = new RealtimeSync(client, state, { wait: async () => {} });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    scanId: 41,
    onEvent: async () => {},
    onReset: async () => {},
  });
  const outer = new AbortController();
  await sync.ensureConnected(outer.signal);
  const waiting = sync.waitForJob(71, 41, 2, outer.signal).then(() => order.push('waiter:resolved'));
  await new Promise((resolve) => setImmediate(resolve));
  streamController.enqueue(encoder.encode(
    'event: stream.reset\ndata: {"v":1,"reason":"cursor_too_old","highwater_event_id":8,"earliest_event_id":5}\n\n',
  ));
  await eventually(() => cursors.length >= 2, 'failed reset reconciliation should reconnect without adopting highwater');
  assert.equal(state.updates.some(({ event_id }) => event_id === 8), false);
  // The second connection's ready handshake re-runs authoritative job REST.
  retryController.enqueue(encoder.encode(ready));
  await waiting;
  await eventually(() => state.updates.some(({ event_id }) => event_id === 8), 'reconciled ready should persist highwater');

  assert(order.lastIndexOf('job:get') < order.indexOf('cursor:8'));
  assert(order.indexOf('cursor:8') < order.indexOf('waiter:resolved'));
  sync.dispose();
});


test('cursor-ahead ready waits for its reset before REST reconciliation and cursor adoption', async () => {
  const state = new MemoryState();
  state.values.set('lomoCodeSecurity.events.cursor.v1', {
    v: 1,
    endpoint: 'http://127.0.0.1:8080',
    event_id: 8,
  });
  const cursors = [];
  const controls = [];
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      cursors.push(cursor);
      if (cursors.length === 1) {
        return responseFromChunks([
          'event: stream.ready\ndata: {"v":1,"highwater_event_id":3,"earliest_event_id":1}\n\n',
          'event: stream.reset\ndata: {"v":1,"reason":"cursor_ahead","highwater_event_id":3,"earliest_event_id":1}\n\n',
        ]);
      }
      return responseFromChunks([
        'event: stream.ready\ndata: {"v":1,"highwater_event_id":3,"earliest_event_id":1}\n\n',
      ], { hold: true, signal });
    },
  };
  const sync = new RealtimeSync(client, state, { wait: async () => {} });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    onEvent: async () => assert.fail('cursor-ahead recovery must not deliver a domain event'),
    onReset: async () => { controls.push('rest'); },
  });
  await eventually(() => cursors.length === 2, 'cursor-ahead reset should reconnect at the server highwater');

  assert.deepEqual(cursors, [8, 3]);
  assert.deepEqual(controls, ['rest', 'rest']);
  assert.deepEqual(state.updates.map(({ event_id }) => event_id), [3, 3]);
  sync.dispose();
});


test('stream.reset performs an explicit REST resync before adopting the highwater cursor', async () => {
  const state = new MemoryState();
  const cursors = [];
  let resets = 0;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      cursors.push(cursor);
      if (cursors.length === 1) {
        return responseFromChunks([
          ready,
          'event: stream.reset\ndata: {"v":1,"reason":"cursor_too_old","highwater_event_id":8,"earliest_event_id":5}\n\n',
        ]);
      }
      return responseFromChunks([ready], { hold: true, signal });
    },
  };
  const sync = new RealtimeSync(client, state);
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    onEvent: async () => assert.fail('unexpected event'),
    onReset: async () => { resets += 1; },
  });
  await eventually(() => cursors.length === 2, 'reset should reconnect from the adopted highwater');

  assert.equal(resets, 3);
  assert.deepEqual(cursors, [0, 8]);
  assert.equal(state.updates.at(-1).event_id, 8);
  sync.dispose();
});


test('failed reconciliation is replayed from the prior cursor before any cursor advancement', async () => {
  const state = new MemoryState();
  const cursors = [];
  let attempts = 0;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      cursors.push(cursor);
      return responseFromChunks([readyAtZero, event(7, 'scan.changed', 'scan')], {
        hold: cursors.length > 1,
        signal,
      });
    },
  };
  const sync = new RealtimeSync(client, state, {
    random: () => 0.5,
    wait: async () => {},
  });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    scanId: 41,
    onEvent: async () => {
      attempts += 1;
      if (attempts === 1) throw new Error('deterministic REST reconciliation failure');
    },
    onReset: async () => {},
  });
  await eventually(() => state.updates.at(-1)?.event_id === 7, 'replayed event should eventually reconcile');

  assert.deepEqual(cursors.slice(0, 2), [0, 0]);
  assert.equal(attempts, 2);
  assert.deepEqual(state.updates.map(({ event_id }) => event_id), [0, 0, 7]);
  sync.dispose();
});


test('fresh ready highwater is stored only after bounded REST reconciliation succeeds', async () => {
  const state = new MemoryState();
  const cursors = [];
  let resets = 0;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      cursors.push(cursor);
      return responseFromChunks([ready], { hold: cursors.length > 1, signal });
    },
  };
  const sync = new RealtimeSync(client, state, {
    random: () => 0.5,
    wait: async () => {},
  });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    onEvent: async () => {},
    onReset: async () => {
      resets += 1;
      if (resets === 1) throw new Error('snapshot failed before highwater adoption');
    },
  });
  await eventually(() => state.updates.at(-1)?.event_id === 8, 'fresh reconciliation should retry and adopt highwater');

  assert.deepEqual(cursors.slice(0, 2), [0, 0]);
  assert.equal(resets, 2);
  assert.deepEqual(state.updates.map(({ event_id }) => event_id), [8]);
  sync.dispose();
});


test('terminal reconnect failure preserves the last typed stream explanation', async () => {
  const state = new MemoryState();
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async () => {
      throw new CodeSecurityRequestError(
        'CodeSecurity event stream failed with status 429.',
        429,
        false,
      );
    },
  };
  const sync = new RealtimeSync(client, state, {
    maxReconnectFailures: 0,
    wait: async () => {},
    random: () => 0.5,
  });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    onEvent: async () => {},
    onReset: async () => {},
  });

  await assert.rejects(
    sync.ensureConnected(new AbortController().signal),
    (error) => {
      assert(error instanceof CodeSecurityRequestError);
      assert.equal(error.status, 429);
      assert.match(error.message, /Last connection failure: CodeSecurity event stream failed with status 429\. \(HTTP 429\)/);
      return true;
    },
  );
  sync.dispose();
});


test('a first durable action immediately replaces an unavailable retry owner without re-pairing', async () => {
  const state = new MemoryState();
  const states = [];
  const cursors = [];
  const signals = [];
  let endpointAvailable = false;
  let opens = 0;
  let submissions = 0;
  let markUnavailableWait;
  const unavailableWait = new Promise((resolve) => { markUnavailableWait = resolve; });
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      opens += 1;
      cursors.push(cursor);
      signals.push(signal);
      if (!endpointAvailable) {
        throw new CodeSecurityRequestError(
          'Could not reach the local CodeSecurity event stream.',
          undefined,
          true,
        );
      }
      return responseFromChunks([readyAtZero], { hold: true, signal });
    },
  };
  const sync = new RealtimeSync(client, state, {
    maxReconnectFailures: 0,
    random: () => 0.5,
    onState: (value) => states.push(value),
    wait: (_milliseconds, signal) => new Promise((_resolve, reject) => {
      const stop = () => {
        signal.removeEventListener('abort', stop);
        reject(new DOMException('stopped', 'AbortError'));
      };
      signal.addEventListener('abort', stop, { once: true });
      markUnavailableWait();
    }),
  });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    onEvent: async () => {},
    onReset: async () => {},
  });
  await unavailableWait;
  assert.equal(sync.currentState, 'unavailable');

  endpointAvailable = true;
  const firstDurableAction = async () => {
    await sync.ensureConnected(new AbortController().signal);
    submissions += 1;
  };
  await firstDurableAction();

  assert.equal(submissions, 1, 'the real action must continue after its owned reconnect');
  assert.equal(opens, 2, 'the action must replace the unavailable retry owner immediately');
  assert.deepEqual(cursors, [0, 0], 'the replacement must preserve the durable cursor');
  assert.equal(signals[0].aborted, true);
  assert.equal(signals[1].aborted, false);
  assert(states.includes('unavailable'));
  assert.equal(states.at(-1), 'connected');
  sync.dispose();
});


test('an established capability reconnects after retryable control-plane downtime', async () => {
  const state = new MemoryState();
  const encoder = new TextEncoder();
  const delays = [];
  const states = [];
  const cursors = [];
  let firstStream;
  let endpointAvailable = true;
  let opens = 0;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      opens += 1;
      cursors.push(cursor);
      if (!endpointAvailable) {
        throw new CodeSecurityRequestError(
          'Could not reach the local CodeSecurity event stream.',
          undefined,
          true,
        );
      }
      if (opens === 1) {
        return new Response(new ReadableStream({
          start(controller) {
            firstStream = controller;
            controller.enqueue(encoder.encode(readyAtZero));
          },
        }), { headers: { 'Content-Type': 'text/event-stream' } });
      }
      return responseFromChunks([readyAtZero], { hold: true, signal });
    },
  };
  const sync = new RealtimeSync(client, state, {
    maxReconnectFailures: 0,
    random: () => 0.5,
    onState: (value) => states.push(value),
    wait: (_milliseconds, signal) => new Promise((resolve, reject) => {
      const stop = () => {
        signal.removeEventListener('abort', stop);
        reject(new DOMException('stopped', 'AbortError'));
      };
      const delay = {
        release: () => {
          signal.removeEventListener('abort', stop);
          resolve();
        },
      };
      delays.push(delay);
      signal.addEventListener('abort', stop, { once: true });
    }),
  });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    onEvent: async () => {},
    onReset: async () => {},
  });
  await sync.ensureConnected(new AbortController().signal);

  endpointAvailable = false;
  firstStream.error(new TypeError('terminated'));
  await eventually(
    () => delays.length === 1 && sync.currentState === 'unavailable',
    'transport loss should be typed retryable and retain the unavailable recovery owner',
  );
  delays[0].release();
  await eventually(
    () => opens === 2 && delays.length === 2 && sync.currentState === 'unavailable',
    'retry exhaustion should remain the owner of a retryable disconnected stream',
  );

  endpointAvailable = true;
  delays[1].release();
  await eventually(
    () => opens === 3 && sync.currentState === 'connected',
    'the same restored endpoint should reconnect without pairing or rebinding',
  );

  assert.deepEqual(cursors, [0, 0, 0]);
  assert(states.includes('unavailable'));
  assert.equal(states.at(-1), 'connected');
  sync.dispose();
});


test('a validated ready clears the wire handshake deadline before a slow REST reconciliation', async () => {
  const state = new MemoryState();
  let streamSignal;
  let releaseReset;
  const resetGate = new Promise((resolve) => { releaseReset = resolve; });
  let markResetStarted;
  const resetStarted = new Promise((resolve) => { markResetStarted = resolve; });
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (_cursor, signal) => {
      streamSignal = signal;
      return responseFromChunks([ready], { hold: true, signal });
    },
  };
  const sync = new RealtimeSync(client, state, { handshakeTimeoutMs: 5 });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    scanId: 41,
    onEvent: async () => {},
    onReset: async () => {
      markResetStarted();
      await resetGate;
    },
  });
  const connected = sync.ensureConnected(new AbortController().signal);
  await resetStarted;
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(streamSignal.aborted, false, 'REST work must not inherit the missing-ready deadline');
  releaseReset();
  await connected;
  sync.dispose();
});


test('a cursor-ahead ready retains the bounded handshake deadline until its required reset arrives', async () => {
  const state = new MemoryState();
  state.values.set('lomoCodeSecurity.events.cursor.v1', {
    v: 1,
    endpoint: 'http://127.0.0.1:8080',
    event_id: 8,
  });
  const signals = [];
  let opens = 0;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (_cursor, signal) => {
      opens += 1;
      signals.push(signal);
      return responseFromChunks([
        'event: stream.ready\ndata: {"v":1,"highwater_event_id":3,"earliest_event_id":1}\n\n',
      ], { hold: true, signal });
    },
  };
  const sync = new RealtimeSync(client, state, {
    handshakeTimeoutMs: 5,
    wait: async () => {},
    random: () => 0.5,
  });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    scanId: 41,
    onEvent: async () => {},
    onReset: async () => assert.fail('cursor-ahead ready cannot reconcile without its reset'),
  });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(signals[0].aborted, true, 'missing cursor-ahead reset must retain the wire deadline');
  assert(opens >= 2, 'missing cursor-ahead reset should reconnect');
  sync.dispose();
});


test('ready reconnects and reconciles a workspace bound during highwater adoption before cursor persistence', async () => {
  const state = new MemoryState();
  const cursors = [];
  const order = [];
  let releaseFirstReset;
  const firstResetGate = new Promise((resolve) => { releaseFirstReset = resolve; });
  let markFirstResetStarted;
  const firstResetStarted = new Promise((resolve) => { markFirstResetStarted = resolve; });
  let aResets = 0;
  let bResets = 0;
  const update = state.update.bind(state);
  state.update = async (key, value) => {
    order.push(`cursor:${value.event_id}`);
    await update(key, value);
  };
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      cursors.push(cursor);
      return responseFromChunks([ready], { hold: true, signal });
    },
  };
  const sync = new RealtimeSync(client, state, { wait: async () => {}, random: () => 0.5 });
  sync.bindWorkspace('file:///a', {
    projectId: 7,
    scanId: 41,
    onEvent: async () => {},
    onReset: async () => {
      aResets += 1;
      if (aResets === 1) {
        markFirstResetStarted();
        await firstResetGate;
      }
      order.push('reset:a');
    },
  });
  await firstResetStarted;
  sync.bindWorkspace('file:///b', {
    projectId: 8,
    scanId: 42,
    onEvent: async () => {},
    onReset: async () => {
      bResets += 1;
      order.push('reset:b');
    },
  });
  releaseFirstReset();

  await eventually(
    () => bResets === 1 && state.updates.at(-1)?.event_id === 8,
    'the added workspace should be reconciled on replay before highwater adoption',
  );
  assert.deepEqual(cursors.slice(0, 2), [0, 0]);
  assert.equal(state.updates.filter(({ event_id }) => event_id === 8).length, 1);
  assert(order.indexOf('reset:b') < order.indexOf('cursor:8'));
  sync.dispose();
});


test('ready reconnects for a job waiter added after the active-job snapshot before cursor persistence', async () => {
  const state = new MemoryState();
  const cursors = [];
  const order = [];
  let releaseFirstOpen;
  const firstOpenGate = new Promise((resolve) => { releaseFirstOpen = resolve; });
  let releaseFirstJob;
  const firstJobGate = new Promise((resolve) => { releaseFirstJob = resolve; });
  let markFirstJobStarted;
  const firstJobStarted = new Promise((resolve) => { markFirstJobStarted = resolve; });
  let firstJobHeld = false;
  const update = state.update.bind(state);
  state.update = async (key, value) => {
    order.push(`cursor:${value.event_id}`);
    await update(key, value);
  };
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      cursors.push(cursor);
      if (cursors.length === 1) await firstOpenGate;
      return responseFromChunks([ready], { hold: true, signal });
    },
    request: async (path) => {
      order.push(`get:${path}`);
      const jobId = Number(path.slice('/v1/jobs/'.length));
      if (jobId === 71 && !firstJobHeld) {
        firstJobHeld = true;
        markFirstJobStarted();
        await firstJobGate;
      }
      return { id: jobId, kind: 'scan', scan_id: 41, revision: 3 };
    },
  };
  const sync = new RealtimeSync(client, state, { wait: async () => {}, random: () => 0.5 });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    scanId: 41,
    onEvent: async () => {},
    onReset: async () => {},
  });
  const outer = new AbortController();
  const job71 = sync.waitForJob(71, 41, 2, outer.signal);
  releaseFirstOpen();
  await firstJobStarted;
  const job72 = sync.waitForJob(72, 41, 2, outer.signal);
  releaseFirstJob();

  await Promise.all([job71, job72]);
  assert.deepEqual(cursors.slice(0, 2), [0, 0]);
  assert.equal(state.updates.filter(({ event_id }) => event_id === 8).length, 1);
  assert(order.indexOf('get:/v1/jobs/72') < order.indexOf('cursor:8'));
  assert.equal(order.filter((value) => value === 'get:/v1/jobs/71').length, 2);
  sync.dispose();
});


test('a workspace bound while highwater storage is pending is REST-reconciled on replay before connected', async () => {
  const state = new MemoryState();
  const cursors = [];
  const order = [];
  let highwaterWrites = 0;
  let releaseFirstWrite;
  const firstWriteGate = new Promise((resolve) => { releaseFirstWrite = resolve; });
  let markFirstWriteStarted;
  const firstWriteStarted = new Promise((resolve) => { markFirstWriteStarted = resolve; });
  const update = state.update.bind(state);
  state.update = async (key, value) => {
    highwaterWrites += 1;
    const write = highwaterWrites;
    order.push(`cursor:start:${write}`);
    if (write === 1) {
      markFirstWriteStarted();
      await firstWriteGate;
    }
    await update(key, value);
    order.push(`cursor:done:${write}`);
  };
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      cursors.push(cursor);
      return responseFromChunks([ready], { hold: true, signal });
    },
  };
  const sync = new RealtimeSync(client, state, { wait: async () => {}, random: () => 0.5 });
  sync.bindWorkspace('file:///a', {
    projectId: 7,
    scanId: 41,
    onEvent: async () => {},
    onReset: async () => { order.push('reset:a'); },
  });
  const connected = sync.ensureConnected(new AbortController().signal);
  await firstWriteStarted;
  sync.bindWorkspace('file:///b', {
    projectId: 8,
    scanId: 42,
    onEvent: async () => {},
    onReset: async () => { order.push('reset:b'); },
  });
  releaseFirstWrite();
  await connected;

  assert.deepEqual(cursors.slice(0, 2), [0, 8]);
  assert.equal(highwaterWrites, 2);
  assert(order.indexOf('cursor:done:1') < order.indexOf('reset:b'));
  assert(order.indexOf('reset:b') < order.indexOf('cursor:start:2'));
  sync.dispose();
});


test('a job waiter registered while highwater storage is pending resolves only after replay REST and cursor storage', async () => {
  const state = new MemoryState();
  const cursors = [];
  const order = [];
  let highwaterWrites = 0;
  let releaseFirstWrite;
  const firstWriteGate = new Promise((resolve) => { releaseFirstWrite = resolve; });
  let markFirstWriteStarted;
  const firstWriteStarted = new Promise((resolve) => { markFirstWriteStarted = resolve; });
  const update = state.update.bind(state);
  state.update = async (key, value) => {
    highwaterWrites += 1;
    const write = highwaterWrites;
    order.push(`cursor:start:${write}`);
    if (write === 1) {
      markFirstWriteStarted();
      await firstWriteGate;
    }
    await update(key, value);
    order.push(`cursor:done:${write}`);
  };
  let jobReads = 0;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (cursor, signal) => {
      cursors.push(cursor);
      return responseFromChunks([ready], { hold: true, signal });
    },
    request: async (path) => {
      assert.equal(path, '/v1/jobs/71');
      jobReads += 1;
      order.push('job:get');
      return { id: 71, kind: 'scan', scan_id: 41, revision: 3 };
    },
  };
  const sync = new RealtimeSync(client, state, { wait: async () => {}, random: () => 0.5 });
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    scanId: 41,
    onEvent: async () => {},
    onReset: async () => {},
  });
  await firstWriteStarted;
  const outer = new AbortController();
  const waiting = sync.waitForJob(71, 41, 2, outer.signal).then(() => order.push('waiter:resolved'));
  releaseFirstWrite();
  await waiting;

  assert.deepEqual(cursors.slice(0, 2), [0, 8]);
  assert.equal(highwaterWrites, 2);
  assert.equal(jobReads, 1);
  assert(order.indexOf('cursor:done:1') < order.indexOf('job:get'));
  assert(order.indexOf('job:get') < order.indexOf('cursor:start:2'));
  assert(order.indexOf('cursor:done:2') < order.indexOf('waiter:resolved'));
  sync.dispose();
});


test('ready cannot report connected after its last binding is removed before cursor adoption', async () => {
  const state = new MemoryState();
  const controllers = [];
  const signals = [];
  const encoder = new TextEncoder();
  let sync;
  let bResets = 0;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (_cursor, signal) => new Response(new ReadableStream({
      start(controller) {
        controllers.push(controller);
        signals.push(signal);
        signal.addEventListener(
          'abort',
          () => controller.error(new DOMException('stopped', 'AbortError')),
          { once: true },
        );
      },
    }), { headers: { 'Content-Type': 'text/event-stream' } }),
  };
  sync = new RealtimeSync(client, state, { wait: async () => {}, random: () => 0.5 });
  sync.bindWorkspace('file:///a', {
    projectId: 7,
    scanId: 41,
    onEvent: async () => {},
    onReset: async () => { sync.unbindWorkspace('file:///a', true); },
  });
  await eventually(() => controllers.length === 1, 'the first stream should open');
  controllers[0].enqueue(encoder.encode(readyAtZero));
  await eventually(() => signals[0].aborted, 'the empty ready reconciliation should stop its stream');
  assert.equal(sync.currentState, 'idle');

  sync.bindWorkspace('file:///b', {
    projectId: 8,
    scanId: 42,
    onEvent: async () => {},
    onReset: async () => { bResets += 1; },
  });
  let connected = false;
  const connection = sync.ensureConnected(new AbortController().signal).then(() => { connected = true; });
  await eventually(() => controllers.length === 2, 'new demand should open a second stream');
  assert.equal(connected, false);
  assert.notEqual(sync.currentState, 'connected');
  controllers[1].enqueue(encoder.encode(readyAtZero));
  await connection;
  assert.equal(bResets, 1);
  assert.equal(sync.currentState, 'connected');
  sync.dispose();
});


test('pairing bootstrap connects without a workspace and yields to the first durable binding', async () => {
  const state = new MemoryState();
  const signals = [];
  let opens = 0;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (_cursor, signal) => {
      opens += 1;
      signals.push(signal);
      return responseFromChunks([readyAtZero], { hold: true, signal });
    },
  };
  const sync = new RealtimeSync(client, state);
  const authority = new AbortController();

  await sync.reconnectPairedCapability(authority.signal);
  assert.equal(opens, 1);
  assert.equal(sync.currentState, 'connected');
  assert.equal(signals[0].aborted, false);

  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    onEvent: async () => {},
    onReset: async () => {},
  });
  sync.unbindWorkspace('file:///workspace');
  await eventually(() => signals[0].aborted, 'the first durable binding should release bootstrap presence');
  assert.equal(sync.currentState, 'idle');
  sync.dispose();
});


test('workspace observer teardown releases its job wait and aborts the final live stream', async () => {
  const state = new MemoryState();
  let streamSignal;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (_cursor, signal) => {
      streamSignal = signal;
      return responseFromChunks([ready], { hold: true, signal });
    },
  };
  const sync = new RealtimeSync(client, state);
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    onEvent: async () => {},
    onReset: async () => {},
  });
  const external = new AbortController();
  await sync.ensureConnected(external.signal);
  const waiting = sync.waitForJob(71, 41, 2, external.signal);
  external.abort();
  await assert.rejects(waiting, (error) => error.name === 'AbortError');
  sync.unbindWorkspace('file:///workspace');
  assert.equal(streamSignal.aborted, true);
  sync.dispose();
});


test('workspace removal aborts a REST reconciliation that is waiting on the live stream signal', async () => {
  const state = new MemoryState();
  let reconciliationSignal;
  let stopped;
  const stoppedPromise = new Promise((resolve) => { stopped = resolve; });
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (_cursor, signal) => responseFromChunks([ready], { hold: true, signal }),
  };
  const sync = new RealtimeSync(client, state);
  sync.bindWorkspace('file:///workspace', {
    projectId: 7,
    onEvent: async () => {},
    onReset: async (signal) => {
      reconciliationSignal = signal;
      await new Promise((_resolve, reject) => signal.addEventListener('abort', () => {
        stopped();
        reject(new DOMException('stopped', 'AbortError'));
      }, { once: true }));
    },
  });
  await eventually(() => reconciliationSignal instanceof AbortSignal, 'ready should begin REST reconciliation');
  sync.unbindWorkspace('file:///workspace');
  await stoppedPromise;

  assert.equal(reconciliationSignal.aborted, true);
  sync.dispose();
});


test('an immediate bind after the last unbind restarts the aborted shared stream', async () => {
  const state = new MemoryState();
  const signals = [];
  let opens = 0;
  let reconciledB = 0;
  const client = {
    endpointIdentity: () => 'http://127.0.0.1:8080',
    openEventStream: async (_cursor, signal) => {
      opens += 1;
      signals.push(signal);
      return responseFromChunks([readyAtZero], { hold: true, signal });
    },
  };
  const sync = new RealtimeSync(client, state);
  sync.bindWorkspace('file:///a', {
    projectId: 7,
    onEvent: async () => {},
    onReset: async () => {},
  });
  const connected = new AbortController();
  await sync.ensureConnected(connected.signal);
  sync.unbindWorkspace('file:///a');
  sync.bindWorkspace('file:///b', {
    projectId: 8,
    onEvent: async () => {},
    onReset: async () => { reconciledB += 1; },
  });
  await eventually(() => opens === 2 && reconciledB === 1, 'new demand should restart the settling aborted run');

  assert.equal(signals[0].aborted, true);
  assert.equal(signals[1].aborted, false);
  sync.dispose();
});
