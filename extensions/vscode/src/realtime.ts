import {
  CodeSecurityClient,
  CodeSecurityRequestError,
  PairingRequiredError,
} from './client';


const CURSOR_KEY = 'lomoCodeSecurity.events.cursor.v1';
const MAX_FRAME_BYTES = 16_384;
const MAX_BUFFER_BYTES = 65_536;
const MAX_RECONNECT_FAILURES = 7;
const HANDSHAKE_TIMEOUT_MS = 10_000;
const STREAM_IDLE_TIMEOUT_MS = 45_000;
const MAX_TRACKED_JOB_REVISIONS = 2_048;

export type DomainEventKind =
  | 'project.changed'
  | 'scan.changed'
  | 'job.changed'
  | 'findings.changed';

export type DomainEvent = Readonly<{
  v: 1;
  event_id: number;
  kind: DomainEventKind;
  aggregate: Readonly<{
    type: 'project' | 'scan' | 'job' | 'findings';
    id: string;
    revision: number;
  }>;
  occurred_at: string;
  scope: Readonly<{
    project_id?: number;
    scan_id?: number;
    job_id?: number;
  }>;
  change: 'created' | 'updated' | 'deleted';
  hint: Readonly<Record<string, string | number | boolean | null>>;
}>;

export type StreamControl = Readonly<{
  v: 1;
  highwater_event_id: number;
  earliest_event_id: number;
  reason?: string;
}>;

export type SourceOpenCommand = Readonly<{
  v: 1;
  command_id: string;
  project_id: number;
  scan_id: number;
  finding_id: number;
  scan_finding_number: number;
  expected_finding_revision: number;
  expected_findings_revision: number;
  expires_at: string;
}>;

export type RealtimeState = 'idle' | 'connecting' | 'connected' | 'reconnecting' | 'unavailable' | 'pair required';

export interface CursorStorageLike {
  get<T>(key: string): T | undefined;
  update(key: string, value: unknown): PromiseLike<void>;
}

type CursorRecord = Readonly<{ v: 1; endpoint: string; event_id: number }>;

type WorkspaceBinding = Readonly<{
  projectId: number;
  scanId?: number;
  onEvent: (event: DomainEvent, signal: AbortSignal) => Promise<void>;
  onReset: (signal: AbortSignal) => Promise<void>;
}>;

type ManagedWorkspaceBinding = WorkspaceBinding & { tail: Promise<void> };

type JobWaiter = {
  scanId: number;
  afterRevision: number;
  reconciledRevision?: number;
  resolve: () => void;
  reject: (error: Error) => void;
  signal: AbortSignal;
  stop: () => void;
};

type DurableJobRevision = Readonly<{
  scanId: number;
  revision: number;
}>;

type BootstrapPresence = 'inactive' | 'awaiting_workspace';

type RawSseMessage = Readonly<{ event: string; id?: string; data: string }>;

type RealtimeOptions = Readonly<{
  onState?: (state: RealtimeState) => void;
  onSourceOpen?: (command: SourceOpenCommand, signal: AbortSignal) => Promise<void>;
  wait?: (milliseconds: number, signal: AbortSignal) => Promise<void>;
  random?: () => number;
  maxReconnectFailures?: number;
  handshakeTimeoutMs?: number;
}>;


function abortError(): DOMException {
  return new DOMException('The CodeSecurity event subscription was stopped.', 'AbortError');
}


function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}


function abortableDelay(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(abortError());
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', stop);
      resolve();
    }, milliseconds);
    const stop = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', stop);
      reject(abortError());
    };
    signal.addEventListener('abort', stop, { once: true });
  });
}


function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}


function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}


function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => allowed.has(key));
}


function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}


function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}


function strictUtcTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/.exec(value);
  if (!match) return false;
  const [, year, month, day, hour, minute, second] = match;
  const parsed = new Date(value);
  return Number.isFinite(parsed.valueOf())
    && parsed.getUTCFullYear() === Number(year)
    && parsed.getUTCMonth() + 1 === Number(month)
    && parsed.getUTCDate() === Number(day)
    && parsed.getUTCHours() === Number(hour)
    && parsed.getUTCMinutes() === Number(minute)
    && parsed.getUTCSeconds() === Number(second);
}


type AuthoritativeScanJob = Readonly<{
  id: number;
  kind: 'scan';
  scan_id: number;
  revision: number;
}>;


export function validateAuthoritativeScanJob(
  value: unknown,
  jobId: number,
  scanId: number,
  minimumRevision: number,
): AuthoritativeScanJob {
  const job = record(value);
  if (
    !job
    || job.id !== jobId
    || job.kind !== 'scan'
    || job.scan_id !== scanId
    || !positiveInteger(job.revision)
    || job.revision < minimumRevision
  ) {
    throw new CodeSecurityRequestError(
      'CodeSecurity returned job state outside the active scan event revision.',
    );
  }
  return job as unknown as AuthoritativeScanJob;
}


const EVENT_AGGREGATES: Readonly<Record<DomainEventKind, DomainEvent['aggregate']['type']>> = Object.freeze({
  'project.changed': 'project',
  'scan.changed': 'scan',
  'job.changed': 'job',
  'findings.changed': 'findings',
});
const EVENT_KINDS = new Set(Object.keys(EVENT_AGGREGATES));
const CHANGES = new Set(['created', 'updated', 'deleted']);
const SCOPE_KEYS = new Set(['project_id', 'scan_id', 'job_id']);
const HINT_KEYS = new Set(['status', 'stage', 'progress', 'decision', 'count']);


export function validateDomainEvent(value: unknown, wireId?: string, wireEvent?: string): DomainEvent {
  const envelope = record(value);
  if (!envelope || !exactKeys(envelope, [
    'v', 'event_id', 'kind', 'aggregate', 'scope', 'change', 'hint', 'occurred_at',
  ])) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid event envelope.');
  }
  const kind = envelope.kind;
  if (
    envelope.v !== 1
    || !positiveInteger(envelope.event_id)
    || typeof kind !== 'string'
    || !EVENT_KINDS.has(kind)
    || wireEvent !== undefined && wireEvent !== kind
    || wireId !== undefined && wireId !== String(envelope.event_id)
    || typeof envelope.change !== 'string'
    || !CHANGES.has(envelope.change)
    || !strictUtcTimestamp(envelope.occurred_at)
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid event envelope.');
  }
  const typedKind = kind as DomainEventKind;
  const aggregate = record(envelope.aggregate);
  if (
    !aggregate
    || !exactKeys(aggregate, ['type', 'id', 'revision'])
    || aggregate.type !== EVENT_AGGREGATES[typedKind]
    || typeof aggregate.id !== 'string'
    || !/^[1-9][0-9]{0,18}$/.test(aggregate.id)
    || !positiveInteger(aggregate.revision)
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid event aggregate.');
  }
  const scope = record(envelope.scope);
  if (!scope || Object.keys(scope).some((key) => !SCOPE_KEYS.has(key))) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid event scope.');
  }
  for (const value of Object.values(scope)) {
    if (!positiveInteger(value)) throw new CodeSecurityRequestError('CodeSecurity returned an invalid event scope.');
  }
  const hasProject = positiveInteger(scope.project_id);
  const hasScan = positiveInteger(scope.scan_id);
  const hasJob = positiveInteger(scope.job_id);
  const scopeValid = typedKind === 'project.changed'
    ? hasProject && scope.project_id === Number(aggregate.id) && !hasScan && !hasJob
    : typedKind === 'scan.changed' || typedKind === 'findings.changed'
      ? hasProject && hasScan && scope.scan_id === Number(aggregate.id) && !hasJob
      // Installation jobs (catalog checks and cache preparation) have no
      // repository. Scan jobs carry both coordinates; a partial pair is never
      // enough to route or wake an active scan observer.
      : hasJob && scope.job_id === Number(aggregate.id) && hasProject === hasScan;
  if (!scopeValid) throw new CodeSecurityRequestError('CodeSecurity returned a misdirected event scope.');
  const hint = record(envelope.hint);
  if (!hint || Object.keys(hint).length > HINT_KEYS.size || Object.keys(hint).some((key) => !HINT_KEYS.has(key))) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid event hint.');
  }
  for (const value of Object.values(hint)) {
    if (value === null || typeof value === 'boolean') continue;
    if (
      typeof value === 'number'
      && Number.isSafeInteger(value)
      && value >= -(2 ** 31)
      && value <= 2 ** 31 - 1
    ) continue;
    if (
      typeof value === 'string'
      && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$/.test(value)
    ) continue;
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid event hint.');
  }
  return envelope as unknown as DomainEvent;
}


export function validateSourceOpenCommand(value: unknown): SourceOpenCommand {
  const command = record(value);
  const integerKeys = [
    'project_id',
    'scan_id',
    'finding_id',
    'scan_finding_number',
    'expected_finding_revision',
    'expected_findings_revision',
  ];
  if (
    !command
    || !exactKeys(command, [
      'v',
      'command_id',
      ...integerKeys,
      'expires_at',
    ])
    || command.v !== 1
    || typeof command.command_id !== 'string'
    || !/^[0-9a-f]{32}$/.test(command.command_id)
    || integerKeys.some((key) => !positiveInteger(command[key]))
    || !strictUtcTimestamp(command.expires_at)
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid targeted source-open command.');
  }
  return command as unknown as SourceOpenCommand;
}


export function validateStreamControl(value: unknown, reset: boolean): StreamControl {
  const control = record(value);
  if (
    !control
    || !exactKeys(control, ['v', 'highwater_event_id', 'earliest_event_id'], reset ? ['reason'] : [])
    || control.v !== 1
    || !nonNegativeInteger(control.highwater_event_id)
    || !nonNegativeInteger(control.earliest_event_id)
    || control.earliest_event_id > control.highwater_event_id + 1
    || reset && (typeof control.reason !== 'string' || !/^[a-z0-9_.-]{1,40}$/.test(control.reason))
  ) {
    throw new CodeSecurityRequestError('CodeSecurity returned an invalid event-stream control message.');
  }
  return control as unknown as StreamControl;
}


async function* rawMessages(response: Response, signal: AbortSignal): AsyncGenerator<RawSseMessage> {
  const reader = response.body!.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let buffer = '';
  let bufferBytes = 0;
  let event = '';
  let id: string | undefined;
  let data: string[] = [];
  let dataBytes = 0;
  const dispatch = (): RawSseMessage | undefined => {
    if (data.length === 0) {
      event = '';
      id = undefined;
      dataBytes = 0;
      return undefined;
    }
    const message = { event: event || 'message', id, data: data.join('\n') };
    event = '';
    id = undefined;
    data = [];
    dataBytes = 0;
    return message;
  };
  const line = (value: string): RawSseMessage | undefined => {
    if (!value) return dispatch();
    if (value.startsWith(':')) return undefined;
    const separator = value.indexOf(':');
    const field = separator < 0 ? value : value.slice(0, separator);
    let contents = separator < 0 ? '' : value.slice(separator + 1);
    if (contents.startsWith(' ')) contents = contents.slice(1);
    if (field === 'event') event = contents;
    if (field === 'id') {
      if (contents.includes('\0') || !/^[1-9][0-9]{0,18}$/.test(contents)) {
        throw new CodeSecurityRequestError('CodeSecurity returned an invalid event ID.');
      }
      id = contents;
    }
    if (field === 'data') {
      data.push(contents);
      dataBytes += utf8Bytes(contents);
      if (dataBytes > MAX_FRAME_BYTES) {
        throw new CodeSecurityRequestError('CodeSecurity returned an oversized event frame.');
      }
    }
    return undefined;
  };

  try {
    while (!signal.aborted) {
      const read = reader.read();
      const result = await new Promise<ReadableStreamReadResult<Uint8Array>>((resolve, reject) => {
        const stop = () => {
          clearTimeout(timeout);
          signal.removeEventListener('abort', stop);
          reject(abortError());
        };
        const timeout = setTimeout(() => {
          signal.removeEventListener('abort', stop);
          reject(new CodeSecurityRequestError(
            'The local event stream missed its bounded keepalive window.',
            undefined,
            true,
          ));
        }, STREAM_IDLE_TIMEOUT_MS);
        signal.addEventListener('abort', stop, { once: true });
        read.then(
          (value) => {
            clearTimeout(timeout);
            signal.removeEventListener('abort', stop);
            resolve(value);
          },
          (error) => {
            clearTimeout(timeout);
            signal.removeEventListener('abort', stop);
            if (isAbortError(error) || error instanceof CodeSecurityRequestError) {
              reject(error);
              return;
            }
            reject(new CodeSecurityRequestError(
              'The local event stream was interrupted while reading.',
              undefined,
              true,
            ));
          },
        );
      });
      if (!result.done) bufferBytes += result.value.byteLength;
      buffer += result.done ? decoder.decode() : decoder.decode(result.value, { stream: true });
      if (bufferBytes > MAX_BUFFER_BYTES) {
        throw new CodeSecurityRequestError('CodeSecurity returned an oversized event-stream buffer.');
      }
      let newline = buffer.indexOf('\n');
      while (newline >= 0) {
        const rawLine = buffer.slice(0, newline + 1);
        let value = rawLine.slice(0, -1);
        buffer = buffer.slice(newline + 1);
        bufferBytes = Math.max(0, bufferBytes - utf8Bytes(rawLine));
        if (value.endsWith('\r')) value = value.slice(0, -1);
        const message = line(value);
        if (message) yield message;
        newline = buffer.indexOf('\n');
      }
      if (result.done) {
        if (buffer) {
          const message = line(buffer.endsWith('\r') ? buffer.slice(0, -1) : buffer);
          if (message) yield message;
        }
        const finalMessage = dispatch();
        if (finalMessage) yield finalMessage;
        return;
      }
    }
    throw abortError();
  } catch (error) {
    if (signal.aborted) throw abortError();
    if (error instanceof TypeError) {
      throw new CodeSecurityRequestError('CodeSecurity returned malformed UTF-8 in the event stream.');
    }
    throw error;
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}


export async function consumeEventStream(
  response: Response,
  signal: AbortSignal,
  handlers: Readonly<{
    ready: (control: StreamControl) => Promise<void>;
    reset: (control: StreamControl) => Promise<void>;
    event: (event: DomainEvent) => Promise<void>;
    sourceOpen: (command: SourceOpenCommand) => Promise<void>;
  }>,
): Promise<'reset' | 'closed'> {
  let ready = false;
  for await (const message of rawMessages(response, signal)) {
    let payload: unknown;
    try {
      payload = JSON.parse(message.data);
    } catch {
      throw new CodeSecurityRequestError('CodeSecurity returned invalid JSON in the event stream.');
    }
    if (message.event === 'stream.ready') {
      if (ready || message.id !== undefined) {
        throw new CodeSecurityRequestError('CodeSecurity returned an invalid event-stream handshake.');
      }
      ready = true;
      await handlers.ready(validateStreamControl(payload, false));
      continue;
    }
    if (message.event === 'stream.reset') {
      if (!ready || message.id !== undefined) {
        throw new CodeSecurityRequestError('CodeSecurity returned an invalid event-stream reset.');
      }
      await handlers.reset(validateStreamControl(payload, true));
      return 'reset';
    }
    if (message.event === 'ide.source.open') {
      if (!ready || message.id !== undefined) {
        throw new CodeSecurityRequestError('CodeSecurity returned an invalid targeted source-open event.');
      }
      await handlers.sourceOpen(validateSourceOpenCommand(payload));
      continue;
    }
    if (!ready || !message.id) {
      throw new CodeSecurityRequestError('CodeSecurity returned a domain event before the stream handshake.');
    }
    await handlers.event(validateDomainEvent(payload, message.id, message.event));
  }
  if (!ready) throw new CodeSecurityRequestError('CodeSecurity closed the event stream before its handshake.');
  return 'closed';
}


function storedCursor(storage: CursorStorageLike, endpoint: string): number {
  const value = storage.get<unknown>(CURSOR_KEY);
  const candidate = record(value);
  return candidate
    && candidate.v === 1
    && candidate.endpoint === endpoint
    && nonNegativeInteger(candidate.event_id)
    ? candidate.event_id
    : 0;
}


export class RealtimeSync {
  private readonly workspaces = new Map<string, ManagedWorkspaceBinding>();
  private readonly jobWaiters = new Map<number, Set<JobWaiter>>();
  private readonly latestJobRevision = new Map<number, DurableJobRevision>();
  private readonly connectedWaiters = new Set<{ resolve: () => void; reject: (error: Error) => void; stop: () => void }>();
  private readonly wait: (milliseconds: number, signal: AbortSignal) => Promise<void>;
  private readonly random: () => number;
  private readonly maxReconnectFailures: number;
  private controller?: AbortController;
  private run?: Promise<void>;
  private state: RealtimeState = 'idle';
  private disposed = false;
  private stopAfterCursor = false;
  private reconciliationDemandGeneration = 0;
  private bootstrapPresence: BootstrapPresence = 'inactive';

  constructor(
    private readonly client: CodeSecurityClient,
    private readonly storage: CursorStorageLike,
    private readonly options: RealtimeOptions = {},
  ) {
    this.wait = options.wait || abortableDelay;
    this.random = options.random || Math.random;
    this.maxReconnectFailures = options.maxReconnectFailures ?? MAX_RECONNECT_FAILURES;
  }

  get currentState(): RealtimeState {
    return this.state;
  }

  bindWorkspace(key: string, binding: WorkspaceBinding): void {
    if (this.disposed) throw new Error('CodeSecurity real-time synchronization is disposed.');
    const existing = this.workspaces.get(key);
    const identityChanged = !existing
      || existing.projectId !== binding.projectId
      || existing.scanId !== binding.scanId;
    const managed: ManagedWorkspaceBinding = {
      ...binding,
      tail: existing?.tail || Promise.resolve(),
    };
    this.workspaces.set(key, managed);
    // Pairing keeps one capability stream present before a project exists so
    // Settings can truthfully target the exact editor. The first durable
    // workspace binding takes ownership of that demand; removing the last
    // binding can then stop the stream normally.
    this.bootstrapPresence = 'inactive';
    if (identityChanged) this.reconciliationDemandGeneration += 1;
    this.start();
    // If another workspace already owns a healthy shared stream, close the
    // snapshot-to-subscription gap for this newly added binding immediately.
    if (this.state === 'connected' && identityChanged) {
      const signal = this.controller?.signal;
      if (signal) void this.reconcileWorkspace(managed, undefined, signal).catch(() => this.restart());
    }
  }

  unbindWorkspace(key: string, afterCursor = false): void {
    this.workspaces.delete(key);
    if (afterCursor && this.workspaces.size === 0 && this.jobWaiters.size === 0) {
      // A deletion reconciliation owns the current stream signal. Let its
      // caller persist the event/reset cursor before stopping the last stream;
      // aborting here would turn a successful teardown into an endless replay.
      this.stopAfterCursor = true;
      return;
    }
    this.stopIfIdle();
  }

  updateWorkspaceScan(key: string, scanId: number | undefined): void {
    const current = this.workspaces.get(key);
    if (!current) return;
    if (current.scanId === scanId) return;
    this.workspaces.set(key, { ...current, scanId, tail: current.tail });
    this.reconciliationDemandGeneration += 1;
  }

  start(): void {
    if (this.disposed || this.run || !this.hasDemand()) return;
    const controller = new AbortController();
    this.controller = controller;
    this.setState('connecting');
    this.run = this.runLoop(controller.signal).catch((error: unknown) => {
      if (controller.signal.aborted || this.disposed) return;
      const unavailable = error instanceof Error
        ? error
        : new CodeSecurityRequestError('CodeSecurity event synchronization failed.');
      this.setState('unavailable');
      this.rejectConnected(unavailable);
      this.rejectJobs(unavailable);
    }).finally(() => {
      const restartAfterAbortedRun = controller.signal.aborted
        && !this.disposed
        && this.hasDemand();
      if (this.controller === controller) this.controller = undefined;
      this.run = undefined;
      if (restartAfterAbortedRun) this.start();
    });
  }

  async ensureConnected(signal: AbortSignal): Promise<void> {
    if (this.state === 'connected') return;
    if (this.state === 'pair required') throw new PairingRequiredError();
    // A retryable background owner can remain in unavailable while it waits
    // for its next bounded attempt. A new user action owns an immediate fresh
    // connection attempt instead of failing before its durable command is
    // submitted. Restart preserves the same authority, cursor, and demand;
    // it never rotates or silently replaces the stored capability.
    if (this.state === 'unavailable') this.restart();
    else this.start();
    if (signal.aborted) throw abortError();
    return new Promise((resolve, reject) => {
      const stop = () => {
        signal.removeEventListener('abort', stop);
        this.connectedWaiters.delete(waiter);
        reject(abortError());
      };
      const waiter = {
        resolve: () => {
          signal.removeEventListener('abort', stop);
          resolve();
        },
        reject: (error: Error) => {
          signal.removeEventListener('abort', stop);
          reject(error);
        },
        stop,
      };
      this.connectedWaiters.add(waiter);
      signal.addEventListener('abort', stop, { once: true });
    });
  }

  async reconnectPairedCapability(signal: AbortSignal): Promise<void> {
    if (this.disposed) {
      throw new CodeSecurityRequestError('CodeSecurity event synchronization is disposed.');
    }
    if (signal.aborted) throw abortError();
    // A fresh editor has no project binding yet, but its newly stored
    // capability must have exactly one live stream before Pair reports
    // connected. This bootstrap demand is bounded by the first real workspace
    // binding, authority reset, or disposal.
    this.bootstrapPresence = this.workspaces.size === 0 ? 'awaiting_workspace' : 'inactive';
    this.setState(this.run ? 'reconnecting' : 'connecting');
    // A re-pair rotates the bearer used by an existing stream. Abort it even if
    // it is healthy so the validated ready below belongs to the new authority.
    this.restart();
    await this.ensureConnected(signal);
  }

  waitForJob(jobId: number, scanId: number, afterRevision: number, signal: AbortSignal): Promise<void> {
    if (!positiveInteger(jobId) || !positiveInteger(scanId) || !positiveInteger(afterRevision)) {
      return Promise.reject(new CodeSecurityRequestError('CodeSecurity requires a valid job revision wait.'));
    }
    if (this.durableJobRevisionCovers(jobId, scanId, afterRevision)) return Promise.resolve();
    if (signal.aborted) return Promise.reject(abortError());
    return new Promise((resolve, reject) => {
      const remove = () => {
        signal.removeEventListener('abort', stop);
        const values = this.jobWaiters.get(jobId);
        values?.delete(waiter);
        if (values?.size === 0) this.jobWaiters.delete(jobId);
      };
      const stop = () => {
        remove();
        this.stopIfIdle();
        reject(abortError());
      };
      const finish = () => {
        remove();
        resolve();
      };
      const fail = (error: Error) => {
        remove();
        reject(error);
      };
      const waiter: JobWaiter = { scanId, afterRevision, resolve: finish, reject: fail, signal, stop };
      const values = this.jobWaiters.get(jobId) || new Set<JobWaiter>();
      values.add(waiter);
      this.jobWaiters.set(jobId, values);
      this.reconciliationDemandGeneration += 1;
      signal.addEventListener('abort', stop, { once: true });
      this.start();
      if (this.durableJobRevisionCovers(jobId, scanId, afterRevision)) finish();
    });
  }

  wakeAllJobs(): void {
    for (const values of [...this.jobWaiters.values()]) {
      for (const waiter of [...values]) waiter.resolve();
    }
  }

  restart(): void {
    if (this.disposed) return;
    this.controller?.abort();
    const prior = this.run;
    if (prior) {
      void prior.finally(() => this.start());
    } else {
      this.start();
    }
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.workspaces.clear();
    this.controller?.abort();
    const error = abortError();
    this.rejectConnected(error);
    for (const values of this.jobWaiters.values()) {
      for (const waiter of values) {
        waiter.signal.removeEventListener('abort', waiter.stop);
        waiter.reject(error);
      }
    }
    this.jobWaiters.clear();
    this.latestJobRevision.clear();
    this.bootstrapPresence = 'inactive';
    this.setState('idle');
  }

  private async runLoop(signal: AbortSignal): Promise<void> {
    const endpoint = this.client.endpointIdentity();
    let cursor = storedCursor(this.storage, endpoint);
    let failures = 0;
    let unavailabilityReported = false;
    while (!signal.aborted && !this.disposed && this.hasDemand()) {
      this.setState(failures === 0
        ? 'connecting'
        : unavailabilityReported
          ? 'unavailable'
          : 'reconnecting');
      const connection = new AbortController();
      const stopConnection = () => connection.abort();
      signal.addEventListener('abort', stopConnection, { once: true });
      let handshakeTimedOut = false;
      let handshakeComplete = false;
      let cursorAheadReady: StreamControl | undefined;
      const handshakeDeadline = setTimeout(() => {
        if (handshakeComplete) return;
        handshakeTimedOut = true;
        connection.abort();
      }, this.options.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS);
      try {
        const response = await this.client.openEventStream(cursor, connection.signal);
        const result = await consumeEventStream(response, connection.signal, {
          ready: async (control) => {
            if (control.highwater_event_id < cursor) {
              // The server intentionally sends ready before a cursor_ahead
              // reset. Do not reconcile, mark connected, or overwrite the
              // durable cursor until that reset is received and verified.
              cursorAheadReady = control;
              return;
            }
            // The wire handshake is complete once a validated normal ready is
            // received. REST reconciliation has its own request deadlines and
            // may legitimately exceed the short missing-handshake deadline.
            handshakeComplete = true;
            clearTimeout(handshakeDeadline);
            // A fresh stream may intentionally start at its current highwater.
            // Reconcile every bound REST projection before adopting that
            // highwater so pre-connect commits can never be silently skipped.
            const demandGeneration = await this.reconcileHighwaterDemand(connection.signal);
            const nextCursor = control.highwater_event_id;
            await this.persistCursor(endpoint, nextCursor);
            cursor = nextCursor;
            this.assertHighwaterDemandUnchanged(demandGeneration);
            this.commitAllReconciledJobRevisions();
            if (this.stopAfterCursorIfIdle() || signal.aborted || connection.signal.aborted) return;
            this.resolveAllReconciledJobWaiters();
            failures = 0;
            unavailabilityReported = false;
            handshakeComplete = true;
            clearTimeout(handshakeDeadline);
            this.setState('connected');
            this.resolveConnected();
          },
          reset: async (control) => {
            if (
              cursorAheadReady && (
                control.reason !== 'cursor_ahead'
                || control.highwater_event_id !== cursorAheadReady.highwater_event_id
                || control.earliest_event_id !== cursorAheadReady.earliest_event_id
              )
              || !cursorAheadReady && control.reason === 'cursor_ahead'
            ) {
              throw new CodeSecurityRequestError(
                'CodeSecurity returned an event-stream reset inconsistent with its highwater.',
              );
            }
            // A cursor-ahead ready intentionally leaves the handshake timer
            // armed until this required reset control arrives. Once validated,
            // do not apply that wire deadline to the ensuing REST gap close.
            handshakeComplete = true;
            clearTimeout(handshakeDeadline);
            const demandGeneration = await this.reconcileHighwaterDemand(connection.signal);
            const nextCursor = control.highwater_event_id;
            await this.persistCursor(endpoint, nextCursor);
            cursor = nextCursor;
            this.assertHighwaterDemandUnchanged(demandGeneration);
            this.commitAllReconciledJobRevisions();
            this.stopAfterCursorIfIdle();
            this.resolveAllReconciledJobWaiters();
            failures = 0;
            unavailabilityReported = false;
          },
          event: async (event) => {
            if (cursorAheadReady) {
              throw new CodeSecurityRequestError(
                'CodeSecurity returned a domain event before the required cursor reset.',
              );
            }
            if (event.kind === 'job.changed') {
              const jobId = Number(event.aggregate.id);
              const waiters = [...(this.jobWaiters.get(jobId) || [])]
                .filter((waiter) => event.aggregate.revision > waiter.afterRevision);
              if (waiters.length > 0) {
                const expectedScanId = waiters[0].scanId;
                if (
                  waiters.some((waiter) => waiter.scanId !== expectedScanId)
                  || event.scope.scan_id !== expectedScanId
                ) {
                  throw new CodeSecurityRequestError(
                    'CodeSecurity returned a job event outside the active workspace scan.',
                  );
                }
                await this.reconcileJob(
                  jobId,
                  expectedScanId,
                  event.aggregate.revision,
                  connection.signal,
                );
              }
            }
            if (event.event_id <= cursor) return;
            if (event.kind !== 'job.changed') {
              for (const binding of [...this.workspaces.values()]) {
                const relevant = event.scope.project_id === binding.projectId
                  || event.scope.scan_id !== undefined && event.scope.scan_id === binding.scanId;
                if (relevant) await this.reconcileWorkspace(binding, event, connection.signal);
              }
            }
            cursor = event.event_id;
            await this.persistCursor(endpoint, cursor);
            this.stopAfterCursorIfIdle();
            if (event.kind === 'job.changed' && event.scope.scan_id !== undefined) {
              const jobId = Number(event.aggregate.id);
              this.commitReconciledJobRevision(
                jobId,
                event.scope.scan_id,
                event.aggregate.revision,
              );
              this.resolveReconciledJobWaiters(jobId);
            }
            failures = 0;
          },
          sourceOpen: async (command) => {
            if (!this.options.onSourceOpen) {
              throw new CodeSecurityRequestError(
                'CodeSecurity received a source-open command without an active IDE handler.',
              );
            }
            await this.options.onSourceOpen(command, connection.signal);
            failures = 0;
          },
        });
        if (result === 'reset') continue;
        throw new CodeSecurityRequestError('The local event stream closed unexpectedly.', undefined, true);
      } catch (error) {
        if (signal.aborted || this.disposed) return;
        if (handshakeTimedOut) {
          error = new CodeSecurityRequestError(
            'The local event stream did not complete its handshake in time.',
            undefined,
            true,
          );
        } else if (isAbortError(error)) {
          // A workspace-local reconciliation can be aborted while other roots
          // still share this subscription. Only the outer stream signal above
          // authorizes shutdown; otherwise reconnect so remaining bindings do
          // not stay falsely "connected" without a live reader.
          error = new CodeSecurityRequestError(
            'A workspace event reconciliation was superseded; reconnecting for durable replay.',
            409,
            true,
          );
        }
        if (error instanceof PairingRequiredError) {
          this.setState('pair required');
          this.rejectConnected(error);
          this.rejectJobs(error);
          return;
        }
        const typedFailure = error instanceof CodeSecurityRequestError ? error : undefined;
        failures = Math.min(failures + 1, this.maxReconnectFailures + 1);
        if (failures > this.maxReconnectFailures) {
          const failureDetail = typedFailure
            ? ` Last connection failure: ${typedFailure.message}${typedFailure.status === undefined ? '' : ` (HTTP ${typedFailure.status})`}`
            : ' Last connection failure: the local client reported an unexpected stream error.';
          const unavailable = new CodeSecurityRequestError(
            (typedFailure?.retryable === true
              ? 'The local event stream is unavailable; persisted work continues and CodeSecurity will keep reconnecting in the background.'
              : 'The local event stream stayed unavailable; persisted work continues and a manual refresh can reconcile it.')
            + failureDetail,
            typedFailure?.status,
            typedFailure?.retryable,
            typedFailure ? {
              code: typedFailure.code,
              action: typedFailure.action,
              correlationId: typedFailure.correlationId,
              sourceBoundary: typedFailure.sourceBoundary,
            } : undefined,
          );
          if (!unavailabilityReported) {
            unavailabilityReported = true;
            this.setState('unavailable');
            this.rejectConnected(unavailable);
            this.rejectJobs(unavailable);
          }
          if (typedFailure?.retryable !== true || !this.hasDemand()) return;
        } else {
          this.setState('reconnecting');
        }
        const baseline = Math.min(250 * 2 ** (failures - 1), 15_000);
        const jitter = 0.75 + Math.min(Math.max(this.random(), 0), 1) * 0.5;
        await this.wait(Math.round(baseline * jitter), signal);
      } finally {
        clearTimeout(handshakeDeadline);
        signal.removeEventListener('abort', stopConnection);
        connection.abort();
      }
    }
    this.setState('idle');
  }

  private async persistCursor(endpoint: string, eventId: number): Promise<void> {
    const value: CursorRecord = { v: 1, endpoint, event_id: eventId };
    await this.storage.update(CURSOR_KEY, value);
  }

  private async reconcileHighwaterDemand(signal: AbortSignal): Promise<number> {
    const demandGeneration = this.reconciliationDemandGeneration;
    for (const binding of [...this.workspaces.values()]) {
      await this.reconcileWorkspace(binding, undefined, signal);
    }
    await this.reconcileActiveJobs(signal);
    this.assertHighwaterDemandUnchanged(demandGeneration);
    return demandGeneration;
  }

  private assertHighwaterDemandUnchanged(demandGeneration: number): void {
    if (this.reconciliationDemandGeneration === demandGeneration) return;
    throw new CodeSecurityRequestError(
      'CodeSecurity synchronization demand changed during highwater reconciliation; reconnecting before cursor adoption.',
      409,
      true,
    );
  }

  private reconcileWorkspace(
    binding: ManagedWorkspaceBinding,
    event: DomainEvent | undefined,
    signal: AbortSignal,
  ): Promise<void> {
    const task = binding.tail.then(() => {
      if (signal.aborted) throw abortError();
      const operation = event ? binding.onEvent(event, signal) : binding.onReset(signal);
      return Promise.race([
        operation,
        new Promise<never>((_resolve, reject) => {
          const stop = () => reject(abortError());
          signal.addEventListener('abort', stop, { once: true });
          void operation.finally(() => signal.removeEventListener('abort', stop)).catch(() => undefined);
        }),
      ]);
    });
    binding.tail = task.catch(() => undefined);
    return task;
  }

  private rememberJobRevision(jobId: number, scanId: number, revision: number): void {
    this.latestJobRevision.delete(jobId);
    this.latestJobRevision.set(jobId, { scanId, revision });
    while (this.latestJobRevision.size > MAX_TRACKED_JOB_REVISIONS) {
      const oldest = this.latestJobRevision.keys().next().value as number | undefined;
      if (oldest === undefined) return;
      this.latestJobRevision.delete(oldest);
    }
  }

  private durableJobRevisionCovers(jobId: number, scanId: number, afterRevision: number): boolean {
    const durable = this.latestJobRevision.get(jobId);
    return durable?.scanId === scanId && durable.revision > afterRevision;
  }

  private async reconcileActiveJobs(signal: AbortSignal): Promise<void> {
    for (const [jobId, values] of [...this.jobWaiters.entries()]) {
      const waiters = [...values];
      if (waiters.length === 0) continue;
      const scanId = waiters[0].scanId;
      if (waiters.some((waiter) => waiter.scanId !== scanId)) {
        throw new CodeSecurityRequestError('CodeSecurity active job waits crossed workspace scans.');
      }
      await this.reconcileJob(jobId, scanId, 1, signal);
    }
  }

  private async reconcileJob(
    jobId: number,
    scanId: number,
    minimumRevision: number,
    signal: AbortSignal,
  ): Promise<void> {
    const job = validateAuthoritativeScanJob(
      await this.client.request<unknown>(`/v1/jobs/${jobId}`, { signal }),
      jobId,
      scanId,
      minimumRevision,
    );
    const values = this.jobWaiters.get(jobId);
    const resolved: JobWaiter[] = [];
    for (const waiter of [...(values || [])]) {
      if (job.revision > waiter.afterRevision) resolved.push(waiter);
    }
    // Return the acknowledged job wait to its foreground observer only after
    // this caller persists the SSE cursor. This prevents the observer from
    // tearing down the shared stream between REST reconciliation and cursor
    // adoption.
    for (const waiter of resolved) waiter.reconciledRevision = job.revision;
  }

  private resolveReconciledJobWaiters(jobId: number): void {
    const values = this.jobWaiters.get(jobId);
    for (const waiter of [...(values || [])]) {
      if (
        (waiter.reconciledRevision || 0) > waiter.afterRevision
        || this.durableJobRevisionCovers(jobId, waiter.scanId, waiter.afterRevision)
      ) waiter.resolve();
    }
  }

  private commitReconciledJobRevision(jobId: number, scanId: number, eventRevision = 0): void {
    let revision = eventRevision;
    for (const waiter of this.jobWaiters.get(jobId) || []) {
      if (waiter.scanId !== scanId) continue;
      revision = Math.max(revision, waiter.reconciledRevision || 0);
    }
    if (revision > 0) this.rememberJobRevision(jobId, scanId, revision);
  }

  private commitAllReconciledJobRevisions(): void {
    for (const [jobId, values] of this.jobWaiters) {
      const waiter = values.values().next().value as JobWaiter | undefined;
      if (waiter) this.commitReconciledJobRevision(jobId, waiter.scanId);
    }
  }

  private resolveAllReconciledJobWaiters(): void {
    for (const jobId of [...this.jobWaiters.keys()]) this.resolveReconciledJobWaiters(jobId);
  }

  private setState(state: RealtimeState): void {
    if (this.state === state) return;
    this.state = state;
    this.options.onState?.(state);
  }

  private resolveConnected(): void {
    for (const waiter of [...this.connectedWaiters]) {
      this.connectedWaiters.delete(waiter);
      waiter.resolve();
    }
  }

  private rejectConnected(error: Error): void {
    for (const waiter of [...this.connectedWaiters]) {
      this.connectedWaiters.delete(waiter);
      waiter.reject(error);
    }
  }

  private rejectJobs(error: Error): void {
    for (const values of [...this.jobWaiters.values()]) {
      for (const waiter of [...values]) waiter.reject(error);
    }
    this.jobWaiters.clear();
  }

  private stopIfIdle(): void {
    if (!this.hasDemand()) {
      this.stopAfterCursor = false;
      this.controller?.abort();
      this.setState('idle');
    }
  }

  private stopAfterCursorIfIdle(): boolean {
    if (!this.stopAfterCursor) return false;
    this.stopAfterCursor = false;
    const stopped = !this.hasDemand();
    this.stopIfIdle();
    return stopped;
  }

  private hasDemand(): boolean {
    return this.bootstrapPresence === 'awaiting_workspace'
      || this.workspaces.size > 0
      || this.jobWaiters.size > 0;
  }
}
