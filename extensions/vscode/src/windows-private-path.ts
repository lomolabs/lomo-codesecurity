import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import type { EventEmitter } from 'node:events';
import { win32 } from 'node:path';
import { performance } from 'node:perf_hooks';

const FULL_CONTROL = 0x1f01ff;
const SYSTEM_SID = 'S-1-5-18';
const ADMINISTRATORS_SID = 'S-1-5-32-544';
const SID = /^S-1-[0-9]{1,15}(?:-[0-9]{1,10}){1,15}$/u;
const REQUEST_ID = /^[0-9a-f]{32}$/u;
const REQUEST_TIMEOUT_MS = 10_000;
const IDLE_MS = 1_000;
const REAP_MS = 1_000;
const MAX_QUEUE = 16;
const MAX_RESPONSE_BYTES = 16 * 1024;
const PHASE_ENV = 'LOMO_WINDOWS_STORAGE_PHASE_DIAGNOSTIC';
const PHASE_SCHEMA = 'lomo-windows-storage-helper-phase/v1';
const MAX_PHASE_MS = 86_400_000;
const MAX_SUCCESS_SUMMARIES = 32;

export type WindowsPrivatePathFailure = 'unavailable' | 'permissions_refused' | 'disposed'
  | 'queue_full' | 'worker_failed' | 'request_timeout' | 'request_too_large'
  | 'helper_start' | 'helper_stderr' | 'helper_stdin' | 'helper_exit'
  | 'invalid_response' | 'response_identity' | 'unexpected_output' | 'response_too_large'
  | 'powershell_failed';

export class WindowsPrivatePathError extends Error {
  constructor(
    readonly code: 'windows_private_path_insecure' | 'windows_private_path_unavailable',
    readonly diagnosticReason: WindowsPrivatePathFailure = code === 'windows_private_path_insecure'
      ? 'permissions_refused' : 'unavailable',
  ) {
    super(code === 'windows_private_path_insecure'
      ? 'CodeSecurity requires account-private Windows storage owned by this user. Review permissions on this exact profile or installer state; existing permissions were not repaired.'
      : 'CodeSecurity could not verify Windows storage permissions. Restore access to Windows PowerShell and this exact profile or installer state before reconnecting.');
    this.name = 'WindowsPrivatePathError';
  }
}

export function canonicalWindowsLocalPath(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 4 && value.length <= 4096
    && /^[A-Za-z]:\\/u.test(value) && !/[<>:"/|?*\p{Cc}\p{Cf}]/u.test(value.slice(3))
    && value.slice(3).split('\\').every((part) => part.length > 0 && part !== '.' && part !== '..'
      && !/[. ]$/u.test(part) && !/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu.test(part))
    && win32.normalize(value) === value;
}

// Fixed metadata-only program. Paths use stdin, never shell interpolation;
// no bootstrap or profile credential bytes enter this process.
const ACL_COMMAND = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
function Refuse-PrivatePath { $script:failureCode = 'windows_private_path_insecure'; throw 'private-path-refused' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function Read-PrivateMetadata {
    $item = Get-Item -LiteralPath $metadataTarget -Force
    $acl = Get-Acl -LiteralPath $metadataTarget
    $access = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($access.Count -lt 1 -or $access.Count -gt 16 -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        [bool]$item.PSIsContainer -ne ($request.kind -eq 'directory') -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid) { Refuse-PrivatePath }
    $ownerFull = @($access | Where-Object { $_.IdentityReference.Value -eq $sid -and
        $_.AccessControlType -eq 'Allow' -and [int]$_.FileSystemRights -eq 0x1f01ff -and
        ([int]$_.PropagationFlags -band 2) -eq 0 }).Count -gt 0
    $rules = @($access | ForEach-Object {
        $trustee = $_.IdentityReference.Value
        $rights = [int]$_.FileSystemRights
        if ($_.AccessControlType -ne 'Allow' -or $trustee -notin @($sid,'S-1-5-18','S-1-5-32-544') -or
            $rights -le 0 -or ($rights -band 0x1f01ff) -ne $rights) { Refuse-PrivatePath }
        [ordered]@{sid=$trustee; allow=$true; rights=$rights; inherited=[bool]$_.IsInherited;
            inheritance=[int]$_.InheritanceFlags; propagation=[int]$_.PropagationFlags}
    })
    if (-not $ownerFull) { Refuse-PrivatePath }
    return [ordered]@{schema='lomo-windows-account-private/v1'; path=$target; current_sid=$sid;
        owner_sid=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;
        directory=[bool]$item.PSIsContainer; reparse=$false;
        protected=[bool]$acl.AreAccessRulesProtected; rules=$rules}
}
$raw = [Console]::In.ReadLine()
while ($null -ne $raw) {
  $failureCode = 'windows_private_path_unavailable'
  $requestId = ''
  try {
    if ($raw.Length -gt 8192) { Refuse-PrivatePath }
    $request = ConvertFrom-Json -InputObject $raw
    if (@($request.PSObject.Properties).Count -ne 4 -or
        $request.request_id -cnotmatch '^[0-9a-f]{32}$' -or
        $request.kind -notin @('directory','file') -or $request.protect_new -isnot [bool]) { Refuse-PrivatePath }
    $requestId = $request.request_id
    $target = [IO.Path]::GetFullPath($request.path)
    if ($target -notmatch '^[A-Za-z]:\\' -or $target.Length -lt 4 -or
        -not $target.Equals($request.path, [StringComparison]::OrdinalIgnoreCase)) { Refuse-PrivatePath }
    # Windows PowerShell's provider otherwise reports long existing paths as
    # missing. Keep the original canonical path in the proof; only native
    # filesystem calls receive the extended local-drive spelling.
    $metadataTarget = '\\?\' + $target
    $proof = Read-PrivateMetadata
    if ($request.protect_new) {
        $item = Get-Item -LiteralPath $metadataTarget -Force
        if ($request.kind -eq 'directory') {
            if (@(Get-ChildItem -LiteralPath $metadataTarget -Force | Select-Object -First 1).Count -ne 0) { Refuse-PrivatePath }
        } elseif ($item.Length -ne 0) { Refuse-PrivatePath }
        $acl = Get-Acl -LiteralPath $metadataTarget
        $acl.SetAccessRuleProtection($true, $true)
        Set-Acl -LiteralPath $metadataTarget -AclObject $acl
        $proof = Read-PrivateMetadata
    }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject ([ordered]@{request_id=$requestId; proof=$proof}) -Depth 6 -Compress))
  } catch {
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject ([ordered]@{request_id=$requestId; error_code=$failureCode}) -Compress))
    exit 1
  }
  $raw = [Console]::In.ReadLine()
}
`;

// The owned diagnostic launch selects this fixed variant. Derive it from the
// same permission program: markers never replace metadata or proof validation.
function diagnosticCommand(): string {
  let program = ACL_COMMAND;
  const replace = (before: string, after: string): void => {
    if (program.split(before).length !== 2) throw new Error('fixed Windows diagnostic seam changed');
    program = program.replace(before, after);
  };
  replace("$ErrorActionPreference = 'Stop'", String.raw`$ErrorActionPreference = 'Stop'
$lomoClock = [Diagnostics.Stopwatch]::StartNew()
$lomoOrdinal = 0
$requestId = ''
function Write-LomoPhase([string]$phase) {
    $elapsed = [Math]::Min([long]86400000, $lomoClock.ElapsedMilliseconds)
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject ([ordered]@{schema='lomo-windows-storage-helper-phase/v1'; phase=$phase; ordinal=$lomoOrdinal; request_id=$requestId; elapsed_ms=$elapsed}) -Compress))
    [Console]::Out.Flush()
}`);
  replace("$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "Write-LomoPhase 'entered'\n$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value");
  replace('    $item = Get-Item -LiteralPath $metadataTarget -Force\n    $acl = Get-Acl -LiteralPath $metadataTarget\n    $access =',
    "    Write-LomoPhase 'get_item'\n    $item = Get-Item -LiteralPath $metadataTarget -Force\n    Write-LomoPhase 'got_item'\n    Write-LomoPhase 'get_acl'\n    $acl = Get-Acl -LiteralPath $metadataTarget\n    Write-LomoPhase 'got_acl'\n    Write-LomoPhase 'rules'\n    $access =");
  replace('    return [ordered]@{schema=', "    Write-LomoPhase 'got_rules'\n    return [ordered]@{schema=");
  replace('$raw = [Console]::In.ReadLine()\nwhile', "Write-LomoPhase 'ready'\n$raw = [Console]::In.ReadLine()\nwhile");
  replace("  $requestId = ''\n  try {", "  $requestId = ''\n  $lomoOrdinal += 1\n  Write-LomoPhase 'request_read'\n  try {");
  replace('    $requestId = $request.request_id', "    $requestId = $request.request_id\n    Write-LomoPhase 'parsed'");
  replace('    if ($request.protect_new) {', "    if ($request.protect_new) {\n        Write-LomoPhase 'protect_new'");
  replace('        Set-Acl -LiteralPath $metadataTarget -AclObject $acl',
    "        Set-Acl -LiteralPath $metadataTarget -AclObject $acl\n        Write-LomoPhase 'protected_new'");
  replace('    [Console]::Out.WriteLine((ConvertTo-Json -InputObject ([ordered]@{request_id=$requestId; proof=$proof}) -Depth 6 -Compress))',
    "    $lomoResponse = ConvertTo-Json -InputObject ([ordered]@{request_id=$requestId; proof=$proof}) -Depth 6 -Compress\n    Write-LomoPhase 'response_ready'\n    [Console]::Out.WriteLine($lomoResponse)");
  return program;
}
const ACL_PHASE_COMMAND = diagnosticCommand();

export function windowsPrivatePathInvocation(
  target: string, kind: 'directory' | 'file', protectNew: boolean,
  environment: NodeJS.ProcessEnv = process.env,
): Readonly<{ executable: string; args: readonly string[]; input: string; requestId: string }> {
  if (!canonicalWindowsLocalPath(target) || !canonicalWindowsLocalPath(environment.SystemRoot)) {
    throw new WindowsPrivatePathError('windows_private_path_insecure');
  }
  const requestId = randomUUID().replaceAll('-', '');
  return Object.freeze({
    executable: win32.join(environment.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    args: Object.freeze(['-NoProfile', '-NonInteractive', '-Command',
      environment[PHASE_ENV] === '1' ? ACL_PHASE_COMMAND : ACL_COMMAND]),
    input: JSON.stringify({ request_id: requestId, path: target, kind, protect_new: protectNew }),
    requestId,
  });
}

export function validateWindowsPrivatePathProof(
  value: unknown, target: string, kind: 'directory' | 'file', requireProtected = false,
): void {
  const refuse = () => { throw new WindowsPrivatePathError('windows_private_path_insecure'); };
  if (!value || typeof value !== 'object' || Array.isArray(value)) return refuse();
  const proof = value as Record<string, unknown>;
  if (Object.keys(proof).sort().join(',') !== 'current_sid,directory,owner_sid,path,protected,reparse,rules,schema'
    || proof.schema !== 'lomo-windows-account-private/v1' || proof.path !== target
    || typeof proof.current_sid !== 'string' || !SID.test(proof.current_sid)
    || proof.owner_sid !== proof.current_sid || proof.directory !== (kind === 'directory') || proof.reparse !== false
    || typeof proof.protected !== 'boolean' || requireProtected && !proof.protected
    || !Array.isArray(proof.rules) || proof.rules.length < 1 || proof.rules.length > 16) return refuse();
  const trustees = new Set([proof.current_sid, SYSTEM_SID, ADMINISTRATORS_SID]);
  let ownerFull = false;
  for (const item of proof.rules) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return refuse();
    const rule = item as Record<string, unknown>;
    if (Object.keys(rule).sort().join(',') !== 'allow,inheritance,inherited,propagation,rights,sid'
      || typeof rule.sid !== 'string' || !trustees.has(rule.sid) || rule.allow !== true
      || typeof rule.inherited !== 'boolean' || !Number.isSafeInteger(rule.rights)
      || (rule.rights as number) <= 0 || ((rule.rights as number) & FULL_CONTROL) !== rule.rights
      || !Number.isInteger(rule.inheritance) || (rule.inheritance as number) < 0 || (rule.inheritance as number) > 3
      || !Number.isInteger(rule.propagation) || (rule.propagation as number) < 0 || (rule.propagation as number) > 3
      || kind === 'file' && (rule.inheritance !== 0 || rule.propagation !== 0)
      || proof.protected && rule.inherited) return refuse();
    if (rule.sid === proof.current_sid && rule.rights === FULL_CONTROL && ((rule.propagation as number) & 2) === 0) ownerFull = true;
  }
  if (!ownerFull) refuse();
}

type Invocation = ReturnType<typeof windowsPrivatePathInvocation>;
const READ_PHASES = ['get_item', 'got_item', 'get_acl', 'got_acl', 'rules', 'got_rules'] as const;
const PHASE_NAMES = new Set(['entered', 'ready', 'request_read', 'parsed', ...READ_PHASES,
  'protect_new', 'protected_new', 'response_ready']);
type PhaseEvent = { phase: string; helper_ms: number; parent_ms: number | null };
type RequestPhases = { ordinal: number; sequence: readonly string[]; events: PhaseEvent[]; bytes: number };
type WorkerPhases = { ready: PhaseEvent[]; ordinal: number; lastHelperMs: number };
type Pending = {
  invocation: Invocation;
  target: string;
  kind: 'directory' | 'file';
  protectNew: boolean;
  resolve: () => void;
  reject: (error: WindowsPrivatePathError) => void;
  timeout: NodeJS.Timeout;
  enqueuedAt: number | undefined;
  dispatchedAt?: number;
  writeCallbackAt?: number;
  workerTiming?: WorkerTiming;
  phases?: RequestPhases;
};

let worker: ChildProcessWithoutNullStreams | undefined;
let workerInvocation: Invocation | undefined;
let closing = false;
let disposed = false;
let active: Pending | undefined;
const queue: Pending[] = [];
let output = Buffer.alloc(0);
let idleTimer: NodeJS.Timeout | undefined;
let reapTimer: NodeJS.Timeout | undefined;
type WorkerTiming = { startedAt: number | undefined; spawnObservedAt?: number; phases?: WorkerPhases };
let workerTiming: WorkerTiming | undefined;
let successSummaries = 0;

function diagnosticNow(): number | undefined {
  try {
    const value = performance.now();
    return Number.isFinite(value) && value >= 0 ? value : undefined;
  } catch { return undefined; }
}

function timeoutDiagnostic(request: Pending): string | undefined {
  // Parent observations only. Neither spawn nor a write callback proves that
  // PowerShell is ready or that an ACL operation has begun or completed.
  try {
    const now = diagnosticNow();
    let capped = false;
    const elapsed = (start: number | undefined, end = now): number | null => {
      if (start === undefined || end === undefined || end < start) return null;
      const value = Math.floor(end - start);
      if (value > 86_400_000) capped = true;
      return Math.min(value, 86_400_000);
    };
    const age = elapsed(request.enqueuedAt);
    const detail = {
      schema: 'lomo-windows-storage-timeout/v1',
      request_state: active === request ? 'active' : queue.includes(request) ? 'queued' : 'settled',
      active_present: active !== undefined,
      queued_count: queue.length,
      closing,
      dispatched: request.workerTiming !== undefined,
      request_worker_current: request.workerTiming ? request.workerTiming === workerTiming : null,
      worker_present: worker !== undefined,
      age_ms: age,
      queue_ms: elapsed(request.enqueuedAt, request.dispatchedAt ?? now),
      active_ms: elapsed(request.dispatchedAt),
      write_callback_ms: request.writeCallbackAt === undefined ? null
        : elapsed(request.dispatchedAt, request.writeCallbackAt),
      worker_age_ms: elapsed(workerTiming?.startedAt),
      spawn_observed_ms: workerTiming?.spawnObservedAt === undefined ? null
        : elapsed(workerTiming.startedAt, workerTiming.spawnObservedAt),
      timeout_lateness_ms: age === null ? null : Math.max(0, age - REQUEST_TIMEOUT_MS),
      timings_capped: capped,
    };
    return JSON.stringify(detail);
  } catch { return undefined; }
}

function helperPhaseDiagnostic(request: Pending, outcome: 'verified' | 'request_timeout'): string | undefined {
  if (request.invocation.args[3] !== ACL_PHASE_COMMAND) return undefined;
  if (outcome === 'verified' && successSummaries >= MAX_SUCCESS_SUMMARIES) return undefined;
  if (outcome === 'verified') successSummaries += 1;
  try {
    // An undispatched timed request has no worker phases. Never borrow those
    // belonging to another active request merely because it shares the queue.
    const phases = request.phases ? [...(request.workerTiming?.phases?.ready ?? []), ...request.phases.events] : [];
    return JSON.stringify({ schema: 'lomo-windows-storage-helper-phases/v1', outcome,
      request_state: active === request ? 'active' : queue.includes(request) ? 'queued' : 'settled',
      worker_current: request.workerTiming ? request.workerTiming === workerTiming : null,
      success_summaries_capped: successSummaries >= MAX_SUCCESS_SUMMARIES,
      timings_capped: phases.some(phase => phase.helper_ms === MAX_PHASE_MS || phase.parent_ms === MAX_PHASE_MS), phases });
  } catch { return undefined; }
}

function reportHelperPhases(detail: string | undefined): void {
  if (detail === undefined) return;
  try { console.warn('[Lomo CodeSecurity] Windows storage helper phases:', detail); }
  catch { /* Diagnostic output cannot change a permission decision or cleanup. */ }
}

function unavailable(reason: WindowsPrivatePathFailure = 'unavailable'): WindowsPrivatePathError {
  return new WindowsPrivatePathError('windows_private_path_unavailable', reason);
}

function reportFailure(error: WindowsPrivatePathError): void {
  // Fixed local diagnostics only: never include paths, protocol bytes or stderr.
  try { console.warn('[Lomo CodeSecurity] Windows storage check failed:', error.diagnosticReason); }
  catch { /* A closed log destination must not interrupt rejection or cleanup. */ }
}

function refuseAdmission(reason: 'disposed' | 'queue_full'): WindowsPrivatePathError {
  const error = unavailable(reason);
  reportFailure(error);
  return error;
}

function rejectPending(request: Pending, error: WindowsPrivatePathError): void {
  clearTimeout(request.timeout);
  request.reject(error);
}

function clearIdle(): void {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = undefined;
}

function closeWorker(force: boolean): void {
  if (!worker) return;
  if (closing) { if (force) worker.kill(); return; }
  closing = true;
  clearIdle();
  if (force) worker.kill();
  else worker.stdin.end();
  const owned = worker;
  reapTimer = setTimeout(() => { if (worker === owned) owned.kill(); }, REAP_MS);
  reapTimer.unref();
}

function failWorker(error: WindowsPrivatePathError, report = true, timedRequest?: Pending): void {
  const detail = timedRequest && (active === timedRequest || queue.includes(timedRequest))
    ? timeoutDiagnostic(timedRequest) : undefined;
  const phases = timedRequest && (active === timedRequest || queue.includes(timedRequest))
    ? helperPhaseDiagnostic(timedRequest, 'request_timeout') : undefined;
  if (report && !closing && (active || queue.length > 0)) {
    reportFailure(error);
  }
  if (active) { rejectPending(active, error); active = undefined; }
  for (const request of queue.splice(0)) rejectPending(request, unavailable('worker_failed'));
  output = Buffer.alloc(0);
  closeWorker(true);
  // Snapshot before mutation, but do not delay rejection or owned cleanup with
  // another synchronous log write. Legacy reason reporting remains unchanged.
  if (detail !== undefined) {
    try { console.warn('[Lomo CodeSecurity] Windows storage timeout detail:', detail); }
    catch { /* A closed log destination cannot affect permission decisions. */ }
  }
  reportHelperPhases(phases);
}

function onHostExit(): void {
  worker?.kill();
}

function handlePhase(response: Record<string, unknown>, request: Pending): void {
  const state = request.phases, timing = request.workerTiming, owner = timing?.phases;
  if (!state || !owner || timing !== workerTiming
    || Object.keys(response).sort().join(',') !== 'elapsed_ms,ordinal,phase,request_id,schema'
    || response.schema !== PHASE_SCHEMA || typeof response.phase !== 'string' || !PHASE_NAMES.has(response.phase)
    || !Number.isSafeInteger(response.ordinal) || !Number.isSafeInteger(response.elapsed_ms)
    || (response.elapsed_ms as number) < owner.lastHelperMs || (response.elapsed_ms as number) > MAX_PHASE_MS) {
    failWorker(unavailable('invalid_response')); return;
  }
  const ready = response.phase === 'entered' || response.phase === 'ready';
  if (ready ? response.phase !== ['entered', 'ready'][owner.ready.length] || response.ordinal !== 0
      || response.request_id !== '' || state.events.length !== 0
    : owner.ready.length !== 2 || response.phase !== state.sequence[state.events.length]
      || response.ordinal !== state.ordinal
      || response.request_id !== (response.phase === 'request_read' ? '' : request.invocation.requestId)) {
    failWorker(unavailable('response_identity')); return;
  }
  const now = diagnosticNow();
  const elapsed = timing.startedAt === undefined || now === undefined || now < timing.startedAt
    ? null : Math.min(MAX_PHASE_MS, Math.floor(now - timing.startedAt));
  const event = { phase: response.phase, helper_ms: response.elapsed_ms as number, parent_ms: elapsed };
  owner.lastHelperMs = event.helper_ms;
  if (ready) owner.ready.push(event); else state.events.push(event);
}

function handleResponse(line: Buffer): void {
  const request = active;
  if (!request || closing) { failWorker(unavailable('unexpected_output')); return; }
  let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line)); }
  catch { failWorker(unavailable('invalid_response')); return; }
  if (!value || typeof value !== 'object' || Array.isArray(value)) { failWorker(unavailable('invalid_response')); return; }
  const response = value as Record<string, unknown>;
  if (request.phases && response.schema === PHASE_SCHEMA) { handlePhase(response, request); return; }
  if (response.request_id !== request.invocation.requestId || !REQUEST_ID.test(request.invocation.requestId)) {
    failWorker(unavailable('response_identity')); return;
  }
  if (Object.keys(response).sort().join(',') === 'error_code,request_id') {
    failWorker(new WindowsPrivatePathError(response.error_code === 'windows_private_path_insecure'
      ? 'windows_private_path_insecure' : 'windows_private_path_unavailable',
      response.error_code === 'windows_private_path_insecure' ? 'permissions_refused' : 'powershell_failed'));
    return;
  }
  if (Object.keys(response).sort().join(',') !== 'proof,request_id') { failWorker(unavailable('invalid_response')); return; }
  if (output.length) { failWorker(unavailable('unexpected_output')); return; }
  if (request.phases && (request.workerTiming?.phases?.ready.length !== 2
    || request.phases.events.length !== request.phases.sequence.length)) {
    failWorker(unavailable('invalid_response')); return;
  }
  try { validateWindowsPrivatePathProof(response.proof, request.target, request.kind, request.protectNew); }
  catch { failWorker(new WindowsPrivatePathError('windows_private_path_insecure')); return; }
  const phases = helperPhaseDiagnostic(request, 'verified');
  clearTimeout(request.timeout);
  active = undefined;
  request.resolve();
  queueMicrotask(pump);
  reportHelperPhases(phases);
}

function onOutput(chunk: Buffer): void {
  const request = active;
  const bytes = request?.phases ? request.phases.bytes + chunk.length : output.length + chunk.length;
  if (closing || !request || bytes > MAX_RESPONSE_BYTES) {
    failWorker(unavailable(bytes > MAX_RESPONSE_BYTES ? 'response_too_large' : 'unexpected_output')); return;
  }
  if (request.phases) request.phases.bytes = bytes;
  output = Buffer.concat([output, chunk]);
  do {
    const newline = output.indexOf(10);
    if (newline < 0) return;
    const line = output.subarray(0, newline);
    output = output.subarray(newline + 1);
    if (line.length === 0 || line.length > MAX_RESPONSE_BYTES) { failWorker(unavailable('invalid_response')); return; }
    handleResponse(line);
  } while (request.phases && active === request && !closing && output.length);
}

function startWorker(invocation: Invocation): void {
  const startedAt = diagnosticNow();
  try {
    worker = spawn(invocation.executable, [...invocation.args], {
      windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch { failWorker(unavailable('helper_start')); return; }
  const owned = worker;
  workerTiming = { startedAt, ...(invocation.args[3] === ACL_PHASE_COMMAND
    ? { phases: { ready: [], ordinal: 0, lastHelperMs: 0 } } : {}) };
  const timing = workerTiming;
  (owned as unknown as EventEmitter).on('spawn', () => {
    if (worker === owned) timing.spawnObservedAt = diagnosticNow();
  });
  workerInvocation = invocation;
  process.on('exit', onHostExit);
  owned.stdout.on('data', (chunk: Buffer) => { if (worker === owned) onOutput(chunk); });
  owned.stderr.on('data', () => { if (worker === owned) failWorker(unavailable('helper_stderr')); });
  owned.stdin.on('error', () => { if (worker === owned) failWorker(unavailable('helper_stdin')); });
  (owned as unknown as EventEmitter).on('error', () => { if (worker === owned) failWorker(unavailable('helper_start')); });
  (owned as unknown as EventEmitter).on('close', () => {
    if (worker !== owned) return;
    const wasClosing = closing;
    if (!wasClosing) failWorker(unavailable('helper_exit'));
    process.off('exit', onHostExit);
    if (reapTimer) clearTimeout(reapTimer);
    reapTimer = undefined;
    worker = undefined;
    workerTiming = undefined;
    workerInvocation = undefined;
    closing = false;
    output = Buffer.alloc(0);
    pump();
  });
}

function pump(): void {
  if (disposed || closing || active) return;
  clearIdle();
  if (queue.length === 0) {
    if (worker) {
      idleTimer = setTimeout(() => closeWorker(false), IDLE_MS);
      idleTimer.unref();
    }
    return;
  }
  if (worker && (workerInvocation?.executable !== queue[0].invocation.executable
    || workerInvocation.args.length !== queue[0].invocation.args.length
    || workerInvocation.args.some((argument, index) => argument !== queue[0].invocation.args[index]))) {
    closeWorker(false);
    return;
  }
  if (!worker) startWorker(queue[0].invocation);
  if (!worker || closing) return;
  active = queue.shift();
  if (!active) return;
  if (Buffer.byteLength(active.invocation.input, 'utf8') > 8192) { failWorker(unavailable('request_too_large')); return; }
  const owned = worker;
  const request = active;
  request.dispatchedAt = diagnosticNow();
  request.workerTiming = workerTiming;
  if (workerTiming?.phases) {
    const ordinal = ++workerTiming.phases.ordinal;
    if (!Number.isSafeInteger(ordinal)) { failWorker(unavailable('invalid_response')); return; }
    request.phases = { ordinal, bytes: 0, events: [], sequence: ['request_read', 'parsed', ...READ_PHASES,
      ...(request.protectNew ? ['protect_new', 'protected_new', ...READ_PHASES] : []), 'response_ready'] };
  }
  owned.stdin.write(request.invocation.input + '\n', 'utf8', (error) => {
    if (!error && worker === owned && active === request) request.writeCallbackAt = diagnosticNow();
    if (error && worker === owned) failWorker(unavailable('helper_stdin'));
  });
}

/** Stop only this helper's child; deactivation never leaves a PowerShell worker behind. */
export function disposeWindowsPrivatePathVerifier(): void {
  disposed = true;
  failWorker(unavailable('disposed'), false);
}

/** Re-arm only when the extension begins a new activation lifecycle. */
export function activateWindowsPrivatePathVerifier(): void {
  disposed = false;
  successSummaries = 0;
}

export async function verifyWindowsPrivatePath(target: string, kind: 'directory' | 'file', protectNew = false): Promise<void> {
  if (disposed) throw refuseAdmission('disposed');
  const invocation = windowsPrivatePathInvocation(target, kind, protectNew);
  if (queue.length >= MAX_QUEUE) throw refuseAdmission('queue_full');
  return new Promise<void>((resolve, reject) => {
    const request: Pending = {
      invocation, target, kind, protectNew, resolve, reject,
      enqueuedAt: diagnosticNow(),
      timeout: setTimeout(() => failWorker(unavailable('request_timeout'), true, request), REQUEST_TIMEOUT_MS),
    };
    queue.push(request);
    pump();
  });
}
