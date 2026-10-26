const assert = require('node:assert/strict');
const test = require('node:test');
const { EventEmitter } = require('node:events');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');

// Exercise the maintained compiled module. Native spawning and timers are
// replaced; no installed extension or real storage is touched.
const compiled = readFileSync(require.resolve('../../dist/windows-private-path.js'), 'utf8');
const TARGET = String.raw`C:\Users\private-canary\AppData\Local\credential-canary`;
const SID = 'S-1-5-21-100-200-300-1001';
const PREFIX = '[Lomo CodeSecurity] Windows storage timeout detail:';

function fixture({phases=false}={}) {
  const state = { now: 0, clockThrows: false, logThrows: false, logs: [], timers: new Set(),
    timerDurations: [], children: [], microtasks: [], cleanupAtDetail: [] };
  class Child extends EventEmitter {
    constructor() {
      super(); this.stdout = new EventEmitter(); this.stderr = new EventEmitter();
      this.writes = []; this.killed = false; this.ended = false;
      this.stdin = new EventEmitter();
      this.stdin.write = (line, encoding, callback) => {
        assert.equal(encoding, 'utf8');
        this.writes.push({ request: JSON.parse(line), callback });
      };
      this.stdin.end = () => { this.ended = true; };
    }
    kill() { this.killed = true; return true; }
  }
  const processStub = new EventEmitter();
  processStub.env = { SystemRoot: String.raw`C:\Windows` };
  if(phases)processStub.env.LOMO_WINDOWS_STORAGE_PHASE_DIAGNOSTIC='1';
  const exports = {};
  vm.runInNewContext(compiled, {
    exports, module: { exports }, Buffer, TextDecoder,
    process: processStub,
    require(name) {
      if (name === 'node:child_process') return { spawn(executable,args) {
        const child = new Child(); child.args=args; state.children.push(child); return child;
      } };
      if (name === 'node:perf_hooks') return { performance: { now() {
        if (state.clockThrows) throw new Error('clock-canary');
        return state.now;
      } } };
      assert(['node:crypto', 'node:path'].includes(name));
      return require(name);
    },
    console: { warn(...args) {
      if (state.logThrows) throw new Error('log-canary');
      if (args[0] === PREFIX) state.cleanupAtDetail.push(
        state.children.every(child => child.killed)
        && ![...state.timers].some(timer => timer.duration === 10_000));
      state.logs.push(args);
    } },
    setTimeout(callback, duration) {
      const timer = { callback, duration, unref() {} };
      state.timers.add(timer); state.timerDurations.push(duration); return timer;
    },
    clearTimeout(timer) { state.timers.delete(timer); },
    queueMicrotask(callback) { state.microtasks.push(callback); },
  });
  const flush = () => { while (state.microtasks.length) state.microtasks.shift()(); };
  const expire = timer => { assert(state.timers.delete(timer)); timer.callback(); };
  const pendingTimer = () => [...state.timers].find(timer => timer.duration === 10_000);
  const proofLine = (child, index = child.writes.length - 1) => {
    const request = child.writes[index].request;
    const proof = { schema: 'lomo-windows-account-private/v1', path: request.path,
      current_sid: SID, owner_sid: SID, directory: true, reparse: false, protected: request.protect_new,
      rules: [{ sid: SID, allow: true, rights: 0x1f01ff, inherited: false, inheritance: 3, propagation: 0 }] };
    return Buffer.from(JSON.stringify({ request_id: request.request_id, proof }) + '\n');
  };
  const success = (child, index = child.writes.length - 1) => {
    child.stdout.emit('data',proofLine(child,index));
    flush();
  };
  const detail = () => {
    const rows = state.logs.filter(row => row[0] === PREFIX);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].length, 2);
    assert(rows[0][1].length < 1024);
    const value = JSON.parse(rows[0][1]);
    assert.equal(value.schema, 'lomo-windows-storage-timeout/v1');
    assert.deepEqual(Object.keys(value).sort(), [
      'schema', 'request_state', 'active_present', 'queued_count', 'closing',
      'dispatched', 'request_worker_current', 'worker_present', 'age_ms', 'queue_ms',
      'active_ms', 'write_callback_ms', 'worker_age_ms', 'spawn_observed_ms',
      'timeout_lateness_ms', 'timings_capped',
    ].sort());
    assert(value.queued_count <= 16);
    for (const [key, item] of Object.entries(value))
      if (key.endsWith('_ms')) assert(item === null || item <= 86_400_000);
    assert.deepEqual(state.cleanupAtDetail, [true], 'new log follows rejection and owned close request');
    const allowedStrings = new Set(['lomo-windows-storage-timeout/v1', 'active', 'queued', 'settled']);
    for (const item of Object.values(value)) {
      if (typeof item === 'string') assert(allowedStrings.has(item));
      else if (typeof item === 'number') assert(Number.isSafeInteger(item) && item >= 0 && item <= 1_000_000_000);
      else assert(item === null || typeof item === 'boolean');
    }
    const serialized = JSON.stringify(state.logs);
    for (const secret of [TARGET, SID, 'private-canary', 'credential-canary', 'clock-canary', 'log-canary',
      ...state.children.flatMap(child => child.writes.map(row => row.request.request_id))])
      assert(!serialized.includes(secret), 'diagnostics must not contain private inputs');
    return value;
  };
  const phaseLines=(child,index=child.writes.length-1)=>{
    const request=child.writes[index].request,read=['get_item','got_item','get_acl','got_acl','rules','got_rules'];
    const sequence=['request_read','parsed',...read,...(request.protect_new?['protect_new','protected_new',...read]:[]),'response_ready'];
    const frames=[];
    if(!child.phaseReady){frames.push(...['entered','ready'].map(phase=>({phase,ordinal:0,request_id:''})));child.phaseReady=true;}
    frames.push(...sequence.map(phase=>({phase,ordinal:index+1,request_id:phase==='request_read'?'':request.request_id})));
    return frames.map(frame=>({...frame,schema:'lomo-windows-storage-helper-phase/v1',elapsed_ms:(child.phaseElapsed=(child.phaseElapsed??0)+1)}));
  };
  const emitFrames=(child,frames)=>child.stdout.emit('data',Buffer.from(frames.map(frame=>JSON.stringify(frame)+'\n').join('')));
  const phaseSummary=()=>state.logs.filter(row=>row[0]==='[Lomo CodeSecurity] Windows storage helper phases:').map(row=>JSON.parse(row[1]));
  return { state, helper: exports, processStub, flush, expire, pendingTimer, success, detail, proofLine,phaseLines,emitFrames,phaseSummary };
}

test('active timeout records parent timings and keeps enqueue deadlines and failure fan-out', async () => {
  const f = fixture();
  const first = f.helper.verifyWindowsPrivatePath(TARGET, 'directory');
  const timer = f.pendingTimer();
  f.state.now = 5; f.state.children[0].emit('spawn');
  f.state.now = 20; f.state.children[0].writes[0].callback();
  f.state.now = 1000;
  const second = f.helper.verifyWindowsPrivatePath(TARGET, 'directory');
  const results = Promise.allSettled([first, second]);
  f.state.now = 10_125; f.expire(timer);
  assert.deepEqual((await results).map(row => row.reason.diagnosticReason), ['request_timeout', 'worker_failed']);
  const detail = f.detail();
  assert.equal(detail.request_state, 'active');
  assert.equal(detail.age_ms, 10_125); assert.equal(detail.queue_ms, 0);
  assert.equal(detail.active_ms, 10_125); assert.equal(detail.timeout_lateness_ms, 125);
  assert.equal(detail.write_callback_ms, 20); assert.equal(detail.spawn_observed_ms, 5);
  assert.equal(detail.queued_count, 1); assert.equal(detail.timings_capped, false);
  assert.deepEqual(f.state.timerDurations.filter(ms => ms === 10_000), [10_000, 10_000]);
  assert(f.state.children[0].killed);
  assert.equal([...f.state.timers].filter(row => row.duration === 10_000).length, 0);
});

test('time spent in the queue remains inside the same ten-second request clock', async () => {
  const f = fixture();
  const first = f.helper.verifyWindowsPrivatePath(TARGET, 'directory');
  f.state.now = 100;
  const second = f.helper.verifyWindowsPrivatePath(TARGET, 'directory');
  const settled = Promise.allSettled([first, second]);
  f.state.now = 9000; f.success(f.state.children[0]);
  f.state.now = 10_100; f.expire(f.pendingTimer());
  const results = await settled;
  assert.equal(results[0].status, 'fulfilled');
  assert.equal(results[1].reason.diagnosticReason, 'request_timeout');
  const detail = f.detail();
  assert.equal(detail.age_ms, 10_000); assert.equal(detail.queue_ms, 8900);
  assert.equal(detail.active_ms, 1100); assert.equal(detail.dispatched, true);
  assert.equal(detail.write_callback_ms, null);
});

test('queued expiry while a previous worker closes is classified without dispatch or a duplicate legacy line', async () => {
  const f = fixture();
  const first = f.helper.verifyWindowsPrivatePath(TARGET, 'directory');
  f.success(f.state.children[0]); await first;
  f.state.now = 100; f.processStub.env.SystemRoot = String.raw`D:\Windows`;
  const second = f.helper.verifyWindowsPrivatePath(TARGET, 'directory');
  const settled = Promise.allSettled([second]);
  assert(f.state.children[0].ended); assert.equal(f.state.children.length, 1);
  f.state.now = 10_100; f.expire(f.pendingTimer());
  assert.equal((await settled)[0].reason.diagnosticReason, 'worker_failed');
  const detail = f.detail();
  assert.equal(detail.request_state, 'queued'); assert.equal(detail.closing, true);
  assert.equal(detail.age_ms, 10_000); assert.equal(detail.queue_ms, 10_000);
  assert.equal(detail.active_ms, null); assert.equal(detail.request_worker_current, null);
  assert.equal(detail.active_present, false); assert.equal(detail.dispatched, false);
  assert.equal(f.state.logs.length, 1, 'the previous legacy reporting gate is unchanged');
  assert(f.state.children[0].killed);
});

test('a late successful write callback for an earlier request cannot annotate its successor', async () => {
  const f = fixture();
  const first = f.helper.verifyWindowsPrivatePath(TARGET, 'directory');
  const oldCallback = f.state.children[0].writes[0].callback;
  f.success(f.state.children[0]); await first;
  f.state.now = 100;
  const second = f.helper.verifyWindowsPrivatePath(TARGET, 'directory');
  const settled = Promise.allSettled([second]);
  f.state.now = 200; oldCallback();
  f.state.now = 10_100; f.expire(f.pendingTimer()); await settled;
  assert.equal(f.detail().write_callback_ms, null);
});

for (const invalidClock of ['throws', 'non-finite']) {
  test(`an unavailable monotonic clock (${invalidClock}) cannot prevent failure or owned cleanup`, async () => {
    const f = fixture();
    if (invalidClock === 'throws') f.state.clockThrows = true; else f.state.now = NaN;
    const pending = f.helper.verifyWindowsPrivatePath(TARGET, 'directory');
    const settled = Promise.allSettled([pending]);
    f.expire(f.pendingTimer());
    assert.equal((await settled)[0].reason.diagnosticReason, 'request_timeout');
    assert.equal(f.detail().age_ms, null); assert(f.state.children[0].killed);
  });
}

test('a closed diagnostic log destination cannot prevent rejection or owned cleanup', async () => {
  const f = fixture(); f.state.logThrows = true;
  const pending = f.helper.verifyWindowsPrivatePath(TARGET, 'directory');
  const settled = Promise.allSettled([pending]);
  f.expire(f.pendingTimer());
  assert.equal((await settled)[0].reason.diagnosticReason, 'request_timeout');
  assert(f.state.children[0].killed);
});

test('extreme scheduling delay is bounded and explicitly marked as capped', async () => {
  const f = fixture();
  const pending = f.helper.verifyWindowsPrivatePath(TARGET, 'directory');
  const settled = Promise.allSettled([pending]);
  f.state.now = 172_800_000; f.expire(f.pendingTimer()); await settled;
  const detail = f.detail();
  assert.equal(detail.age_ms, 86_400_000); assert.equal(detail.timings_capped, true);
});

test('successful fresh ACL verification produces no timeout diagnostic', async () => {
  const f = fixture();
  const pending = f.helper.verifyWindowsPrivatePath(TARGET, 'directory');
  f.success(f.state.children[0]); await pending;
  assert.equal(f.state.logs.length, 0);
  assert.equal([...f.state.timers].filter(row => row.duration === 10_000).length, 0);
  f.helper.disposeWindowsPrivatePathVerifier(); assert(f.state.children[0].killed);
});

test('opt-in phases do not resolve authority or renew the original enqueue timer',async()=>{
  const f=fixture({phases:true}),pending=f.helper.verifyWindowsPrivatePath(TARGET,'directory'),timer=f.pendingTimer();
  let resolved=false;pending.then(()=>{resolved=true;});
  const child=f.state.children[0];f.emitFrames(child,f.phaseLines(child));await Promise.resolve();
  assert.equal(resolved,false);assert(f.state.timers.has(timer));assert.deepEqual(f.state.timerDurations,[10000]);
  f.success(child);await pending;assert.equal(resolved,true);assert(!f.state.timers.has(timer));
  const [summary]=f.phaseSummary();assert.equal(summary.outcome,'verified');assert.equal(summary.phases.length,11);
  assert.equal(summary.phases.at(-1).phase,'response_ready');assert.equal(f.state.logs.length,1);
  for(const secret of[TARGET,SID,child.writes[0].request.request_id,'private-canary','credential-canary'])
    assert(!JSON.stringify(f.state.logs).includes(secret));
});

test('timeout retains the last helper phase and logs only after owned cleanup',async()=>{
  const f=fixture({phases:true}),pending=f.helper.verifyWindowsPrivatePath(TARGET,'directory'),settled=Promise.allSettled([pending]);
  const child=f.state.children[0];f.state.now=20;f.emitFrames(child,f.phaseLines(child).slice(0,7));
  f.state.now=10100;f.expire(f.pendingTimer());assert.equal((await settled)[0].reason.diagnosticReason,'request_timeout');
  const [summary]=f.phaseSummary();assert.equal(summary.outcome,'request_timeout');assert.equal(summary.phases.at(-1).phase,'get_acl');
  assert.equal(summary.worker_current,true);assert(child.killed);assert.deepEqual(f.state.cleanupAtDetail,[true]);f.detail();
});

test('queued timeout never borrows another active request helper phases',async()=>{
  const f=fixture({phases:true}),first=f.helper.verifyWindowsPrivatePath(TARGET,'directory'),firstTimer=f.pendingTimer();
  f.emitFrames(f.state.children[0],f.phaseLines(f.state.children[0]).slice(0,7));
  f.state.now=1;const second=f.helper.verifyWindowsPrivatePath(TARGET,'directory'),settled=Promise.allSettled([first,second]);
  const secondTimer=[...f.state.timers].find(timer=>timer.duration===10000&&timer!==firstTimer);
  f.state.now=10001;f.expire(secondTimer);await settled;
  const [summary]=f.phaseSummary();assert.equal(summary.request_state,'queued');assert.equal(summary.worker_current,null);
  assert.deepEqual(summary.phases,[]);assert.equal(f.detail().request_state,'queued');
});

test('coalesced and fragmented phase frames plus final proof retain strict framing',async()=>{
  for(const protectNew of[false,true]){
    const f=fixture({phases:true}),pending=f.helper.verifyWindowsPrivatePath(TARGET,'directory',protectNew),child=f.state.children[0];
    const frames=f.phaseLines(child),bytes=Buffer.concat([Buffer.from(frames.map(frame=>JSON.stringify(frame)+'\n').join('')),f.proofLine(child)]);
    child.stdout.emit('data',bytes.subarray(0,17));child.stdout.emit('data',bytes.subarray(17));await pending;
    assert.equal(f.phaseSummary()[0].phases.length,protectNew?19:11);assert.equal(child.killed,false);
  }
});

for(const [name,mutate]of[
  ['wrong request identity',frames=>{frames[3].request_id='0'.repeat(32);}],
  ['wrong request ordinal',frames=>{frames[2].ordinal=2;}],
  ['duplicate ready',frames=>{frames[2]={...frames[1]};}],
  ['out of order',frames=>{frames[4].phase='get_acl';}],
  ['negative time',frames=>{frames[0].elapsed_ms=-1;}],
  ['decreasing time',frames=>{frames[1].elapsed_ms=0;}],
  ['unbounded time',frames=>{frames[0].elapsed_ms=86400001;}],
  ['unknown keys',frames=>{frames[0].path=TARGET;}],
  ['unknown phase',frames=>{frames[0].phase='private-canary';}],
])test(`diagnostic ${name} refuses and closes without authority`,async()=>{
  const f=fixture({phases:true}),pending=f.helper.verifyWindowsPrivatePath(TARGET,'directory'),settled=Promise.allSettled([pending]);
  const child=f.state.children[0],frames=f.phaseLines(child);mutate(frames);f.emitFrames(child,frames);
  const[result]=await settled;assert.equal(result.status,'rejected');assert(child.killed);
  assert(!JSON.stringify(f.state.logs).includes('private-canary'));assert(!JSON.stringify(f.state.logs).includes(TARGET));
});

test('a proof without diagnostic phases and a second final frame both refuse',async()=>{
  for(const missing of[true,false]){
    const f=fixture({phases:true}),pending=f.helper.verifyWindowsPrivatePath(TARGET,'directory'),settled=Promise.allSettled([pending]);
    const child=f.state.children[0];if(!missing)f.emitFrames(child,f.phaseLines(child));
    child.stdout.emit('data',Buffer.concat([f.proofLine(child),...(missing?[]:[f.proofLine(child)])]));
    assert.equal((await settled)[0].status,'rejected');assert(child.killed);
  }
});

test('phase output stays inside the original cumulative16KiB response ceiling',async()=>{
  const f=fixture({phases:true}),pending=f.helper.verifyWindowsPrivatePath(TARGET,'directory'),settled=Promise.allSettled([pending]);
  const child=f.state.children[0];for(const frame of f.phaseLines(child)){
    child.stdout.emit('data',Buffer.from(JSON.stringify(frame)+' '.repeat(4000)+'\n'));if(child.killed)break;
  }
  assert.equal((await settled)[0].reason.diagnosticReason,'response_too_large');assert(child.killed);
});

test('late old-worker phases cannot annotate a successor and fresh requests reuse one worker',async()=>{
  const f=fixture({phases:true}),old=f.helper.verifyWindowsPrivatePath(TARGET,'directory'),oldSettled=Promise.allSettled([old]),oldChild=f.state.children[0];
  const oldFrames=f.phaseLines(oldChild);f.expire(f.pendingTimer());await oldSettled;oldChild.emit('close',0);
  for(let index=0;index<2;index++){
    const pending=f.helper.verifyWindowsPrivatePath(TARGET,'directory'),child=f.state.children[1];
    f.emitFrames(oldChild,oldFrames);f.emitFrames(child,f.phaseLines(child));f.success(child);f.flush();await pending;
  }
  assert.equal(f.state.children.length,2);assert.equal(f.state.children[1].writes.length,2);
  assert.deepEqual(f.phaseSummary().map(row=>row.outcome),['request_timeout','verified','verified']);
});

test('success summaries have a fixed cap but later timeouts retain their own phases',async()=>{
  const f=fixture({phases:true});
  for(let index=0;index<34;index++){
    const pending=f.helper.verifyWindowsPrivatePath(TARGET,'directory'),child=f.state.children[0];
    f.emitFrames(child,f.phaseLines(child));f.success(child);f.flush();await pending;
  }
  assert.equal(f.phaseSummary().length,32);assert.equal(f.phaseSummary().at(-1).success_summaries_capped,true);
  const pending=f.helper.verifyWindowsPrivatePath(TARGET,'directory'),settled=Promise.allSettled([pending]);
  f.expire(f.pendingTimer());await settled;
  assert.equal(f.phaseSummary().length,33);assert.equal(f.phaseSummary().at(-1).outcome,'request_timeout');
  assert.deepEqual(f.phaseSummary().at(-1).phases.map(row=>row.phase),['entered','ready']);
});

test('complete phases cannot authorize a private-path proof with broad ACL grants',async()=>{
  const f=fixture({phases:true}),pending=f.helper.verifyWindowsPrivatePath(TARGET,'directory'),settled=Promise.allSettled([pending]),child=f.state.children[0];
  f.emitFrames(child,f.phaseLines(child));const value=JSON.parse(f.proofLine(child));value.proof.rules.push({...value.proof.rules[0],sid:'S-1-1-0'});
  child.stdout.emit('data',Buffer.from(JSON.stringify(value)+'\n'));
  assert.equal((await settled)[0].reason.code,'windows_private_path_insecure');assert(child.killed);assert.deepEqual(f.phaseSummary(),[]);
});
