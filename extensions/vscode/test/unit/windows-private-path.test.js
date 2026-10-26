const assert = require('node:assert/strict');
const test = require('node:test');
const { EventEmitter } = require('node:events');
const Module = require('node:module');
const { createHash } = require('node:crypto');
const {
  canonicalWindowsLocalPath, validateWindowsPrivatePathProof, windowsPrivatePathInvocation, WindowsPrivatePathError,
} = require('../../dist/windows-private-path.js');

const TARGET = String.raw`C:\Users\qa\AppData\Local\lomo-kodesec`;
const CURRENT_SID = 'S-1-5-21-100-200-300-1001';
function metadata(directory = true) {
  return { schema: 'lomo-windows-account-private/v1', path: TARGET, current_sid: CURRENT_SID, owner_sid: CURRENT_SID,
    directory, reparse: false, protected: false,
    rules: [CURRENT_SID, 'S-1-5-18', 'S-1-5-32-544'].map((sid) => ({ sid, allow: true,
      rights: 0x1f01ff, inherited: true, inheritance: directory ? 3 : 0, propagation: 0 })) };
}

test('Windows production ACL permits only effective account-private grants, including safe inherited OS administrators', () => {
  for (const directory of [true, false]) {
    const kind = directory ? 'directory' : 'file';
    const proof = metadata(directory);
    validateWindowsPrivatePathProof(proof, TARGET, kind);
    assert.throws(() => validateWindowsPrivatePathProof(proof, TARGET, kind, true), WindowsPrivatePathError);
    proof.protected = true;
    proof.rules.forEach((rule) => { rule.inherited = false; });
    validateWindowsPrivatePathProof(proof, TARGET, kind, true);
    for (const change of [
      (p) => { p.owner_sid = 'S-1-5-18'; },
      (p) => { p.reparse = true; },
      (p) => { p.path = String.raw`C:\Users\other\state`; },
      (p) => { p.rules = []; },
      (p) => { p.rules[0].rights = 0x120089; },
      (p) => { p.rules[0].propagation = 2; },
      (p) => { p.rules[0].allow = false; },
      (p) => { p.rules[0].inherited = true; },
      (p) => { p.rules.push({ ...p.rules[0], sid: 'S-1-1-0' }); },
      (p) => { p.rules.push({ ...p.rules[0], sid: 'S-1-5-32-545', inherited: true }); },
      (p) => { p.rules.push({ ...p.rules[0], sid: 'S-1-5-21-100-200-300-1002' }); },
      (p) => { p.extra = true; },
    ]) {
      const invalid = structuredClone(proof); change(invalid);
      assert.throws(() => validateWindowsPrivatePathProof(invalid, TARGET, kind), WindowsPrivatePathError);
    }
  }
});

test('Windows permission invocation is fixed, bounded-path metadata without credential arguments or PATH lookup', () => {
  assert(canonicalWindowsLocalPath(TARGET));
  for (const path of [String.raw`C:\qa\NUL`, String.raw`C:\qa\folder `, String.raw`C:\qa\\state`, '/mnt/c/state']) {
    assert.equal(canonicalWindowsLocalPath(path), false);
  }
  const invocation = windowsPrivatePathInvocation(TARGET, 'directory', false, { SystemRoot: String.raw`C:\Windows` });
  assert.equal(invocation.executable, String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`);
  assert.equal(invocation.args.includes(TARGET), false);
  assert.match(invocation.requestId, /^[0-9a-f]{32}$/u);
  assert.deepEqual(JSON.parse(invocation.input), { request_id: invocation.requestId,
    path: TARGET, kind: 'directory', protect_new: false });
  assert.match(invocation.args.at(-1), /Get-Acl -LiteralPath \$metadataTarget/);
  assert.match(invocation.args.at(-1), /\$metadataTarget = '\\\\\?\\' \+ \$target/);
  assert.match(invocation.args.at(-1), /path=\$target/);
  assert.doesNotMatch(invocation.args.at(-1), /(?:Get-Item|Get-Acl|Set-Acl|Get-ChildItem) -LiteralPath \$target(?:\s|$)/m);
  assert.match(invocation.args.at(-1), /Read-PrivateMetadata/);
  assert.match(invocation.args.at(-1), /SetAccessRuleProtection\(\$true, \$true\)/);
  assert.match(invocation.args.at(-1), /\[Console\]::InputEncoding = \[System\.Text\.UTF8Encoding\]::new\(\$false\)/);
  assert.match(invocation.args.at(-1), /\[Console\]::OutputEncoding = \[System\.Text\.UTF8Encoding\]::new\(\$false\)/);
  assert.match(invocation.args.at(-1), /\[Console\]::In.ReadLine\(\)/);
  assert.doesNotMatch(invocation.args.at(-1), /Get-Content|ReadAllText|bootstrap_token|capability/);
  assert.throws(() => windowsPrivatePathInvocation(TARGET, 'file', false, {}), WindowsPrivatePathError);
});

test('only the exact owned phase opt-in selects a fixed diagnostic program; default native program is unchanged',()=>{
  const base={SystemRoot:String.raw`C:\Windows`},normal=windowsPrivatePathInvocation(TARGET,'directory',false,base);
  assert.equal(createHash('sha256').update(normal.args[3]).digest('hex'),'97d2e89426c353e79eef4f60b49fb7fb099565ded018b9dd7567fa5de5085f11');
  for(const value of[undefined,'','0','true','1\n'])assert.deepEqual(windowsPrivatePathInvocation(TARGET,'directory',false,
    {...base,LOMO_WINDOWS_STORAGE_PHASE_DIAGNOSTIC:value}).args,normal.args);
  const diagnostic=windowsPrivatePathInvocation(TARGET,'directory',false,{...base,LOMO_WINDOWS_STORAGE_PHASE_DIAGNOSTIC:'1'});
  assert.equal(diagnostic.args.length,4);assert.match(diagnostic.args[3],/Stopwatch/);
  assert.match(diagnostic.args[3],/Write-LomoPhase 'ready'/);assert.match(diagnostic.args[3],/Write-LomoPhase 'response_ready'/);
  assert.equal(diagnostic.args.includes(TARGET),false);assert.deepEqual(Object.keys(diagnostic),Object.keys(normal));
  assert.deepEqual(Object.keys(JSON.parse(diagnostic.input)),Object.keys(JSON.parse(normal.input)));
});

async function mockedWorker(respond, run, timerMap = (ms) => ms) {
  const modulePath = require.resolve('../../dist/windows-private-path.js');
  const priorModule = require.cache[modulePath];
  const priorLoad = Module._load;
  const priorRoot = process.env.SystemRoot;
  const priorSetTimeout = global.setTimeout;
  const priorWarn = console.warn;
  const diagnostics = [];
  const children = [];
  class FakeChild extends EventEmitter {
    constructor() {
      super();
      this.stdout = new EventEmitter();
      this.stderr = new EventEmitter();
      this.writes = [];
      this.killed = false;
      this.closed = false;
      this.deferWriteCallback = false;
      this.writeCallbacks = [];
      this.stdin = new EventEmitter();
      this.stdin.write = (line, encoding, callback) => {
        assert.equal(encoding, 'utf8');
        assert(line.endsWith('\n'));
        const request = JSON.parse(line);
        this.writes.push(request);
        respond(this, request);
        if (this.deferWriteCallback) this.writeCallbacks.push(callback);
        else callback();
      };
      this.stdin.end = () => { setImmediate(() => this.close()); };
    }
    close() { if (!this.closed) { this.closed = true; this.emit('close', 0); } }
    kill() { this.killed = true; setImmediate(() => this.close()); return true; }
  }
  Module._load = function (request, parent, isMain) {
    if (request === 'node:child_process' && parent?.filename === modulePath) return {
      spawn(executable, args, options) {
        assert.match(executable, /^[A-Z]:\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe$/u);
        assert.deepEqual(options.stdio, ['pipe', 'pipe', 'pipe']);
        assert.equal(options.windowsHide, true);
        assert.equal(args.includes(TARGET), false);
        const child = new FakeChild(); child.executable = executable; children.push(child); return child;
      },
    };
    return priorLoad.call(this, request, parent, isMain);
  };
  global.setTimeout = (callback, ms, ...args) => priorSetTimeout(callback, timerMap(ms), ...args);
  console.warn = (...args) => diagnostics.push(args);
  process.env.SystemRoot = String.raw`C:\Windows`;
  delete require.cache[modulePath];
  const helper = require(modulePath);
  try { await run(helper, children, diagnostics); }
  finally {
    helper.disposeWindowsPrivatePathVerifier();
    await new Promise((resolve) => setImmediate(resolve));
    Module._load = priorLoad;
    global.setTimeout = priorSetTimeout;
    console.warn = priorWarn;
    if (priorRoot === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = priorRoot;
    delete require.cache[modulePath];
    require.cache[modulePath] = priorModule;
  }
}

function success(child, request, proof = metadata(request.kind === 'directory')) {
  setImmediate(() => child.stdout.emit('data', Buffer.from(JSON.stringify({ request_id: request.request_id,
    proof: { ...proof, path: proof.path === TARGET ? request.path : proof.path } }) + '\r\n')));
}

test('one short-lived worker rechecks fresh ACL metadata for each request and refuses changed grants', async () => {
  let calls = 0;
  await mockedWorker((child, request) => {
    calls += 1;
    const proof = metadata();
    if (calls === 3) proof.rules.push({ ...proof.rules[0], sid: 'S-1-1-0' });
    success(child, request, proof);
  }, async (helper, children) => {
    await helper.verifyWindowsPrivatePath(TARGET, 'directory');
    await helper.verifyWindowsPrivatePath(TARGET, 'directory');
    assert.equal(children.length, 1);
    assert.equal(children[0].writes.length, 2);
    assert.notEqual(children[0].writes[0].request_id, children[0].writes[1].request_id);
    await assert.rejects(helper.verifyWindowsPrivatePath(TARGET, 'directory'),
      (error) => error.code === 'windows_private_path_insecure');
    assert.equal(children[0].killed, true);
  });
});

test('response ID or path mismatch kills the owned worker and late output cannot satisfy its successor', async () => {
  for (const mismatch of ['id', 'path']) {
    await mockedWorker((child, request) => {
      if (mismatch === 'id') success(child, { ...request, request_id: '0'.repeat(32) });
      else success(child, request, { ...metadata(), path: String.raw`C:\Users\other` });
    }, async (helper, children) => {
      await assert.rejects(helper.verifyWindowsPrivatePath(TARGET, 'directory'),
        (error) => error.code === 'windows_private_path_unavailable'
          || error.code === 'windows_private_path_insecure');
      assert.equal(children[0].killed, true);
      await new Promise((resolve) => setImmediate(resolve));
      children[0].stdout.emit('data', Buffer.from('{}\n'));
      const next = helper.verifyWindowsPrivatePath(TARGET, 'directory');
      await assert.rejects(next);
      assert.equal(children.length, 2);
    });
  }
});

test('request timeout rejects queued work, reaps the worker, and idle disposal closes it', async () => {
  await mockedWorker(() => {}, async (helper, children, diagnostics) => {
    const first = helper.verifyWindowsPrivatePath(TARGET, 'directory');
    const second = helper.verifyWindowsPrivatePath(TARGET, 'directory');
    await assert.rejects(first, (error) => error.code === 'windows_private_path_unavailable'
      && error.diagnosticReason === 'request_timeout');
    await assert.rejects(second, (error) => error.code === 'windows_private_path_unavailable'
      && error.diagnosticReason === 'worker_failed');
    assert.equal(diagnostics.length, 2);
    assert.deepEqual(diagnostics[0], ['[Lomo CodeSecurity] Windows storage check failed:', 'request_timeout']);
    assert.equal(diagnostics[1][0], '[Lomo CodeSecurity] Windows storage timeout detail:');
    assert.equal(JSON.parse(diagnostics[1][1]).request_state, 'active');
    assert.equal(children[0].killed, true);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(children[0].closed, true);
  }, (ms) => ms === 10_000 ? 10 : ms);
  await mockedWorker((child, request) => success(child, request), async (helper, children) => {
    await helper.verifyWindowsPrivatePath(TARGET, 'directory');
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.equal(children[0].closed, true);
    await helper.verifyWindowsPrivatePath(TARGET, 'directory');
    assert.equal(children.length, 2);
    helper.disposeWindowsPrivatePathVerifier();
    assert.equal(children[1].killed, true);
  }, (ms) => ms === 1_000 ? 5 : ms);
});

for (const [reason, respond] of [
  ['helper_stderr', (child) => child.stderr.emit('data', Buffer.from('private-canary C:\\sensitive\\profile'))],
  ['helper_stdin', (child) => child.stdin.emit('error', new Error('private-canary'))],
  ['helper_start', (child) => child.emit('error', new Error('private-canary'))],
  ['helper_exit', (child) => child.close()],
  ['invalid_response', (child) => child.stdout.emit('data', Buffer.from('private-canary\n'))],
  ['response_identity', (child) => child.stdout.emit('data', Buffer.from('{"request_id":"wrong"}\n'))],
  ['powershell_failed', (child, request) => child.stdout.emit('data', Buffer.from(JSON.stringify({
    request_id: request.request_id, error_code: 'windows_private_path_unavailable',
  }) + '\n'))],
]) {
  test(`Windows failure diagnostics identify ${reason} without private data or duplicate queue reports`, async () => {
    await mockedWorker((child, request) => setImmediate(() => respond(child, request)),
      async (helper, children, diagnostics) => {
        const results = await Promise.allSettled([
          helper.verifyWindowsPrivatePath(TARGET, 'directory'),
          helper.verifyWindowsPrivatePath(TARGET, 'directory'),
        ]);
        assert(results.every(result => result.status === 'rejected'));
        assert.equal(results[0].reason.diagnosticReason, reason);
        assert.equal(results[1].reason.diagnosticReason, 'worker_failed');
        assert.deepEqual(diagnostics, [['[Lomo CodeSecurity] Windows storage check failed:', reason]]);
        assert.equal(children[0].closed || children[0].killed, true);
        assert(!JSON.stringify(diagnostics).includes('private-canary'));
        assert(!JSON.stringify(diagnostics).includes(TARGET));
      });
  });
}

test('queue admission remains bounded and reports its distinct safe failure reason', async () => {
  await mockedWorker(() => {}, async (helper, children, diagnostics) => {
    const pending = Array.from({ length: 17 }, () => helper.verifyWindowsPrivatePath(TARGET, 'directory'));
    const settled = Promise.allSettled(pending);
    await assert.rejects(helper.verifyWindowsPrivatePath(TARGET, 'directory'), error =>
      error.code === 'windows_private_path_unavailable' && error.diagnosticReason === 'queue_full');
    assert.equal(children.length, 1);
    assert.equal(children[0].writes.length, 1);
    children[0].stderr.emit('data', Buffer.from('private-canary'));
    assert((await settled).every(result => result.status === 'rejected'));
    assert.deepEqual(diagnostics, [
      ['[Lomo CodeSecurity] Windows storage check failed:', 'queue_full'],
      ['[Lomo CodeSecurity] Windows storage check failed:', 'helper_stderr'],
    ]);
  });
});

test('an unavailable log destination cannot prevent refusal or owned-worker cleanup', async () => {
  await mockedWorker(child => setImmediate(() => child.stderr.emit('data', Buffer.from('private-canary'))),
    async (helper, children) => {
      console.warn = () => { throw new Error('closed log destination'); };
      await assert.rejects(helper.verifyWindowsPrivatePath(TARGET, 'directory'), error =>
        error.code === 'windows_private_path_unavailable' && error.diagnosticReason === 'helper_stderr');
      assert.equal(children[0].killed, true);
    });
});

test('protect-new checks require a new protected proof and explicit ACL refusal stays insecure', async () => {
  await mockedWorker((child, request) => {
    if (request.protect_new) {
      const proof = metadata();
      proof.protected = true;
      proof.rules.forEach((rule) => { rule.inherited = false; });
      success(child, request, proof);
    } else setImmediate(() => child.stdout.emit('data', Buffer.from(JSON.stringify({
      request_id: request.request_id, error_code: 'windows_private_path_insecure',
    }) + '\n')));
  }, async (helper, children) => {
    await helper.verifyWindowsPrivatePath(TARGET, 'directory', true);
    assert.equal(children[0].writes[0].protect_new, true);
    await assert.rejects(helper.verifyWindowsPrivatePath(TARGET, 'directory'),
      (error) => error.code === 'windows_private_path_insecure');
    assert.equal(children[0].killed, true);
  });
});

test('unsolicited second line rejects the request before it can authorize another one', async () => {
  await mockedWorker((child, request) => {
    const proof = metadata();
    child.stdout.emit('data', Buffer.from(JSON.stringify({ request_id: request.request_id, proof })
      + '\n' + JSON.stringify({ request_id: request.request_id, proof }) + '\n'));
  }, async (helper, children) => {
    await assert.rejects(helper.verifyWindowsPrivatePath(TARGET, 'directory'),
      (error) => error.code === 'windows_private_path_unavailable');
    assert.equal(children[0].killed, true);
    assert.equal(children[0].writes.length, 1);
  });
});

test('Unicode profile paths retain exact UTF-8 request bytes; controls never reach the worker', async () => {
  const unicode = String.raw`C:\Users\Žana\AppData\Local\lomo-kodesec`;
  await mockedWorker((child, request) => success(child, request), async (helper, children) => {
    await helper.verifyWindowsPrivatePath(unicode, 'directory');
    assert.equal(children[0].writes[0].path, unicode);
    for (const invalid of [String.raw`C:\Users\qa\bad` + '\n' + 'path', String.raw`C:\Users\qa\bad` + '\r' + 'path']) {
      await assert.rejects(helper.verifyWindowsPrivatePath(invalid, 'directory'),
        (error) => error.code === 'windows_private_path_insecure');
    }
    assert.equal(children[0].writes.length, 1);
  });
});

test('invalid UTF-8 response bytes are refused before proof parsing', async () => {
  await mockedWorker((child) => setImmediate(() => child.stdout.emit('data', Buffer.from([0xff, 0x0a]))),
    async (helper, children) => {
      await assert.rejects(helper.verifyWindowsPrivatePath(TARGET, 'directory'),
        (error) => error.code === 'windows_private_path_unavailable');
      assert.equal(children[0].killed, true);
    });
});

test('a changed SystemRoot starts a newly bound worker after the prior child closes', async () => {
  await mockedWorker((child, request) => success(child, request), async (helper, children) => {
    await helper.verifyWindowsPrivatePath(TARGET, 'directory');
    process.env.SystemRoot = String.raw`D:\Windows`;
    await helper.verifyWindowsPrivatePath(TARGET, 'directory');
    assert.equal(children.length, 2);
    assert.equal(children[0].closed, true);
    assert.equal(children[0].executable, String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`);
    assert.equal(children[1].executable, String.raw`D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`);
  });
});

test('deactivation fences new requests and a late old write error cannot kill a successor', async () => {
  await mockedWorker((child, request) => {
    if (request.path === TARGET && child.executable.startsWith('C:')) child.deferWriteCallback = true;
    success(child, request);
  }, async (helper, children) => {
    await helper.verifyWindowsPrivatePath(TARGET, 'directory');
    helper.disposeWindowsPrivatePathVerifier();
    await assert.rejects(helper.verifyWindowsPrivatePath(TARGET, 'directory'),
      (error) => error.code === 'windows_private_path_unavailable');
    await new Promise((resolve) => setImmediate(resolve));
    helper.activateWindowsPrivatePathVerifier();
    process.env.SystemRoot = String.raw`D:\Windows`;
    await helper.verifyWindowsPrivatePath(TARGET, 'directory');
    assert.equal(children.length, 2);
    children[0].writeCallbacks[0](new Error('late old write failure'));
    assert.equal(children[1].killed, false);
  });
});
