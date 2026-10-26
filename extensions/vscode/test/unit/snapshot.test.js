const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { linkSync, mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  NATIVE_WINDOWS_SNAPSHOT_HELPER,
  admittedNativeWindowsSourceSnapshot,
  collectNativeWindowsSourceSnapshot,
  runBoundedSnapshotHelper,
  admittedSourceSnapshotLimits,
  SOURCE_SNAPSHOT_LIMITS,
} = require('../../dist/snapshot.js');
const { sourceTargetForFileUri, sourceTargetForUri } = require('../../dist/source.js');

function uri(fsPath) {
  const uriPath = `/${fsPath.replaceAll('\\', '/')}`;
  return {
    scheme: 'file', authority: '', path: uriPath, fsPath,
    toString: () => `file://${uriPath}`,
  };
}

function entry(relativePath, text) {
  const content = Buffer.from(text);
  return {
    path: relativePath,
    content_base64: content.toString('base64'),
    sha256: createHash('sha256').update(content).digest('hex'),
    size_bytes: content.length,
  };
}

test('native transfer admits large unchanged regular assets and keeps exact bounds and digests', async () => {
  const root = { name: 'project', uri: uri(String.raw`C:\work\project`) };
  const target = sourceTargetForUri(root.uri, [root], 'win32');
  for (const size of [1_997_816, 5_800_000, 8 * 1024 * 1024]) {
    const content = Buffer.alloc(size, 0x89);
    const file = entry('docs/image.png', content);
    const upload = await collectNativeWindowsSourceSnapshot(target, undefined,
      async () => ({ directory_scope: null, files: [file] }));
    assert.deepEqual(Buffer.from(upload.files[0].content_base64, 'base64'), content);
    assert.equal(upload.files[0].sha256, file.sha256);
    await assert.rejects(collectNativeWindowsSourceSnapshot(target, undefined,
      async () => ({ directory_scope: null, files: [{ ...file, sha256: '0'.repeat(64) }] })), /immutable binding/);
  }
  await assert.rejects(collectNativeWindowsSourceSnapshot(target, undefined,
    async () => ({ directory_scope: null, files: [entry('image.png', Buffer.alloc(8 * 1024 * 1024 + 1))] })), /base64|immutable binding/);
});

test('source transfer capability refuses older, malformed, or widened contracts', () => {
  assert.deepEqual(admittedSourceSnapshotLimits({ ...SOURCE_SNAPSHOT_LIMITS }), SOURCE_SNAPSHOT_LIMITS);
  for (const value of [undefined, {}, { ...SOURCE_SNAPSHOT_LIMITS, max_file_bytes: 1_048_576 },
    { ...SOURCE_SNAPSHOT_LIMITS, max_total_bytes: 128 * 1024 * 1024 },
    { ...SOURCE_SNAPSHOT_LIMITS, eligible_source_max_file_bytes: 8 * 1024 * 1024 }]) {
    assert.throws(() => admittedSourceSnapshotLimits(value), /source-transfer contract/);
  }
});

test('descriptor helper transfers large regular assets unchanged and refuses hard links', () => {
  withHelper(({ temporary, helperPath }) => {
    const root = path.join(temporary, 'approved');
    mkdirSync(root);
    const assets = [Buffer.alloc(1_997_816, 0x89), Buffer.alloc(5_800_000, 0x80)];
    assets.forEach((content, index) => writeFileSync(path.join(root, `image-${index}.png`), content));
    const result = spawnSync('python3', ['-I', helperPath, '--root-posix', root],
      { encoding: 'utf8', maxBuffer: 112 * 1024 * 1024 });
    assert.equal(result.status, 0, result.stderr);
    const files = JSON.parse(result.stdout).files;
    files.forEach((file, index) => {
      assert.deepEqual(Buffer.from(file.content_base64, 'base64'), assets[index]);
      assert.equal(file.sha256, createHash('sha256').update(assets[index]).digest('hex'));
    });
    linkSync(path.join(root, 'image-0.png'), path.join(root, 'hard-linked.png'));
    const linked = spawnSync('python3', ['-I', helperPath, '--root-posix', root],
      { encoding: 'utf8', maxBuffer: 112 * 1024 * 1024 });
    assert.equal(linked.status, 23);
    assert.equal(linked.stdout, '');
    assert.equal(JSON.parse(linked.stderr).code, 'non_regular_entry');
  });
});

test('descriptor transfer preserves the complete whole/folder source and control universe, excluding only exact .git directories', () => {
  withHelper(({ temporary, helperPath }) => {
    const root = path.join(temporary, 'approved');
    const contents = new Map([
      ['README.md', Buffer.from('root only\n')],
      ['selected/.gitleaksignore', Buffer.from('preserve control bytes\n')],
      ['selected/.gitleaks.toml', Buffer.from('[allowlist]\nregexes=[".*"]\n')],
      ['selected/.gitignore', Buffer.from('vendor/\ndist/\n')],
      ...['vendor', 'dist', 'node_modules', 'build', 'target', '.venv', 'venv', '__pycache__',
        '.next', '.turbo', '.cache', '.kodesec-state', '.hg', '.svn', '.GIT']
        .map((directory, i) => [`selected/${directory}/source-${i}.js`, Buffer.from(`source-${i}\n`)]),
      ['selected/vendor/asset.bin', Buffer.from([0, 255, 127, 0, 128])],
      ['selected/plain/.git', Buffer.from('regular .git is not a directory\n')],
    ]);
    for (const [name, bytes] of contents) {
      const destination = path.join(root, ...name.split('/'));
      mkdirSync(path.dirname(destination), { recursive: true }); writeFileSync(destination, bytes);
    }
    for (const metadata of ['.git/objects/blob', 'selected/subtree/.git/config', 'selected/vendor/.git/config']) {
      const destination = path.join(root, ...metadata.split('/'));
      mkdirSync(path.dirname(destination), { recursive: true }); writeFileSync(destination, 'excluded Git metadata\n');
    }
    for (const directory of [null, 'selected']) {
      const argv = ['-I', helperPath, '--root-posix', root, ...(directory ? ['--target-directory', directory] : [])];
      const result = spawnSync('python3', argv, { encoding: 'utf8', timeout: 15_000, maxBuffer: 112 * 1024 * 1024 });
      assert.equal(result.status, 0, result.stderr);
      const actual = JSON.parse(result.stdout), expected = [...contents].filter(([name]) => !directory || name.startsWith(directory + '/'));
      assert.equal(actual.directory_scope, directory);
      assert.deepEqual(actual.files.map(file => file.path).sort(), expected.map(([name]) => name).sort());
      for (const file of actual.files) {
        const bytes = contents.get(file.path);
        assert.deepEqual(Buffer.from(file.content_base64, 'base64'), bytes);
        assert.equal(file.size_bytes, bytes.length);
        assert.equal(file.sha256, createHash('sha256').update(bytes).digest('hex'));
      }
      assert.equal(result.stdout.includes('excluded Git metadata'), false);
    }
    symlinkSync(path.join(root, 'README.md'), path.join(root, 'selected', 'vendor', 'linked.js'));
    const linked = spawnSync('python3', ['-I', helperPath, '--root-posix', root], { encoding: 'utf8', timeout: 15_000 });
    assert.equal(linked.status, 23); assert.equal(linked.stdout, '');
    assert.equal(JSON.parse(linked.stderr).code, 'linked_entry');
  });
});

test('formerly excluded source cannot silently evade the unchanged capture file-size, file-count or total-byte bounds', () => {
  withHelper(({ temporary, helperPath }) => {
    for (const scope of ['vendor', 'dist', '.kodesec-data']) {
      const root = path.join(temporary, scope), selected = path.join(root, scope);
      mkdirSync(selected, { recursive: true });
      if (scope === 'vendor') writeFileSync(path.join(selected, 'large.js'), Buffer.alloc(8 * 1024 * 1024 + 1));
      else if (scope === 'dist') for (let i = 0; i <= 5_000; i++) writeFileSync(path.join(selected, `${i}.js`), 'x');
      else { const bytes = Buffer.alloc(8 * 1024 * 1024);
        for (let i = 0; i < 8; i++) writeFileSync(path.join(selected, `${i}.bin`), bytes);
        writeFileSync(path.join(selected, 'overflow.bin'), 'x'); }
      for (const targeted of [false, true]) {
        const result = spawnSync('python3', ['-I', helperPath, '--root-posix', root,
          ...(targeted ? ['--target-directory', scope] : [])], { encoding: 'utf8', timeout: 15_000, maxBuffer: 112 * 1024 * 1024 });
        assert.equal(result.status, 23, result.stderr);
        assert.equal(result.stdout, '', 'no truncated successful snapshot is published');
        assert.equal(JSON.parse(result.stderr).code, scope === 'vendor' ? 'file_too_large' : scope === 'dist' ? 'too_many_files' : 'snapshot_too_large');
      }
    }
  });
});

test('bounded collector awaits terminal child exit for cancellation and deadline', async (t) => {
  const temporary = mkdtempSync(path.join(realpathSync(os.tmpdir()), 'lomo-collector-lifecycle-'));
  t.after(() => rmSync(temporary, { force: true, recursive: true }));
  const program = NATIVE_WINDOWS_SNAPSHOT_HELPER.replace("if __name__ == '__main__':", 'if False:') + `
import time
with open(sys.argv.pop(), 'w') as record:
    record.write(str(os.getpid()))
def held_collection(*args):
    time.sleep(120)
collect_snapshot = held_collection
try:
    _main()
except SnapshotBoundaryError as exc:
    sys.stderr.write(json.dumps({'code': exc.code}))
    raise SystemExit(23)
`;
  for (const mode of ['cancelled', 'deadline']) {
    const pidFile = path.join(temporary, mode);
    const controller = new AbortController();
    const running = runBoundedSnapshotHelper('python3', ['-I', '-c', program, '--root-posix', '/unused', '--owned-input', pidFile],
      controller.signal, mode === 'deadline' ? 100 : 10_000);
    const rejection = assert.rejects(running, mode === 'cancelled' ? { name: 'AbortError' } : { code: 'native_snapshot_deadline' });
    if (mode === 'cancelled') setTimeout(() => controller.abort(), 100);
    await rejection;
    const pid = Number(require('node:fs').readFileSync(pidFile, 'utf8'));
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  }
  const uncooperative = runBoundedSnapshotHelper(process.execPath,
    ['-e', 'process.stdin.resume();setInterval(()=>{},1000)'], undefined, 20);
  await assert.rejects(uncooperative, { code: 'native_snapshot_cleanup_unconfirmed' });
  const alarmProgram = program.replace('signal.setitimer(signal.ITIMER_REAL, 60)',
    'signal.setitimer(signal.ITIMER_REAL, 0.02)');
  const alarmPid = path.join(temporary, 'alarm');
  await assert.rejects(runBoundedSnapshotHelper('python3',
    ['-I', '-c', alarmProgram, '--root-posix', '/unused', '--owned-input', alarmPid], undefined, 1000),
    { code: 'native_snapshot_deadline' });
  assert.throws(() => process.kill(Number(require('node:fs').readFileSync(alarmPid, 'utf8')), 0), { code: 'ESRCH' });
});

test('native Windows nested-folder snapshot retains the bounded owner identity and project-relative scope', async () => {
  const root = { name: 'project', uri: uri(String.raw`C:\work\project`) };
  const target = sourceTargetForUri(uri(String.raw`C:\work\project\services\api`), [root], 'win32');
  const upload = await collectNativeWindowsSourceSnapshot(
    target,
    undefined,
    async () => ({ directory_scope: 'services/api', files: [
      entry('services/api/app.py', 'print("api")\n'),
    ] }),
  );
  assert.deepEqual(upload.files.map((item) => item.path), ['services/api/app.py']);
  assert.equal(upload.source_id, target.sourceId);
  assert.equal(upload.name, 'project');
  assert.equal(upload.directory_scope, 'services/api');
  assert.equal(target.targetPath, 'services/api');
  assert.equal(target.folder, root);
  await assert.rejects(
    collectNativeWindowsSourceSnapshot(
      target,
      undefined,
      async () => ({
        directory_scope: 'services/api',
        files: [entry('README.md', 'outside selected directory')],
      }),
    ),
    /outside the exact selected scope/,
  );
});

test('descriptor helper snapshots only a selected directory with owner-relative paths', () => {
  withHelper(({ temporary, helperPath }) => {
    const approved = path.join(temporary, 'approved');
    mkdirSync(path.join(approved, 'services', 'api'), { recursive: true });
    writeFileSync(path.join(approved, 'services', 'api', 'app.py'), 'print("api")\n');
    writeFileSync(path.join(approved, 'sibling.py'), 'print("sibling")\n');
    const result = spawnSync(
      'python3',
      ['-I', helperPath, '--root-posix', approved, '--target-directory', 'services/api'],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(
      JSON.parse(result.stdout).files.map((item) => item.path),
      ['services/api/app.py'],
    );
    assert.equal(JSON.parse(result.stdout).directory_scope, 'services/api');
    assert.equal(result.stdout.includes('sibling'), false);

    symlinkSync(
      path.join(approved, 'sibling.py'),
      path.join(approved, 'services', 'api', 'linked-sibling.py'),
    );
    const linked = spawnSync(
      'python3',
      ['-I', helperPath, '--root-posix', approved, '--target-directory', 'services/api'],
      { encoding: 'utf8' },
    );
    assert.equal(linked.status, 23);
    assert.deepEqual(JSON.parse(linked.stderr), { code: 'linked_entry' });
    assert.equal(linked.stdout, '');
  });
});

test('native Windows empty selected directory remains materializable and excludes siblings', async () => {
  const root = { name: 'project', uri: uri(String.raw`C:\work\project`) };
  const target = sourceTargetForUri(uri(String.raw`C:\work\project\services\empty`), [root], 'win32');
  const upload = await collectNativeWindowsSourceSnapshot(
    target,
    undefined,
    async () => ({ directory_scope: 'services/empty', files: [] }),
  );
  assert.equal(upload.directory_scope, 'services/empty');
  assert.deepEqual(upload.files, []);
  const receipt = {
    project: { id: 17, name: 'project', repo_path: target.repoPath, revision: 1 },
    snapshot_digest: 'a'.repeat(64),
    directory_scope: 'services/empty',
    file_count: 0,
    total_bytes: 0,
  };
  assert.equal(
    admittedNativeWindowsSourceSnapshot(receipt, target, upload).snapshotDigest,
    'a'.repeat(64),
  );
  assert.throws(
    () => admittedNativeWindowsSourceSnapshot({ ...receipt, directory_scope: null }, target, upload),
    /wrong immutable binding/,
  );
  await assert.rejects(
    collectNativeWindowsSourceSnapshot(
      target,
      undefined,
      async () => ({ directory_scope: null, files: [] }),
    ),
    /wrong exact selected directory scope/,
  );

  withHelper(({ temporary, helperPath }) => {
    const approved = path.join(temporary, 'approved');
    mkdirSync(path.join(approved, 'services', 'empty', '.git'), { recursive: true });
    writeFileSync(path.join(approved, 'services', 'empty', '.git', 'skipped.js'), 'skipped\n');
    writeFileSync(path.join(approved, 'sibling.py'), 'sibling\n');
    const result = spawnSync(
      'python3',
      ['-I', helperPath, '--root-posix', approved, '--target-directory', 'services/empty'],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {
      directory_scope: 'services/empty',
      files: [],
    });
    assert.equal(result.stdout.includes('sibling'), false);
    assert.equal(result.stdout.includes('skipped'), false);
  });
});

test('native Windows exact-file snapshot preserves and fences the project-relative target', async () => {
  const root = { name: 'project', uri: uri(String.raw`C:\work\project`) };
  const selected = uri(String.raw`C:\work\project\k8s\deployment.yaml`);
  const target = sourceTargetForFileUri(selected, [root], 'win32');
  const upload = await collectNativeWindowsSourceSnapshot(
    target,
    undefined,
    async () => ({
      directory_scope: null,
      files: [entry('k8s/deployment.yaml', 'kind: Deployment\n')],
    }),
  );
  assert.deepEqual(upload.files.map((item) => item.path), ['k8s/deployment.yaml']);
  assert.equal(upload.directory_scope, null);
  await assert.rejects(
    collectNativeWindowsSourceSnapshot(
      target,
      undefined,
      async () => ({ directory_scope: null, files: [entry('app.py', 'outside exact file')] }),
    ),
    /outside the exact selected scope/,
  );
});

test('native snapshot admission rejects UNC targets before invoking the helper', async () => {
  const root = { name: 'project', uri: uri(String.raw`C:\work\project`) };
  const localTarget = sourceTargetForUri(root.uri, [root], 'win32');
  let helperCalls = 0;
  const runHelper = async () => {
    helperCalls += 1;
    throw new Error('UNC admission must not invoke the snapshot helper');
  };
  const wslUnc = {
    scheme: 'file',
    authority: 'wsl.localhost',
    path: '/Ubuntu-26.04/home/qa/project',
    fsPath: String.raw`\\wsl.localhost\Ubuntu-26.04\home\qa\project`,
    toString: () => 'file://wsl.localhost/Ubuntu-26.04/home/qa/project',
  };
  await assert.rejects(
    collectNativeWindowsSourceSnapshot({ ...localTarget, uri: wslUnc }, undefined, runHelper),
    (error) => error.code === 'native_windows_unc_requires_remote_wsl'
      && error.action === 'reopen_in_remote_wsl',
  );
  const genericUnc = {
    scheme: 'file',
    authority: 'server',
    path: '/share/project',
    fsPath: String.raw`\\server\share\project`,
    toString: () => 'file://server/share/project',
  };
  await assert.rejects(
    collectNativeWindowsSourceSnapshot({ ...localTarget, uri: genericUnc }, undefined, runHelper),
    /UNC and virtual filesystem roots are not supported/,
  );
  assert.equal(helperCalls, 0);
});

function withHelper(run) {
  const temporary = mkdtempSync(path.join(realpathSync(os.tmpdir()), 'lomo-native-snapshot-'));
  const helperPath = path.join(temporary, 'snapshot-helper.py');
  writeFileSync(helperPath, NATIVE_WINDOWS_SNAPSHOT_HELPER, { mode: 0o600 });
  try {
    return run({ temporary, helperPath });
  } finally {
    rmSync(temporary, { force: true, recursive: true });
  }
}

test('descriptor helper rejects a selected ancestor swapped to an outside junction before open', () => {
  withHelper(({ temporary, helperPath }) => {
    const approved = path.join(temporary, 'approved');
    const outside = path.join(temporary, 'outside');
    mkdirSync(approved);
    mkdirSync(outside);
    writeFileSync(path.join(approved, 'inside.py'), 'approved bytes\n');
    writeFileSync(path.join(outside, 'outside.py'), 'outside secret bytes\n');
    const wrapper = String.raw`
import json, os, runpy, sys
namespace = runpy.run_path(sys.argv[1], run_name='snapshot_helper')
root, outside = sys.argv[2], sys.argv[3]
original_open = namespace['os'].open
root_name = os.path.basename(root)
swapped = False
def guarded_open(name, flags, mode=0o777, *, dir_fd=None):
    global swapped
    if not swapped and dir_fd is not None and name == root_name:
        os.rename(root, root + '-original')
        os.symlink(outside, root, target_is_directory=True)
        swapped = True
    if dir_fd is None:
        return original_open(name, flags, mode)
    return original_open(name, flags, mode, dir_fd=dir_fd)
namespace['os'].open = guarded_open
try:
    print(json.dumps(namespace['collect_snapshot'](root)))
except namespace['SnapshotBoundaryError'] as error:
    print(json.dumps({'code': error.code}))
`;
    const result = spawnSync('python3', ['-I', '-c', wrapper, helperPath, approved, outside], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { code: 'linked_or_changed_directory' });
    assert.equal(result.stdout.includes('outside secret bytes'), false);
  });
});

test('descriptor helper rejects a same-size file replacement during its pinned read', () => {
  withHelper(({ temporary, helperPath }) => {
    const approved = path.join(temporary, 'approved');
    mkdirSync(approved);
    const selected = path.join(approved, 'inside.py');
    writeFileSync(selected, 'approved');
    const wrapper = String.raw`
import json, os, runpy, sys
namespace = runpy.run_path(sys.argv[1], run_name='snapshot_helper')
root = sys.argv[2]
selected = os.path.join(root, 'inside.py')
original_read = namespace['os'].read
swapped = False
def guarded_read(descriptor, count):
    global swapped
    if not swapped:
        os.rename(selected, selected + '-original')
        with open(selected, 'wb') as replacement:
            replacement.write(b'outside!')
        swapped = True
    return original_read(descriptor, count)
namespace['os'].read = guarded_read
try:
    print(json.dumps(namespace['collect_snapshot'](root)))
except namespace['SnapshotBoundaryError'] as error:
    print(json.dumps({'code': error.code}))
`;
    const result = spawnSync('python3', ['-I', '-c', wrapper, helperPath, approved], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { code: 'source_changed' });
    assert.equal(result.stdout.includes('outside!'), false);
  });
});

test('descriptor helper refuses static linked entries without reading their targets', () => {
  withHelper(({ temporary, helperPath }) => {
    const approved = path.join(temporary, 'approved');
    const outside = path.join(temporary, 'outside');
    mkdirSync(approved);
    mkdirSync(outside);
    writeFileSync(path.join(outside, 'secret.py'), 'outside secret bytes\n');
    symlinkSync(outside, path.join(approved, 'linked'), 'dir');
    const result = spawnSync(
      'python3',
      ['-I', helperPath, '--root-posix', approved],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 23);
    assert.deepEqual(JSON.parse(result.stderr), { code: 'linked_entry' });
    assert.equal(result.stdout, '');
  });
});
