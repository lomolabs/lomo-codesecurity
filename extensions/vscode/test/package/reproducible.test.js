const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { constants } = require('node:fs');
const { chmod, copyFile, cp, lstat, mkdir, mkdtemp, open, readFile, rm, stat, symlink, utimes, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { dirname, resolve } = require('node:path');
const test = require('node:test');

const yauzl = require('yauzl');

const extensionRoot = resolve(__dirname, '..', '..');
const repoRoot = resolve(extensionRoot, '..', '..');
const packageManifest = require(resolve(extensionRoot, 'package.json'));
const outputPath = resolve(
  repoRoot,
  '.kodesec-test',
  'vscode',
  `code-security-${packageManifest.version}.vsix`,
);
const generatedBundlePath = resolve(extensionRoot, 'dist', 'extension.js');
const packagedInputs = [
  resolve(extensionRoot, 'LICENSE'),
  resolve(extensionRoot, 'README.md'),
  resolve(extensionRoot, 'media', 'lomo-icon.png'),
  resolve(extensionRoot, 'media', 'lomo-view.svg'),
  resolve(extensionRoot, 'media', 'setup-backend.md'),
  resolve(extensionRoot, 'media', 'setup-connection.md'),
  resolve(extensionRoot, 'media', 'setup-repositories.md'),
  resolve(extensionRoot, 'media', 'setup-scan.md'),
  resolve(extensionRoot, 'media', 'setup-review.md'),
  resolve(extensionRoot, 'media', 'setup-protection.md'),
  resolve(extensionRoot, 'package.json'),
];

test('one-shot extension and standalone Git helper builds stop cleanly and need no editor runtime', { timeout: 30_000 }, () => {
  const result = spawnSync(process.execPath, ['./scripts/build.mjs'], {
    cwd: extensionRoot,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    timeout: 20_000,
  });
  const output = `${result.stdout}\n${result.stderr}`;
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.signal, null, output);
  assert.equal(result.status, 0, output);
  assert.doesNotMatch(
    output,
    /fatal error:|too many writes on closed pipe|RangeError: Invalid array length|Unhandled 'error' event/u,
  );
  // The shipped helper must load under plain Node with no VS Code module,
  // profile, credentials or API. Invalid invocation must stop before any I/O.
  const helper = spawnSync(process.execPath, ['./dist/git-push-cli.js'], {
    cwd: extensionRoot,
    encoding: 'utf8',
    timeout: 5000,
    env: { ...process.env, NO_COLOR: '1' },
  });
  assert.equal(helper.error, undefined, helper.error?.message);
  assert.equal(helper.signal, null, helper.stderr);
  assert.equal(helper.status, 2, helper.stderr);
  assert.equal(helper.stdout, '');
  assert.equal(helper.stderr, 'Usage: git-push-cli --hook <private-config> <remote-name> <destination>\n');
});

test('VSIX bytes and ZIP metadata are reproducible across input mtimes and timezones', { timeout: 30_000 }, async () => {
  const originalTimes = new Map();
  for (const path of packagedInputs) {
    const sourceStat = await stat(path);
    originalTimes.set(path, { atime: sourceStat.atime, mtime: sourceStat.mtime });
  }

  try {
    await setInputTimes(new Date('2001-02-03T04:05:06.000Z'));
    runPackage('UTC');
    const first = await readSecureOutput();
    await assertIndependentContentCandidate();
    const firstGeneratedMtime = (await stat(generatedBundlePath)).mtimeMs;

    await setInputTimes(new Date('2037-11-12T13:14:16.000Z'));
    runPackage('Pacific/Auckland');
    const second = await readSecureOutput();
    await assertIndependentContentCandidate();
    const secondGeneratedMtime = (await stat(generatedBundlePath)).mtimeMs;

    assert.notEqual(secondGeneratedMtime, firstGeneratedMtime);
    assert.equal(sha256(second), sha256(first));
    assert.deepEqual(second, first);
    assert.deepEqual(await readArchiveMetadata(outputPath), expectedMetadata());
    assertCanonicalEndOfCentralDirectory(second);
  } finally {
    for (const [path, { atime, mtime }] of originalTimes) {
      await utimes(path, atime, mtime);
    }
  }
});

test('unpacked committed source packages without Git and retains its explicit input identity', { timeout: 120_000 }, async () => {
  const temporary = await mkdtemp(resolve(tmpdir(), 'lomo-unpacked-package-'));
  const runtime = await mkdtemp(resolve(tmpdir(), 'lomo-unpacked-runtime-'));
  try {
    // Build an independent source download, not a worktree or fake Git repo.
    const archive = spawnSync('git', ['archive', '--format=tar', 'HEAD'], {
      cwd: repoRoot, maxBuffer: 64 * 1024 * 1024, timeout: 10_000,
    });
    assert.equal(archive.error, undefined, archive.error?.message);
    assert.equal(archive.status, 0, archive.stderr.toString());
    const extracted = spawnSync('tar', ['-xf', '-', '-C', temporary], {
      input: archive.stdout, timeout: 10_000, encoding: 'utf8',
    });
    assert.equal(extracted.error, undefined, extracted.error?.message);
    assert.equal(extracted.status, 0, extracted.stderr);
    await assert.rejects(lstat(resolve(temporary, '.git')), { code: 'ENOENT' });
    for (const input of ['scripts/source_provenance.py', 'extensions/vscode/scripts/package.mjs']) {
      assert.deepEqual(await readFile(resolve(temporary, input)), await readFile(resolve(repoRoot, input)),
        `Commit the reviewed ${input} before this committed-source regression`);
    }
    // ZIP extractors can drop executable bits. The normal setup path must use
    // explicit interpreters, without changing permissions on existing sources.
    for (const script of ['init-runtime.sh', 'compose-build.sh', 'auth-info.sh', 'rotate-auth.sh']) {
      await chmod(resolve(temporary, 'scripts', script), 0o644);
    }
    const initialize = () => {
      const result = spawnSync('make', ['init', `STATE_DIR=${runtime}`, `RUNTIME_ENV=${resolve(runtime, 'runtime.env')}`], {
        cwd: temporary, encoding: 'utf8', timeout: 10_000,
      });
      assert.equal(result.error, undefined, result.error?.message);
      assert.equal(result.status, 0, result.stderr);
    };
    initialize();
    const runtimePath = resolve(runtime, 'runtime.env');
    const runtimeDigest = sha256(await readFile(runtimePath));
    assert.equal((await stat(runtimePath)).mode & 0o777, 0o600);
    initialize();
    assert.equal(sha256(await readFile(runtimePath)), runtimeDigest);
    const unpackedExtension = resolve(temporary, 'extensions/vscode');
    // Reuse the installed, lock-bound development dependencies without downloads.
    // Copy rather than link: authored snapshot roots reject symlink substitutes.
    await cp(resolve(extensionRoot, 'node_modules'), resolve(unpackedExtension, 'node_modules'), {
      recursive: true, verbatimSymlinks: true,
    });
    const identity = () => {
      const observed = spawnSync('python3', ['scripts/source_provenance.py', '--json'], {
        cwd: temporary, encoding: 'utf8', timeout: 10_000,
      });
      assert.equal(observed.error, undefined, observed.error?.message);
      assert.equal(observed.status, 0, observed.stderr);
      return JSON.parse(observed.stdout);
    };
    const before = identity();
    assert.deepEqual(Object.keys(before).sort(), ['digest', 'kind']);
    assert.equal(before.kind, 'source-sha256');
    assert.match(before.digest, /^[a-f0-9]{64}$/u);
    runPackage('UTC', unpackedExtension, 60_000);
    assert.deepEqual(identity(), before);
    const resultPath = resolve(temporary, '.kodesec-test/vscode', `code-security-${packageManifest.version}.vsix`);
    const bytes = await readFile(resultPath);
    assert.deepEqual(await readArchiveMetadata(resultPath), expectedMetadata());
    assertCanonicalEndOfCentralDirectory(bytes);
    assert.deepEqual(await readFile(resolve(temporary, '.kodesec-test/vscode/candidates', sha256(bytes),
      `code-security-${packageManifest.version}.vsix`)), bytes);
  } finally {
    await rm(temporary, { recursive: true, force: true });
    await rm(runtime, { recursive: true, force: true });
  }
});

function runPackage(timezone, root = extensionRoot, timeout = 12_000) {
  const result = spawnSync(process.execPath, ['./scripts/package.mjs'], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, TZ: timezone },
    timeout,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.signal, null, `${result.stdout}\n${result.stderr}`);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
}

async function readSecureOutput() {
  const outputStat = await lstat(outputPath);
  assert.equal(outputStat.isFile(), true);
  assert.equal(outputStat.isSymbolicLink(), false);
  assert.equal(outputStat.nlink, 1);
  const file = await open(outputPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    return await file.readFile();
  } finally {
    await file.close();
  }
}

async function assertIndependentContentCandidate() {
  const output = await readFile(outputPath);
  const candidatePath = resolve(
    dirname(outputPath),
    'candidates',
    sha256(output),
    `code-security-${packageManifest.version}.vsix`,
  );
  const [outputStat, candidateStat] = await Promise.all([
    lstat(outputPath),
    lstat(candidatePath),
  ]);
  assert.equal(candidateStat.isFile(), true);
  assert.equal(candidateStat.isSymbolicLink(), false);
  assert.equal(candidateStat.nlink, 1);
  assert.notDeepEqual(
    { dev: candidateStat.dev, ino: candidateStat.ino },
    { dev: outputStat.dev, ino: outputStat.ino },
  );
}

async function setInputTimes(time) {
  for (const path of packagedInputs) {
    await utimes(path, time, time);
  }
}

function readArchiveMetadata(path) {
  return new Promise((resolveArchive, rejectArchive) => {
    yauzl.open(path, { lazyEntries: true }, (openError, zipfile) => {
      if (openError || !zipfile) {
        rejectArchive(openError || new Error('VSIX could not be opened.'));
        return;
      }
      const entries = [];
      zipfile.on('error', rejectArchive);
      zipfile.on('entry', (entry) => {
        entries.push({
          name: entry.fileName,
          versionMadeBy: entry.versionMadeBy,
          versionNeededToExtract: entry.versionNeededToExtract,
          generalPurposeBitFlag: entry.generalPurposeBitFlag,
          compressionMethod: entry.compressionMethod,
          lastModFileTime: entry.lastModFileTime,
          lastModFileDate: entry.lastModFileDate,
          externalFileAttributes: entry.externalFileAttributes,
          extraFieldCount: entry.extraFields.length,
          fileCommentLength: entry.fileCommentLength,
        });
        zipfile.readEntry();
      });
      zipfile.on('end', () => resolveArchive(entries));
      zipfile.readEntry();
    });
  });
}

function expectedMetadata() {
  const names = [
    '[Content_Types].xml',
    'extension.vsixmanifest',
    'extension/LICENSE.txt',
    'extension/dist/extension.js',
    'extension/dist/git-push-cli.js',
    'extension/media/lomo-icon.png',
    'extension/media/lomo-view.svg',
    'extension/media/setup-backend.md',
    'extension/media/setup-connection.md',
    'extension/media/setup-repositories.md',
    'extension/media/setup-scan.md',
    'extension/media/setup-review.md',
    'extension/media/setup-protection.md',
    'extension/package.json',
    'extension/readme.md',
  ].sort();
  return names.map((name) => ({
    name,
    versionMadeBy: 0x033f,
    versionNeededToExtract: 20,
    generalPurposeBitFlag: 0x0800,
    compressionMethod: 0,
    lastModFileTime: 0,
    lastModFileDate: 33,
    externalFileAttributes: (0o100644 << 16) >>> 0,
    extraFieldCount: 0,
    fileCommentLength: 0,
  }));
}

function assertCanonicalEndOfCentralDirectory(content) {
  const offset = content.length - 22;
  assert(offset >= 0);
  assert.equal(content.readUInt32LE(offset), 0x06054b50);
  assert.equal(content.readUInt16LE(offset + 4), 0);
  assert.equal(content.readUInt16LE(offset + 6), 0);
  assert.equal(content.readUInt16LE(offset + 8), expectedMetadata().length);
  assert.equal(content.readUInt16LE(offset + 10), expectedMetadata().length);
  assert.equal(content.readUInt16LE(offset + 20), 0);
}

function sha256(content) {
  return createHash('sha256').update(content).digest('hex');
}

const buildCompilerFailures = /RangeError|Invalid array length|Unhandled 'error' event|service was stopped/u;

async function buildOutputFixture(t) {
  const root = await mkdtemp(resolve(tmpdir(), 'lomo-build-output-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(resolve(root, 'scripts'));
  await mkdir(resolve(root, 'src'));
  await copyFile(resolve(extensionRoot, 'scripts/build.mjs'), resolve(root, 'scripts/build.mjs'));
  await symlink(resolve(extensionRoot, 'node_modules'), resolve(root, 'node_modules'), 'junction');
  await writeFile(resolve(root, 'src/extension.ts'), 'export const fixture = 1;\n');
  await writeFile(resolve(root, 'src/git-push-cli.ts'), 'export const helper = 2;\n');
  return root;
}

async function buildToRegularFile(root) {
  const log = await open(resolve(root, 'build.log'), 'w', 0o600);
  let result;
  try {
    result = spawnSync(process.execPath, ['scripts/build.mjs'], {
      cwd: root, stdio: ['ignore', log.fd, log.fd], timeout: 20_000,
      env: { ...process.env, NO_COLOR: '1' },
    });
  } finally { await log.close(); }
  const output = await readFile(resolve(root, 'build.log'), 'utf8');
  assert.equal(result.error, undefined, output);
  assert.equal(result.signal, null, output);
  assert.doesNotMatch(output, buildCompilerFailures);
  return { status: result.status, output };
}

test('redirected builds preserve bundle bytes, warnings and nonzero syntax failures', { timeout: 60_000 }, async (t) => {
  const root = await buildOutputFixture(t);
  const piped = spawnSync(process.execPath, ['scripts/build.mjs'], {
    cwd: root, encoding: 'utf8', timeout: 20_000,
  });
  assert.equal(piped.status, 0, piped.stderr);
  const expected = await Promise.all(['extension.js', 'git-push-cli.js'].map((name) => readFile(resolve(root, 'dist', name))));
  const ordinary = await buildToRegularFile(root);
  assert.equal(ordinary.status, 0, ordinary.output);
  for (const [i, name] of ['extension.js', 'git-push-cli.js'].entries()) {
    assert.deepEqual(await readFile(resolve(root, 'dist', name)), expected[i]);
  }
  await writeFile(resolve(root, 'src/extension.ts'), 'console.log({ duplicate: 1, duplicate: 2 });\n');
  const warning = await buildToRegularFile(root);
  assert.equal(warning.status, 0, warning.output);
  assert.match(warning.output, /Duplicate key "duplicate"/u);
  await writeFile(resolve(root, 'src/extension.ts'), 'export const broken = ;\n');
  const error = await buildToRegularFile(root);
  assert.notEqual(error.status, 0);
  assert.match(error.output, /Unexpected ";"/u);
  assert.match(error.output, /src\/extension\.ts/u);
});

test('redirected watch rebuilds after an error and can be stopped', { timeout: 40_000 }, async (t) => {
  const root = await buildOutputFixture(t);
  const log = await open(resolve(root, 'watch.log'), 'w', 0o600);
  const child = spawn(process.execPath, ['scripts/build.mjs', '--watch'], {
    cwd: root, stdio: ['ignore', log.fd, log.fd], env: { ...process.env, NO_COLOR: '1' },
  });
  let exited = false;
  const closed = new Promise((resolveClose, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => { exited = true; resolveClose({ code, signal }); });
  });
  async function waitFor(predicate) {
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      const output = await readFile(resolve(root, 'watch.log'), 'utf8');
      assert.doesNotMatch(output, buildCompilerFailures);
      if (predicate(output)) return output;
      assert.equal(exited, false, output);
      await new Promise((done) => setTimeout(done, 50));
    }
    assert.fail('Watch did not produce the expected build evidence within 10 seconds.');
  }
  try {
    await waitFor((text) => text.includes('Built dist/extension.js') && text.includes('Built dist/git-push-cli.js'));
    await writeFile(resolve(root, 'src/extension.ts'), 'export const broken = ;\n');
    await waitFor((text) => text.includes('Unexpected ";"'));
    await writeFile(resolve(root, 'src/extension.ts'), 'export const recovered = 3;\n');
    await waitFor((text) => text.split('Built dist/extension.js').length === 3);
    assert.match(await readFile(resolve(root, 'dist/extension.js'), 'utf8'), /recovered/u);
    child.kill('SIGINT');
    const result = await Promise.race([closed, new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error('Watch shutdown exceeded 5 seconds.')), 5000);
      timer.unref();
    })]);
    // Windows emulates child.kill(SIGINT) as unconditional termination; it
    // does not deliver the POSIX signal handler used by the build driver.
    // https://nodejs.org/api/process.html#signal-events
    assert.deepEqual(result, process.platform === 'win32'
      ? { code: null, signal: 'SIGINT' }
      : { code: 130, signal: null });
  } finally {
    if (!exited) { child.kill('SIGKILL'); await closed; }
    await log.close();
  }
});
