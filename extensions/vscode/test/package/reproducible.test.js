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

async function runPackagingDependencyProgram(program, { timeout = 5000 } = {}) {
  const home = await mkdtemp(resolve(tmpdir(), 'lomo-package-consumer-'));
  try {
    // Deliberately do not inherit AZURE_*, VSCE_PAT, NODE_OPTIONS, npm tokens,
    // proxy settings, SSH agents, credential paths or the owner's home.
    const env = {
      HOME: home, USERPROFILE: home, TMPDIR: home, TMP: home, TEMP: home,
      XDG_CONFIG_HOME: home, XDG_CACHE_HOME: home, PATH: '', NO_COLOR: '1',
      LANG: 'C.UTF-8', AZURE_TENANT_ID: '11111111-1111-4111-8111-111111111111',
      AZURE_CLIENT_ID: '22222222-2222-4222-8222-222222222222',
      AZURE_CLIENT_SECRET: 'fixture-only-client-secret',
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
      ...(process.env.WINDIR ? { WINDIR: process.env.WINDIR } : {}),
    };
    const result = spawnSync(process.execPath,
      ['--unhandled-rejections=strict', '-e', program], {
        cwd: extensionRoot, encoding: 'utf8', env, timeout, maxBuffer: 64 * 1024,
      });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.signal, null, result.stderr);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, 'ok\n');
    assert.doesNotMatch(result.stderr,
      /Unhandled|uncaught|fixture-network-denied|fixture-cli-denied/iu);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

const packagingNoNetworkOrCli = String.raw`
const assert = require('node:assert/strict');
const { createRequire, syncBuiltinESMExports } = require('node:module');
const deniedNetwork = () => { throw new Error('fixture-network-denied'); };
const deniedCli = () => { throw new Error('fixture-cli-denied'); };
require('node:net').Socket.prototype.connect = deniedNetwork;
require('node:tls').connect = deniedNetwork;
for (const protocol of ['node:http', 'node:https']) {
  require(protocol).request = deniedNetwork;
  require(protocol).get = deniedNetwork;
}
globalThis.fetch = deniedNetwork;
const childProcess = require('node:child_process');
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
  childProcess[name] = deniedCli;
}
syncBuiltinESMExports();
const vsceRequire = createRequire(require.resolve('@vscode/vsce'));
`;

const packagingMsalImports = String.raw`
const identityRequire = createRequire(vsceRequire.resolve('@azure/identity'));
const msal = identityRequire('@azure/msal-node');
`;

test('scoped MSAL upgrade preserves the actual VSCE credential consumer and auth-code guard',
  { timeout: 15000 }, async () => {
    // Compatibility smoke: patch the MSAL token call, not Azure Identity or
    // VSCE's chain. All five selected credential constructors still execute.
    await runPackagingDependencyProgram(packagingNoNetworkOrCli + packagingMsalImports + String.raw`
(async () => {
  const calls = [];
  const prototype = msal.ConfidentialClientApplication.prototype;
  const original = prototype.acquireTokenByClientCredential;
  prototype.acquireTokenByClientCredential = async function (request) {
    calls.push({ scopes: request.scopes });
    return { accessToken: 'fixture-only-access-token',
      expiresOn: new Date(Date.now() + 60000), tokenType: 'Bearer' };
  };
  try {
    const { getAzureCredentialAccessToken } = vsceRequire('./auth.js');
    assert.equal(await getAzureCredentialAccessToken(), 'fixture-only-access-token');
    assert.deepEqual(calls, [{ scopes: ['499b84ac-1321-427f-aa17-267ca6975798/.default'] }]);
  } finally {
    prototype.acquireTokenByClientCredential = original;
  }
  console.log('ok');
})().catch(error => { console.error(error); process.exitCode = 1; });
`);

    // Security regression: stub only CCA's parent method. Stubbing CCA's own
    // acquireTokenByCode would skip the sanitizing override being tested.
    await runPackagingDependencyProgram(packagingNoNetworkOrCli + packagingMsalImports + String.raw`
(async () => {
  const CCA = msal.ConfidentialClientApplication;
  const config = { auth: { clientId: process.env.AZURE_CLIENT_ID,
    authority: 'https://login.microsoftonline.com/' + process.env.AZURE_TENANT_ID,
    clientSecret: process.env.AZURE_CLIENT_SECRET },
    system: { loggerOptions: { loggerCallback() {}, piiLoggingEnabled: false } } };
  const client = new CCA(config);
  const request = { scopes: ['fixture/.default'], code: 'fixture-request-code',
    nonce: 'fixture-request-nonce', redirectUri: 'http://localhost' };
  const payload = { code: 'fixture-payload-code', state: 'fixture-returned-state',
    nonce: 'fixture-payload-nonce', cloud_instance_host_name: 'untrusted.invalid',
    cloud_instance_name: 'untrusted-cloud', cloud_graph_host_name: 'untrusted.invalid',
    msgraph_host: 'untrusted.invalid', client_info: 'fixture-client-info' };
  const before = JSON.stringify({ request, payload });
  const parent = Object.getPrototypeOf(CCA.prototype);
  const original = parent.acquireTokenByCode;
  let observed;
  parent.acquireTokenByCode = async (seenRequest, seenPayload) => {
    observed = { request: seenRequest, payload: seenPayload };
    return {};
  };
  try {
    await client.acquireTokenByCode(request, payload);
    assert.equal(observed.request, request);
    assert.deepEqual(observed.payload, { code: request.code,
      state: payload.state, nonce: request.nonce });
    assert.equal(JSON.stringify({ request, payload }), before);
  } finally {
    parent.acquireTokenByCode = original;
  }
  assert.throws(() => new CCA({ ...config,
    auth: { ...config.auth, instanceAware: true } }),
    error => error.errorCode === 'unsupported_cca_instance_aware');
  for (const value of ['true', 'false', '']) {
    await assert.rejects(client.getAuthCodeUrl({ scopes: ['fixture/.default'],
      redirectUri: 'http://localhost', extraQueryParameters: { instance_aware: value } }),
      error => error.errorCode === 'unsupported_cca_instance_aware');
  }
  await assert.rejects(client.acquireTokenByCode({ ...request, state: 'expected-state' },
    { code: 'fixture-code', state: 'different-state' }),
    error => error.errorCode === 'state_mismatch');
  console.log('ok');
})().catch(error => { console.error(error); process.exitCode = 1; });
`);
  });

test('patched Markdown preserves VSCE README inspection and bounded reference behavior',
  { timeout: 10000 }, async () => {
    await runPackagingDependencyProgram(packagingNoNetworkOrCli + String.raw`
(async () => {
  const md = vsceRequire('markdown-it')({ html: true });
  assert.equal(md.render('[docs][ref]\n\n[ref]: https://example.invalid/ "Fixture"\n'),
    '<p><a href="https://example.invalid/" title="Fixture">docs</a></p>\n');
  for (const character of ['a', '😀']) {
    for (const length of [999, 1000]) {
      const environment = {};
      md.render('[' + character.repeat(length) + ']: https://example.invalid/\n', environment);
      assert.equal(Object.keys(environment.references || {}).length, length === 999 ? 1 : 0);
    }
  }
  const { ReadmeProcessor } = vsceRequire('./package.js');
  const manifest = require('./package.json');
  const ordinary = '# Fixture\n\n[docs][ref]\n\n[ref]: https://example.invalid/\n';
  const processor = new ReadmeProcessor(manifest, { rewriteRelativeLinks: false });
  const result = await processor.onFile({ path: 'extension/readme.md', contents: Buffer.from(ordinary) });
  assert.equal(result.path, 'extension/readme.md');
  assert.equal(result.contents.toString('utf8'), ordinary);
  assert.deepEqual(processor.assets, [{
    type: 'Microsoft.VisualStudio.Services.Content.Details', path: 'extension/readme.md' }]);
  await assert.rejects(new ReadmeProcessor(manifest, { rewriteRelativeLinks: false }).onFile({
    path: 'extension/readme.md', contents: Buffer.from('<svg><text>fixture</text></svg>') }),
    /SVG tags are not allowed/);
  // Fixed small shapes, not the upstream 300000-line workload. The semantic
  // label boundary above distinguishes the old unlimited-label behavior.
  md.render('[a]: /u "' + 'x\n'.repeat(4096));
  md.render('[' + 'a\n'.repeat(4096));
  const cheerio = vsceRequire('cheerio');
  assert.equal(cheerio.load('<h1>Fixture</h1>')('h1').text(), 'Fixture');
  console.log('ok');
})().catch(error => { console.error(error); process.exitCode = 1; });
`);
  });

test('patched consumer undici rejects an excessive-coding early close without an unhandled error',
  { timeout: 10000 }, async () => {
    // This child intentionally owns one loopback-only server. It inherits no
    // proxy/credential environment and uses an explicit direct Client.
    await runPackagingDependencyProgram(String.raw`
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const { createServer } = require('node:net');
const { once } = require('node:events');
const vsceRequire = createRequire(require.resolve('@vscode/vsce'));
const cheerioRequire = createRequire(vsceRequire.resolve('cheerio'));
const { fetch, Client } = cheerioRequire('undici');
(async () => {
  const sockets = new Set();
  let resolveClosed;
  const socketClosed = new Promise(resolve => { resolveClosed = resolve; });
  const response = Buffer.from('HTTP/1.1 200 OK\r\n' +
    'Content-Encoding: gzip, gzip, gzip, gzip, gzip, gzip\r\n' +
    'Content-Length: 1\r\nConnection: close\r\n\r\n');
  const server = createServer(socket => {
    sockets.add(socket);
    socket.once('close', () => { sockets.delete(socket); resolveClosed(); });
    socket.once('data', () => socket.end(response));
  });
  let client;
  try {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const origin = 'http://127.0.0.1:' + server.address().port;
    client = new Client(origin, { connect: { timeout: 1000 },
      headersTimeout: 1000, bodyTimeout: 1000 });
    await assert.rejects(fetch(origin, { dispatcher: client,
      signal: AbortSignal.timeout(1500) }), error => {
      assert.match(error.cause?.message || '', /content-encoding/);
      return true;
    });
    await socketClosed;
    await client.close();
  } finally {
    if (client) await client.destroy();
    for (const socket of sockets) socket.destroy();
    if (server.listening) await new Promise((resolve, reject) =>
      server.close(error => error ? reject(error) : resolve()));
  }
  console.log('ok');
})().catch(error => { console.error(error); process.exitCode = 1; });
`);
  });

test('patched fast-uri preserves VSCE Secretlint and relative schema references',
  { timeout: 10000 }, async () => {
    await runPackagingDependencyProgram(packagingNoNetworkOrCli + String.raw`
(async () => {
  // Resolve each dependency from the actual locked consumer, not a root import.
  const secretlintRequire = createRequire(vsceRequire.resolve('@secretlint/node'));
  const loaderRequire = createRequire(secretlintRequire.resolve('@secretlint/config-loader'));
  const Ajv = loaderRequire('ajv');
  const ajvRequire = createRequire(loaderRequire.resolve('ajv'));
  const uri = ajvRequire('fast-uri');
  assert.equal(ajvRequire('fast-uri/package.json').version, '3.1.9');

  // Actual packaging consumer: its generated SCHEMA#/definitions/... validators
  // compile and retain both successful validation and a real rejection.
  const { lintText } = vsceRequire('./secretLint.js');
  const clean = await lintText('Fixture text only.\n', 'fixture.txt', false, true);
  assert.equal(clean.ok, true);
  assert.deepEqual(clean.results, []);
  const blocked = await lintText('FIXTURE=value\n', '.env', false, true);
  assert.equal(blocked.ok, false);
  assert.deepEqual(blocked.results.map(result => result.ruleId),
    ['@secretlint/secretlint-rule-no-dotenv']);

  // Cross-document resolution is the relevant URI compatibility boundary.
  const ajv = new Ajv();
  ajv.addSchema({
    $id: 'https://schemas.example.invalid/common/types.json',
    definitions: { enabled: { type: 'boolean' } },
  });
  const validate = ajv.compile({
    $id: 'https://schemas.example.invalid/nested/root.json',
    type: 'object',
    properties: { enabled: { $ref: '../common/types.json#/definitions/enabled' } },
    required: ['enabled'], additionalProperties: false,
  });
  assert.equal(validate({ enabled: true }), true);
  assert.equal(validate({ enabled: 'yes' }), false);
  assert.equal(validate({}), false);

  // GHSA-w74x-v6f9-j3xg: encoded schemes stay malformed/inert.
  for (const input of ['%6Aavascript:alert(1)', '%u006Aavascript:alert(1)']) {
    assert.equal(uri.parse(input).error, 'URI scheme is malformed.');
    assert.equal(uri.normalize(input), input);
    assert.throws(() => uri.resolve('https://example.invalid/', input),
      /URI scheme is malformed\./);
  }
  assert.equal(uri.equal('%68ttp://a/', 'http://a/'), false);

  // GHSA-wjr9-j795-jxcr: neither an extra @ nor a stripped control may move host.
  for (const input of ['http://a@b@evil.example/', 'http://ev\til.example/']) {
    assert.equal(uri.parse(input).error, 'URI host is malformed.');
    assert.equal(uri.normalize(input), input);
    assert.throws(() => uri.resolve('https://example.invalid/', input),
      /URI host is malformed\./);
  }
  assert.equal(uri.normalize('http://Example.COM/'), 'http://example.com/');

  // GHSA-xhq7-xmqj-769h: normalization preserves relative-reference meaning.
  const base = 'https://example.invalid/p/q/r';
  for (const [input, normalized, resolved] of [
    ['../x', '../x', 'https://example.invalid/p/x'],
    ['a/../b', 'b', 'https://example.invalid/p/q/b'],
  ]) {
    assert.equal(uri.normalize(input), normalized);
    assert.equal(uri.resolve(base, normalized), resolved);
    assert.equal(uri.resolve(base, normalized), uri.resolve(base, input));
  }
  assert.equal(uri.equal('../x', 'x'), false);

  // GHSA-333x-w4r6-6crp: suffix references cannot synthesize a live scheme.
  const suffix = { reference: 'suffix', scheme: 'x' };
  const escaped = uri.normalize('javascript:alert(1)', suffix);
  assert.equal(escaped, 'javascript%3Aalert(1)');
  assert.equal(uri.parse(escaped).scheme, undefined);
  assert.equal(uri.normalize('a/b:c', suffix), 'a/b:c');
  console.log('ok');
})().catch(error => { console.error(error); process.exitCode = 1; });
`, { timeout: 7500 });
  });
