import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter, once } from 'node:events';
import { createConnection, createServer } from 'node:net';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import test from 'node:test';

import {
  CORE_SERVICES,
  PLAYWRIGHT_ALLOWED_PROJECTS,
  PLAYWRIGHT_ALLOWED_SPECS,
  PLAYWRIGHT_COMPOSE_SPEC,
  PLAYWRIGHT_CONTAINER_IMAGE,
  PLAYWRIGHT_EXECUTION_REPORT,
  PLAYWRIGHT_EXECUTION_REPORT_SCHEMA,
  PLAYWRIGHT_RAW_EXECUTION_REPORT,
  PLAYWRIGHT_FOUNDATION_SPEC,
  PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC,
  PLAYWRIGHT_PROXY_CONFORMANCE_SPEC,
  PLAYWRIGHT_FINDINGS_SCALE_SPEC,
  PLAYWRIGHT_OFFLINE_SNAPSHOT_UPDATE_FLAG,
  PLAYWRIGHT_OFFLINE_TARGETED_FLAG,
  PLAYWRIGHT_OFFLINE_BROWSER_CPUS,
  PLAYWRIGHT_OFFLINE_CONTROLLER_CPUS,
  PLAYWRIGHT_REMOTE_NODE_MODULES,
  PLAYWRIGHT_CONTAINER_STORAGE_STATE,
  PLAYWRIGHT_HEADED_DISPLAY,
  PLAYWRIGHT_CONTAINER_XAUTHORITY,
  PLAYWRIGHT_CONTAINER_X11_SOCKET,
  composeArguments,
  composeImageInspectArguments,
  coreContainerRecoveryReady,
  createPlaywrightResultDirectory,
  exactPlaywrightWSEndpoint,
  exactLoopbackBaseURL,
  exactScannerImage,
  isolatedComposeEnvironment,
  isolatedOfflineLocalEnvironment,
  offlineBrowserServiceArguments,
  offlineControllerArguments,
  offlineControllerSupportFiles,
  offlinePlaywrightInvocation,
  parseEnvironment,
  publishPlaywrightExecutionReport,
  runPlaywrightWithExecutionPublication,
  playwrightContainerAbsenceArguments,
  playwrightContainerCleanupArguments,
  playwrightContainerStopArguments,
  playwrightBrowserCompletionHealthy,
  playwrightContainerArguments,
  playwrightRunnerKind,
  playwrightReferenceCpuEvidence,
  playwrightExecutionScopeComplete,
  playwrightServerReady,
  replaceEnvironmentFields,
  sanitizedCommand,
  snapshotUpdateRunnerArguments,
  summarizePlaywrightContainerInspect,
  summarizePlaywrightControllerNetworkNamespace,
  summarizePlaywrightJsonReport,
  summarizeCgroupCpuWindow,
  summarizePlaywrightImageInspect,
  unexpectedCoreContainerExitArguments,
  unexpectedCoreContainerExitStatusAccepted,
  validateIdentifiers,
} from './compose-harness-lib.mjs';
import {
  createLocalResultDirectory,
  expectedPlatformBaselinePaths,
  platformBaselineEvidence,
  localDependencyEvidence,
  localPlaywrightEnvironment,
  linuxHeadedDesktopEvidence,
  nativeHeadedDesktopEvidence,
  playwrightControllerTimeoutMs,
  playwrightPerformanceBudgetMode,
  qualificationScopeComplete,
  runLocalFallback,
  sameLinuxHeadedDesktopEvidence,
  terminalNativeHeadedDesktopEvidence,
} from './offline-playwright.mjs';
import { fixtureServerSpawnOptions, sanitizedFixtureServerEnvironment } from './server-launcher.mjs';
import { exactProxyContextOptions, exactProxyOrigin, proxyTargetPath } from './exact-origin-proxy.mjs';

test('controller timeout accepts only native Linux and exact 2x nested budgets', () => {
  assert.equal(playwrightControllerTimeoutMs({}), 600_000);
  assert.equal(
    playwrightControllerTimeoutMs({ LOMO_PLAYWRIGHT_CONTROLLER_TIMEOUT_MS: '1200000' }),
    1_200_000,
  );
  assert.throws(
    () => playwrightControllerTimeoutMs({ LOMO_PLAYWRIGHT_CONTROLLER_TIMEOUT_MS: '1200001' }),
    (error) => error?.code === 'controller_timeout_invalid',
  );
});

test('performance budgets block on native Linux and remain advisory under nested WSL', () => {
  assert.equal(playwrightPerformanceBudgetMode(600_000), 'blocking');
  assert.equal(playwrightPerformanceBudgetMode(1_200_000), 'advisory');
  assert.throws(
    () => playwrightPerformanceBudgetMode(1_200_001),
    (error) => error?.code === 'performance_budget_mode_invalid',
  );
});

function writeFixtureFile(path, contents = 'fixture\n') {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
}

function localBrowserFixturePaths(suiteRoot, platform, architecture, revision = '1228') {
  if (platform === 'darwin') {
    return {
      chromium: resolve(
        suiteRoot,
        '.browsers',
        `chromium-${revision}`,
        `chrome-mac-${architecture}`,
        'Google Chrome for Testing.app',
        'Contents',
        'MacOS',
        'Google Chrome for Testing',
      ),
      chromiumHeadlessShell: resolve(
        suiteRoot,
        '.browsers',
        `chromium_headless_shell-${revision}`,
        `chrome-headless-shell-mac-${architecture}`,
        'chrome-headless-shell',
      ),
    };
  }
  if (platform === 'win32' && ['x64', 'arm64'].includes(architecture)) {
    return {
      chromium: resolve(
        suiteRoot,
        '.browsers',
        `chromium-${revision}`,
        'chrome-win64',
        'chrome.exe',
      ),
      chromiumHeadlessShell: resolve(
        suiteRoot,
        '.browsers',
        `chromium_headless_shell-${revision}`,
        'chrome-headless-shell-win64',
        'chrome-headless-shell.exe',
      ),
    };
  }
  throw new Error(`Unsupported local browser fixture: ${platform}/${architecture}`);
}

function fixtureBrowserRegistry(revision = '1228', browserVersion = '149.0.7827.55') {
  return {
    browsers: [
      {
        name: 'chromium', revision, installByDefault: true, browserVersion,
      },
      {
        name: 'chromium-headless-shell', revision, installByDefault: true, browserVersion,
      },
    ],
  };
}

function localRunnerFixture(t, platform = 'darwin') {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'kodesec-local-playwright-')));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const suiteRoot = resolve(root, 'tests', 'playwright');
  const scriptRoot = resolve(suiteRoot, 'scripts');
  const webDistRoot = resolve(root, 'apps', 'web', 'dist');
  writeFixtureFile(resolve(scriptRoot, 'offline-playwright.mjs'));
  writeFixtureFile(resolve(scriptRoot, 'compose-harness-lib.mjs'));
  writeFixtureFile(resolve(scriptRoot, 'playwright.mjs'));
  writeFixtureFile(resolve(scriptRoot, 'server-launcher.mjs'));
  for (const file of Object.values(offlineControllerSupportFiles(suiteRoot))) {
    writeFixtureFile(file);
  }
  writeFixtureFile(resolve(suiteRoot, 'playwright.config.ts'));
  writeFixtureFile(resolve(suiteRoot, 'package-lock.json'), '{}\n');
  writeFixtureFile(resolve(suiteRoot, 'server.mjs'));
  writeFixtureFile(resolve(suiteRoot, 'tests', 'foundation.spec.ts'));
  writeFixtureFile(resolve(webDistRoot, 'index.html'), '<!doctype html>\n');
  writeFixtureFile(resolve(suiteRoot, 'package.json'), JSON.stringify({
    devDependencies: {
      '@axe-core/playwright': '4.10.2',
      '@playwright/test': '1.61.1',
    },
  }));
  writeFixtureFile(resolve(suiteRoot, 'node_modules', '@playwright', 'test', 'cli.js'));
  writeFixtureFile(resolve(suiteRoot, 'node_modules', '@playwright', 'test', 'package.json'), JSON.stringify({
    name: '@playwright/test',
    version: '1.61.1',
    dependencies: { playwright: '1.61.1' },
  }));
  writeFixtureFile(resolve(suiteRoot, 'node_modules', '.package-lock.json'), '{}\n');
  writeFixtureFile(resolve(suiteRoot, 'node_modules', 'playwright', 'package.json'), JSON.stringify({
    name: 'playwright',
    version: '1.61.1',
    dependencies: { 'playwright-core': '1.61.1' },
  }));
  writeFixtureFile(
    resolve(suiteRoot, 'node_modules', 'playwright', 'node_modules', 'playwright-core', 'package.json'),
    JSON.stringify({ name: 'playwright-core', version: '1.61.1' }),
  );
  writeFixtureFile(
    resolve(suiteRoot, 'node_modules', 'playwright', 'node_modules', 'playwright-core', 'browsers.json'),
    JSON.stringify(fixtureBrowserRegistry()),
  );
  writeFixtureFile(resolve(suiteRoot, 'node_modules', '@axe-core', 'playwright', 'package.json'), JSON.stringify({
    name: '@axe-core/playwright',
    version: '4.10.2',
    peerDependencies: { 'playwright-core': '>=1.0.0' },
  }));
  writeFixtureFile(resolve(suiteRoot, 'node_modules', 'playwright-core', 'package.json'), JSON.stringify({
    name: 'playwright-core',
    version: '9.99.0',
  }));
  writeFixtureFile(
    resolve(suiteRoot, 'node_modules', 'playwright-core', 'browsers.json'),
    JSON.stringify(fixtureBrowserRegistry('9999', '999.0.0.0')),
  );
  const architecture = platform === 'darwin' ? 'arm64' : 'x64';
  const browserPaths = localBrowserFixturePaths(suiteRoot, platform, architecture);
  writeFixtureFile(browserPaths.chromium, 'nested chromium fixture\n');
  writeFixtureFile(browserPaths.chromiumHeadlessShell, 'nested chromium headless shell fixture\n');
  chmodSync(browserPaths.chromium, 0o755);
  chmodSync(browserPaths.chromiumHeadlessShell, 0o755);
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.from('fixture'),
  ]);
  for (const path of new Set([
    ...expectedPlatformBaselinePaths(platform),
    ...expectedPlatformBaselinePaths(platform, { headed: false }),
  ])) {
    writeFixtureFile(resolve(
      suiteRoot,
      'tests',
      '__screenshots__',
      'foundation.spec.ts',
      path,
    ), png);
  }
  return { suiteRoot, scriptRoot, webDistRoot, platform, architecture };
}

function qualificationExecutionReport({ failed = false } = {}) {
  const specs = [...PLAYWRIGHT_ALLOWED_SPECS];
  const projects = [...PLAYWRIGHT_ALLOWED_PROJECTS];
  return {
    suites: specs.map((spec, index) => ({
      file: `/private-candidate/${spec}`,
      specs: [{
        file: `/private-candidate/${spec}`,
        title: spec === 'tests/operator-actions.spec.ts'
          ? '[WEB-ACT-001] [WEB-ACT-002] [WEB-ACT-003] [WEB-ACT-004] [WEB-ACT-005] [WEB-ACT-006] [WEB-ACT-007] [WEB-ACT-008] [WEB-ACT-009] qualification fixture'
          : 'qualification fixture',
        tests: [{
          projectName: projects[index % projects.length],
          status: failed && index === 0 ? 'unexpected' : 'expected',
          results: [{ status: failed && index === 0 ? 'failed' : 'passed' }],
        }],
      }],
      suites: [],
    })),
    errors: failed ? [{ message: 'redacted fixture failure' }] : [],
    stats: {
      expected: failed ? specs.length - 1 : specs.length,
      flaky: 0,
      skipped: 0,
      unexpected: failed ? 1 : 0,
      duration: 42,
    },
  };
}

function singleIdentityExecutionReport(suiteFile, specFile) {
  return {
    suites: [{
      file: suiteFile,
      specs: [{
        file: specFile,
        tests: [{
          projectName: 'desktop-1440',
          status: 'expected',
          results: [{ status: 'passed' }],
        }],
      }],
      suites: [],
    }],
    errors: [],
    stats: { expected: 1, flaky: 0, skipped: 0, unexpected: 0, duration: 1 },
  };
}

function composeExecutionReport(projects = PLAYWRIGHT_ALLOWED_PROJECTS) {
  return {
    suites: [{
      file: `/private-candidate/${PLAYWRIGHT_COMPOSE_SPEC}`,
      specs: [{
        file: 'compose.smoke.spec.ts',
        tests: projects.map((projectName) => ({
          projectName,
          status: 'expected',
          results: [{ status: 'passed' }],
        })),
      }],
      suites: [],
    }],
    errors: [],
    stats: { expected: projects.length, flaky: 0, skipped: 0, unexpected: 0, duration: 7 },
  };
}

function completedFakeChild(prepare, { status = 0, signal = null } = {}) {
  prepare();
  const child = new EventEmitter();
  child.pid = 987_654;
  child.exitCode = null;
  child.signalCode = null;
  child.kill = () => false;
  queueMicrotask(() => {
    child.exitCode = status;
    child.signalCode = signal;
    child.emit('close', status, signal);
  });
  return child;
}

async function waitForFixtureFile(path, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      return readFileSync(path, 'utf8');
    } catch {
      await new Promise((resolveWait) => setTimeout(resolveWait, 10));
    }
  }
  throw new Error(`Timed out waiting for fixture file: ${path}`);
}

async function waitForChildClose(child, timeoutMs = 5_000) {
  let timeout;
  try {
    return await Promise.race([
      once(child, 'close'),
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error('Timed out waiting for child process close.')), timeoutMs);
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

function soleLocalRunnerReceipt(suiteRoot) {
  const offlineRoot = resolve(suiteRoot, '.results', 'offline');
  const runIds = readdirSync(offlineRoot).sort();
  assert.equal(runIds.length, 1);
  return resolve(offlineRoot, runIds[0], 'runner-receipt.json');
}

function localSupervisorDriver(fixture, { timeoutMs, graceMs }) {
  const runnerUrl = new URL('./offline-playwright.mjs', import.meta.url).href;
  const driverPath = resolve(fixture.suiteRoot, 'local-supervisor-driver.mjs');
  writeFixtureFile(driverPath, `
import { runLocalFallback } from ${JSON.stringify(runnerUrl)};
const result = await runLocalFallback({
  suiteRoot: ${JSON.stringify(fixture.suiteRoot)},
  scriptRoot: ${JSON.stringify(fixture.scriptRoot)},
  webDistRoot: ${JSON.stringify(fixture.webDistRoot)},
  platform: ${JSON.stringify(fixture.platform)},
  architecture: 'arm64',
  osRelease: 'signal-fixture',
  controllerTimeoutMs: ${timeoutMs},
  childTerminationGraceMs: ${graceMs},
});
process.exitCode = result.exitCode;
`);
  return driverPath;
}

function hangingLocalPlaywrightCli(fixture, readyPath, terminatedPath, { ignoreTerm = false } = {}) {
  const cliPath = resolve(fixture.suiteRoot, 'node_modules', '@playwright', 'test', 'cli.js');
  writeFixtureFile(cliPath, `
import { writeFileSync } from 'node:fs';
writeFileSync(${JSON.stringify(readyPath)}, String(process.pid));
process.on('SIGTERM', () => {
  writeFileSync(${JSON.stringify(terminatedPath)}, 'SIGTERM');
  ${ignoreTerm ? '' : 'process.exit(0);'}
});
setInterval(() => {}, 1_000);
`);
}

function fixtureLauncherTree(fixture, { ignoreTerm = false } = {}) {
  const launcherPath = resolve(fixture.scriptRoot, 'server-launcher.mjs');
  const readyPath = resolve(fixture.suiteRoot, 'fixture-server-ready.json');
  const ownerPath = resolve(fixture.suiteRoot, 'fixture-owner-ready.json');
  const terminatedPath = resolve(fixture.suiteRoot, 'fixture-server-terminated');
  writeFixtureFile(launcherPath, readFileSync(new URL('./server-launcher.mjs', import.meta.url)));
  // This harmless server requests an OS-assigned loopback port. The regression
  // tests process ownership, without opening the product fixture's fixed port.
  writeFixtureFile(resolve(fixture.suiteRoot, 'server.mjs'), `
import { appendFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
const server = createServer((socket) => socket.once('data', () => {
  socket.end();
  server.close(() => process.exit(0));
}));
process.on('SIGTERM', () => {
  appendFileSync(${JSON.stringify(terminatedPath)}, 'SIGTERM\\n');
  ${ignoreTerm ? '' : 'server.close(() => process.exit(0));'}
});
server.listen(0, '127.0.0.1', () => writeFileSync(${JSON.stringify(readyPath)}, JSON.stringify({
  pid: process.pid, port: server.address().port,
})));
`);
  return { launcherPath, readyPath, ownerPath, terminatedPath };
}

function detachedFixtureOwnerCli(fixture, tree, { killOwner = false } = {}) {
  writeFixtureFile(resolve(fixture.suiteRoot, 'node_modules', '@playwright', 'test', 'cli.js'), `
import { spawn } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
const launcher = spawn(process.execPath, [${JSON.stringify(tree.launcherPath)}], {
  cwd: ${JSON.stringify(fixture.suiteRoot)},
  detached: true,
  stdio: ['pipe', 'ignore', 'ignore'],
  env: { KODESEC_PLAYWRIGHT_PORT: '43123' },
});
writeFileSync(${JSON.stringify(tree.ownerPath)}, JSON.stringify({ pid: process.pid, launcher: launcher.pid }));
${killOwner ? `const ready = setInterval(() => {
  if (!existsSync(${JSON.stringify(tree.readyPath)})) return;
  clearInterval(ready);
  setTimeout(() => process.kill(process.pid, 'SIGKILL'), 200);
}, 10);` : ''}
setInterval(() => {}, 1_000);
`);
}

async function fixtureLoopbackConnection(port, finish = false) {
  assert.equal(Number.isSafeInteger(port) && port >= 1024 && port <= 65535, true);
  return new Promise((resolveConnection, rejectConnection) => {
    const socket = createConnection({ host: '127.0.0.1', port });
    socket.setTimeout(1_000, () => {
      socket.destroy();
      rejectConnection(new Error('Owned fixture listener observation timed out.'));
    });
    socket.once('connect', () => {
      if (finish) socket.end('finish');
      else socket.destroy();
      resolveConnection(true);
    });
    socket.once('error', (error) => {
      socket.destroy();
      if (error.code === 'ECONNREFUSED') resolveConnection(false);
      else rejectConnection(error);
    });
  });
}

async function waitForFixturePidsAbsent(pids) {
  for (const pid of pids) assert.equal(Number.isSafeInteger(pid) && pid > 1, true);
  const remaining = new Set(pids);
  const deadline = Date.now() + 5_000;
  while (remaining.size && Date.now() < deadline) {
    for (const pid of remaining) {
      try { process.kill(pid, 0); } catch (error) {
        if (error.code !== 'ESRCH') throw error;
        remaining.delete(pid);
      }
    }
    if (remaining.size) await new Promise((resolveWait) => setTimeout(resolveWait, 20));
  }
  assert.equal(remaining.size, 0, 'every exact fixture PID is absent');
}

async function cleanFixtureLauncherTree(tree, directChild) {
  const pids = new Set();
  if (directChild?.exitCode === null && directChild.signalCode === null) pids.add(directChild.pid);
  for (const [path, keys] of [[tree.ownerPath, ['pid', 'launcher']], [tree.readyPath, ['pid']]]) {
    if (!existsSync(path)) continue;
    const value = JSON.parse(readFileSync(path, 'utf8'));
    for (const key of keys) if (Number.isSafeInteger(value[key]) && value[key] > 1) pids.add(value[key]);
  }
  for (const pid of pids) {
    try { process.kill(pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
  await waitForFixturePidsAbsent([...pids]);
}

test('core smoke starts and measures the durable worker', () => {
  assert.deepEqual(CORE_SERVICES, [
    'postgres',
    'scanner',
    'worker',
    'api',
    'api-ingress',
  ]);
  assert.equal(Object.isFrozen(CORE_SERVICES), true);
});

test('forced recovery exits PID 1 only inside an exact generated core container', () => {
  assert.deepEqual(
    unexpectedCoreContainerExitArguments('lomo-code-security-0123456789ab-scanner-1'),
    ['container', 'exec', 'lomo-code-security-0123456789ab-scanner-1', '/bin/sh', '-c', 'kill -TERM 1'],
  );
  assert.deepEqual(
    unexpectedCoreContainerExitArguments('lomo-code-security-0123456789ab-api-ingress-1'),
    [
      'container', 'exec', 'lomo-code-security-0123456789ab-api-ingress-1',
      '/bin/sh', '-c', 'kill -TERM 1',
    ],
  );
  assert.deepEqual(
    unexpectedCoreContainerExitArguments('lomo-code-security-0123456789ab-postgres-1'),
    [
      'container', 'exec', '--user', 'postgres', 'lomo-code-security-0123456789ab-postgres-1',
      'pg_ctl', '-D', '/var/lib/postgresql/data', '-m', 'immediate', '-w', 'stop',
    ],
  );
  for (const invalid of [
    'scanner',
    'lomo-code-security-0123456789ab-worker-1',
    'lomo-code-security-0123456789ab-scanner-updater-1',
    'lomo-code-security-0123456789ab-scanner-2',
    'lomo-code-security-0123456789ab-scanner-1;host',
  ]) assert.throws(() => unexpectedCoreContainerExitArguments(invalid), /malformed/);
});

test('forced recovery accepts only the scoped PostgreSQL exec shutdown status', () => {
  const scanner = 'lomo-code-security-0123456789ab-scanner-1';
  const api = 'lomo-code-security-0123456789ab-api-1';
  const ingress = 'lomo-code-security-0123456789ab-api-ingress-1';
  const postgres = 'lomo-code-security-0123456789ab-postgres-1';
  assert.equal(unexpectedCoreContainerExitStatusAccepted(scanner, 0), true);
  assert.equal(unexpectedCoreContainerExitStatusAccepted(api, 0), true);
  assert.equal(unexpectedCoreContainerExitStatusAccepted(ingress, 0), true);
  assert.equal(unexpectedCoreContainerExitStatusAccepted(postgres, 0), true);
  assert.equal(unexpectedCoreContainerExitStatusAccepted(postgres, 137), true);
  for (const containerName of [scanner, api, ingress]) {
    assert.equal(unexpectedCoreContainerExitStatusAccepted(containerName, 137), false);
  }
  for (const status of [1, 125, 126, 127, 143, 255]) {
    assert.equal(unexpectedCoreContainerExitStatusAccepted(postgres, status), false);
  }
  assert.throws(() => unexpectedCoreContainerExitStatusAccepted('postgres', 0), /malformed/);
  assert.throws(() => unexpectedCoreContainerExitStatusAccepted(postgres, null), /malformed/);
});

test('forced recovery waits for one healthy restart of the same container', () => {
  const id = 'a'.repeat(64);
  const before = { id, restartCount: 4, running: true, health: 'healthy' };
  assert.equal(coreContainerRecoveryReady(before, before), false);
  assert.equal(coreContainerRecoveryReady(before, {
    id, restartCount: 5, running: true, health: 'starting',
  }), false);
  assert.equal(coreContainerRecoveryReady(before, {
    id, restartCount: 5, running: false, health: 'unhealthy',
  }), false);
  assert.equal(coreContainerRecoveryReady(before, {
    id, restartCount: 5, running: true, health: 'healthy',
  }), true);
  assert.throws(() => coreContainerRecoveryReady(before, {
    id: 'b'.repeat(64), restartCount: 5, running: true, health: 'healthy',
  }), /recreated/);
  assert.throws(() => coreContainerRecoveryReady(before, {
    id, restartCount: 6, running: true, health: 'healthy',
  }), /exact recovery boundary/);
  assert.throws(() => coreContainerRecoveryReady(before, {
    id, restartCount: 3, running: true, health: 'healthy',
  }), /exact recovery boundary/);
  assert.throws(() => coreContainerRecoveryReady(before, {
    id, restartCount: '5', running: true, health: 'healthy',
  }), /malformed/);
});

test('Linux and WSL use the pinned container while other hosts retain the local fallback', () => {
  assert.equal(playwrightRunnerKind('linux'), 'container');
  assert.equal(playwrightRunnerKind('darwin'), 'local');
  assert.equal(playwrightRunnerKind('win32'), 'local');
  assert.equal(
    PLAYWRIGHT_CONTAINER_IMAGE,
    'mcr.microsoft.com/playwright:v1.61.1-noble@sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48',
  );
});

test('snapshot updater uses offline isolation only on Linux and keeps macOS and Windows local', () => {
  assert.deepEqual(snapshotUpdateRunnerArguments({
    platform: 'linux',
    scriptsDirectory: '/workspace/lomo/tests/playwright/scripts',
    extraArguments: ['--grep', 'visual'],
  }), {
    runner: '/workspace/lomo/tests/playwright/scripts/offline-playwright.mjs',
    arguments: [PLAYWRIGHT_OFFLINE_SNAPSHOT_UPDATE_FLAG, PLAYWRIGHT_FOUNDATION_SPEC, '--grep', 'visual'],
  });
  for (const platform of ['darwin', 'win32']) {
    assert.deepEqual(snapshotUpdateRunnerArguments({
      platform,
      scriptsDirectory: '/workspace/lomo/tests/playwright/scripts',
    }), {
      runner: '/workspace/lomo/tests/playwright/scripts/playwright.mjs',
      arguments: ['test', PLAYWRIGHT_FOUNDATION_SPEC, '--update-snapshots=all'],
    });
  }
  assert.throws(() => snapshotUpdateRunnerArguments({
    platform: 'linux',
    scriptsDirectory: '/workspace/lomo/tests/playwright/scripts',
    extraArguments: ['-u=all'],
  }), /not allowed/);
  assert.throws(() => snapshotUpdateRunnerArguments({
    platform: 'linux',
    scriptsDirectory: 'relative/scripts',
  }), /absolute Docker bind path/);
});

test('browser container is loopback-capable, bounded, non-root, and narrowly mounted', () => {
  const args = playwrightContainerArguments({
    suiteDirectory: '/workspace/lomo/tests/playwright',
    resultDirectory: '/workspace/lomo/tests/playwright/.results/compose/run',
    storageState: '/workspace/lomo/.kodesec-test/playwright-compose/run/browser-state.json',
    baseURL: 'http://127.0.0.1:43123',
    containerName: 'lomo-code-security-0123456789ab-browser',
    uid: 1000,
    gid: 1000,
  });
  const securityPrefix = [
    'run', '--rm', '--name', 'lomo-code-security-0123456789ab-browser',
    '--network', 'host', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges:true', '--user', '1000:1000',
    '--memory', '1g', '--memory-swap', '1g', '--cpus', '2', '--pids-limit', '256',
    '--shm-size', '256m', '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700',
    '--mount', 'type=bind,source=/workspace/lomo/tests/playwright,target=/workspace/lomo/tests/playwright,readonly',
    '--tmpfs', '/workspace/lomo/tests/playwright/.results:rw,nosuid,nodev,noexec,size=8m,uid=1000,gid=1000,mode=0700',
    '--mount', 'type=bind,source=/workspace/lomo/tests/playwright/.results/compose/run,target=/workspace/lomo/tests/playwright/.results/compose/run',
  ];
  assert.deepEqual(args.slice(0, securityPrefix.length), securityPrefix);
  assert.ok(args.includes(`type=bind,source=/workspace/lomo/.kodesec-test/playwright-compose/run/browser-state.json,target=${PLAYWRIGHT_CONTAINER_STORAGE_STATE},readonly`));
  assert.ok(args.includes('KODESEC_PLAYWRIGHT_BROWSER_CONTAINER=1'));
  assert.ok(args.includes('PLAYWRIGHT_BROWSERS_PATH=/ms-playwright'));
  assert.ok(args.includes('KODESEC_COMPOSE_BASE_URL=http://127.0.0.1:43123'));
  assert.equal(args.some((value) => value.includes('runtime.env')), false);
  assert.equal(args.some((value) => value.includes('KODESEC_BOOTSTRAP_TOKEN')), false);
  const maskIndex = args.indexOf('/workspace/lomo/tests/playwright/.results:rw,nosuid,nodev,noexec,size=8m,uid=1000,gid=1000,mode=0700');
  const currentResultIndex = args.indexOf('type=bind,source=/workspace/lomo/tests/playwright/.results/compose/run,target=/workspace/lomo/tests/playwright/.results/compose/run');
  assert.ok(maskIndex > 0 && currentResultIndex > maskIndex, 'prior result evidence is masked before the current run is overlaid');
  assert.equal(args.at(-4), PLAYWRIGHT_CONTAINER_IMAGE);
  assert.deepEqual(args.slice(-3), ['node', '/workspace/lomo/tests/playwright/scripts/playwright.mjs', 'test']);
});

test('browser container rejects broad, secret-adjacent, root, and malformed inputs', () => {
  const valid = {
    suiteDirectory: '/workspace/lomo/tests/playwright',
    resultDirectory: '/workspace/lomo/tests/playwright/.results/compose/run',
    storageState: '/workspace/lomo/.kodesec-test/run/browser-state.json',
    baseURL: 'http://127.0.0.1:43123',
    containerName: 'lomo-code-security-0123456789ab-browser',
    uid: 1000,
    gid: 1000,
  };
  assert.throws(() => playwrightContainerArguments({ ...valid, uid: 0 }), /non-root/);
  assert.throws(() => playwrightContainerArguments({ ...valid, containerName: 'browser' }), /name is malformed/);
  assert.throws(() => playwrightContainerArguments({ ...valid, resultDirectory: '/workspace/lomo/.results' }), /masked suite result/);
  assert.throws(() => playwrightContainerArguments({ ...valid, resultDirectory: '/workspace/lomo/tests/playwright/output/run' }), /masked suite result/);
  assert.throws(() => playwrightContainerArguments({ ...valid, storageState: '/workspace/lomo/tests/playwright/state.json' }), /separately/);
  assert.throws(() => playwrightContainerArguments({ ...valid, suiteDirectory: '/workspace/lo,mo/tests/playwright' }), /bind path/);
  assert.throws(() => playwrightContainerArguments({ ...valid, baseURL: 'http://localhost:43123' }), /exact 127\.0\.0\.1/);
});

test('offline browser service is exact, networkless, bounded, and mounts only locked node_modules', () => {
  const args = offlineBrowserServiceArguments({
    suiteDirectory: '/workspace/lomo/tests/playwright',
    containerName: 'lomo-code-security-0123456789ab-browser',
    wsPort: 43821,
    wsPath: '/0123456789ab',
    uid: 1000,
    gid: 1000,
  });
  assert.deepEqual(args.slice(0, 29), [
    'run', '--detach', '--interactive', '--init', '--pull', 'never',
    '--name', 'lomo-code-security-0123456789ab-browser',
    '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges:true', '--user', '1000:1000',
    '--memory', '1g', '--memory-swap', '1g', '--cpus', '4', '--pids-limit', '256',
    '--shm-size', '256m', '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700',
  ]);
  const mounts = args.filter((_value, index) => args[index - 1] === '--mount');
  assert.deepEqual(mounts, [
    `type=bind,source=/workspace/lomo/tests/playwright/node_modules,target=${PLAYWRIGHT_REMOTE_NODE_MODULES},readonly`,
  ]);
  assert.equal(args.includes('--unsafe'), false);
  assert.equal(args.includes('/workspace/lomo/tests/playwright'), false);
  assert.equal(args.includes('KODESEC_COMPOSE_STORAGE_STATE'), false);
  assert.equal(args.at(-14), PLAYWRIGHT_CONTAINER_IMAGE);
  assert.deepEqual(args.slice(-13), [
    'node', `${PLAYWRIGHT_REMOTE_NODE_MODULES}/@playwright/test/cli.js`, 'run-server',
    '--host', '127.0.0.1', '--port', '43821', '--path', '/0123456789ab',
    '--max-clients', '1', '--artifacts-dir', '/tmp/kodesec-artifacts',
  ]);
});

test('headed offline browser mounts only the verified :1 desktop and controller requests headed Chromium', () => {
  const desktop = {
    mode: 'headed-real-x11',
    headed: true,
    display: PLAYWRIGHT_HEADED_DISPLAY,
    hostname: 'fixture-linux-ubuntu',
    xauthority: {
      host_path: '/home/developer/.Xauthority',
      container_path: PLAYWRIGHT_CONTAINER_XAUTHORITY,
    },
    x11_socket: {
      host_path: PLAYWRIGHT_CONTAINER_X11_SOCKET,
      container_path: PLAYWRIGHT_CONTAINER_X11_SOCKET,
    },
    transport: {
      schema: 'lomo-playwright-x11-relay/v1',
      mode: 'owner-scoped-unix-relay',
      ready: true,
      child: { ready: true },
      xauthority: {
        host_path: '/workspace/lomo/tests/playwright/.results/.x11-relay-0123456789ab/Xauthority',
        container_path: PLAYWRIGHT_CONTAINER_XAUTHORITY,
      },
      x11_socket: {
        host_path: '/workspace/lomo/tests/playwright/.results/.x11-relay-0123456789ab/X1',
        container_path: PLAYWRIGHT_CONTAINER_X11_SOCKET,
      },
    },
    preflight_verified: true,
  };
  const browser = offlineBrowserServiceArguments({
    suiteDirectory: '/workspace/lomo/tests/playwright',
    containerName: 'lomo-code-security-0123456789ab-browser',
    wsPort: 43821,
    wsPath: '/0123456789ab',
    uid: 1000,
    gid: 1000,
    desktop,
  });
  assert.ok(browser.includes('DISPLAY=:1'));
  assert.ok(browser.includes(`XAUTHORITY=${PLAYWRIGHT_CONTAINER_XAUTHORITY}`));
  assert.ok(browser.includes('fixture-linux-ubuntu'));
  assert.deepEqual(browser.filter((_value, index) => browser[index - 1] === '--mount'), [
    `type=bind,source=/workspace/lomo/tests/playwright/node_modules,target=${PLAYWRIGHT_REMOTE_NODE_MODULES},readonly`,
    `type=bind,source=/workspace/lomo/tests/playwright/.results/.x11-relay-0123456789ab/Xauthority,target=${PLAYWRIGHT_CONTAINER_XAUTHORITY},readonly`,
    `type=bind,source=/workspace/lomo/tests/playwright/.results/.x11-relay-0123456789ab/X1,target=${PLAYWRIGHT_CONTAINER_X11_SOCKET},readonly`,
  ]);
  assert.equal(browser.includes('host'), false);
  assert.equal(browser.some((value) => /Xvfb|label=disable/u.test(value)), false);
  assert.throws(
    () => offlineBrowserServiceArguments({
      suiteDirectory: '/workspace/lomo/tests/playwright',
      containerName: 'lomo-code-security-0123456789ab-browser',
      wsPort: 43821,
      wsPath: '/0123456789ab',
      uid: 1000,
      gid: 1000,
      desktop: { ...desktop, transport: null },
    }),
    /owner-scoped Unix relay contract/u,
  );

  const controller = offlineControllerArguments({
    suiteDirectory: '/workspace/lomo/tests/playwright',
    webDistDirectory: '/workspace/lomo/apps/web/dist',
    resultDirectory: '/workspace/lomo/tests/playwright/.results/offline/0123456789ab',
    browserContainerName: 'lomo-code-security-0123456789ab-browser',
    controllerContainerName: 'lomo-code-security-0123456789ab-controller',
    wsEndpoint: 'ws://127.0.0.1:43821/0123456789ab',
    fixturePort: 41783,
    uid: 1000,
    gid: 1000,
    headed: true,
  });
  assert.ok(controller.includes('KODESEC_PLAYWRIGHT_HEADED=1'));
  assert.equal(controller.some((value) => value.startsWith('DISPLAY=')), false);
  assert.equal(controller.some((value) => value.startsWith('XAUTHORITY=')), false);
});

test('real Linux desktop evidence rejects drift and records no Xauthority content or digest', () => {
  const xauthorityPath = '/home/developer/.Xauthority';
  const metadata = (kind, inode) => ({
    dev: 8,
    ino: inode,
    uid: 1000,
    gid: 1000,
    mode: kind === 'file' ? 0o100600 : 0o140777,
    nlink: 1,
    size: kind === 'file' ? 143 : 0,
    isFile: () => kind === 'file',
    isSocket: () => kind === 'socket',
    isSymbolicLink: () => false,
  });
  const makeEvidence = (socketInode = 22, mode = 0o100600) => linuxHeadedDesktopEvidence({
    environment: {
      KODESEC_PLAYWRIGHT_HEADED: '1',
      DISPLAY: ':1',
      XAUTHORITY: xauthorityPath,
    },
    uid: 1000,
    gid: 1000,
    hostnameValue: 'fixture-linux-fedora',
    lstatPath: (path) => {
      if (path === xauthorityPath) return { ...metadata('file', 11), mode };
      if (path === PLAYWRIGHT_CONTAINER_X11_SOCKET) return metadata('socket', socketInode);
      throw new Error('unexpected path');
    },
    realpathPath: (path) => path,
  });
  const first = makeEvidence();
  assert.equal(first.mode, 'headed-real-x11');
  assert.equal(first.preflight_verified, true);
  assert.equal(first.xauthority.mode, '0600');
  assert.equal(first.transport, null);
  assert.equal(JSON.stringify(first).includes('sha256'), false);
  assert.equal(JSON.stringify(first).includes('cookie'), false);
  assert.equal(sameLinuxHeadedDesktopEvidence(first, makeEvidence()), true);
  assert.equal(sameLinuxHeadedDesktopEvidence(first, makeEvidence(23)), false);
  assert.throws(() => makeEvidence(22, 0o100644), (error) => error?.code === 'headed_xauthority_invalid');
  assert.throws(
    () => linuxHeadedDesktopEvidence({ environment: { KODESEC_PLAYWRIGHT_HEADED: '1', DISPLAY: ':2' } }),
    (error) => error?.code === 'headed_display_invalid',
  );
});

test('native foreground evidence qualifies only a successful terminal headed browser', () => {
  const headless = nativeHeadedDesktopEvidence({ platform: 'darwin', environment: {} });
  const headlessTerminal = terminalNativeHeadedDesktopEvidence(headless, {
    controller: { exit_code: 0, signal: null, spawn_error: false, timed_out: false, reaped: true },
    fullScopeExecuted: true,
    outcomePassed: true,
  });
  assert.equal(headlessTerminal.terminal_verified, true);
  assert.equal(headlessTerminal.verified, false);
  assert.equal(headlessTerminal.postflight_error_code, 'headed_not_requested');

  const headed = nativeHeadedDesktopEvidence({
    platform: 'win32',
    environment: { KODESEC_PLAYWRIGHT_HEADED: '1' },
  });
  const terminal = terminalNativeHeadedDesktopEvidence(headed, {
    controller: { exit_code: 0, signal: null, spawn_error: false, timed_out: false, reaped: true },
    fullScopeExecuted: true,
    outcomePassed: true,
  });
  assert.equal(terminal.mode, 'headed-native-foreground');
  assert.equal(terminal.terminal_verified, true);
  assert.equal(terminal.verified, true);
  assert.equal(terminal.postflight_error_code, null);
  assert.equal(terminalNativeHeadedDesktopEvidence(headed, {
    controller: { exit_code: 0, signal: null, spawn_error: false, timed_out: false, reaped: true },
    fullScopeExecuted: false,
    outcomePassed: true,
  }).verified, false);
  assert.throws(
    () => nativeHeadedDesktopEvidence({ platform: 'darwin', environment: { KODESEC_PLAYWRIGHT_HEADED: 'yes' } }),
    (error) => error?.code === 'headed_mode_invalid',
  );
});

test('offline controller shares only the browser network namespace and retains narrow evidence mounts', () => {
  const args = offlineControllerArguments({
    suiteDirectory: '/workspace/lomo/tests/playwright',
    webDistDirectory: '/workspace/lomo/apps/web/dist',
    resultDirectory: '/workspace/lomo/tests/playwright/.results/offline/0123456789ab',
    browserContainerName: 'lomo-code-security-0123456789ab-browser',
    controllerContainerName: 'lomo-code-security-0123456789ab-controller',
    wsEndpoint: 'ws://127.0.0.1:43821/0123456789ab',
    fixturePort: 41783,
    uid: 1000,
    gid: 1000,
    playwrightArguments: ['tests/foundation.spec.ts'],
    runnerMode: 'targeted',
    timingFactor: 2,
  });
  assert.deepEqual(args.slice(0, 23), [
    'run', '--init', '--pull', 'never', '--name', 'lomo-code-security-0123456789ab-controller',
    '--network', 'container:lomo-code-security-0123456789ab-browser',
    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
    '--user', '1000:1000', '--memory', '1g', '--memory-swap', '1g',
    '--cpus', '2', '--pids-limit', '256',
  ]);
  assert.equal(args.includes('host'), false);
  assert.ok(args.includes('KODESEC_PLAYWRIGHT_WS_ENDPOINT=ws://127.0.0.1:43821/0123456789ab'));
  assert.ok(args.includes('KODESEC_PLAYWRIGHT_PORT=41783'));
  assert.ok(args.includes('KODESEC_PLAYWRIGHT_TIMING_FACTOR=2'));
  assert.ok(args.includes('KODESEC_PLAYWRIGHT_HEADED=0'));
  assert.ok(args.includes('type=bind,source=/workspace/lomo/tests/playwright,target=/workspace/lomo/tests/playwright,readonly'));
  assert.ok(args.includes('type=bind,source=/workspace/lomo/apps/web/dist,target=/workspace/lomo/apps/web/dist,readonly'));
  assert.deepEqual(args.filter((_value, index) => args[index - 1] === '--mount'), [
    'type=bind,source=/workspace/lomo/tests/playwright,target=/workspace/lomo/tests/playwright,readonly',
    'type=bind,source=/workspace/lomo/apps/web/dist,target=/workspace/lomo/apps/web/dist,readonly',
    'type=bind,source=/workspace/lomo/extensions/vscode/test/ui/bulk-finding-actions.mjs,target=/workspace/lomo/extensions/vscode/test/ui/bulk-finding-actions.mjs,readonly',
    'type=bind,source=/workspace/lomo/extensions/vscode/test/ui/bulk-finding-race.mjs,target=/workspace/lomo/extensions/vscode/test/ui/bulk-finding-race.mjs,readonly',
    'type=bind,source=/workspace/lomo/apps/web/src/findingNavigation.ts,target=/workspace/lomo/apps/web/src/findingNavigation.ts,readonly',
    'type=bind,source=/workspace/lomo/tests/playwright/.results/offline/0123456789ab,target=/workspace/lomo/tests/playwright/.results/offline/0123456789ab',
  ]);
  assert.equal(args.some((value) => value.includes('tests/__screenshots__')), false);
  const maskIndex = args.indexOf('/workspace/lomo/tests/playwright/.results:rw,nosuid,nodev,noexec,size=8m,uid=1000,gid=1000,mode=0700');
  const resultIndex = args.indexOf('type=bind,source=/workspace/lomo/tests/playwright/.results/offline/0123456789ab,target=/workspace/lomo/tests/playwright/.results/offline/0123456789ab');
  assert.ok(maskIndex > 0 && resultIndex > maskIndex);
  assert.equal(args.some((value) => value.includes('browser-state')), false);
  assert.equal(args.at(-5), PLAYWRIGHT_CONTAINER_IMAGE);
  assert.deepEqual(args.slice(-4), [
    'node', '/workspace/lomo/tests/playwright/scripts/playwright.mjs', 'test', 'tests/foundation.spec.ts',
  ]);
});

test('offline controller rejects timing factors outside native Linux and exact 2x nested Windows', () => {
  const controller = {
    suiteDirectory: '/workspace/lomo/tests/playwright',
    webDistDirectory: '/workspace/lomo/apps/web/dist',
    resultDirectory: '/workspace/lomo/tests/playwright/.results/offline/0123456789ab',
    browserContainerName: 'lomo-code-security-0123456789ab-browser',
    controllerContainerName: 'lomo-code-security-0123456789ab-controller',
    wsEndpoint: 'ws://127.0.0.1:43821/0123456789ab',
    fixturePort: 41783,
    uid: 1000,
    gid: 1000,
  };
  assert.throws(() => offlineControllerArguments({ ...controller, timingFactor: 1.5 }), /exactly 1.*2/);
});

test('explicit offline snapshot update overlays only the platform baseline directory writable', () => {
  const args = offlineControllerArguments({
    suiteDirectory: '/workspace/lomo/tests/playwright',
    webDistDirectory: '/workspace/lomo/apps/web/dist',
    resultDirectory: '/workspace/lomo/tests/playwright/.results/offline-update/0123456789ab',
    browserContainerName: 'lomo-code-security-0123456789ab-browser',
    controllerContainerName: 'lomo-code-security-0123456789ab-controller',
    wsEndpoint: 'ws://127.0.0.1:43821/0123456789ab',
    fixturePort: 41783,
    uid: 1000,
    gid: 1000,
    playwrightArguments: ['tests/foundation.spec.ts', '--update-snapshots=all'],
    runnerMode: 'snapshot-update',
    snapshotDirectory: '/workspace/lomo/tests/playwright/tests/__screenshots__',
  });
  const suiteMount = 'type=bind,source=/workspace/lomo/tests/playwright,target=/workspace/lomo/tests/playwright,readonly';
  const snapshotMount = 'type=bind,source=/workspace/lomo/tests/playwright/tests/__screenshots__,target=/workspace/lomo/tests/playwright/tests/__screenshots__';
  const distMount = 'type=bind,source=/workspace/lomo/apps/web/dist,target=/workspace/lomo/apps/web/dist,readonly';
  assert.ok(args.indexOf(suiteMount) < args.indexOf(snapshotMount));
  assert.ok(args.indexOf(snapshotMount) < args.indexOf(distMount));
  assert.equal(args.filter((value) => value === snapshotMount).length, 1);
  assert.equal(args.some((value) => value === `${snapshotMount},readonly`), false);
  assert.equal(args.some((value) => value.includes('tests/playwright/tests') && value !== snapshotMount), false);
  assert.deepEqual(args.slice(-5), [
    'node', '/workspace/lomo/tests/playwright/scripts/playwright.mjs', 'test', 'tests/foundation.spec.ts', '--update-snapshots=all',
  ]);
});

test('offline Playwright endpoint, readiness, identities, and cleanup fail closed', () => {
  const endpoint = 'ws://127.0.0.1:43821/0123456789ab';
  assert.equal(exactPlaywrightWSEndpoint(endpoint), endpoint);
  assert.equal(playwrightServerReady(`prefix\nListening on ${endpoint}\n`, endpoint), true);
  assert.equal(playwrightServerReady(`Listening on ${endpoint}/session\n`, endpoint), false);
  for (const value of [
    'wss://127.0.0.1:43821/0123456789ab',
    'ws://localhost:43821/0123456789ab',
    'ws://127.0.0.1/0123456789ab',
    'ws://user@127.0.0.1:43821/0123456789ab',
    'ws://127.0.0.1:43821/ABCDEF012345',
    'ws://127.0.0.1:43821/0123456789ab?unsafe=1',
  ]) assert.throws(() => exactPlaywrightWSEndpoint(value), /exact ws:\/\/127\.0\.0\.1/);
  assert.deepEqual(
    playwrightContainerCleanupArguments('lomo-code-security-0123456789ab-controller'),
    ['container', 'rm', '--force', 'lomo-code-security-0123456789ab-controller'],
  );
  assert.deepEqual(
    playwrightContainerCleanupArguments('lomo-code-security-0123456789ab-browser'),
    ['container', 'rm', '--force', 'lomo-code-security-0123456789ab-browser'],
  );
  assert.deepEqual(
    playwrightContainerAbsenceArguments('lomo-code-security-0123456789ab-browser'),
    ['container', 'ls', '--all', '--filter', 'name=^/lomo-code-security-0123456789ab-browser$', '--format', '{{.Names}}'],
  );
  assert.deepEqual(
    playwrightContainerStopArguments('lomo-code-security-0123456789ab-browser'),
    ['container', 'stop', '--time', '5', 'lomo-code-security-0123456789ab-browser'],
  );
  assert.throws(() => playwrightContainerCleanupArguments('owner-browser'), /not a generated/);
  assert.throws(() => playwrightContainerAbsenceArguments('owner-browser'), /not a generated/);
  assert.throws(() => playwrightContainerStopArguments('owner-browser'), /not a generated/);
});

test('offline Playwright arguments reject path, identity, endpoint, port, mount, and CLI widening', () => {
  const browser = {
    suiteDirectory: '/workspace/lomo/tests/playwright',
    containerName: 'lomo-code-security-0123456789ab-browser',
    wsPort: 43821,
    wsPath: '/0123456789ab',
    uid: 1000,
    gid: 1000,
  };
  assert.throws(() => offlineBrowserServiceArguments({ ...browser, uid: 0 }), /non-root/);
  assert.throws(() => offlineBrowserServiceArguments({ ...browser, containerName: 'browser' }), /name is malformed/);
  assert.throws(() => offlineBrowserServiceArguments({ ...browser, wsPort: 80 }), /outside the allowed range/);
  assert.throws(() => offlineBrowserServiceArguments({ ...browser, wsPath: '/0123456789ab/extra' }), /one generated/);
  assert.throws(() => offlineBrowserServiceArguments({ ...browser, wsPath: '/ffffffffffff' }), /identities do not match/);
  assert.throws(() => offlineBrowserServiceArguments({ ...browser, suiteDirectory: '/workspace/lo,mo/tests/playwright' }), /bind path/);

  const controller = {
    suiteDirectory: '/workspace/lomo/tests/playwright',
    webDistDirectory: '/workspace/lomo/apps/web/dist',
    resultDirectory: '/workspace/lomo/tests/playwright/.results/offline/0123456789ab',
    browserContainerName: 'lomo-code-security-0123456789ab-browser',
    controllerContainerName: 'lomo-code-security-0123456789ab-controller',
    wsEndpoint: 'ws://127.0.0.1:43821/0123456789ab',
    fixturePort: 41783,
    uid: 1000,
    gid: 1000,
  };
  assert.throws(() => offlineControllerArguments({ ...controller, controllerContainerName: 'lomo-code-security-ffffffffffff-controller' }), /identities do not match/);
  assert.throws(() => offlineControllerArguments({ ...controller, fixturePort: 43821 }), /ports must be distinct/);
  assert.throws(() => offlineControllerArguments({ ...controller, wsEndpoint: 'ws://127.0.0.1:43821/ffffffffffff' }), /identities do not match/);
  assert.throws(() => offlineControllerArguments({ ...controller, webDistDirectory: '/workspace/lomo/apps/web' }), /apps\/web\/dist/);
  assert.throws(() => offlineControllerArguments({ ...controller, resultDirectory: '/workspace/lomo/.results/run' }), /masked suite result/);
  assert.throws(() => offlineControllerArguments({ ...controller, playwrightArguments: ['tests/foundation.spec.ts'] }), /accept no Playwright CLI overrides/);
  assert.throws(() => offlineControllerArguments({ ...controller, runnerMode: 'targeted', playwrightArguments: ['ok', 'bad\nargument'] }), /not allowed|control characters/);
  assert.throws(() => offlineControllerArguments({ ...controller, runnerMode: 'targeted', playwrightArguments: ['x'.repeat(513)] }), /bounded non-empty strings/);
  assert.throws(() => offlineControllerArguments({ ...controller, runnerMode: 'targeted', playwrightArguments: ['--update-snapshots'] }), /not allowed/);
  assert.throws(() => offlineControllerArguments({ ...controller, runnerMode: 'targeted', playwrightArguments: ['--ignore-snapshots'] }), /not allowed/);
  assert.throws(() => offlineControllerArguments({ ...controller, runnerMode: 'targeted', playwrightArguments: ['--pass-with-no-tests'] }), /not allowed/);
  assert.throws(() => offlineControllerArguments({ ...controller, runnerMode: 'targeted', playwrightArguments: ['--trace=off'] }), /not allowed/);
  assert.throws(() => offlineControllerArguments({ ...controller, runnerMode: 'targeted', playwrightArguments: ['--reporter=null'] }), /not allowed/);
  assert.throws(() => offlineControllerArguments({ ...controller, runnerMode: 'targeted', playwrightArguments: ['--output=/tmp'] }), /not allowed/);
  assert.throws(() => offlineControllerArguments({ ...controller, snapshotDirectory: '/workspace/lomo/tests/playwright/tests/__screenshots__' }), /Ordinary Playwright runs/);
  assert.throws(() => offlineControllerArguments({ ...controller, runnerMode: 'snapshot-update', playwrightArguments: ['--update-snapshots=all'] }), /exact visual foundation spec/);
  assert.throws(() => offlineControllerArguments({
    ...controller,
    runnerMode: 'snapshot-update',
    snapshotDirectory: '/workspace/lomo/tests/playwright/tests',
    playwrightArguments: [PLAYWRIGHT_FOUNDATION_SPEC, '--update-snapshots=all'],
  }), /only to tests\/__screenshots__/);
  assert.throws(() => offlineControllerArguments({
    ...controller,
    runnerMode: 'snapshot-update',
    snapshotDirectory: '/workspace/lomo/tests/playwright/tests/__screenshots__',
    playwrightArguments: [],
  }), /one canonical/);
  assert.throws(() => offlineControllerArguments({
    ...controller,
    runnerMode: 'snapshot-update',
    snapshotDirectory: '/workspace/lomo/tests/playwright/tests/__screenshots__',
    playwrightArguments: ['--update-snapshots=all'],
  }), /exact visual foundation spec/);
  assert.throws(() => offlineControllerArguments({
    ...controller,
    runnerMode: 'snapshot-update',
    snapshotDirectory: '/workspace/lomo/tests/playwright/tests/__screenshots__',
    playwrightArguments: ['-u', '--update-snapshots=all'],
  }), /not allowed/);
});

test('qualification is override-free while targeted and snapshot scopes are explicit and non-qualifying', () => {
  assert.deepEqual(PLAYWRIGHT_ALLOWED_SPECS, [
    'tests/foundation.spec.ts',
    'tests/findings.performance.spec.ts',
    'tests/navigation.performance.spec.ts',
    'tests/operator-actions.spec.ts',
    'tests/scanner-lifecycle.spec.ts',
  ]);
  assert.deepEqual(offlinePlaywrightInvocation([]), {
    mode: 'qualification',
    qualificationEligible: false,
    playwrightArguments: [],
    scope: {
      specs: [...PLAYWRIGHT_ALLOWED_SPECS],
      projects: [...PLAYWRIGHT_ALLOWED_PROJECTS],
      grep: null,
    },
  });
  assert.deepEqual(offlinePlaywrightInvocation([], { headed: true }), {
    mode: 'qualification',
    qualificationEligible: true,
    playwrightArguments: [],
    scope: {
      specs: [...PLAYWRIGHT_ALLOWED_SPECS],
      projects: [...PLAYWRIGHT_ALLOWED_PROJECTS],
      grep: null,
    },
  });
  assert.throws(() => offlinePlaywrightInvocation([], { headed: '1' }), /explicit boolean/u);
  assert.deepEqual(offlinePlaywrightInvocation([
    PLAYWRIGHT_OFFLINE_TARGETED_FLAG,
    PLAYWRIGHT_FOUNDATION_SPEC,
    '--project=desktop-1440',
    '--grep',
    'durable job',
  ]), {
    mode: 'targeted',
    qualificationEligible: false,
    playwrightArguments: [PLAYWRIGHT_FOUNDATION_SPEC, '--project=desktop-1440', '--grep', 'durable job'],
    scope: {
      specs: [PLAYWRIGHT_FOUNDATION_SPEC],
      projects: ['desktop-1440'],
      grep: 'durable job',
    },
  });
  assert.deepEqual(offlinePlaywrightInvocation([
    PLAYWRIGHT_OFFLINE_SNAPSHOT_UPDATE_FLAG,
    PLAYWRIGHT_FOUNDATION_SPEC,
    '--project',
    'mobile-390',
  ]), {
    mode: 'snapshot-update',
    qualificationEligible: false,
    playwrightArguments: [PLAYWRIGHT_FOUNDATION_SPEC, '--project', 'mobile-390', '--update-snapshots=all'],
    scope: {
      specs: [PLAYWRIGHT_FOUNDATION_SPEC],
      projects: ['mobile-390'],
      grep: null,
    },
  });
  for (const argument of [
    '--ignore-snapshots',
    '--pass-with-no-tests',
    '--trace=off',
    '--reporter=null',
    '--output=/tmp',
    '--workers=4',
    '--retries=2',
    '--config=alternate.ts',
    'tests/missing.spec.ts',
  ]) {
    assert.throws(() => offlinePlaywrightInvocation([argument]), /accept no Playwright overrides/);
    assert.throws(() => offlinePlaywrightInvocation([PLAYWRIGHT_OFFLINE_TARGETED_FLAG, argument]), /not allowed/);
  }
  assert.throws(() => offlinePlaywrightInvocation([
    PLAYWRIGHT_OFFLINE_SNAPSHOT_UPDATE_FLAG,
    PLAYWRIGHT_FOUNDATION_SPEC,
    '--ignore-snapshots',
  ]), /not allowed/);
});

test('network conformance admission is sole explicit desktop target and leaves ordinary qualification unchanged', () => {
  const args = [PLAYWRIGHT_OFFLINE_TARGETED_FLAG, PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC, '--project=desktop-1440'];
  const admitted = offlinePlaywrightInvocation(args, { headed: true });
  assert.equal(admitted.mode, 'targeted');
  assert.equal(admitted.qualificationEligible, false);
  assert.deepEqual(admitted.scope, {
    specs: [PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC], projects: ['desktop-1440'], grep: null,
  });
  for (const rejected of [
    [PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC],
    [PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC, '--project=mobile-390'],
    [PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC, '--project=desktop-1440', '--project=desktop-1920'],
    [PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC, PLAYWRIGHT_FOUNDATION_SPEC, '--project=desktop-1440'],
    [PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC, '--project=desktop-1440', '--grep', 'native'],
  ]) assert.throws(() => offlinePlaywrightInvocation([PLAYWRIGHT_OFFLINE_TARGETED_FLAG, ...rejected]), /sole explicit spec/);
  assert.throws(() => offlinePlaywrightInvocation([
    PLAYWRIGHT_OFFLINE_SNAPSHOT_UPDATE_FLAG, PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC, '--project=desktop-1440',
  ]), /only the visual foundation spec/);
  assert.throws(() => offlinePlaywrightInvocation([PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC]), /accept no Playwright overrides/);
  const ordinary = offlinePlaywrightInvocation([], { headed: true });
  assert.equal(ordinary.qualificationEligible, true);
  assert.equal(ordinary.scope.specs.length, 5);
  assert.deepEqual(ordinary.scope.specs, PLAYWRIGHT_ALLOWED_SPECS);
  assert.equal(ordinary.scope.specs.includes(PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC), false);
});

test('network conformance reports require exact explicit scope and remain rejected by default report admission', () => {
  const report = singleIdentityExecutionReport(PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC, 'network-isolation.conformance.spec.ts');
  const scope = { allowedSpecs: [PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC], allowedProjects: ['desktop-1440'] };
  const summary = summarizePlaywrightJsonReport(report, scope);
  assert.deepEqual(summary.specs.map((entry) => entry.name), [PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC]);
  assert.equal(summary.executed_tests, 1);
  const normalized = { schema: PLAYWRIGHT_EXECUTION_REPORT_SCHEMA, ...summary };
  assert.deepEqual(summarizePlaywrightJsonReport(normalized, scope), summary);
  for (const input of [report, normalized]) {
    assert.throws(() => summarizePlaywrightJsonReport(input), input === report
      ? /outside the repository allowlist/
      : /Normalized Playwright report specs contains an unknown or duplicate name/);
    for (const rejectedScope of [
      { allowedSpecs: [PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC, PLAYWRIGHT_FOUNDATION_SPEC], allowedProjects: ['desktop-1440'] },
      { allowedSpecs: [PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC], allowedProjects: ['mobile-390'] },
      { allowedSpecs: [PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC], allowedProjects: PLAYWRIGHT_ALLOWED_PROJECTS },
    ]) assert.throws(() => summarizePlaywrightJsonReport(input, rejectedScope), /outside the repository allowlists/);
  }
  const invocation = offlinePlaywrightInvocation([
    PLAYWRIGHT_OFFLINE_TARGETED_FLAG, PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC, '--project=desktop-1440',
  ], { headed: true });
  assert.equal(playwrightExecutionScopeComplete(invocation.scope, summary), true);
  assert.equal(qualificationScopeComplete(invocation, summary, true), false);
  assert.deepEqual(summarizePlaywrightJsonReport(singleIdentityExecutionReport(
    PLAYWRIGHT_FOUNDATION_SPEC, 'foundation.spec.ts',
  )).specs.map((entry) => entry.name), [PLAYWRIGHT_FOUNDATION_SPEC]);
});

test('navigation proxy A/B admits only its headed sole-target diagnostic without profiler overlap', () => {
  const argumentsToUse = [PLAYWRIGHT_OFFLINE_TARGETED_FLAG, 'tests/navigation.performance.spec.ts', '--project=desktop-1440'];
  const environment = { KODESEC_NAVIGATION_PROXY_AB_DIAGNOSTIC: '1', KODESEC_FINDINGS_RENDER_DIAGNOSTIC: '1' };
  const admitted = offlinePlaywrightInvocation(argumentsToUse, { headed: true, environment });
  assert.equal(admitted.mode, 'targeted');
  assert.equal(admitted.qualificationEligible, false);
  assert.deepEqual(admitted.scope, { specs: ['tests/navigation.performance.spec.ts'], projects: ['desktop-1440'], grep: null });
  for (const args of [[], [PLAYWRIGHT_OFFLINE_TARGETED_FLAG],
    [...argumentsToUse, 'tests/foundation.spec.ts'], [...argumentsToUse, '--project=mobile-390'],
    [...argumentsToUse, '--grep=critical'],
    [PLAYWRIGHT_OFFLINE_TARGETED_FLAG, 'tests/navigation.performance.spec.ts'],
    [PLAYWRIGHT_OFFLINE_TARGETED_FLAG, PLAYWRIGHT_PROXY_CONFORMANCE_SPEC, '--project=desktop-1440']]) {
    assert.throws(() => offlinePlaywrightInvocation(args, { headed: true, environment }), /Proxy A\/B/);
  }
  assert.throws(() => offlinePlaywrightInvocation(argumentsToUse, { headed: false, environment }), /Proxy A\/B/);
  for (const patch of [
    { KODESEC_FINDINGS_RENDER_DIAGNOSTIC: '0' },
    { KODESEC_NAVIGATION_WORKER_CPU_DIAGNOSTIC: '1' },
    { KODESEC_NAVIGATION_RENDERER_METRICS_DIAGNOSTIC: '1' },
    { KODESEC_NAVIGATION_PROXY_AB_DIAGNOSTIC: 'yes' },
  ]) assert.throws(() => offlinePlaywrightInvocation(argumentsToUse, { headed: true, environment: { ...environment, ...patch } }), /Proxy A\/B|proxy A\/B/);
  assert.deepEqual(offlinePlaywrightInvocation([], { headed: true, environment: {} }),
    offlinePlaywrightInvocation([], { headed: true, environment: { KODESEC_NAVIGATION_PROXY_AB_DIAGNOSTIC: '0' } }));
});

test('proxy conformance retains sole-target admission and rejects default or mixed reports', () => {
  const invocation = offlinePlaywrightInvocation([
    PLAYWRIGHT_OFFLINE_TARGETED_FLAG, PLAYWRIGHT_PROXY_CONFORMANCE_SPEC, '--project=desktop-1440',
  ], { headed: true });
  assert.deepEqual(invocation.scope, { specs: [PLAYWRIGHT_PROXY_CONFORMANCE_SPEC], projects: ['desktop-1440'], grep: null });
  assert.equal(invocation.qualificationEligible, false);
  for (const other of [PLAYWRIGHT_FOUNDATION_SPEC, PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC]) {
    assert.throws(() => offlinePlaywrightInvocation([
      PLAYWRIGHT_OFFLINE_TARGETED_FLAG, PLAYWRIGHT_PROXY_CONFORMANCE_SPEC, other, '--project=desktop-1440',
    ]), /sole explicit spec/);
  }
  for (const extra of [[], ['--project=mobile-390'], ['--project=desktop-1440', '--grep', 'proxy']]) {
    assert.throws(() => offlinePlaywrightInvocation([
      PLAYWRIGHT_OFFLINE_TARGETED_FLAG, PLAYWRIGHT_PROXY_CONFORMANCE_SPEC, ...extra,
    ]), /sole explicit spec/);
  }
  const report = singleIdentityExecutionReport(PLAYWRIGHT_PROXY_CONFORMANCE_SPEC, 'proxy-isolation.conformance.spec.ts');
  const scope = { allowedSpecs: invocation.scope.specs, allowedProjects: invocation.scope.projects };
  const summary = summarizePlaywrightJsonReport(report, scope);
  assert.equal(playwrightExecutionScopeComplete(invocation.scope, summary), true);
  assert.equal(qualificationScopeComplete(invocation, summary, true), false);
  for (const input of [report, { schema: PLAYWRIGHT_EXECUTION_REPORT_SCHEMA, ...summary }]) {
    assert.throws(() => summarizePlaywrightJsonReport(input), /outside the repository allowlist|unknown or duplicate name/);
    for (const rejected of [
      { allowedSpecs: [PLAYWRIGHT_PROXY_CONFORMANCE_SPEC, PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC], allowedProjects: ['desktop-1440'] },
      { allowedSpecs: [PLAYWRIGHT_PROXY_CONFORMANCE_SPEC], allowedProjects: ['mobile-390'] },
    ]) assert.throws(() => summarizePlaywrightJsonReport(input, rejected), /outside the repository allowlists/);
  }
  assert.equal(offlinePlaywrightInvocation([]).scope.specs.length, 5);
});

test('exact proxy target admission is fixed-origin read-only and rejects unsupported loopback override', () => {
  const origin = 'http://127.0.0.1:41783';
  const headers = { host: '127.0.0.1:41783' };
  assert.equal(exactProxyOrigin(origin).origin, origin);
  assert.equal(proxyTargetPath(origin, `${origin}/v1/config?token=synthetic`, 'GET', headers), '/v1/config?token=synthetic');
  assert.equal(proxyTargetPath(origin, `${origin}/`, 'HEAD', headers), '/');
  for (const target of ['/v1/config', `${origin}/#fragment`, 'http://localhost:41783/', 'http://127.0.0.1:41784/',
    'https://127.0.0.1:41783/', 'http://user:synthetic@127.0.0.1:41783/', 'http://127.1:41783/', `${origin}/bad path`, `${origin}/${'x'.repeat(8192)}`]) {
    assert.equal(proxyTargetPath(origin, target, 'GET', headers), null);
  }
  for (const method of ['CONNECT', 'POST', 'OPTIONS']) assert.equal(proxyTargetPath(origin, `${origin}/`, method, headers), null);
  for (const changed of [{ host: 'localhost:41783' }, { ...headers, upgrade: 'websocket' },
    { ...headers, 'transfer-encoding': 'chunked' }, { ...headers, 'content-length': '1' }]) {
    assert.equal(proxyTargetPath(origin, `${origin}/`, 'GET', changed), null);
  }
  for (const invalid of ['http://localhost:41783', `${origin}/`, 'https://127.0.0.1:41783', 'http://127.0.0.1:80', 'http://127.0.0.2:41783']) {
    assert.throws(() => exactProxyOrigin(invalid), /Proxy requires/);
  }
  assert.deepEqual(exactProxyContextOptions(origin, {}), { server: origin, bypass: '<-loopback>' });
  for (const value of ['', '0', '1']) assert.throws(() => exactProxyContextOptions(origin, {
    PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK: value,
  }), /refuses the forced-loopback proxy override/);
});

test('receipt summaries retain exact security and resource state without host bind paths', () => {
  const digest = `sha256:${'a'.repeat(64)}`;
  assert.deepEqual(summarizePlaywrightImageInspect({
    Id: digest,
    RepoDigests: [`mcr.microsoft.com/playwright@${digest}`, 'not-a-digest'],
    Architecture: 'amd64',
    Os: 'linux',
  }), {
    id: digest,
    repo_digests: [`mcr.microsoft.com/playwright@${digest}`],
    architecture: 'amd64',
    os: 'linux',
  });
  const summary = summarizePlaywrightContainerInspect({
    State: { Status: 'exited', Running: false, OOMKilled: true, ExitCode: 137, Error: '' },
    Config: { User: '1000:1000', Image: PLAYWRIGHT_CONTAINER_IMAGE },
    HostConfig: {
      NetworkMode: `container:${'b'.repeat(64)}`,
      ReadonlyRootfs: true,
      Memory: 1_073_741_824,
      MemorySwap: 1_073_741_824,
      NanoCpus: 2_000_000_000,
      PidsLimit: 256,
      ShmSize: 268_435_456,
      CapDrop: ['ALL'],
      SecurityOpt: ['no-new-privileges:true'],
    },
    Mounts: [
      { Destination: '/workspace/lomo/tests/playwright', Type: 'bind', RW: false, Source: '/home/owner/private-suite' },
      { Destination: '/workspace/lomo/tests/playwright/.results/offline/0123456789ab', Type: 'bind', RW: true, Source: '/home/owner/private-results' },
    ],
  }, {
    suite: '/workspace/lomo/tests/playwright',
    current_results: '/workspace/lomo/tests/playwright/.results/offline/0123456789ab',
  });
  assert.equal(summary.state.oom_killed, true);
  assert.equal(summary.state.exit_code, 137);
  assert.equal(summary.effective.network_mode, 'container:browser-service');
  assert.equal(summary.effective.nano_cpus, 2_000_000_000);
  assert.equal(PLAYWRIGHT_OFFLINE_BROWSER_CPUS, 4);
  assert.equal(PLAYWRIGHT_OFFLINE_CONTROLLER_CPUS, 2);
  assert.equal(playwrightBrowserCompletionHealthy(summary), false);
  assert.deepEqual(summary.mounts, [
    { purpose: 'current_results', type: 'bind', writable: true },
    { purpose: 'suite', type: 'bind', writable: false },
  ]);
  assert.deepEqual(summary.tmpfs, []);
  assert.equal(JSON.stringify(summary).includes('/home/owner'), false);
  assert.throws(() => summarizePlaywrightImageInspect({ Id: 'latest' }), /exact image ID/);
  assert.equal(playwrightBrowserCompletionHealthy({
    state: { running: true, oom_killed: false, has_runtime_error: false },
  }), true);
  assert.equal(playwrightBrowserCompletionHealthy({
    state: { running: false, oom_killed: false, has_runtime_error: false },
  }), false);
  assert.equal(playwrightBrowserCompletionHealthy({
    state: { running: true, oom_killed: true, has_runtime_error: false },
  }), false);
  assert.equal(playwrightBrowserCompletionHealthy({
    state: { running: true, oom_killed: false, has_runtime_error: true },
  }), false);
});

test('reference CPU evidence makes the four-CPU qualification envelope explicit', () => {
  assert.deepEqual(playwrightReferenceCpuEvidence(4, 6), {
    available_parallelism: 4,
    total_logical_cpus: 6,
    reference_browser_cpus: 4,
    meets_reference_envelope: true,
    shortfall_cpus: 0,
  });
  assert.deepEqual(playwrightReferenceCpuEvidence(2, 6), {
    available_parallelism: 2,
    total_logical_cpus: 6,
    reference_browser_cpus: 4,
    meets_reference_envelope: false,
    shortfall_cpus: 2,
  });
  assert.throws(() => playwrightReferenceCpuEvidence(0, 6), /positive integer CPU counts/);
});

test('controller receipt proves the raw network namespace target without retaining namespace paths', () => {
  const browserId = 'b'.repeat(64);
  const browser = {
    Id: browserId,
    Name: '/lomo-code-security-0123456789ab-browser',
    NetworkSettings: { SandboxKey: '/var/run/docker/netns/private-browser-key' },
  };
  const controller = {
    Name: '/lomo-code-security-0123456789ab-controller',
    HostConfig: { NetworkMode: `container:${browserId}` },
    NetworkSettings: { SandboxKey: '/var/run/docker/netns/private-browser-key' },
  };
  const summary = summarizePlaywrightControllerNetworkNamespace(controller, browser);
  assert.deepEqual(summary, {
    target_matches_browser: true,
    sandbox_identity_available: true,
    sandbox_matches_browser: true,
    verified: true,
  });
  assert.equal(JSON.stringify(summary).includes('/var/run'), false);
  assert.equal(summarizePlaywrightControllerNetworkNamespace({
    ...controller,
    HostConfig: { NetworkMode: `container:${'c'.repeat(64)}` },
  }, browser).verified, false);
  assert.equal(summarizePlaywrightControllerNetworkNamespace({
    ...controller,
    NetworkSettings: { SandboxKey: '/var/run/docker/netns/other-key' },
  }, browser).verified, false);
});

test('JSON execution evidence reports actual allowlisted spec and project outcomes', () => {
  assert.equal(PLAYWRIGHT_EXECUTION_REPORT, 'execution-report.json');
  const summary = summarizePlaywrightJsonReport({
    suites: [{
      file: '/workspace/lomo/tests/playwright/tests/foundation.spec.ts',
      specs: [{
        file: 'foundation.spec.ts',
        tests: [
          {
            projectName: 'desktop-1440',
            status: 'expected',
            results: [{ status: 'passed' }],
          },
          {
            projectName: 'mobile-390',
            status: 'skipped',
            results: [{ status: 'skipped' }],
          },
        ],
      }],
      suites: [],
    }],
    errors: [],
    stats: { expected: 1, flaky: 0, skipped: 1, unexpected: 0, duration: 123.4 },
  });
  assert.deepEqual(summary.stats, {
    expected: 1,
    flaky: 0,
    skipped: 1,
    unexpected: 0,
    duration_ms: 123,
  });
  assert.equal(summary.discovered_tests, 2);
  assert.equal(summary.tests_with_results, 2);
  assert.equal(summary.executed_tests, 1);
  assert.equal(summary.result_attempts, 2);
  assert.deepEqual(summary.specs.map((entry) => entry.name), ['tests/foundation.spec.ts']);
  assert.deepEqual(summary.projects.map((entry) => entry.name), ['desktop-1440', 'mobile-390']);
  assert.equal(JSON.stringify(summary).includes('/workspace/lomo'), false);
  const localBasenameSummary = summarizePlaywrightJsonReport(
    singleIdentityExecutionReport('foundation.spec.ts', 'foundation.spec.ts'),
  );
  assert.deepEqual(localBasenameSummary.specs.map((entry) => entry.name), ['tests/foundation.spec.ts']);
  assert.deepEqual(
    summarizePlaywrightJsonReport(singleIdentityExecutionReport(null, 'foundation.spec.ts'))
      .specs.map((entry) => entry.name),
    ['tests/foundation.spec.ts'],
  );
  assert.throws(
    () => summarizePlaywrightJsonReport(singleIdentityExecutionReport(
      '/workspace/lomo/tests/playwright/tests/scanner-lifecycle.spec.ts',
      'foundation.spec.ts',
    )),
    /conflicting allowlisted spec identities/,
  );
  for (const [suiteFile, specFile, expectedError] of [
    ['foundation.spec.ts', '../../hostile.spec.ts', /outside the repository allowlist/],
    ['../../hostile.spec.ts', 'foundation.spec.ts', /outside the repository allowlist/],
    ['/private/hostile.spec.ts', '../../hostile.spec.ts', /outside the repository allowlist/],
    ['foundation.spec.ts', '', /malformed present spec identity/],
    ['', 'foundation.spec.ts', /malformed present spec identity/],
    ['foundation.spec.ts', 42, /malformed present spec identity/],
    [{ path: 'foundation.spec.ts' }, 'foundation.spec.ts', /malformed present spec identity/],
  ]) {
    assert.throws(
      () => summarizePlaywrightJsonReport(singleIdentityExecutionReport(suiteFile, specFile)),
      expectedError,
    );
  }
  assert.throws(() => summarizePlaywrightJsonReport({
    suites: [],
    errors: [],
    stats: { expected: 1, flaky: 0, skipped: 0, unexpected: 0 },
  }), /statistics do not match/);
  for (const hostileResult of [null, {}, { status: 'garbage' }]) {
    const hostile = singleIdentityExecutionReport('foundation.spec.ts', 'foundation.spec.ts');
    hostile.suites[0].specs[0].tests[0].results = [hostileResult];
    assert.throws(() => summarizePlaywrightJsonReport(hostile), /malformed result attempt/);
  }
});

test('JSON execution evidence admits maintained WEB-ACT-009 and refuses unknown action labels', () => {
  for (const failed of [false, true]) {
    const report = singleIdentityExecutionReport('foundation.spec.ts', 'foundation.spec.ts');
    report.suites[0].specs[0].title = '[WEB-ACT-009] source-boundary recovery deep link';
    if (failed) {
      report.suites[0].specs[0].tests[0].status = 'unexpected';
      report.suites[0].specs[0].tests[0].results[0].status = 'failed';
      report.stats.expected = 0;
      report.stats.unexpected = 1;
    }
    const summary = summarizePlaywrightJsonReport(report);
    assert.equal(summary.executed_tests, 1);
    assert.equal(summary.stats.unexpected, failed ? 1 : 0);
    assert.deepEqual(summary.action_scenario_ids, failed ? [] : ['WEB-ACT-009']);
    report.suites[0].specs[0].title = '[WEB-ACT-010] unrecognized action';
    assert.throws(() => summarizePlaywrightJsonReport(report), /unknown Web action scenario identity/);
  }
});

test('retained execution evidence is normalized atomically without private raw fields', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'kodesec-report-publication-')));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const rawPath = resolve(root, PLAYWRIGHT_RAW_EXECUTION_REPORT);
  const retainedPath = resolve(root, PLAYWRIGHT_EXECUTION_REPORT);
  const marker = '/owner/private-root/PRIVATE_MARKER';
  const raw = {
    ...singleIdentityExecutionReport(
      `${marker}/tests/foundation.spec.ts`,
      'foundation.spec.ts',
    ),
    config: {
      configFile: `${marker}/playwright.config.ts`,
      webServer: { env: { PRIVATE_MARKER: marker, SSH_AUTH_SOCK: `${marker}/agent.sock` } },
    },
  };
  writeFixtureFile(rawPath, JSON.stringify(raw));
  const publication = publishPlaywrightExecutionReport({ rawPath, retainedPath });
  assert.match(publication.sha256, /^[a-f0-9]{64}$/);
  assert.equal(publication.size_bytes, lstatSync(retainedPath).size);
  assert.equal(existsSync(rawPath), false);
  const retained = readFileSync(retainedPath, 'utf8');
  assert.equal(retained.includes(marker), false);
  assert.equal(retained.includes('SSH_AUTH_SOCK'), false);
  assert.equal(retained.includes('configFile'), false);
  assert.equal(JSON.parse(retained).schema, PLAYWRIGHT_EXECUTION_REPORT_SCHEMA);
  assert.deepEqual(
    readdirSync(root).filter((name) => name.includes('.tmp-')),
    [],
  );
  assert.throws(
    () => publishPlaywrightExecutionReport({ rawPath: retainedPath, retainedPath }),
    /distinct paths/,
  );

  const malformedDirectory = resolve(root, 'malformed');
  mkdirSync(malformedDirectory, { mode: 0o700 });
  const malformedRaw = resolve(malformedDirectory, PLAYWRIGHT_RAW_EXECUTION_REPORT);
  const malformedRetained = resolve(malformedDirectory, PLAYWRIGHT_EXECUTION_REPORT);
  writeFixtureFile(malformedRaw, JSON.stringify({
    schema: PLAYWRIGHT_EXECUTION_REPORT_SCHEMA,
    reporter: 'playwright-json',
    unexpected: marker,
  }));
  assert.throws(
    () => publishPlaywrightExecutionReport({ rawPath: malformedRaw, retainedPath: malformedRetained }),
    /unexpected fields/,
  );
  assert.equal(existsSync(malformedRaw), false);
  assert.equal(existsSync(malformedRetained), false);
});

test('execution report publication removes every observed raw node on failure', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'kodesec-report-cleanup-')));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const makePaths = (name) => {
    const directory = resolve(root, name);
    mkdirSync(directory, { mode: 0o700 });
    return {
      rawPath: resolve(directory, PLAYWRIGHT_RAW_EXECUTION_REPORT),
      retainedPath: resolve(directory, PLAYWRIGHT_EXECUTION_REPORT),
    };
  };
  const collision = makePaths('collision');
  writeFixtureFile(collision.rawPath, JSON.stringify(singleIdentityExecutionReport('foundation.spec.ts', 'foundation.spec.ts')));
  writeFixtureFile(collision.retainedPath, 'existing evidence\n');
  assert.throws(() => publishPlaywrightExecutionReport(collision), /must not pre-exist/);
  assert.equal(existsSync(collision.rawPath), false);
  assert.equal(readFileSync(collision.retainedPath, 'utf8'), 'existing evidence\n');

  const externalTarget = resolve(root, 'external-target.json');
  writeFixtureFile(externalTarget, 'external evidence\n');
  const linked = makePaths('linked');
  symlinkSync(externalTarget, linked.rawPath);
  assert.throws(() => publishPlaywrightExecutionReport(linked), /regular file/);
  assert.equal(existsSync(linked.rawPath), false);
  assert.equal(readFileSync(externalTarget, 'utf8'), 'external evidence\n');

  const directory = makePaths('directory');
  mkdirSync(directory.rawPath, { mode: 0o700 });
  writeFixtureFile(resolve(directory.rawPath, 'PRIVATE_MARKER'), 'private\n');
  assert.throws(() => publishPlaywrightExecutionReport(directory), /regular file/);
  assert.equal(existsSync(directory.rawPath), false);

  const oversized = makePaths('oversized');
  writeFixtureFile(oversized.rawPath, 'x');
  truncateSync(oversized.rawPath, (32 * 1024 * 1024) + 1);
  assert.throws(() => publishPlaywrightExecutionReport(oversized), /evidence budget/);
  assert.equal(existsSync(oversized.rawPath), false);
});

test('Compose execution evidence uses its exact spec and complete four-project scope', (t) => {
  const scope = { allowedSpecs: [PLAYWRIGHT_COMPOSE_SPEC], allowedProjects: PLAYWRIGHT_ALLOWED_PROJECTS };
  const summary = summarizePlaywrightJsonReport(composeExecutionReport(), scope);
  assert.deepEqual(summary.specs.map((entry) => entry.name), [PLAYWRIGHT_COMPOSE_SPEC]);
  assert.equal(playwrightExecutionScopeComplete({
    specs: [PLAYWRIGHT_COMPOSE_SPEC],
    projects: PLAYWRIGHT_ALLOWED_PROJECTS,
  }, summary), true);
  const partial = summarizePlaywrightJsonReport(composeExecutionReport(['desktop-1440']), scope);
  assert.equal(playwrightExecutionScopeComplete({
    specs: [PLAYWRIGHT_COMPOSE_SPEC],
    projects: PLAYWRIGHT_ALLOWED_PROJECTS,
  }, partial), false);
  assert.throws(() => summarizePlaywrightJsonReport(composeExecutionReport()), /outside the repository allowlist/);
  assert.throws(
    () => summarizePlaywrightJsonReport(singleIdentityExecutionReport('foundation.spec.ts', 'foundation.spec.ts'), scope),
    /outside the repository allowlist/,
  );

  const root = realpathSync(mkdtempSync(join(tmpdir(), 'kodesec-compose-failure-report-')));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const rawPath = resolve(root, PLAYWRIGHT_RAW_EXECUTION_REPORT);
  const retainedPath = resolve(root, PLAYWRIGHT_EXECUTION_REPORT);
  const marker = '/owner/private-root/PRIVATE_MARKER';
  assert.throws(() => runPlaywrightWithExecutionPublication({
    runPlaywright: () => {
      writeFixtureFile(rawPath, JSON.stringify({
        ...composeExecutionReport(['desktop-1440']),
        config: { webServer: { env: { PRIVATE_MARKER: marker } } },
      }));
      throw new Error('browser failed');
    },
    rawPath,
    retainedPath,
    scope,
  }), /browser failed/);
  assert.equal(existsSync(rawPath), false);
  assert.equal(readFileSync(retainedPath, 'utf8').includes(marker), false);
});

test('shared qualification completion rejects aggregate-only partial coverage', () => {
  const runInvocation = offlinePlaywrightInvocation([], { headed: true });
  const complete = summarizePlaywrightJsonReport(qualificationExecutionReport());
  assert.equal(qualificationScopeComplete(runInvocation, complete), false);
  assert.equal(qualificationScopeComplete(runInvocation, complete, true), true);
  const partialReport = qualificationExecutionReport();
  partialReport.suites[0].specs[0].tests[0].results = [];
  const partial = summarizePlaywrightJsonReport(partialReport);
  assert.equal(partial.executed_tests > 0, true);
  assert.equal(qualificationScopeComplete(runInvocation, partial, true), false);
  const missingRecoveryScenario = qualificationExecutionReport();
  const operator = missingRecoveryScenario.suites.find((suite) => suite.file.endsWith('/operator-actions.spec.ts'));
  operator.specs[0].title = operator.specs[0].title.replace('[WEB-ACT-009] ', '');
  assert.equal(qualificationScopeComplete(
    runInvocation, summarizePlaywrightJsonReport(missingRecoveryScenario), true,
  ), false);
});

test('cgroup CPU evidence uses comparable baseline deltas rather than lifetime counters', () => {
  const makeSample = (finishedElapsedMs, stat) => ({
    finished_elapsed_ms: finishedElapsedMs,
    browser: { cgroup: { path: '/docker/browser.scope', cpu: { stat } } },
  });
  assert.deepEqual(summarizeCgroupCpuWindow([
    makeSample(100, { usage_usec: 1_000, nr_periods: 10, nr_throttled: 1, throttled_usec: 100 }),
    makeSample(1_100, { usage_usec: 3_000, nr_periods: 20, nr_throttled: 3, throttled_usec: 600 }),
  ], 'browser'), {
    available: true,
    start_elapsed_ms: 100,
    end_elapsed_ms: 1_100,
    duration_ms: 1_000,
    delta: { usage_usec: 2_000, nr_periods: 10, nr_throttled: 2, throttled_usec: 500 },
    ratios: {
      throttled_period_ratio: 0.2,
      throttled_usec_per_elapsed_usec: 0.0005,
      usage_usec_per_elapsed_usec: 0.002,
    },
  });
  assert.deepEqual(summarizeCgroupCpuWindow([
    makeSample(100, { usage_usec: 1_000, nr_periods: 10, nr_throttled: 1, throttled_usec: 100 }),
  ], 'browser'), { available: false, reason: 'insufficient_comparable_samples' });
  assert.throws(() => summarizeCgroupCpuWindow([], 'other'), /known container role/);
});

test('local offline fallback removes ambient Compose and runner-owned result state', () => {
  const environment = isolatedOfflineLocalEnvironment({
    PATH: '/bin',
    CI: '1',
    KODESEC_PLAYWRIGHT_PORT: '43123',
    KODESEC_PLAYWRIGHT_MODE: 'compose',
    KODESEC_PLAYWRIGHT_RESULT_DIR: '/owner/private-results',
    KODESEC_PLAYWRIGHT_BROWSER_CONTAINER: '1',
    KODESEC_PLAYWRIGHT_HEADED: '1',
    KODESEC_COMPOSE_BASE_URL: 'http://127.0.0.1:43124',
    KODESEC_COMPOSE_STORAGE_STATE: '/owner/private-state.json',
    KODESEC_COMPOSE_FUTURE_OVERRIDE: 'unsafe',
    kodesec_compose_mixed_case_override: 'unsafe-on-windows',
    kodesec_playwright_result_dir: '/owner/second-private-results',
    kodesec_playwright_headed: '1',
  });
  assert.deepEqual(environment, { PATH: '/bin', CI: '1', KODESEC_PLAYWRIGHT_PORT: '43123' });
  assert.deepEqual(localPlaywrightEnvironment({
    PATH: '/bin',
    KODESEC_PLAYWRIGHT_RESULT_DIR: '/owner/private-results',
    kodesec_playwright_result_dir: '/owner/case-insensitive-override',
    KODESEC_PLAYWRIGHT_HEADED: '1',
    KODESEC_PLAYWRIGHT_MODE: 'compose',
  }, '/private/generated/.results/offline/0123456789ab'), {
    PATH: '/bin',
    KODESEC_PLAYWRIGHT_RESULT_DIR: '/private/generated/.results/offline/0123456789ab',
    KODESEC_PLAYWRIGHT_HEADED: '0',
  });
  assert.equal(localPlaywrightEnvironment({}, '/private/generated/.results/offline/0123456789ab', true)
    .KODESEC_PLAYWRIGHT_HEADED, '1');
});

test('fixture server launcher replaces ambient secrets with the explicit port boundary', () => {
  const hostileEnvironment = {
    KODESEC_PLAYWRIGHT_PORT: '43123',
    PRIVATE_MARKER: '/owner/private-root',
    SSH_AUTH_SOCK: '/owner/private-root/agent.sock',
    PATH: '/private/bin',
  };
  assert.deepEqual(sanitizedFixtureServerEnvironment(hostileEnvironment), {
    KODESEC_PLAYWRIGHT_PORT: '43123',
  });
  const spawnOptions = fixtureServerSpawnOptions(hostileEnvironment);
  assert.deepEqual(spawnOptions.env, { KODESEC_PLAYWRIGHT_PORT: '43123' });
  assert.equal(JSON.stringify(spawnOptions).includes('PRIVATE_MARKER'), false);
  assert.equal(JSON.stringify(spawnOptions).includes('SSH_AUTH_SOCK'), false);
  assert.equal(JSON.stringify(spawnOptions).includes('/owner/private-root'), false);
  assert.throws(
    () => sanitizedFixtureServerEnvironment({ KODESEC_PLAYWRIGHT_PORT: '80' }),
    /explicit decimal port/,
  );
});

for (const scenario of [
  { name: 'controller timeout', killOwner: false, ignoreTerm: false },
  { name: 'owner death with a TERM-ignoring server', killOwner: true, ignoreTerm: true },
]) {
  test(`fixture launcher lifetime closes its detached tree after ${scenario.name}`, {
    skip: process.platform === 'win32' ? 'POSIX detached-owner regression runs on Darwin/Linux.' : false,
    timeout: 10_000,
  }, async (t) => {
    const fixture = localRunnerFixture(t);
    const tree = fixtureLauncherTree(fixture, scenario);
    detachedFixtureOwnerCli(fixture, tree, scenario);
    let directChild;
    let clean = false;
    const resultPromise = runLocalFallback({
      ...fixture,
      controllerTimeoutMs: scenario.killOwner ? 5_000 : 1_000,
      childTerminationGraceMs: 100,
      spawnPlaywright: (...args) => {
        directChild = spawn(...args);
        return directChild;
      },
    });
    try {
      const owner = JSON.parse(await waitForFixtureFile(tree.ownerPath));
      const server = JSON.parse(await waitForFixtureFile(tree.readyPath));
      assert.equal(owner.pid, directChild.pid);
      assert.equal(await fixtureLoopbackConnection(server.port), true);
      const result = await resultPromise;
      assert.equal(result.receipt.outcome.status, 'failed');
      assert.equal(result.receipt.outcome.error_code, scenario.killOwner ? 'playwright_tests_failed' : 'controller_timeout');
      assert.equal(result.receipt.controller.timed_out, !scenario.killOwner);
      assert.equal(result.receipt.controller.reaped, true);
      assert.equal(result.receipt.controller.signal, scenario.killOwner ? 'SIGKILL' : 'SIGTERM');
      // The receipt observes only the CLI. Independently await the actual
      // launcher/server absence; never promote the empty cleanup list.
      assert.deepEqual(result.receipt.cleanup, []);
      await waitForFixturePidsAbsent([owner.pid, owner.launcher, server.pid]);
      assert.equal(await fixtureLoopbackConnection(server.port), false);
      assert.equal(readFileSync(tree.terminatedPath, 'utf8'), 'SIGTERM\n');
      clean = true;
    } finally {
      if (!clean) await cleanFixtureLauncherTree(tree, directChild);
      await resultPromise;
    }
  });
}

test('fixture launcher lifetime ends on normal child exit while its stdin writer stays open', {
  timeout: 10_000,
}, async (t) => {
  const fixture = localRunnerFixture(t);
  const tree = fixtureLauncherTree(fixture);
  const launcher = spawn(process.execPath, [tree.launcherPath], {
    cwd: fixture.suiteRoot,
    env: { KODESEC_PLAYWRIGHT_PORT: '43123' },
    detached: process.platform !== 'win32',
    stdio: ['pipe', 'ignore', 'ignore'],
  });
  let clean = false;
  try {
    const server = JSON.parse(await waitForFixtureFile(tree.readyPath));
    assert.equal(launcher.stdin.writableEnded, false);
    const closePromise = waitForChildClose(launcher);
    assert.equal(await fixtureLoopbackConnection(server.port, true), true);
    const [exitCode, signal] = await closePromise;
    assert.equal(exitCode, 0);
    assert.equal(signal, null);
    assert.equal(launcher.stdin.writableEnded, false, 'the test never closes the parent writer');
    assert.equal(existsSync(tree.terminatedPath), false, 'normal child exit sends no TERM');
    await waitForFixturePidsAbsent([launcher.pid, server.pid]);
    assert.equal(await fixtureLoopbackConnection(server.port), false);
    clean = true;
  } finally {
    if (!clean) await cleanFixtureLauncherTree(tree, launcher);
    launcher.stdin.destroy();
  }
});

test('native local result allocation rejects symlink roots and survives bounded identity collisions', (t) => {
  const suiteRoot = realpathSync(mkdtempSync(join(tmpdir(), 'kodesec-local-result-')));
  t.after(() => rmSync(suiteRoot, { force: true, recursive: true }));
  const identities = ['0123456789ab', '0123456789ab', 'abcdef012345'];
  const runIdFactory = () => identities.shift();
  const first = createLocalResultDirectory({ suiteRoot, runIdFactory });
  const second = createLocalResultDirectory({ suiteRoot, runIdFactory });
  assert.equal(first.runId, '0123456789ab');
  assert.equal(second.runId, 'abcdef012345');
  assert.notEqual(first.resultDirectory, second.resultDirectory);

  const unsafeSuite = realpathSync(mkdtempSync(join(tmpdir(), 'kodesec-local-result-unsafe-')));
  t.after(() => rmSync(unsafeSuite, { force: true, recursive: true }));
  const externalResults = realpathSync(mkdtempSync(join(tmpdir(), 'kodesec-local-result-external-')));
  t.after(() => rmSync(externalResults, { force: true, recursive: true }));
  symlinkSync(externalResults, resolve(unsafeSuite, '.results'), 'dir');
  assert.throws(
    () => createLocalResultDirectory({ suiteRoot: unsafeSuite }),
    /non-symlinked directories/,
  );

  const composeSuite = realpathSync(mkdtempSync(join(tmpdir(), 'kodesec-compose-result-unsafe-')));
  t.after(() => rmSync(composeSuite, { force: true, recursive: true }));
  const externalCompose = realpathSync(mkdtempSync(join(tmpdir(), 'kodesec-compose-result-external-')));
  t.after(() => rmSync(externalCompose, { force: true, recursive: true }));
  mkdirSync(resolve(composeSuite, '.results'), { mode: 0o700 });
  symlinkSync(externalCompose, resolve(composeSuite, '.results', 'compose'), 'dir');
  assert.throws(
    () => createPlaywrightResultDirectory({ suiteRoot: composeSuite, resultKind: 'compose' }),
    /non-symlinked directories/,
  );
});

test('native dependency evidence follows the CLI graph and ignores the hostile hoisted axe peer core', (t) => {
  const fixture = localRunnerFixture(t);
  const evidence = localDependencyEvidence(fixture);
  const nestedRegistry = JSON.stringify(fixtureBrowserRegistry());
  const chromiumContents = 'nested chromium fixture\n';
  const headlessContents = 'nested chromium headless shell fixture\n';
  assert.equal(evidence.playwright_test_version, '1.61.1');
  assert.equal(evidence.playwright_package_version, '1.61.1');
  assert.equal(evidence.playwright_core_version, '1.61.1');
  assert.equal(evidence.playwright_cli.path, 'node_modules/@playwright/test/cli.js');
  assert.equal(evidence.playwright_package_path, 'node_modules/playwright/package.json');
  assert.equal(
    evidence.playwright_core_package_path,
    'node_modules/playwright/node_modules/playwright-core/package.json',
  );
  assert.equal(
    evidence.browser_registry_path,
    'node_modules/playwright/node_modules/playwright-core/browsers.json',
  );
  assert.equal(
    evidence.browser_registry_sha256,
    createHash('sha256').update(nestedRegistry).digest('hex'),
  );
  assert.equal(evidence.browser_selection_claim, 'both-installed-candidates-verified-no-runtime-selection-claim');
  assert.deepEqual(
    {
      revision: evidence.chromium.registry_revision,
      version: evidence.chromium.browser_version,
      bytes: evidence.chromium.executable.size_bytes,
      sha256: evidence.chromium.executable.sha256,
    },
    {
      revision: '1228',
      version: '149.0.7827.55',
      bytes: Buffer.byteLength(chromiumContents),
      sha256: createHash('sha256').update(chromiumContents).digest('hex'),
    },
  );
  assert.deepEqual(
    {
      revision: evidence.chromium_headless_shell.registry_revision,
      version: evidence.chromium_headless_shell.browser_version,
      bytes: evidence.chromium_headless_shell.executable.size_bytes,
      sha256: evidence.chromium_headless_shell.executable.sha256,
    },
    {
      revision: '1228',
      version: '149.0.7827.55',
      bytes: Buffer.byteLength(headlessContents),
      sha256: createHash('sha256').update(headlessContents).digest('hex'),
    },
  );
  assert.match(evidence.chromium.executable.path, /^\.browsers\/chromium-1228\//);
  assert.match(
    evidence.chromium_headless_shell.executable.path,
    /^\.browsers\/chromium_headless_shell-1228\//,
  );
  assert.equal(JSON.stringify(evidence).includes(fixture.suiteRoot), false);

  writeFixtureFile(
    resolve(fixture.suiteRoot, 'node_modules', 'playwright-core', 'package.json'),
    '{"name":"playwright-core","version":"0.0.0-hostile"}',
  );
  writeFixtureFile(
    resolve(fixture.suiteRoot, 'node_modules', 'playwright-core', 'browsers.json'),
    '{"browsers":"hostile-hoisted-registry"}',
  );
  assert.deepEqual(localDependencyEvidence(fixture), evidence);
});

test('native dependency evidence binds valid nested metadata and executable changes exactly', (t) => {
  const fixture = localRunnerFixture(t);
  const coreManifestPath = resolve(
    fixture.suiteRoot,
    'node_modules',
    'playwright',
    'node_modules',
    'playwright-core',
    'package.json',
  );
  const registryPath = resolve(dirname(coreManifestPath), 'browsers.json');
  const browserPaths = localBrowserFixturePaths(
    fixture.suiteRoot,
    fixture.platform,
    fixture.architecture,
  );
  const before = localDependencyEvidence(fixture);
  const changedManifest = JSON.stringify({
    name: 'playwright-core',
    version: '1.61.1',
    provenanceFixture: 'changed',
  });
  const changedRegistry = JSON.stringify(fixtureBrowserRegistry('1228', '149.0.7827.56'));
  const changedExecutable = 'changed nested chromium fixture\n';
  writeFixtureFile(coreManifestPath, changedManifest);
  writeFixtureFile(registryPath, changedRegistry);
  writeFixtureFile(browserPaths.chromium, changedExecutable);
  chmodSync(browserPaths.chromium, 0o755);
  const after = localDependencyEvidence(fixture);
  assert.notEqual(after.playwright_core_package_manifest_sha256, before.playwright_core_package_manifest_sha256);
  assert.equal(
    after.playwright_core_package_manifest_sha256,
    createHash('sha256').update(changedManifest).digest('hex'),
  );
  assert.equal(after.chromium.browser_version, '149.0.7827.56');
  assert.equal(after.chromium_headless_shell.browser_version, '149.0.7827.56');
  assert.equal(after.browser_registry_sha256, createHash('sha256').update(changedRegistry).digest('hex'));
  assert.equal(after.chromium.executable.size_bytes, Buffer.byteLength(changedExecutable));
  assert.equal(
    after.chromium.executable.sha256,
    createHash('sha256').update(changedExecutable).digest('hex'),
  );
  assert.notEqual(after.chromium.executable.sha256, before.chromium.executable.sha256);
});

test('native dependency evidence rejects missing, malformed, symlinked, and mismatched nested artifacts', async (t) => {
  await t.test('missing nested core falls through only to a mismatched peer and is rejected', (nested) => {
    const fixture = localRunnerFixture(nested);
    rmSync(resolve(
      fixture.suiteRoot,
      'node_modules',
      'playwright',
      'node_modules',
      'playwright-core',
      'package.json',
    ));
    assert.throws(
      () => localDependencyEvidence(fixture),
      (error) => error?.code === 'playwright_dependency_version_mismatch',
    );
  });

  await t.test('missing exact registry is rejected', (nested) => {
    const fixture = localRunnerFixture(nested);
    rmSync(resolve(
      fixture.suiteRoot,
      'node_modules',
      'playwright',
      'node_modules',
      'playwright-core',
      'browsers.json',
    ));
    assert.throws(
      () => localDependencyEvidence(fixture),
      (error) => error?.code === 'playwright_browser_registry_missing',
    );
  });

  await t.test('malformed exact registry is rejected', (nested) => {
    const fixture = localRunnerFixture(nested);
    writeFixtureFile(
      resolve(
        fixture.suiteRoot,
        'node_modules',
        'playwright',
        'node_modules',
        'playwright-core',
        'browsers.json',
      ),
      JSON.stringify({ browsers: [
        ...fixtureBrowserRegistry().browsers,
        fixtureBrowserRegistry().browsers[0],
      ] }),
    );
    assert.throws(
      () => localDependencyEvidence(fixture),
      (error) => error?.code === 'playwright_browser_registry_invalid',
    );
  });

  await t.test('missing exact executable is rejected', (nested) => {
    const fixture = localRunnerFixture(nested);
    const browserPaths = localBrowserFixturePaths(
      fixture.suiteRoot,
      fixture.platform,
      fixture.architecture,
    );
    rmSync(browserPaths.chromiumHeadlessShell);
    assert.throws(
      () => localDependencyEvidence(fixture),
      (error) => error?.code === 'playwright_browser_executable_missing',
    );
  });

  await t.test('symlinked exact executable is rejected', (nested) => {
    const fixture = localRunnerFixture(nested);
    const browserPaths = localBrowserFixturePaths(
      fixture.suiteRoot,
      fixture.platform,
      fixture.architecture,
    );
    const externalExecutable = resolve(fixture.suiteRoot, 'external-browser');
    writeFixtureFile(externalExecutable, 'external executable\n');
    chmodSync(externalExecutable, 0o755);
    rmSync(browserPaths.chromium);
    symlinkSync(externalExecutable, browserPaths.chromium, 'file');
    assert.throws(
      () => localDependencyEvidence(fixture),
      (error) => error?.code === 'playwright_browser_executable_unsafe',
    );
  });

  await t.test('resolved package outside suite-owned node_modules is rejected', (nested) => {
    const fixture = localRunnerFixture(nested);
    const installedPlaywright = resolve(fixture.suiteRoot, 'node_modules', 'playwright');
    const escapedPlaywright = resolve(fixture.suiteRoot, 'vendor', 'playwright');
    writeFixtureFile(resolve(escapedPlaywright, 'package.json'), JSON.stringify({
      name: 'playwright',
      version: '1.61.1',
      dependencies: { 'playwright-core': '1.61.1' },
    }));
    writeFixtureFile(
      resolve(escapedPlaywright, 'node_modules', 'playwright-core', 'package.json'),
      JSON.stringify({ name: 'playwright-core', version: '1.61.1' }),
    );
    writeFixtureFile(
      resolve(escapedPlaywright, 'node_modules', 'playwright-core', 'browsers.json'),
      JSON.stringify(fixtureBrowserRegistry()),
    );
    rmSync(installedPlaywright, { recursive: true });
    symlinkSync(escapedPlaywright, installedPlaywright, 'dir');
    assert.throws(
      () => localDependencyEvidence(fixture),
      (error) => error?.code === 'playwright_dependencies_symlinked',
    );
  });

  await t.test('symlinked nested core cannot masquerade as an exact deduped core', (nested) => {
    const fixture = localRunnerFixture(nested);
    const nestedCore = resolve(
      fixture.suiteRoot,
      'node_modules',
      'playwright',
      'node_modules',
      'playwright-core',
    );
    const hoistedCore = resolve(fixture.suiteRoot, 'node_modules', 'playwright-core');
    writeFixtureFile(
      resolve(hoistedCore, 'package.json'),
      JSON.stringify({ name: 'playwright-core', version: '1.61.1' }),
    );
    writeFixtureFile(
      resolve(hoistedCore, 'browsers.json'),
      JSON.stringify(fixtureBrowserRegistry()),
    );
    rmSync(nestedCore, { recursive: true });
    symlinkSync(hoistedCore, nestedCore, 'dir');
    assert.throws(
      () => localDependencyEvidence(fixture),
      (error) => error?.code === 'playwright_dependencies_symlinked',
    );
  });

  await t.test('mismatched nested core version is rejected', (nested) => {
    const fixture = localRunnerFixture(nested);
    writeFixtureFile(
      resolve(
        fixture.suiteRoot,
        'node_modules',
        'playwright',
        'node_modules',
        'playwright-core',
        'package.json',
      ),
      JSON.stringify({ name: 'playwright-core', version: '1.61.2' }),
    );
    assert.throws(
      () => localDependencyEvidence(fixture),
      (error) => error?.code === 'playwright_dependency_version_mismatch',
    );
  });

  await t.test('jointly changed downstream manifests cannot bypass the repository test version', (nested) => {
    const fixture = localRunnerFixture(nested);
    writeFixtureFile(
      resolve(fixture.suiteRoot, 'node_modules', '@playwright', 'test', 'package.json'),
      JSON.stringify({
        name: '@playwright/test',
        version: '1.61.1',
        dependencies: { playwright: '1.61.2' },
      }),
    );
    writeFixtureFile(
      resolve(fixture.suiteRoot, 'node_modules', 'playwright', 'package.json'),
      JSON.stringify({
        name: 'playwright',
        version: '1.61.2',
        dependencies: { 'playwright-core': '1.61.2' },
      }),
    );
    writeFixtureFile(
      resolve(
        fixture.suiteRoot,
        'node_modules',
        'playwright',
        'node_modules',
        'playwright-core',
        'package.json',
      ),
      JSON.stringify({ name: 'playwright-core', version: '1.61.2' }),
    );
    assert.throws(
      () => localDependencyEvidence(fixture),
      (error) => error?.code === 'playwright_dependency_version_mismatch',
    );
  });
});

test('Mac visual modes use disjoint references without changing Linux or Windows paths', () => {
  const headed = expectedPlatformBaselinePaths('darwin');
  const headless = expectedPlatformBaselinePaths('darwin', { headed: false });
  assert.equal(headed.length, 28);
  assert.equal(headless.length, 28);
  assert(headless.every(path => path.endsWith('-darwin-headless.png') && !headed.includes(path)));
  for (const platform of ['linux', 'win32']) {
    assert.deepEqual(expectedPlatformBaselinePaths(platform, { headed: false }), expectedPlatformBaselinePaths(platform));
  }
  assert.throws(() => expectedPlatformBaselinePaths('darwin', { headed: 'false' }), { code: 'baseline_mode_invalid' });
});

test('a missing headless Mac reference cannot fall back to a reviewed headed image', (t) => {
  const fixture = localRunnerFixture(t);
  const headed = platformBaselineEvidence(fixture);
  const headless = platformBaselineEvidence({ ...fixture, headed: false });
  assert.equal(headed.rendering_mode, 'headed');
  assert.equal(headless.rendering_mode, 'headless');
  assert.notEqual(headed.expected_paths_sha256, headless.expected_paths_sha256);
  const path = resolve(fixture.suiteRoot, 'tests/__screenshots__/foundation.spec.ts', expectedPlatformBaselinePaths('darwin', { headed: false })[0]);
  rmSync(path);
  assert.throws(() => platformBaselineEvidence({ ...fixture, headed: false }), { code: 'platform_baseline_incomplete' });
  assert.deepEqual(platformBaselineEvidence(fixture), headed);
});

test('native local qualification owns a unique result directory and terminally binds full evidence', async (t) => {
  const fixture = localRunnerFixture(t);
  const result = await runLocalFallback({
    ...fixture,
    architecture: 'arm64',
    osRelease: 'fixture-release',
    hostEnvironment: {
      PATH: '/bin',
      PRIVATE_MARKER: '/owner/private-root',
      KODESEC_PLAYWRIGHT_MODE: 'compose',
      KODESEC_PLAYWRIGHT_RESULT_DIR: '/owner/private-results',
      KODESEC_COMPOSE_STORAGE_STATE: '/owner/private-state.json',
      KODESEC_PLAYWRIGHT_HEADED: '1',
    },
    runInvocation: offlinePlaywrightInvocation([], { headed: true }),
    spawnPlaywright: (_program, argumentsToRun, options) => completedFakeChild(() => {
      assert.deepEqual(argumentsToRun.slice(-2), [
        resolve(fixture.suiteRoot, 'node_modules', '@playwright', 'test', 'cli.js'),
        'test',
      ]);
      assert.equal(options.cwd, fixture.suiteRoot);
      assert.equal(options.env.KODESEC_PLAYWRIGHT_MODE, undefined);
      assert.equal(options.env.KODESEC_COMPOSE_STORAGE_STATE, undefined);
      assert.equal(options.env.KODESEC_PLAYWRIGHT_HEADED, '1');
      assert.equal(options.env.PLAYWRIGHT_BROWSERS_PATH, resolve(fixture.suiteRoot, '.browsers'));
      assert.match(options.env.KODESEC_PLAYWRIGHT_RESULT_DIR, /[\\/]\.results[\\/]offline[\\/][a-f0-9]{12}$/);
      writeFixtureFile(
        resolve(options.env.KODESEC_PLAYWRIGHT_RESULT_DIR, PLAYWRIGHT_RAW_EXECUTION_REPORT),
        JSON.stringify(qualificationExecutionReport()),
      );
    }),
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.receipt.schema, 'lomo-playwright-offline-runner/v2');
  assert.match(result.resultDirectory, /[\\/]\.results[\\/]offline[\\/][a-f0-9]{12}$/);
  assert.equal(result.receipt.run_id, result.resultDirectory.split(/[\\/]/).at(-1));
  assert.equal(result.receipt.runtime.kind, 'local-locked-browser');
  assert.equal(result.receipt.runtime.result_environment_owned, true);
  assert.equal(result.receipt.qualification_eligible, true);
  assert.equal(result.receipt.system.desktop.mode, 'headed-native-foreground');
  assert.equal(result.receipt.system.desktop.terminal_verified, true);
  assert.equal(result.receipt.system.desktop.verified, true);
  assert.equal(result.receipt.baseline.platform_suffix, 'darwin');
  assert.equal(result.receipt.baseline.file_count, 28);
  assert.equal(result.receipt.baseline.complete, true);
  assert.match(result.receipt.baseline.sha256, /^[a-f0-9]{64}$/);
  assert.match(result.receipt.dependencies.browser_registry_sha256, /^[a-f0-9]{64}$/);
  assert.equal(result.receipt.dependencies.playwright_test_version, '1.61.1');
  assert.equal(result.receipt.dependencies.playwright_package_version, '1.61.1');
  assert.equal(result.receipt.dependencies.playwright_core_version, '1.61.1');
  assert.equal(
    result.receipt.dependencies.playwright_core_package_path,
    'node_modules/playwright/node_modules/playwright-core/package.json',
  );
  assert.equal(result.receipt.dependencies.chromium.registry_revision, '1228');
  assert.equal(result.receipt.dependencies.chromium.browser_version, '149.0.7827.55');
  assert.match(result.receipt.dependencies.chromium.executable.sha256, /^[a-f0-9]{64}$/);
  assert.equal(result.receipt.dependencies.chromium_headless_shell.registry_revision, '1228');
  assert.equal(result.receipt.dependencies.chromium_headless_shell.browser_version, '149.0.7827.55');
  assert.match(
    result.receipt.dependencies.chromium_headless_shell.executable.sha256,
    /^[a-f0-9]{64}$/,
  );
  assert.match(result.receipt.candidate.runner_files.fixture_server_launcher_sha256, /^[a-f0-9]{64}$/);
  assert.match(result.receipt.candidate.runner_files.bulk_finding_actions_sha256, /^[a-f0-9]{64}$/);
  assert.match(result.receipt.candidate.runner_files.bulk_finding_race_sha256, /^[a-f0-9]{64}$/);
  assert.match(result.receipt.candidate.runner_files.finding_navigation_source_sha256, /^[a-f0-9]{64}$/);
  assert.equal(result.receipt.test_execution.qualification_scope_complete, true);
  assert.equal(result.receipt.test_execution.summary.discovered_tests, 5);
  assert.deepEqual(result.receipt.test_execution.summary.action_scenario_ids, [
    'WEB-ACT-001', 'WEB-ACT-002', 'WEB-ACT-003', 'WEB-ACT-004',
    'WEB-ACT-005', 'WEB-ACT-006', 'WEB-ACT-007', 'WEB-ACT-008',
    'WEB-ACT-009',
  ]);
  assert.match(result.receipt.test_execution.report_sha256, /^[a-f0-9]{64}$/);
  assert.equal(result.receipt.test_execution.report_size_bytes > 0, true);
  assert.deepEqual(result.receipt.outcome, {
    status: 'passed', exit_code: 0, signal: null, error_code: null,
  });
  assert.equal(result.receipt.failure_artifacts.required, false);
  assert.equal(result.receipt.failure_artifacts_preserved, null);
  assert.equal(result.receipt.controller.reaped, true);
  assert.equal(result.receipt.controller.timed_out, false);
  const retainedExecutionReportPath = resolve(result.resultDirectory, PLAYWRIGHT_EXECUTION_REPORT);
  const retainedExecutionReport = readFileSync(retainedExecutionReportPath, 'utf8');
  assert.equal(JSON.parse(retainedExecutionReport).schema, PLAYWRIGHT_EXECUTION_REPORT_SCHEMA);
  assert.equal(retainedExecutionReport.includes('/owner/private-root'), false);
  assert.equal(retainedExecutionReport.includes(fixture.suiteRoot), false);
  assert.equal(JSON.stringify(result.receipt).includes('/owner/private-root'), false);
  assert.equal(JSON.stringify(result.receipt).includes(fixture.suiteRoot), false);
  assert.equal(existsSync(resolve(result.resultDirectory, PLAYWRIGHT_RAW_EXECUTION_REPORT)), false);
  assert.deepEqual(JSON.parse(readFileSync(result.receiptPath, 'utf8')), result.receipt);
  assert.deepEqual(
    readdirSync(result.resultDirectory).filter((name) => name.includes('.tmp-')),
    [],
  );
});

test('native no-argument headless full suite passes only as explicitly non-qualifying', async (t) => {
  const fixture = localRunnerFixture(t);
  const result = await runLocalFallback({
    ...fixture,
    architecture: 'arm64',
    osRelease: 'fixture-release',
    hostEnvironment: { KODESEC_PLAYWRIGHT_HEADED: '0' },
    runInvocation: offlinePlaywrightInvocation([]),
    spawnPlaywright: (_program, _argumentsToRun, options) => completedFakeChild(() => {
      assert.equal(options.env.KODESEC_PLAYWRIGHT_HEADED, '0');
      writeFixtureFile(
        resolve(options.env.KODESEC_PLAYWRIGHT_RESULT_DIR, PLAYWRIGHT_RAW_EXECUTION_REPORT),
        JSON.stringify(qualificationExecutionReport()),
      );
    }),
  });
  assert.equal(result.exitCode, 0);
  assert.deepEqual(result.receipt.outcome, {
    status: 'passed', exit_code: 0, signal: null, error_code: null,
  });
  assert.equal(result.receipt.qualification_eligible, false);
  assert.equal(result.receipt.test_execution.qualification_scope_complete, false);
  assert.equal(result.receipt.system.desktop.mode, 'headless');
  assert.equal(result.receipt.system.desktop.terminal_verified, true);
  assert.equal(result.receipt.system.desktop.verified, false);
  assert.equal(result.receipt.system.desktop.postflight_error_code, 'headed_not_requested');
});

test('native local qualification terminal receipt preserves bounded failure artifacts', async (t) => {
  const fixture = localRunnerFixture(t, 'win32');
  const result = await runLocalFallback({
    ...fixture,
    architecture: 'x64',
    osRelease: 'fixture-windows-release',
    hostEnvironment: { KODESEC_PLAYWRIGHT_HEADED: '1' },
    runInvocation: offlinePlaywrightInvocation([], { headed: true }),
    spawnPlaywright: (_program, _argumentsToRun, options) => completedFakeChild(() => {
      const resultDirectory = options.env.KODESEC_PLAYWRIGHT_RESULT_DIR;
      writeFixtureFile(
        resolve(resultDirectory, PLAYWRIGHT_RAW_EXECUTION_REPORT),
        JSON.stringify(qualificationExecutionReport({ failed: true })),
      );
      writeFixtureFile(resolve(resultDirectory, 'artifacts', 'failed-test', 'trace.zip'));
      writeFixtureFile(resolve(resultDirectory, 'artifacts', 'failed-test', 'failure.png'));
    }, { status: 1 }),
  });
  assert.equal(result.exitCode, 1);
  assert.equal(result.receipt.system.platform, 'win32');
  assert.equal(result.receipt.qualification_eligible, false);
  assert.equal(result.receipt.system.desktop.verified, false);
  assert.equal(result.receipt.baseline.platform_suffix, 'win32');
  assert.equal(result.receipt.test_execution.qualification_scope_complete, false);
  assert.equal(result.receipt.test_execution.report_present, true);
  assert.equal(result.receipt.test_execution.error_code, null);
  assert.equal(result.receipt.test_execution.summary.executed_tests, 5);
  assert.equal(result.receipt.test_execution.summary.stats.expected, 4);
  assert.equal(result.receipt.test_execution.summary.stats.unexpected, 1);
  assert.match(result.receipt.test_execution.report_sha256, /^[a-f0-9]{64}$/);
  assert.equal(existsSync(resolve(result.resultDirectory, PLAYWRIGHT_RAW_EXECUTION_REPORT)), false);
  assert.deepEqual(result.receipt.outcome, {
    status: 'failed', exit_code: 1, signal: null, error_code: 'playwright_tests_failed',
  });
  assert.equal(result.receipt.failure_artifacts.required, true);
  assert.equal(result.receipt.failure_artifacts.present, true);
  assert.equal(result.receipt.failure_artifacts.inventory.trace_files, 1);
  assert.equal(result.receipt.failure_artifacts.inventory.screenshot_files, 1);
  assert.equal(result.receipt.failure_artifacts_preserved, true);
  assert.deepEqual(JSON.parse(readFileSync(result.receiptPath, 'utf8')), result.receipt);
});

test('native local terminal evidence preserves invalid-report failure after private raw cleanup', async (t) => {
  for (const cliStatus of [0, 1]) {
    await t.test(`CLI exit ${cliStatus}`, async (t) => {
      const fixture = localRunnerFixture(t);
      const privateMarker = 'PRIVATE_RAW_REPORT_MARKER';
      const result = await runLocalFallback({
        ...fixture,
        architecture: 'arm64',
        osRelease: 'fixture-release',
        hostEnvironment: { KODESEC_PLAYWRIGHT_HEADED: '1' },
        runInvocation: offlinePlaywrightInvocation([], { headed: true }),
        spawnPlaywright: (_program, _argumentsToRun, options) => completedFakeChild(() => {
          const report = qualificationExecutionReport();
          report.suites[0].specs[0].title = `[WEB-ACT-010] ${privateMarker}`;
          writeFixtureFile(
            resolve(options.env.KODESEC_PLAYWRIGHT_RESULT_DIR, PLAYWRIGHT_RAW_EXECUTION_REPORT),
            JSON.stringify(report),
          );
        }, { status: cliStatus }),
      });
      assert.equal(result.exitCode, 1);
      assert.equal(result.receipt.outcome.error_code,
        cliStatus === 0 ? 'execution_report_invalid' : 'playwright_tests_failed');
      assert.deepEqual(result.receipt.test_execution, {
        report_file: PLAYWRIGHT_EXECUTION_REPORT,
        report_present: false,
        report_sha256: null,
        report_size_bytes: null,
        qualification_scope_complete: false,
        summary: null,
        error_code: 'execution_report_invalid',
      });
      assert.equal(existsSync(resolve(result.resultDirectory, PLAYWRIGHT_RAW_EXECUTION_REPORT)), false);
      assert.equal(existsSync(resolve(result.resultDirectory, PLAYWRIGHT_EXECUTION_REPORT)), false);
      assert.equal(JSON.stringify(result.receipt).includes(privateMarker), false);
      assert.deepEqual(JSON.parse(readFileSync(result.receiptPath, 'utf8')), result.receipt);
    });
  }
});

test('native local SIGINT supervises and reaps the direct CLI before writing an interrupted receipt', {
  skip: process.platform === 'win32' ? 'POSIX signal delivery regression runs on Darwin/Linux.' : false,
  timeout: 10_000,
}, async (t) => {
  const fixture = localRunnerFixture(t);
  const readyPath = resolve(fixture.suiteRoot, 'signal-child-ready');
  const terminatedPath = resolve(fixture.suiteRoot, 'signal-child-terminated');
  hangingLocalPlaywrightCli(fixture, readyPath, terminatedPath);
  const driver = localSupervisorDriver(fixture, { timeoutMs: 5_000, graceMs: 100 });
  const outer = spawn(process.execPath, [driver], {
    cwd: fixture.suiteRoot,
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  outer.stdout.on('data', (chunk) => { stdout += chunk; });
  outer.stderr.on('data', (chunk) => { stderr += chunk; });
  t.after(() => {
    if (outer.exitCode === null && outer.signalCode === null) outer.kill('SIGKILL');
  });
  const directChildPid = Number(await waitForFixtureFile(readyPath));
  assert.equal(Number.isSafeInteger(directChildPid), true);
  const closePromise = waitForChildClose(outer);
  assert.equal(outer.kill('SIGINT'), true);
  const [exitCode, signal] = await closePromise;
  assert.equal(exitCode, 130, `${stdout}\n${stderr}`);
  assert.equal(signal, null, `${stdout}\n${stderr}`);
  assert.equal(readFileSync(terminatedPath, 'utf8'), 'SIGTERM');
  assert.throws(
    () => process.kill(directChildPid, 0),
    (error) => error?.code === 'ESRCH',
  );
  const receipt = JSON.parse(readFileSync(soleLocalRunnerReceipt(fixture.suiteRoot), 'utf8'));
  assert.deepEqual(receipt.outcome, {
    status: 'interrupted',
    exit_code: null,
    signal: 'SIGINT',
    error_code: 'runner_interrupted',
  });
  assert.equal(receipt.controller.timed_out, false);
  assert.equal(receipt.controller.reaped, true);
  assert.equal(receipt.controller.termination_requested, true);
  assert.equal(receipt.controller.termination_signal, 'SIGTERM');
  assert.equal(receipt.controller.kill_escalated, false);
  assert.equal(receipt.failure_artifacts.required, true);
  assert.equal(receipt.failure_artifacts_preserved, false);
});

test('native local fixed timeout escalates an uncooperative direct CLI and reaps it', {
  skip: process.platform === 'win32' ? 'POSIX SIGKILL escalation regression runs on Darwin/Linux.' : false,
  timeout: 10_000,
}, async (t) => {
  const fixture = localRunnerFixture(t);
  const readyPath = resolve(fixture.suiteRoot, 'timeout-child-ready');
  const terminatedPath = resolve(fixture.suiteRoot, 'timeout-child-terminated');
  hangingLocalPlaywrightCli(fixture, readyPath, terminatedPath, { ignoreTerm: true });
  const driver = localSupervisorDriver(fixture, { timeoutMs: 1_000, graceMs: 100 });
  const outer = spawn(process.execPath, [driver], {
    cwd: fixture.suiteRoot,
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  outer.stdout.on('data', (chunk) => { stdout += chunk; });
  outer.stderr.on('data', (chunk) => { stderr += chunk; });
  t.after(() => {
    if (outer.exitCode === null && outer.signalCode === null) outer.kill('SIGKILL');
  });
  const directChildPid = Number(await waitForFixtureFile(readyPath));
  assert.equal(Number.isSafeInteger(directChildPid), true);
  const [exitCode, signal] = await waitForChildClose(outer);
  assert.equal(exitCode, 1, `${stdout}\n${stderr}`);
  assert.equal(signal, null, `${stdout}\n${stderr}`);
  assert.equal(readFileSync(terminatedPath, 'utf8'), 'SIGTERM');
  assert.throws(
    () => process.kill(directChildPid, 0),
    (error) => error?.code === 'ESRCH',
  );
  const receipt = JSON.parse(readFileSync(soleLocalRunnerReceipt(fixture.suiteRoot), 'utf8'));
  assert.equal(receipt.outcome.status, 'failed');
  assert.equal(receipt.outcome.error_code, 'controller_timeout');
  assert.equal(receipt.controller.timed_out, true);
  assert.equal(receipt.controller.reaped, true);
  assert.equal(receipt.controller.termination_requested, true);
  assert.equal(receipt.controller.termination_signal, 'SIGTERM');
  assert.equal(receipt.controller.kill_escalated, true);
  assert.equal(receipt.controller.signal, 'SIGKILL');
});

test('runtime fields are replaced without exposing or duplicating generated secrets', () => {
  const original = '# generated\nCONTROL_PORT=8080\nPOSTGRES_PASSWORD=private-value\n';
  const updated = replaceEnvironmentFields(original, {
    CONTROL_PORT: '43123',
    KODESEC_AI_MODE: 'off',
  });
  const parsed = parseEnvironment(updated);
  assert.equal(parsed.get('CONTROL_PORT'), '43123');
  assert.equal(parsed.get('POSTGRES_PASSWORD'), 'private-value');
  assert.equal(parsed.get('KODESEC_AI_MODE'), 'off');
  assert.equal(updated.match(/CONTROL_PORT=/g)?.length, 1);
});

test('runtime parser rejects duplicate and malformed fields', () => {
  assert.throws(() => parseEnvironment('CONTROL_PORT=1\nCONTROL_PORT=2\n'), /duplicate field/);
  assert.throws(() => parseEnvironment('not-valid=value\n'), /invalid field name/);
  assert.throws(() => parseEnvironment('MISSING_SEPARATOR\n'), /malformed field/);
});

test('project and image identities must be matching generated values', () => {
  validateIdentifiers('lomo-code-security-0123456789ab', 'lomo-kodesec-control:0123456789ab');
  assert.equal(exactScannerImage('lomo-kodesec-scanner:abcdef012345'), 'lomo-kodesec-scanner:abcdef012345');
  assert.throws(
    () => validateIdentifiers('lomo-code-security-0123456789ab', 'lomo-kodesec-control:ffffffffffff'),
    /do not match/,
  );
  assert.throws(() => validateIdentifiers('main', 'lomo-kodesec-control:0123456789ab'), /malformed/);
  for (const value of [
    'lomo-code-security-0123456789ab-scanner:latest',
    'lomo-kodesec-scanner:latest',
    'lomo-kodesec-scanner:ABCDEF012345',
  ]) assert.throws(() => exactScannerImage(value), /malformed/);
  assert.deepEqual(composeImageInspectArguments(
    'lomo-kodesec-control:0123456789ab',
    'lomo-kodesec-scanner:abcdef012345',
  ), [
    'image', 'inspect',
    'lomo-kodesec-control:0123456789ab',
    'lomo-kodesec-scanner:abcdef012345',
    '--format', '{{json .}}',
  ]);
  assert.throws(() => composeImageInspectArguments(
    'lomo-kodesec-control:latest',
    'lomo-kodesec-scanner:abcdef012345',
  ), /malformed/);
});

test('only exact explicit-port 127.0.0.1 origins are accepted', () => {
  assert.equal(exactLoopbackBaseURL('http://127.0.0.1:43123'), 'http://127.0.0.1:43123');
  for (const value of [
    'https://127.0.0.1:43123',
    'http://localhost:43123',
    'http://127.0.0.1',
    'http://user@127.0.0.1:43123',
    'http://127.0.0.1:43123/path',
    'http://127.0.0.1:43123/?token=value',
  ]) assert.throws(() => exactLoopbackBaseURL(value), /exact 127\.0\.0\.1 HTTP origin/);
});

test('Compose commands are explicitly project and runtime scoped', () => {
  const args = composeArguments({
    repository: '/workspace/lomo',
    runtimeEnvironment: '/workspace/lomo/.kodesec-test/run/runtime.env',
    projectName: 'lomo-code-security-0123456789ab',
  }, 'down', '--volumes', '--remove-orphans');
  assert.deepEqual(args, [
    'compose', '--project-name', 'lomo-code-security-0123456789ab',
    '--env-file', '/workspace/lomo/.kodesec-test/run/runtime.env',
    '--file', '/workspace/lomo/docker-compose.yml',
    'down', '--volumes', '--remove-orphans',
  ]);
  assert.equal(sanitizedCommand(args).includes('private-value'), false);
  assert.equal(sanitizedCommand(['compose', '--password=private-value']), 'docker compose <redacted-argument>');
});

test('generated runtime fields override shell Compose configuration', () => {
  const runtime = new Map([
    ['COMPOSE_PROJECT_NAME', 'lomo-code-security-0123456789ab'],
    ['CONTROL_PORT', '43123'],
    ['POSTGRES_PASSWORD', 'generated-private-value'],
  ]);
  const environment = isolatedComposeEnvironment({
    PATH: '/bin',
    COMPOSE_FILE: '/owner/compose.yml',
    COMPOSE_PROJECT_NAME: 'owner-project',
    CONTROL_PORT: '8080',
    POSTGRES_PASSWORD: 'owner-private-value',
  }, runtime);
  assert.equal(environment.PATH, '/bin');
  assert.equal(environment.COMPOSE_FILE, undefined);
  assert.equal(environment.COMPOSE_PROJECT_NAME, 'lomo-code-security-0123456789ab');
  assert.equal(environment.CONTROL_PORT, '43123');
  assert.equal(environment.POSTGRES_PASSWORD, 'generated-private-value');
  assert.equal(environment.COMPOSE_PROFILES, '');
  assert.equal(environment.COMPOSE_PARALLEL_LIMIT, '2');
});


test('synthetic Findings scale is exact targeted-only scope and preserves ordinary qualification', () => {
  const ordinary = offlinePlaywrightInvocation([], { headed: true, environment: {} });
  assert.equal(ordinary.qualificationEligible, true);
  assert.equal(ordinary.scope.specs.includes(PLAYWRIGHT_FINDINGS_SCALE_SPEC), false);
  const scale = offlinePlaywrightInvocation([PLAYWRIGHT_OFFLINE_TARGETED_FLAG, PLAYWRIGHT_FINDINGS_SCALE_SPEC], { headed: true, environment: {} });
  assert.equal(scale.mode, 'targeted');
  assert.equal(scale.qualificationEligible, false);
  assert.deepEqual(scale.scope.specs, [PLAYWRIGHT_FINDINGS_SCALE_SPEC]);
  assert.deepEqual(scale.scope.projects, PLAYWRIGHT_ALLOWED_PROJECTS);
  for (const args of [
    [PLAYWRIGHT_FINDINGS_SCALE_SPEC],
    [PLAYWRIGHT_OFFLINE_TARGETED_FLAG, PLAYWRIGHT_FINDINGS_SCALE_SPEC, PLAYWRIGHT_FOUNDATION_SPEC],
    [PLAYWRIGHT_OFFLINE_TARGETED_FLAG, PLAYWRIGHT_FINDINGS_SCALE_SPEC, '--grep', '1000'],
    [PLAYWRIGHT_OFFLINE_TARGETED_FLAG, PLAYWRIGHT_FINDINGS_SCALE_SPEC, '--project', 'desktop-1440'],
    [PLAYWRIGHT_OFFLINE_TARGETED_FLAG, 'tests/unknown.scale.spec.ts'],
    [PLAYWRIGHT_OFFLINE_SNAPSHOT_UPDATE_FLAG, PLAYWRIGHT_FINDINGS_SCALE_SPEC],
  ]) {
    assert.throws(() => offlinePlaywrightInvocation(args, { headed: true, environment: {} }));
  }
});


test('synthetic Findings scale report refuses mixed specs or missing viewports', () => {
  const specPath = `/candidate/${PLAYWRIGHT_FINDINGS_SCALE_SPEC}`;
  const report = singleIdentityExecutionReport(specPath, specPath);
  const admittedScope = {
    allowedSpecs: [PLAYWRIGHT_FINDINGS_SCALE_SPEC],
    allowedProjects: [...PLAYWRIGHT_ALLOWED_PROJECTS],
  };
  assert.doesNotThrow(() => summarizePlaywrightJsonReport(report, admittedScope));
  assert.throws(() => summarizePlaywrightJsonReport(report, {
    ...admittedScope,
    allowedSpecs: [PLAYWRIGHT_FINDINGS_SCALE_SPEC, PLAYWRIGHT_FOUNDATION_SPEC],
  }));
  assert.throws(() => summarizePlaywrightJsonReport(report, {
    ...admittedScope,
    allowedProjects: ['desktop-1440'],
  }));
  const summary = summarizePlaywrightJsonReport(report, admittedScope);
  assert.equal(playwrightExecutionScopeComplete({
    specs: [PLAYWRIGHT_FINDINGS_SCALE_SPEC],
    projects: [...PLAYWRIGHT_ALLOWED_PROJECTS],
    grep: null,
  }, summary), false, 'one case cannot claim all four viewports complete');
});

test('synthetic Findings HTTP fixtures preserve exact totals and enforce revision fences', { timeout: 30_000 }, async (t) => {
  const fixture = localRunnerFixture(t);
  writeFileSync(resolve(fixture.suiteRoot, 'server.mjs'), readFileSync(new URL('../server.mjs', import.meta.url)));
  const launcherPath = resolve(fixture.scriptRoot, 'server-launcher.mjs');
  writeFileSync(launcherPath, readFileSync(new URL('./server-launcher.mjs', import.meta.url)));
  // The existing fixture root provides only a static placeholder index. This
  // test covers real HTTP API behavior, never browser/bundle performance.
  const reservation = createServer();
  await new Promise((resolveListen, reject) => {
    const timer = setTimeout(() => {
      reservation.close();
      reject(new Error('Fixture port reservation deadline'));
    }, 1_000);
    reservation.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    reservation.listen(0, '127.0.0.1', () => {
      clearTimeout(timer);
      resolveListen();
    });
  });
  const port = reservation.address().port;
  await new Promise((resolveClose, reject) => reservation.close((error) => error ? reject(error) : resolveClose()));
  const origin = `http://127.0.0.1:${port}`;
  const launcher = spawn(process.execPath, [launcherPath], {
    cwd: fixture.suiteRoot,
    env: sanitizedFixtureServerEnvironment({ KODESEC_PLAYWRIGHT_PORT: String(port) }),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  // Reuse the maintained launcher and close waiter: closing its owned stdin
  // terminates/reaps its exact server child, with its existing TERM/KILL grace.
  const terminal = waitForChildClose(launcher, 27_000);
  void terminal.catch(() => undefined);
  let outputBytes = 0;
  for (const stream of [launcher.stdout, launcher.stderr]) {
    stream.on('data', (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > 32_768) launcher.stdin.end();
    });
  }
  const deadline = performance.now() + 23_000;
  const request = async (path, options = {}) => {
    const remaining = Math.ceil(deadline - performance.now());
    assert.ok(remaining > 0, 'whole HTTP fixture test deadline');
    const response = await fetch(`${origin}${path}`, {
      ...options,
      signal: AbortSignal.timeout(Math.min(remaining, 1_000)),
    });
    return { status: response.status, value: await response.json() };
  };
  try {
    const readinessDeadline = performance.now() + 5_000;
    while (true) {
      try {
        assert.equal((await request('/healthz')).status, 200);
        break;
      } catch (error) {
        if (performance.now() >= readinessDeadline || launcher.exitCode !== null || launcher.signalCode !== null) throw error;
        await new Promise((resolveWait) => setTimeout(resolveWait, 20));
      }
    }
    for (const [profile, count] of [
      ['findings-scale-1000', 1_000],
      ['findings-scale-5000', 5_000],
      ['findings-scale-10000', 10_000],
      ['large-findings', 10_005],
      ['paginated-findings', 460],
    ]) {
      const reset = await request('/__test/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile, generation: 1 }),
      });
      assert.equal(reset.status, 200);
      assert.equal(reset.value.profile, profile);
      const summary = await request('/v1/scans/41/summary');
      assert.equal(summary.status, 200);
      assert.equal(summary.value.findings.total, count);
      const ids = new Set();
      const numbers = new Set();
      let cursor = null;
      let pages = 0;
      do {
        const query = new URLSearchParams({ limit: '200', expected_revision: '1' });
        if (cursor !== null) query.set('cursor', cursor);
        const page = await request(`/v1/scans/41/findings?${query}`);
        assert.equal(page.status, 200);
        assert.equal(page.value.total, count);
        assert.equal(page.value.revision, 1);
        assert.equal(page.value.items.length, Math.min(200, count - numbers.size));
        for (const item of page.value.items) {
          assert.equal(Number.isSafeInteger(item.id), true);
          assert.equal(ids.has(item.id), false);
          assert.equal(item.scan_finding_number, numbers.size + 1);
          ids.add(item.id);
          numbers.add(item.scan_finding_number);
          assert.equal(Object.hasOwn(item, 'code_snippet'), false, 'summary pages exclude detail payload');
        }
        cursor = page.value.next_cursor;
        assert.equal(page.value.truncated, cursor !== null);
        if (cursor !== null) assert.equal(typeof cursor, 'string');
        pages += 1;
        assert.ok(pages <= Math.ceil(count / 200), 'finite cursor traversal');
      } while (cursor !== null);
      assert.equal(ids.size, count);
      assert.equal(numbers.size, count);
      assert.equal(pages, Math.ceil(count / 200));
      const anchor = await request('/v1/scans/41/findings?limit=200&anchor_scan_finding_number=250&expected_revision=1');
      assert.equal(anchor.status, 200);
      assert.equal(anchor.value.revision, 1);
      assert.equal(anchor.value.items[0].scan_finding_number, 201);
      assert.equal(anchor.value.items.at(-1).scan_finding_number, 400);
    }
    const unfenced = await request('/v1/scans/41/findings?limit=200');
    assert.equal(unfenced.status, 200, 'existing requests without the optional fence remain valid');
    for (const raw of ['1', '01', '+1', ' 1 ', '1.00', '0_1', '\t1\n', '\u00851\u0085', '\u00a01\u00a0']) {
      const query = new URLSearchParams({ limit: '200', expected_revision: raw });
      assert.equal((await request(`/v1/scans/41/findings?${query}`)).status, 200, JSON.stringify(raw));
    }
    for (const raw of ['2', '2.00', '0_2']) {
      const query = new URLSearchParams({ expected_revision: raw });
      const stale = await request(`/v1/scans/41/findings?${query}`);
      assert.equal(stale.status, 409);
      assert.deepEqual(stale.value.detail, {
        code: 'revision_conflict',
        message: 'findings changed after the selected manifest snapshot',
        revision: 1,
      });
    }
    for (const raw of ['0', '-1', '2147483648', 'not-a-revision', '', '1e0', '0x1', '1__0', '_1', '1_', '1.', '1.0_0', '1.1', '\u0661', '\ufeff1\ufeff']) {
      const query = new URLSearchParams({ expected_revision: raw });
      assert.equal((await request(`/v1/scans/41/findings?${query}`)).status, 422, JSON.stringify(raw));
    }
    assert.ok(outputBytes <= 32_768, 'fixture launcher output stays bounded');
  } finally {
    let cleanupTimer;
    try {
      launcher.stdin.end();
      const [code, signal] = await Promise.race([
        terminal,
        new Promise((_, reject) => {
          cleanupTimer = setTimeout(() => reject(new Error('Owned fixture launcher cleanup unknown')), 3_000);
        }),
      ]);
      assert.equal(signal, null);
      assert.equal(code, 143, 'requested stdin closure observed/reaped the exact server child');
    } finally {
      clearTimeout(cleanupTimer);
    }
  }
});

test('D020 Web waits require exact policy and platform without extending legacy inputs', () => {
  for (const [platform, seconds] of [['mac', 600000], ['linux', 1560000], ['windows', 2340000]]) {
    const env = { LOMO_PLAYWRIGHT_TIMING_POLICY: 'D-020', LOMO_PLAYWRIGHT_PERFORMANCE_PLATFORM: platform };
    assert.equal(playwrightControllerTimeoutMs(env), seconds);
    assert.equal(playwrightPerformanceBudgetMode(seconds, env), platform === 'mac' ? 'blocking' : 'advisory');
    assert.throws(() => playwrightControllerTimeoutMs({ ...env, LOMO_PLAYWRIGHT_CONTROLLER_TIMEOUT_MS: String(seconds + 1) }));
  }
  for (const env of [{ LOMO_PLAYWRIGHT_TIMING_POLICY: 'D-021' },
    { LOMO_PLAYWRIGHT_TIMING_POLICY: 'D-020', LOMO_PLAYWRIGHT_PERFORMANCE_PLATFORM: 'wsl' },
    { LOMO_PLAYWRIGHT_CONTROLLER_TIMEOUT_MS: '1560000' }]) assert.throws(() => playwrightControllerTimeoutMs(env));
});

test('D020 Web controller receives one lane factor and refuses mismatched policy', () => {
  const config = { suiteDirectory: '/workspace/lomo/tests/playwright', webDistDirectory: '/workspace/lomo/apps/web/dist',
    resultDirectory: '/workspace/lomo/tests/playwright/.results/offline/0123456789ab',
    browserContainerName: 'lomo-code-security-0123456789ab-browser', controllerContainerName: 'lomo-code-security-0123456789ab-controller',
    wsEndpoint: 'ws://127.0.0.1:43821/0123456789ab', fixturePort: 41783, uid: 1000, gid: 1000,
    playwrightArguments: ['tests/foundation.spec.ts'], runnerMode: 'targeted', timingPolicy: 'D-020' };
  for (const [performancePlatform, timingFactor] of [['mac', 1], ['linux', 2.6], ['windows', 3.9]]) {
    const args = offlineControllerArguments({ ...config, performancePlatform, timingFactor });
    assert.ok(args.includes(`KODESEC_PLAYWRIGHT_TIMING_FACTOR=${timingFactor}`));
    assert.ok(args.includes('KODESEC_PLAYWRIGHT_TIMING_POLICY=D-020'));
    assert.ok(args.includes(`KODESEC_PLAYWRIGHT_PERFORMANCE_PLATFORM=${performancePlatform}`));
    assert.throws(() => offlineControllerArguments({ ...config, performancePlatform, timingFactor: 2 }));
  }
  assert.throws(() => offlineControllerArguments({ ...config, performancePlatform: 'linux', timingFactor: 2.6, timingPolicy: undefined }));
});

test('D020 local Web environment translates the validated lane without copying ambient timing', () => {
  for (const [platform, factor] of [['mac', '1'], ['windows', '3.9']]) {
    const env = localPlaywrightEnvironment({ LOMO_PLAYWRIGHT_TIMING_POLICY: 'D-020',
      LOMO_PLAYWRIGHT_PERFORMANCE_PLATFORM: platform, KODESEC_PLAYWRIGHT_TIMING_FACTOR: '100',
      KODESEC_PLAYWRIGHT_TIMING_POLICY: 'untrusted' }, '/private/generated/.results/offline/0123456789ab');
    assert.equal(env.KODESEC_PLAYWRIGHT_TIMING_FACTOR, factor);
    assert.equal(env.KODESEC_PLAYWRIGHT_TIMING_POLICY, 'D-020');
    assert.equal(env.KODESEC_PLAYWRIGHT_PERFORMANCE_PLATFORM, platform);
  }
  for (const lane of ['constructor', 'toString', '__proto__', 'wsl']) {
    assert.throws(() => playwrightControllerTimeoutMs({ LOMO_PLAYWRIGHT_TIMING_POLICY: 'D-020', LOMO_PLAYWRIGHT_PERFORMANCE_PLATFORM: lane }));
  }
});
