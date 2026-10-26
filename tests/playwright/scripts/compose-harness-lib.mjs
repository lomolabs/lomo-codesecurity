import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { createServer } from 'node:net';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';

const PROJECT_PATTERN = /^lomo-code-security-[a-f0-9]{12}$/;
const IMAGE_PATTERN = /^lomo-kodesec-control:[a-f0-9]{12}$/;
const SCANNER_IMAGE_PATTERN = /^lomo-kodesec-scanner:[a-f0-9]{12}$/;
const CORE_CONTAINER_PATTERN = /^lomo-code-security-[a-f0-9]{12}-(?:postgres|scanner|api|api-ingress)-1$/;
const BROWSER_CONTAINER_PATTERN = /^lomo-code-security-[a-f0-9]{12}-browser$/;
const CONTROLLER_CONTAINER_PATTERN = /^lomo-code-security-[a-f0-9]{12}-controller$/;
const PLAYWRIGHT_PATH_PATTERN = /^\/[a-f0-9]{12}$/;

export const CORE_SERVICES = Object.freeze([
  'postgres',
  'scanner',
  'worker',
  'api',
  'api-ingress',
]);
export const PLAYWRIGHT_CONTAINER_IMAGE = 'mcr.microsoft.com/playwright:v1.61.1-noble@sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48';
export const PLAYWRIGHT_CONTAINER_STORAGE_STATE = '/run/kodesec-browser-state.json';
export const PLAYWRIGHT_REMOTE_NODE_MODULES = '/opt/kodesec-playwright/node_modules';
export const PLAYWRIGHT_HEADED_DISPLAY = ':1';
export const PLAYWRIGHT_CONTAINER_XAUTHORITY = '/run/lomo-xauthority';
export const PLAYWRIGHT_CONTAINER_X11_SOCKET = '/tmp/.X11-unix/X1';
export const PLAYWRIGHT_OFFLINE_BROWSER_CPUS = 4;
export const PLAYWRIGHT_OFFLINE_CONTROLLER_CPUS = 2;
export const PLAYWRIGHT_EXECUTION_REPORT = 'execution-report.json';
export const PLAYWRIGHT_RAW_EXECUTION_REPORT = 'execution-report.raw.json';
export const PLAYWRIGHT_EXECUTION_REPORT_SCHEMA = 'lomo-playwright-execution-report/v2';
const MAX_PLAYWRIGHT_EXECUTION_REPORT_BYTES = 32 * 1024 * 1024;
const PLAYWRIGHT_RESULT_DIRECTORY_ATTEMPTS = 16;
export const PLAYWRIGHT_OFFLINE_SNAPSHOT_UPDATE_FLAG = '--kodesec-offline-snapshot-update';
export const PLAYWRIGHT_OFFLINE_TARGETED_FLAG = '--kodesec-offline-targeted';
export const PLAYWRIGHT_FOUNDATION_SPEC = 'tests/foundation.spec.ts';
export const PLAYWRIGHT_COMPOSE_SPEC = 'tests/compose.smoke.spec.ts';
export const PLAYWRIGHT_OPERATOR_ACTION_SPEC = 'tests/operator-actions.spec.ts';
export const PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC = 'tests/network-isolation.conformance.spec.ts';
export const PLAYWRIGHT_PROXY_CONFORMANCE_SPEC = 'tests/proxy-isolation.conformance.spec.ts';
export const PLAYWRIGHT_FINDINGS_SCALE_SPEC = 'tests/findings.scale.spec.ts';
export const PLAYWRIGHT_OPERATOR_ACTION_SCENARIO_IDS = Object.freeze([
  'WEB-ACT-001',
  'WEB-ACT-002',
  'WEB-ACT-003',
  'WEB-ACT-004',
  'WEB-ACT-005',
  'WEB-ACT-006',
  'WEB-ACT-007',
  'WEB-ACT-008',
  'WEB-ACT-009',
]);
export const PLAYWRIGHT_ALLOWED_SPECS = Object.freeze([
  PLAYWRIGHT_FOUNDATION_SPEC,
  'tests/findings.performance.spec.ts',
  'tests/navigation.performance.spec.ts',
  PLAYWRIGHT_OPERATOR_ACTION_SPEC,
  'tests/scanner-lifecycle.spec.ts',
]);
export const PLAYWRIGHT_ALLOWED_PROJECTS = Object.freeze([
  'desktop-1440',
  'desktop-1920',
  'tablet-768',
  'mobile-390',
]);

const PLAYWRIGHT_REPORT_STATUSES = Object.freeze(['expected', 'flaky', 'skipped', 'unexpected']);
const PLAYWRIGHT_RESULT_STATUSES = Object.freeze(['passed', 'failed', 'timedOut', 'skipped', 'interrupted']);

function validateBindPath(value, name) {
  if (typeof value !== 'string' || !isAbsolute(value) || /[\0\r\n,]/.test(value)) {
    throw new Error(`${name} must be an absolute Docker bind path without control characters or commas.`);
  }
}

function isStrictDescendant(parent, candidate) {
  const child = relative(parent, candidate);
  return child !== '' && child !== '..' && !child.startsWith(`..${sep}`) && !isAbsolute(child);
}

function sameResolvedPath(left, right, platform = process.platform) {
  const normalizedLeft = resolve(left);
  const normalizedRight = resolve(right);
  return platform === 'win32'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function ensureSafePlaywrightResultDirectory(path, { create = false, platform = process.platform } = {}) {
  if (!existsSync(path)) {
    if (!create) throw new Error('Playwright result parent is missing.');
    mkdirSync(path, { mode: 0o700 });
  }
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || !sameResolvedPath(realpathSync(path), path, platform)) {
    throw new Error('Playwright result directories must be real, non-symlinked directories.');
  }
}

export function createPlaywrightResultDirectory({
  suiteRoot,
  resultKind,
  platform = process.platform,
  runIdFactory = () => randomBytes(6).toString('hex'),
} = {}) {
  if (!['offline', 'offline-update', 'compose'].includes(resultKind)) {
    throw new Error('Playwright result kind is outside the repository contract.');
  }
  const resolvedSuite = resolve(suiteRoot);
  ensureSafePlaywrightResultDirectory(resolvedSuite, { platform });
  const resultsRoot = resolve(resolvedSuite, '.results');
  const kindRoot = resolve(resultsRoot, resultKind);
  ensureSafePlaywrightResultDirectory(resultsRoot, { create: true, platform });
  ensureSafePlaywrightResultDirectory(kindRoot, { create: true, platform });
  if (!isStrictDescendant(resolvedSuite, resultsRoot) || !isStrictDescendant(resultsRoot, kindRoot)) {
    throw new Error('Playwright result paths escaped the suite result root.');
  }
  for (let attempt = 0; attempt < PLAYWRIGHT_RESULT_DIRECTORY_ATTEMPTS; attempt += 1) {
    const runId = runIdFactory();
    if (typeof runId !== 'string' || !/^[a-f0-9]{12}$/.test(runId)) {
      throw new Error('Playwright run identities must be exactly twelve lowercase hexadecimal characters.');
    }
    const resultDirectory = resolve(kindRoot, runId);
    if (!isStrictDescendant(kindRoot, resultDirectory)) {
      throw new Error('Playwright result paths escaped the generated run root.');
    }
    try {
      mkdirSync(resultDirectory, { mode: 0o700 });
    } catch (error) {
      if (error?.code === 'EEXIST') continue;
      throw error;
    }
    if (!sameResolvedPath(realpathSync(resultDirectory), resultDirectory, platform)) {
      throw new Error('Playwright run results must not resolve through a symlink.');
    }
    return { runId, resultsRoot, resultDirectory };
  }
  throw new Error('Could not allocate a unique Playwright result directory.');
}

export function playwrightRunnerKind(platform) {
  return platform === 'linux' ? 'container' : 'local';
}

export function isolatedOfflineLocalEnvironment(hostEnvironment) {
  const environment = { ...hostEnvironment };
  for (const key of Object.keys(environment)) {
    const normalizedKey = key.toUpperCase();
    if (
      normalizedKey === 'KODESEC_PLAYWRIGHT_MODE'
      || normalizedKey === 'KODESEC_PLAYWRIGHT_RESULT_DIR'
      || normalizedKey === 'KODESEC_PLAYWRIGHT_BROWSER_CONTAINER'
      || normalizedKey === 'KODESEC_PLAYWRIGHT_HEADED'
      || normalizedKey.startsWith('KODESEC_COMPOSE_')
    ) delete environment[key];
  }
  return environment;
}

export function playwrightReferenceCpuEvidence(availableParallelism, totalLogicalCpus) {
  if (
    !Number.isSafeInteger(availableParallelism)
    || availableParallelism < 1
    || !Number.isSafeInteger(totalLogicalCpus)
    || totalLogicalCpus < 1
  ) {
    throw new Error('Playwright reference CPU evidence requires positive integer CPU counts.');
  }
  return {
    available_parallelism: availableParallelism,
    total_logical_cpus: totalLogicalCpus,
    reference_browser_cpus: PLAYWRIGHT_OFFLINE_BROWSER_CPUS,
    meets_reference_envelope: availableParallelism >= PLAYWRIGHT_OFFLINE_BROWSER_CPUS,
    shortfall_cpus: Math.max(0, PLAYWRIGHT_OFFLINE_BROWSER_CPUS - availableParallelism),
  };
}

function validateScopedPlaywrightArguments(argumentsToValidate, { foundationOnly = false } = {}) {
  if (!Array.isArray(argumentsToValidate) || argumentsToValidate.length > 16) {
    throw new Error('Targeted Playwright arguments must be a bounded array.');
  }
  const specs = [];
  const projects = [];
  const grep = [];
  for (let index = 0; index < argumentsToValidate.length; index += 1) {
    const argument = argumentsToValidate[index];
    if (typeof argument !== 'string' || !argument || argument.length > 256 || /[\0\r\n]/.test(argument)) {
      throw new Error('Targeted Playwright arguments must be bounded non-empty strings without control characters.');
    }
    if (PLAYWRIGHT_ALLOWED_SPECS.includes(argument) || argument === PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC || argument === PLAYWRIGHT_PROXY_CONFORMANCE_SPEC || argument === PLAYWRIGHT_FINDINGS_SCALE_SPEC) {
      if (foundationOnly && argument !== PLAYWRIGHT_FOUNDATION_SPEC) {
        throw new Error('Snapshot updates may select only the visual foundation spec.');
      }
      if (specs.includes(argument)) throw new Error(`Duplicate Playwright spec selector: ${argument}`);
      specs.push(argument);
      continue;
    }
    const projectValue = argument === '--project'
      ? argumentsToValidate[++index]
      : argument.startsWith('--project=') ? argument.slice('--project='.length) : undefined;
    if (projectValue !== undefined) {
      if (!PLAYWRIGHT_ALLOWED_PROJECTS.includes(projectValue) || projects.includes(projectValue)) {
        throw new Error('Targeted Playwright projects must be unique repository viewport names.');
      }
      projects.push(projectValue);
      continue;
    }
    const grepValue = argument === '--grep'
      ? argumentsToValidate[++index]
      : argument.startsWith('--grep=') ? argument.slice('--grep='.length) : undefined;
    if (grepValue !== undefined) {
      if (typeof grepValue !== 'string' || !grepValue || grepValue.length > 256 || /[\0\r\n]/.test(grepValue)) {
        throw new Error('Targeted Playwright grep selectors must be bounded non-empty strings without control characters.');
      }
      if (grep.length > 0) throw new Error('Targeted Playwright accepts at most one grep selector.');
      grep.push(grepValue);
      continue;
    }
    throw new Error(`Playwright argument is not allowed by the repository runner: ${argument}`);
  }
  if (foundationOnly && (specs.length !== 1 || specs[0] !== PLAYWRIGHT_FOUNDATION_SPEC)) {
    throw new Error('Snapshot updates require the exact visual foundation spec.');
  }
  if (specs.some((spec) => spec === PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC || spec === PLAYWRIGHT_PROXY_CONFORMANCE_SPEC)
    && (specs.length !== 1 || projects.length !== 1 || projects[0] !== 'desktop-1440' || grep.length !== 0)) {
    throw new Error('Network conformance requires its sole explicit spec and desktop-1440 project, without grep.');
  }
  if (specs.includes(PLAYWRIGHT_FINDINGS_SCALE_SPEC)
    && (specs.length !== 1 || projects.length !== 0 || grep.length !== 0)) {
    throw new Error('Findings scale requires its sole explicit spec and all four default viewports, without grep.');
  }
  return {
    specs: specs.length > 0 ? specs : [...PLAYWRIGHT_ALLOWED_SPECS],
    projects: projects.length > 0 ? projects : [...PLAYWRIGHT_ALLOWED_PROJECTS],
    grep: grep[0] || null,
  };
}

export function offlinePlaywrightInvocation(requestedArguments, { headed = false, environment = process.env } = {}) {
  if (!Array.isArray(requestedArguments)) throw new Error('Playwright runner arguments must be an array.');
  if (typeof headed !== 'boolean') throw new Error('Playwright headed eligibility must be one explicit boolean.');
  const proxyDiagnostic = environment.KODESEC_NAVIGATION_PROXY_AB_DIAGNOSTIC;
  if (proxyDiagnostic !== undefined && proxyDiagnostic !== '0' && proxyDiagnostic !== '1') {
    throw new Error('Navigation proxy A/B diagnostic must be exactly 0 or 1.');
  }
  if (proxyDiagnostic === '1') {
    const [mode, ...args] = requestedArguments;
    const scope = mode === PLAYWRIGHT_OFFLINE_TARGETED_FLAG ? validateScopedPlaywrightArguments(args) : null;
    if (!headed || environment.KODESEC_FINDINGS_RENDER_DIAGNOSTIC !== '1'
      || environment.KODESEC_NAVIGATION_WORKER_CPU_DIAGNOSTIC === '1'
      || environment.KODESEC_NAVIGATION_RENDERER_METRICS_DIAGNOSTIC === '1'
      || !scope || scope.specs.length !== 1 || scope.specs[0] !== 'tests/navigation.performance.spec.ts'
      || scope.projects.length !== 1 || scope.projects[0] !== 'desktop-1440' || scope.grep !== null) {
      throw new Error('Proxy A/B requires sole targeted navigation/desktop-1440, headed rendering diagnostic without CPU or renderer counters.');
    }
  }
  if (requestedArguments.length === 0) {
    return {
      mode: 'qualification',
      qualificationEligible: headed,
      playwrightArguments: [],
      scope: {
        specs: [...PLAYWRIGHT_ALLOWED_SPECS],
        projects: [...PLAYWRIGHT_ALLOWED_PROJECTS],
        grep: null,
      },
    };
  }
  const [selector, ...selectedArguments] = requestedArguments;
  if (selector === PLAYWRIGHT_OFFLINE_TARGETED_FLAG) {
    const scope = validateScopedPlaywrightArguments(selectedArguments);
    return {
      mode: 'targeted',
      qualificationEligible: false,
      playwrightArguments: selectedArguments,
      scope,
    };
  }
  if (selector === PLAYWRIGHT_OFFLINE_SNAPSHOT_UPDATE_FLAG) {
    const scope = validateScopedPlaywrightArguments(selectedArguments, { foundationOnly: true });
    return {
      mode: 'snapshot-update',
      qualificationEligible: false,
      playwrightArguments: [...selectedArguments, '--update-snapshots=all'],
      scope,
    };
  }
  throw new Error(
    `Qualification runs accept no Playwright overrides. Use ${PLAYWRIGHT_OFFLINE_TARGETED_FLAG} for an explicitly non-qualifying targeted run.`,
  );
}

export function snapshotUpdateRunnerArguments({ platform, scriptsDirectory, extraArguments = [] }) {
  validateBindPath(scriptsDirectory, 'Playwright scripts directory');
  offlinePlaywrightInvocation([
    PLAYWRIGHT_OFFLINE_SNAPSHOT_UPDATE_FLAG,
    PLAYWRIGHT_FOUNDATION_SPEC,
    ...extraArguments,
  ]);
  if (playwrightRunnerKind(platform) === 'container') {
    return {
      runner: resolve(scriptsDirectory, 'offline-playwright.mjs'),
      arguments: [PLAYWRIGHT_OFFLINE_SNAPSHOT_UPDATE_FLAG, PLAYWRIGHT_FOUNDATION_SPEC, ...extraArguments],
    };
  }
  return {
    runner: resolve(scriptsDirectory, 'playwright.mjs'),
    arguments: ['test', PLAYWRIGHT_FOUNDATION_SPEC, ...extraArguments, '--update-snapshots=all'],
  };
}

export function playwrightContainerArguments({
  suiteDirectory,
  resultDirectory,
  storageState,
  baseURL,
  containerName,
  uid,
  gid,
}) {
  validateBindPath(suiteDirectory, 'Playwright suite directory');
  validateBindPath(resultDirectory, 'Playwright result directory');
  validateBindPath(storageState, 'Playwright storage state');
  const resultsRoot = resolve(suiteDirectory, '.results');
  if (!isStrictDescendant(resultsRoot, resultDirectory)) {
    throw new Error('Playwright results must remain beneath the masked suite result directory.');
  }
  if (storageState === suiteDirectory || isStrictDescendant(suiteDirectory, storageState)) {
    throw new Error('Playwright storage state must be mounted separately from the suite.');
  }
  if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid < 0) {
    throw new Error('The Playwright browser container requires a non-root host user identity.');
  }
  if (!BROWSER_CONTAINER_PATTERN.test(containerName)) {
    throw new Error('Generated Playwright browser container name is malformed.');
  }
  const origin = exactLoopbackBaseURL(baseURL);
  return [
    'run', '--rm',
    '--name', containerName,
    '--network', 'host',
    '--read-only',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges:true',
    '--user', `${uid}:${gid}`,
    '--memory', '1g',
    '--memory-swap', '1g',
    '--cpus', '2',
    '--pids-limit', '256',
    '--shm-size', '256m',
    '--tmpfs', `/tmp:rw,nosuid,nodev,size=512m,uid=${uid},gid=${gid},mode=0700`,
    '--mount', `type=bind,source=${suiteDirectory},target=${suiteDirectory},readonly`,
    '--tmpfs', `${resultsRoot}:rw,nosuid,nodev,noexec,size=8m,uid=${uid},gid=${gid},mode=0700`,
    '--mount', `type=bind,source=${resultDirectory},target=${resultDirectory}`,
    '--mount', `type=bind,source=${storageState},target=${PLAYWRIGHT_CONTAINER_STORAGE_STATE},readonly`,
    '--workdir', suiteDirectory,
    '--env', 'CI=1',
    '--env', 'HOME=/tmp/kodesec-home',
    '--env', 'TMPDIR=/tmp',
    '--env', 'XDG_CACHE_HOME=/tmp/kodesec-home/.cache',
    '--env', 'XDG_CONFIG_HOME=/tmp/kodesec-home/.config',
    '--env', 'KODESEC_PLAYWRIGHT_BROWSER_CONTAINER=1',
    '--env', 'PLAYWRIGHT_BROWSERS_PATH=/ms-playwright',
    '--env', 'KODESEC_PLAYWRIGHT_MODE=compose',
    '--env', `KODESEC_COMPOSE_BASE_URL=${origin}`,
    '--env', `KODESEC_COMPOSE_STORAGE_STATE=${PLAYWRIGHT_CONTAINER_STORAGE_STATE}`,
    '--env', `KODESEC_PLAYWRIGHT_RESULT_DIR=${resultDirectory}`,
    PLAYWRIGHT_CONTAINER_IMAGE,
    'node', resolve(suiteDirectory, 'scripts', 'playwright.mjs'), 'test',
  ];
}

function validateContainerName(value, pattern, label) {
  if (!pattern.test(value)) throw new Error(`Generated Playwright ${label} container name is malformed.`);
}

function validateNonRootIdentity(uid, gid) {
  if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid < 0) {
    throw new Error('The isolated Playwright containers require a non-root host user identity.');
  }
}

function validatePlaywrightPort(value) {
  if (!Number.isSafeInteger(value) || value < 1024 || value > 65535) {
    throw new Error('The Playwright server port is outside the allowed range.');
  }
}

function validatePlaywrightPath(value) {
  if (!PLAYWRIGHT_PATH_PATTERN.test(value)) {
    throw new Error('The Playwright server path must be one generated 12-character lowercase hexadecimal segment.');
  }
}

export function exactPlaywrightWSEndpoint(value) {
  const parsed = new URL(value);
  const port = Number.parseInt(parsed.port, 10);
  if (
    parsed.protocol !== 'ws:'
    || parsed.hostname !== '127.0.0.1'
    || !parsed.port
    || !Number.isInteger(port)
    || port < 1024
    || port > 65535
    || parsed.username
    || parsed.password
    || !PLAYWRIGHT_PATH_PATTERN.test(parsed.pathname)
    || parsed.search
    || parsed.hash
    || value !== `ws://127.0.0.1:${port}${parsed.pathname}`
  ) {
    throw new Error('Playwright WebSocket endpoint must be an exact ws://127.0.0.1:<port>/<generated-id> URL.');
  }
  return value;
}

export function playwrightHeadedDesktopContract(desktop) {
  if (desktop === null || desktop === undefined) return null;
  if (!desktop || typeof desktop !== 'object' || Array.isArray(desktop)) {
    throw new Error('Headed Playwright desktop evidence must be one object.');
  }
  if (
    desktop.headed !== true
    || desktop.preflight_verified !== true
    || desktop.display !== PLAYWRIGHT_HEADED_DISPLAY
    || typeof desktop.hostname !== 'string'
    || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(desktop.hostname)
  ) {
    throw new Error('Headed Playwright requires the verified real :1 desktop and one safe hostname.');
  }
  const transport = desktop.transport;
  const xauthorityPath = transport?.xauthority?.host_path;
  const x11SocketPath = transport?.x11_socket?.host_path;
  if (
    transport?.schema !== 'lomo-playwright-x11-relay/v1'
    || transport?.mode !== 'owner-scoped-unix-relay'
    || transport?.ready !== true
    || transport?.child?.ready !== true
    || transport?.xauthority?.container_path !== PLAYWRIGHT_CONTAINER_XAUTHORITY
    || transport?.x11_socket?.container_path !== PLAYWRIGHT_CONTAINER_X11_SOCKET
  ) {
    throw new Error('Headed Playwright requires the ready owner-scoped Unix relay contract.');
  }
  validateBindPath(xauthorityPath, 'Headed Playwright Xauthority path');
  validateBindPath(x11SocketPath, 'Headed Playwright X11 socket path');
  return {
    display: PLAYWRIGHT_HEADED_DISPLAY,
    hostname: desktop.hostname,
    xauthorityPath,
    x11SocketPath,
  };
}

export function offlineBrowserServiceArguments({
  suiteDirectory,
  containerName,
  wsPort,
  wsPath,
  uid,
  gid,
  desktop = null,
}) {
  validateBindPath(suiteDirectory, 'Playwright suite directory');
  validateContainerName(containerName, BROWSER_CONTAINER_PATTERN, 'browser-service');
  validateNonRootIdentity(uid, gid);
  validatePlaywrightPort(wsPort);
  validatePlaywrightPath(wsPath);
  const runId = containerName.slice('lomo-code-security-'.length, -'-browser'.length);
  if (wsPath !== `/${runId}`) throw new Error('Playwright browser-service name and server path identities do not match.');
  const nodeModules = resolve(suiteDirectory, 'node_modules');
  const headedDesktop = playwrightHeadedDesktopContract(desktop);
  return [
    'run', '--detach', '--interactive', '--init', '--pull', 'never',
    '--name', containerName,
    '--network', 'none',
    '--read-only',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges:true',
    ...(headedDesktop ? ['--hostname', headedDesktop.hostname] : []),
    '--user', `${uid}:${gid}`,
    '--memory', '1g',
    '--memory-swap', '1g',
    '--cpus', String(PLAYWRIGHT_OFFLINE_BROWSER_CPUS),
    '--pids-limit', '256',
    '--shm-size', '256m',
    '--tmpfs', `/tmp:rw,nosuid,nodev,size=512m,uid=${uid},gid=${gid},mode=0700`,
    '--mount', `type=bind,source=${nodeModules},target=${PLAYWRIGHT_REMOTE_NODE_MODULES},readonly`,
    ...(headedDesktop ? [
      '--mount', `type=bind,source=${headedDesktop.xauthorityPath},target=${PLAYWRIGHT_CONTAINER_XAUTHORITY},readonly`,
      '--mount', `type=bind,source=${headedDesktop.x11SocketPath},target=${PLAYWRIGHT_CONTAINER_X11_SOCKET},readonly`,
    ] : []),
    '--env', 'HOME=/tmp/kodesec-home',
    '--env', 'TMPDIR=/tmp',
    '--env', 'PLAYWRIGHT_BROWSERS_PATH=/ms-playwright',
    ...(headedDesktop ? [
      '--env', `DISPLAY=${headedDesktop.display}`,
      '--env', `XAUTHORITY=${PLAYWRIGHT_CONTAINER_XAUTHORITY}`,
    ] : []),
    PLAYWRIGHT_CONTAINER_IMAGE,
    'node', `${PLAYWRIGHT_REMOTE_NODE_MODULES}/@playwright/test/cli.js`,
    'run-server',
    '--host', '127.0.0.1',
    '--port', String(wsPort),
    '--path', wsPath,
    '--max-clients', '1',
    '--artifacts-dir', '/tmp/kodesec-artifacts',
  ];
}

export function offlineControllerSupportFiles(suiteDirectory) {
  validateBindPath(suiteDirectory, 'Playwright suite directory');
  const directory = resolve(suiteDirectory, '..', '..', 'extensions', 'vscode', 'test', 'ui');
  return Object.freeze({
    bulk_finding_actions: resolve(directory, 'bulk-finding-actions.mjs'),
    bulk_finding_race: resolve(directory, 'bulk-finding-race.mjs'),
  });
}

export function offlineControllerArguments({
  suiteDirectory,
  webDistDirectory,
  resultDirectory,
  browserContainerName,
  controllerContainerName,
  wsEndpoint,
  fixturePort,
  uid,
  gid,
  playwrightArguments = [],
  runnerMode = 'qualification',
  snapshotDirectory,
  timingFactor = 1,
  timingPolicy,
  performancePlatform,
  headed = false,
}) {
  validateBindPath(suiteDirectory, 'Playwright suite directory');
  validateBindPath(webDistDirectory, 'Built web distribution directory');
  validateBindPath(resultDirectory, 'Playwright result directory');
  validateContainerName(browserContainerName, BROWSER_CONTAINER_PATTERN, 'browser-service');
  validateContainerName(controllerContainerName, CONTROLLER_CONTAINER_PATTERN, 'controller');
  if (browserContainerName.replace(/-browser$/, '') !== controllerContainerName.replace(/-controller$/, '')) {
    throw new Error('Playwright browser-service and controller identities do not match.');
  }
  validateNonRootIdentity(uid, gid);
  validatePlaywrightPort(fixturePort);
  const endpoint = exactPlaywrightWSEndpoint(wsEndpoint);
  const runId = browserContainerName.slice('lomo-code-security-'.length, -'-browser'.length);
  if (new URL(endpoint).pathname !== `/${runId}`) {
    throw new Error('Playwright container and WebSocket path identities do not match.');
  }
  if (Number.parseInt(new URL(endpoint).port, 10) === fixturePort) {
    throw new Error('Playwright server and fixture server ports must be distinct.');
  }
  const expectedWebDist = resolve(suiteDirectory, '..', '..', 'apps', 'web', 'dist');
  if (resolve(webDistDirectory) !== expectedWebDist) {
    throw new Error('Built web distribution mount must be the repository apps/web/dist directory.');
  }
  const resultsRoot = resolve(suiteDirectory, '.results');
  if (!isStrictDescendant(resultsRoot, resultDirectory)) {
    throw new Error('Playwright results must remain beneath the masked suite result directory.');
  }
  if (!['qualification', 'targeted', 'snapshot-update'].includes(runnerMode)) {
    throw new Error('Offline Playwright runner mode is invalid.');
  }
  const currentTiming = timingPolicy === 'D-020';
  const laneFactor = { mac: 1, linux: 2.6, windows: 3.9 }[performancePlatform];
  if (currentTiming ? timingFactor !== laneFactor
    : timingPolicy !== undefined || ![1, 2].includes(timingFactor)) {
    throw new Error('Playwright timing factor must be exactly 1 for native Linux or 2 for nested Windows/WSL.');
  }
  if (typeof headed !== 'boolean') {
    throw new Error('Playwright headed mode must be one explicit boolean.');
  }
  if (runnerMode === 'qualification') {
    if (playwrightArguments.length !== 0) throw new Error('Qualification runs accept no Playwright CLI overrides.');
    offlinePlaywrightInvocation([], { headed });
  } else if (runnerMode === 'targeted') {
    offlinePlaywrightInvocation([PLAYWRIGHT_OFFLINE_TARGETED_FLAG, ...playwrightArguments]);
  } else {
    if (playwrightArguments.at(-1) !== '--update-snapshots=all') {
      throw new Error('Offline snapshot-update mode requires one canonical terminal --update-snapshots=all argument.');
    }
    offlinePlaywrightInvocation([
      PLAYWRIGHT_OFFLINE_SNAPSHOT_UPDATE_FLAG,
      ...playwrightArguments.slice(0, -1),
    ]);
  }
  const snapshotUpdate = runnerMode === 'snapshot-update';
  if (snapshotUpdate) {
    validateBindPath(snapshotDirectory, 'Playwright snapshot directory');
    const expectedSnapshotDirectory = resolve(suiteDirectory, 'tests', '__screenshots__');
    if (resolve(snapshotDirectory) !== expectedSnapshotDirectory) {
      throw new Error('Playwright snapshot updates may write only to tests/__screenshots__.');
    }
  } else {
    if (snapshotDirectory !== undefined) throw new Error('Ordinary Playwright runs may not mount a writable snapshot directory.');
  }
  return [
    'run', '--init', '--pull', 'never',
    '--name', controllerContainerName,
    '--network', `container:${browserContainerName}`,
    '--read-only',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges:true',
    '--user', `${uid}:${gid}`,
    '--memory', '1g',
    '--memory-swap', '1g',
    '--cpus', String(PLAYWRIGHT_OFFLINE_CONTROLLER_CPUS),
    '--pids-limit', '256',
    '--tmpfs', `/tmp:rw,nosuid,nodev,size=512m,uid=${uid},gid=${gid},mode=0700`,
    '--mount', `type=bind,source=${suiteDirectory},target=${suiteDirectory},readonly`,
    ...(snapshotUpdate ? ['--mount', `type=bind,source=${snapshotDirectory},target=${snapshotDirectory}`] : []),
    '--mount', `type=bind,source=${webDistDirectory},target=${webDistDirectory},readonly`,
    ...Object.values(offlineControllerSupportFiles(suiteDirectory))
      .flatMap(file => ['--mount', `type=bind,source=${file},target=${file},readonly`]),
    '--tmpfs', `${resultsRoot}:rw,nosuid,nodev,noexec,size=8m,uid=${uid},gid=${gid},mode=0700`,
    '--mount', `type=bind,source=${resultDirectory},target=${resultDirectory}`,
    '--workdir', suiteDirectory,
    '--env', 'CI=1',
    '--env', 'HOME=/tmp/kodesec-home',
    '--env', 'TMPDIR=/tmp',
    '--env', `KODESEC_PLAYWRIGHT_PORT=${fixturePort}`,
    '--env', `KODESEC_PLAYWRIGHT_WS_ENDPOINT=${endpoint}`,
    '--env', `KODESEC_PLAYWRIGHT_RESULT_DIR=${resultDirectory}`,
    '--env', `KODESEC_PLAYWRIGHT_TIMING_FACTOR=${timingFactor}`,
    ...(currentTiming ? ['--env', 'KODESEC_PLAYWRIGHT_TIMING_POLICY=D-020',
      '--env', `KODESEC_PLAYWRIGHT_PERFORMANCE_PLATFORM=${performancePlatform}`] : []),
    '--env', `KODESEC_PLAYWRIGHT_HEADED=${headed ? '1' : '0'}`,
    PLAYWRIGHT_CONTAINER_IMAGE,
    'node', resolve(suiteDirectory, 'scripts', 'playwright.mjs'), 'test',
    ...playwrightArguments,
  ];
}

export function playwrightContainerCleanupArguments(containerName) {
  if (!BROWSER_CONTAINER_PATTERN.test(containerName) && !CONTROLLER_CONTAINER_PATTERN.test(containerName)) {
    throw new Error('Playwright cleanup target is not a generated browser-service or controller container.');
  }
  return ['container', 'rm', '--force', containerName];
}

export function playwrightContainerStopArguments(containerName) {
  if (!BROWSER_CONTAINER_PATTERN.test(containerName) && !CONTROLLER_CONTAINER_PATTERN.test(containerName)) {
    throw new Error('Playwright stop target is not a generated browser-service or controller container.');
  }
  return ['container', 'stop', '--time', '5', containerName];
}

export function playwrightContainerAbsenceArguments(containerName) {
  if (!BROWSER_CONTAINER_PATTERN.test(containerName) && !CONTROLLER_CONTAINER_PATTERN.test(containerName)) {
    throw new Error('Playwright absence target is not a generated browser-service or controller container.');
  }
  return ['container', 'ls', '--all', '--filter', `name=^/${containerName}$`, '--format', '{{.Names}}'];
}

export function unexpectedCoreContainerExitArguments(containerName) {
  if (!CORE_CONTAINER_PATTERN.test(containerName)) {
    throw new Error('Generated Compose recovery container name is malformed.');
  }
  if (containerName.endsWith('-postgres-1')) {
    return [
      'container', 'exec', '--user', 'postgres', containerName,
      'pg_ctl', '-D', '/var/lib/postgresql/data', '-m', 'immediate', '-w', 'stop',
    ];
  }
  // An engine-level stop or kill is an operator action and deliberately
  // suppresses `unless-stopped`. Signal PID 1 from inside the scoped container
  // so Docker observes the process exit and applies the service policy.
  // SIGTERM is handled by Docker's init; a PID-namespace init is protected
  // from an unhandled SIGKILL sent inside its own namespace.
  return ['container', 'exec', containerName, '/bin/sh', '-c', 'kill -TERM 1'];
}

export function unexpectedCoreContainerExitStatusAccepted(containerName, status) {
  if (!CORE_CONTAINER_PATTERN.test(containerName)) {
    throw new Error('Generated Compose recovery container name is malformed.');
  }
  if (!Number.isSafeInteger(status) || status < 0 || status > 255) {
    throw new Error('Compose recovery command status is malformed.');
  }
  // Docker can terminate the attached exec process with SIGKILL while
  // PostgreSQL PID 1 is completing the requested immediate shutdown. The
  // following exact restart and health transition remains authoritative.
  return status === 0 || (containerName.endsWith('-postgres-1') && status === 137);
}

function validateCoreRecoverySnapshot(snapshot) {
  if (
    !snapshot
    || typeof snapshot !== 'object'
    || Array.isArray(snapshot)
    || typeof snapshot.id !== 'string'
    || !/^[a-f0-9]{64}$/.test(snapshot.id)
    || !Number.isSafeInteger(snapshot.restartCount)
    || snapshot.restartCount < 0
    || typeof snapshot.running !== 'boolean'
    || !['starting', 'healthy', 'unhealthy'].includes(snapshot.health)
  ) throw new Error('Compose recovery snapshot is malformed.');
}

export function coreContainerRecoveryReady(before, after) {
  validateCoreRecoverySnapshot(before);
  validateCoreRecoverySnapshot(after);
  if (after.id !== before.id) throw new Error('Compose service was recreated instead of restarted.');
  if (after.restartCount < before.restartCount || after.restartCount > before.restartCount + 1) {
    throw new Error('Compose service restart count left the exact recovery boundary.');
  }
  return after.restartCount === before.restartCount + 1
    && after.running
    && after.health === 'healthy';
}

function mountPurpose(destination, expectedTargets) {
  for (const [purpose, target] of Object.entries(expectedTargets)) {
    if (target && destination === target) return purpose;
  }
  return 'other';
}

export function summarizePlaywrightImageInspect(inspect) {
  if (!inspect || typeof inspect !== 'object' || Array.isArray(inspect)) {
    throw new Error('Playwright image inspection must be one object.');
  }
  if (typeof inspect.Id !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(inspect.Id)) {
    throw new Error('Playwright image inspection is missing an exact image ID.');
  }
  const repoDigests = Array.isArray(inspect.RepoDigests)
    ? inspect.RepoDigests.filter((value) => typeof value === 'string' && /@sha256:[a-f0-9]{64}$/.test(value)).sort()
    : [];
  return {
    id: inspect.Id,
    repo_digests: repoDigests,
    architecture: typeof inspect.Architecture === 'string' ? inspect.Architecture : null,
    os: typeof inspect.Os === 'string' ? inspect.Os : null,
  };
}

export function summarizePlaywrightContainerInspect(inspect, expectedTargets = {}) {
  if (!inspect || typeof inspect !== 'object' || Array.isArray(inspect)) {
    throw new Error('Playwright container inspection must be one object.');
  }
  const host = inspect.HostConfig || {};
  const state = inspect.State || {};
  const networkMode = typeof host.NetworkMode === 'string' && host.NetworkMode.startsWith('container:')
    ? 'container:browser-service'
    : host.NetworkMode || null;
  const environment = Object.fromEntries(
    ['DISPLAY', 'XAUTHORITY', 'KODESEC_PLAYWRIGHT_HEADED'].map((name) => {
      const values = Array.isArray(inspect.Config?.Env)
        ? inspect.Config.Env.filter((value) => typeof value === 'string' && value.startsWith(`${name}=`))
        : [];
      return [name, values.length === 1 ? values[0].slice(name.length + 1) : null];
    }),
  );
  return {
    state: {
      status: typeof state.Status === 'string' ? state.Status : null,
      running: state.Running === true,
      oom_killed: state.OOMKilled === true,
      exit_code: Number.isInteger(state.ExitCode) ? state.ExitCode : null,
      has_runtime_error: Boolean(state.Error),
    },
    effective: {
      user: typeof inspect.Config?.User === 'string' ? inspect.Config.User : null,
      image: typeof inspect.Config?.Image === 'string' ? inspect.Config.Image : null,
      network_mode: networkMode,
      read_only_root: host.ReadonlyRootfs === true,
      memory_bytes: Number.isSafeInteger(host.Memory) ? host.Memory : null,
      memory_swap_bytes: Number.isSafeInteger(host.MemorySwap) ? host.MemorySwap : null,
      nano_cpus: Number.isSafeInteger(host.NanoCpus) ? host.NanoCpus : null,
      pids_limit: Number.isSafeInteger(host.PidsLimit) ? host.PidsLimit : null,
      shm_size_bytes: Number.isSafeInteger(host.ShmSize) ? host.ShmSize : null,
      cap_drop: Array.isArray(host.CapDrop) ? [...host.CapDrop].sort() : [],
      security_opt: Array.isArray(host.SecurityOpt) ? [...host.SecurityOpt].sort() : [],
      hostname: typeof inspect.Config?.Hostname === 'string' ? inspect.Config.Hostname : null,
      environment,
    },
    mounts: Array.isArray(inspect.Mounts) ? inspect.Mounts.map((mount) => ({
      purpose: mountPurpose(mount.Destination, expectedTargets),
      type: typeof mount.Type === 'string' ? mount.Type : null,
      writable: mount.RW === true,
    })).sort((left, right) => left.purpose.localeCompare(right.purpose)) : [],
    tmpfs: host.Tmpfs && typeof host.Tmpfs === 'object' ? Object.entries(host.Tmpfs).map(([destination, options]) => ({
      purpose: mountPurpose(destination, expectedTargets),
      options: typeof options === 'string' && /^[A-Za-z0-9=,]+$/.test(options) ? options : null,
    })).sort((left, right) => left.purpose.localeCompare(right.purpose)) : [],
  };
}

export function summarizePlaywrightControllerNetworkNamespace(controllerInspect, browserInspect) {
  const controllerName = typeof controllerInspect?.Name === 'string'
    ? controllerInspect.Name.replace(/^\//, '')
    : '';
  const browserName = typeof browserInspect?.Name === 'string'
    ? browserInspect.Name.replace(/^\//, '')
    : '';
  const browserId = typeof browserInspect?.Id === 'string' && /^[a-f0-9]{64}$/.test(browserInspect.Id)
    ? browserInspect.Id
    : '';
  const networkMode = typeof controllerInspect?.HostConfig?.NetworkMode === 'string'
    ? controllerInspect.HostConfig.NetworkMode
    : '';
  const networkTarget = networkMode.startsWith('container:') ? networkMode.slice('container:'.length) : '';
  const namesMatch = CONTROLLER_CONTAINER_PATTERN.test(controllerName)
    && BROWSER_CONTAINER_PATTERN.test(browserName)
    && controllerName.replace(/-controller$/, '') === browserName.replace(/-browser$/, '');
  const targetMatches = namesMatch
    && Boolean(browserId)
    && (networkTarget === browserId || networkTarget === browserName);
  const controllerSandbox = controllerInspect?.NetworkSettings?.SandboxKey;
  const browserSandbox = browserInspect?.NetworkSettings?.SandboxKey;
  const sandboxComparable = typeof controllerSandbox === 'string'
    && controllerSandbox.length > 0
    && typeof browserSandbox === 'string'
    && browserSandbox.length > 0;
  const sandboxMatches = sandboxComparable ? controllerSandbox === browserSandbox : null;
  return {
    target_matches_browser: targetMatches,
    sandbox_identity_available: sandboxComparable,
    sandbox_matches_browser: sandboxMatches,
    verified: targetMatches && (sandboxMatches === null || sandboxMatches === true),
  };
}

function reportSpecName(value, allowedSpecs) {
  if (typeof value !== 'string') return null;
  const normalized = value.replace(/\\/g, '/');
  const canonical = allowedSpecs.find((spec) => (
    normalized === spec || normalized.endsWith(`/${spec}`)
  ));
  if (canonical) return canonical;
  if (normalized.includes('/')) return null;
  const basenameMatches = allowedSpecs.filter((spec) => spec.split('/').at(-1) === normalized);
  return basenameMatches.length === 1 ? basenameMatches[0] : null;
}

function reconciledReportSpecName(specFile, suiteFile, allowedSpecs) {
  const present = [specFile, suiteFile].filter((value) => value !== undefined && value !== null);
  if (present.length === 0) {
    throw new Error('Playwright JSON report contains a test outside the repository allowlist.');
  }
  const resolved = present.map((value) => {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error('Playwright JSON report contains a malformed present spec identity.');
    }
    const canonical = reportSpecName(value, allowedSpecs);
    if (!canonical) {
      throw new Error('Playwright JSON report contains a test outside the repository allowlist.');
    }
    return canonical;
  });
  if (new Set(resolved).size !== 1) {
    throw new Error('Playwright JSON report contains conflicting allowlisted spec identities.');
  }
  return resolved[0];
}

function nonNegativeReportInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Playwright JSON report ${label} must be a non-negative integer.`);
  }
  return value;
}

function summarizeRawPlaywrightJsonReport(report, allowedSpecs, allowedProjects) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error('Playwright JSON report must be one object.');
  }
  if (!report.stats || typeof report.stats !== 'object' || Array.isArray(report.stats)) {
    throw new Error('Playwright JSON report is missing its statistics.');
  }
  const stats = Object.fromEntries(PLAYWRIGHT_REPORT_STATUSES.map((status) => [
    status,
    nonNegativeReportInteger(report.stats[status], `stats.${status}`),
  ]));
  const bySpec = new Map();
  const byProject = new Map();
  let discoveredTests = 0;
  let testsWithResults = 0;
  let executedTests = 0;
  let resultAttempts = 0;
  const executedActionScenarioIds = new Set();

  const incrementGroup = (groups, name, status, executed, resultCount) => {
    const group = groups.get(name) || {
      name,
      discovered_tests: 0,
      tests_with_results: 0,
      executed_tests: 0,
      result_attempts: 0,
      outcomes: Object.fromEntries(PLAYWRIGHT_REPORT_STATUSES.map((value) => [value, 0])),
    };
    group.discovered_tests += 1;
    group.tests_with_results += resultCount > 0 ? 1 : 0;
    group.executed_tests += executed ? 1 : 0;
    group.result_attempts += resultCount;
    group.outcomes[status] += 1;
    groups.set(name, group);
  };

  const visitSuite = (suite) => {
    if (!suite || typeof suite !== 'object' || Array.isArray(suite)) {
      throw new Error('Playwright JSON report contains a malformed suite.');
    }
    for (const spec of Array.isArray(suite.specs) ? suite.specs : []) {
      const specName = reconciledReportSpecName(spec?.file, suite.file, allowedSpecs);
      const scenarioIds = typeof spec?.title === 'string'
        ? [...spec.title.matchAll(/\bWEB-ACT-\d{3}\b/gu)].map((match) => match[0])
        : [];
      if (scenarioIds.some((scenarioId) => !PLAYWRIGHT_OPERATOR_ACTION_SCENARIO_IDS.includes(scenarioId))) {
        throw new Error('Playwright JSON report contains an unknown Web action scenario identity.');
      }
      if (!Array.isArray(spec.tests)) throw new Error('Playwright JSON report contains a malformed test list.');
      for (const reportedTest of spec.tests) {
        const status = reportedTest?.status;
        if (!PLAYWRIGHT_REPORT_STATUSES.includes(status)) {
          throw new Error('Playwright JSON report contains an unknown test outcome.');
        }
        const projectName = reportedTest?.projectName;
        if (!allowedProjects.includes(projectName)) {
          throw new Error('Playwright JSON report contains an unknown project.');
        }
        if (!Array.isArray(reportedTest.results)) {
          throw new Error('Playwright JSON report contains a malformed result list.');
        }
        const results = reportedTest.results;
        for (const result of results) {
          if (
            !result
            || typeof result !== 'object'
            || Array.isArray(result)
            || !PLAYWRIGHT_RESULT_STATUSES.includes(result.status)
          ) throw new Error('Playwright JSON report contains a malformed result attempt.');
        }
        const executed = results.some((result) => result?.status !== 'skipped');
        if (executed && status !== 'unexpected') {
          for (const scenarioId of scenarioIds) executedActionScenarioIds.add(scenarioId);
        }
        discoveredTests += 1;
        testsWithResults += results.length > 0 ? 1 : 0;
        executedTests += executed ? 1 : 0;
        resultAttempts += results.length;
        incrementGroup(bySpec, specName, status, executed, results.length);
        incrementGroup(byProject, projectName, status, executed, results.length);
      }
    }
    for (const child of Array.isArray(suite.suites) ? suite.suites : []) visitSuite(child);
  };
  for (const suite of Array.isArray(report.suites) ? report.suites : []) visitSuite(suite);

  const outcomeTotal = Object.values(stats).reduce((total, value) => total + value, 0);
  if (outcomeTotal !== discoveredTests) {
    throw new Error('Playwright JSON report statistics do not match discovered tests.');
  }
  const serializeGroups = (groups) => [...groups.values()].sort((left, right) => left.name.localeCompare(right.name));
  return {
    reporter: 'playwright-json',
    stats: {
      ...stats,
      duration_ms: Number.isFinite(report.stats.duration) && report.stats.duration >= 0
        ? Math.round(report.stats.duration)
        : null,
    },
    report_errors: Array.isArray(report.errors) ? report.errors.length : null,
    discovered_tests: discoveredTests,
    tests_with_results: testsWithResults,
    executed_tests: executedTests,
    result_attempts: resultAttempts,
    action_scenario_ids: [...executedActionScenarioIds].sort(),
    specs: serializeGroups(bySpec),
    projects: serializeGroups(byProject),
  };
}

function exactReportKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Normalized Playwright report ${label} must be one object.`);
  }
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(required)) {
    throw new Error(`Normalized Playwright report ${label} has unexpected fields.`);
  }
}

function normalizedReportGroups(value, allowedNames, label) {
  if (!Array.isArray(value) || value.length === 0 || value.length > allowedNames.length) {
    throw new Error(`Normalized Playwright report ${label} must be a bounded non-empty array.`);
  }
  const seen = new Set();
  const groups = value.map((entry) => {
    exactReportKeys(entry, [
      'name',
      'discovered_tests',
      'tests_with_results',
      'executed_tests',
      'result_attempts',
      'outcomes',
    ], `${label} entry`);
    if (!allowedNames.includes(entry.name) || seen.has(entry.name)) {
      throw new Error(`Normalized Playwright report ${label} contains an unknown or duplicate name.`);
    }
    seen.add(entry.name);
    exactReportKeys(entry.outcomes, PLAYWRIGHT_REPORT_STATUSES, `${label} outcomes`);
    const group = {
      name: entry.name,
      discovered_tests: nonNegativeReportInteger(entry.discovered_tests, `${label}.discovered_tests`),
      tests_with_results: nonNegativeReportInteger(entry.tests_with_results, `${label}.tests_with_results`),
      executed_tests: nonNegativeReportInteger(entry.executed_tests, `${label}.executed_tests`),
      result_attempts: nonNegativeReportInteger(entry.result_attempts, `${label}.result_attempts`),
      outcomes: Object.fromEntries(PLAYWRIGHT_REPORT_STATUSES.map((status) => [
        status,
        nonNegativeReportInteger(entry.outcomes[status], `${label}.outcomes.${status}`),
      ])),
    };
    const outcomeTotal = Object.values(group.outcomes).reduce((total, count) => total + count, 0);
    if (
      group.discovered_tests === 0
      || outcomeTotal !== group.discovered_tests
      || group.tests_with_results > group.discovered_tests
      || group.executed_tests > group.tests_with_results
      || group.result_attempts < group.tests_with_results
    ) throw new Error(`Normalized Playwright report ${label} counts are inconsistent.`);
    return group;
  });
  const names = groups.map((entry) => entry.name);
  if (JSON.stringify(names) !== JSON.stringify([...names].sort())) {
    throw new Error(`Normalized Playwright report ${label} must use canonical order.`);
  }
  return groups;
}

function summarizeNormalizedPlaywrightJsonReport(report, allowedSpecs, allowedProjects) {
  exactReportKeys(report, [
    'schema',
    'reporter',
    'stats',
    'report_errors',
    'discovered_tests',
    'tests_with_results',
    'executed_tests',
    'result_attempts',
    'action_scenario_ids',
    'specs',
    'projects',
  ], 'root');
  if (report.schema !== PLAYWRIGHT_EXECUTION_REPORT_SCHEMA || report.reporter !== 'playwright-json') {
    throw new Error('Normalized Playwright report identity is invalid.');
  }
  exactReportKeys(report.stats, [...PLAYWRIGHT_REPORT_STATUSES, 'duration_ms'], 'stats');
  const stats = Object.fromEntries(PLAYWRIGHT_REPORT_STATUSES.map((status) => [
    status,
    nonNegativeReportInteger(report.stats[status], `stats.${status}`),
  ]));
  const durationMs = report.stats.duration_ms;
  if (durationMs !== null && (!Number.isSafeInteger(durationMs) || durationMs < 0)) {
    throw new Error('Normalized Playwright report duration must be null or a non-negative integer.');
  }
  if (report.report_errors !== null && (!Number.isSafeInteger(report.report_errors) || report.report_errors < 0)) {
    throw new Error('Normalized Playwright report error count must be null or a non-negative integer.');
  }
  const summary = {
    reporter: 'playwright-json',
    stats: { ...stats, duration_ms: durationMs },
    report_errors: report.report_errors,
    discovered_tests: nonNegativeReportInteger(report.discovered_tests, 'discovered_tests'),
    tests_with_results: nonNegativeReportInteger(report.tests_with_results, 'tests_with_results'),
    executed_tests: nonNegativeReportInteger(report.executed_tests, 'executed_tests'),
    result_attempts: nonNegativeReportInteger(report.result_attempts, 'result_attempts'),
    action_scenario_ids: report.action_scenario_ids,
    specs: normalizedReportGroups(report.specs, allowedSpecs, 'specs'),
    projects: normalizedReportGroups(report.projects, allowedProjects, 'projects'),
  };
  if (
    !Array.isArray(summary.action_scenario_ids)
    || new Set(summary.action_scenario_ids).size !== summary.action_scenario_ids.length
    || summary.action_scenario_ids.some((scenarioId) => !PLAYWRIGHT_OPERATOR_ACTION_SCENARIO_IDS.includes(scenarioId))
    || JSON.stringify(summary.action_scenario_ids) !== JSON.stringify([...summary.action_scenario_ids].sort())
  ) throw new Error('Normalized Playwright report action scenario identities are invalid.');
  const outcomeTotal = Object.values(stats).reduce((total, count) => total + count, 0);
  if (
    summary.discovered_tests === 0
    || outcomeTotal !== summary.discovered_tests
    || summary.tests_with_results > summary.discovered_tests
    || summary.executed_tests > summary.tests_with_results
    || summary.result_attempts < summary.tests_with_results
  ) throw new Error('Normalized Playwright report totals are inconsistent.');
  for (const groups of [summary.specs, summary.projects]) {
    for (const field of ['discovered_tests', 'tests_with_results', 'executed_tests', 'result_attempts']) {
      if (groups.reduce((total, entry) => total + entry[field], 0) !== summary[field]) {
        throw new Error('Normalized Playwright report grouped totals are inconsistent.');
      }
    }
    for (const status of PLAYWRIGHT_REPORT_STATUSES) {
      if (groups.reduce((total, entry) => total + entry.outcomes[status], 0) !== stats[status]) {
        throw new Error('Normalized Playwright report grouped outcomes are inconsistent.');
      }
    }
  }
  return summary;
}

export function summarizePlaywrightJsonReport(report, {
  allowedSpecs = PLAYWRIGHT_ALLOWED_SPECS,
  allowedProjects = PLAYWRIGHT_ALLOWED_PROJECTS,
} = {}) {
  if (
    !Array.isArray(allowedSpecs)
    || allowedSpecs.length === 0
    || new Set(allowedSpecs).size !== allowedSpecs.length
    || !Array.isArray(allowedProjects)
    || allowedProjects.length === 0
    || new Set(allowedProjects).size !== allowedProjects.length
  ) {
    throw new Error('Playwright report scope must declare bounded spec and project allowlists.');
  }
  const offlineScope = allowedSpecs.every((spec) => PLAYWRIGHT_ALLOWED_SPECS.includes(spec));
  const composeScope = allowedSpecs.length === 1 && allowedSpecs[0] === PLAYWRIGHT_COMPOSE_SPEC;
  const networkConformanceScope = allowedSpecs.length === 1
    && (allowedSpecs[0] === PLAYWRIGHT_NETWORK_CONFORMANCE_SPEC || allowedSpecs[0] === PLAYWRIGHT_PROXY_CONFORMANCE_SPEC)
    && allowedProjects.length === 1 && allowedProjects[0] === 'desktop-1440';
  const findingsScaleScope = allowedSpecs.length === 1 && allowedSpecs[0] === PLAYWRIGHT_FINDINGS_SCALE_SPEC
    && allowedProjects.length === PLAYWRIGHT_ALLOWED_PROJECTS.length
    && PLAYWRIGHT_ALLOWED_PROJECTS.every((project) => allowedProjects.includes(project));
  if (
    (!offlineScope && !composeScope && !networkConformanceScope && !findingsScaleScope)
    || !allowedProjects.every((project) => PLAYWRIGHT_ALLOWED_PROJECTS.includes(project))
  ) throw new Error('Playwright report scope is outside the repository allowlists.');
  if (report && typeof report === 'object' && !Array.isArray(report) && 'schema' in report) {
    return summarizeNormalizedPlaywrightJsonReport(report, allowedSpecs, allowedProjects);
  }
  return summarizeRawPlaywrightJsonReport(report, allowedSpecs, allowedProjects);
}

export function normalizePlaywrightJsonReport(report, scope) {
  const summary = summarizePlaywrightJsonReport(report, scope);
  return { schema: PLAYWRIGHT_EXECUTION_REPORT_SCHEMA, ...summary };
}

export function playwrightExecutionScopeComplete(expectedScope, summary) {
  if (
    !expectedScope
    || !Array.isArray(expectedScope.specs)
    || !Array.isArray(expectedScope.projects)
    || !summary
  ) return false;
  const actualSpecs = summary.specs.map((entry) => entry.name).sort();
  const actualProjects = summary.projects.map((entry) => entry.name).sort();
  const expectedSpecs = [...expectedScope.specs].sort();
  const expectedProjects = [...expectedScope.projects].sort();
  const requiresOperatorActions = expectedSpecs.includes(PLAYWRIGHT_OPERATOR_ACTION_SPEC);
  return JSON.stringify(actualSpecs) === JSON.stringify(expectedSpecs)
    && JSON.stringify(actualProjects) === JSON.stringify(expectedProjects)
    && summary.discovered_tests > 0
    && summary.tests_with_results === summary.discovered_tests
    && summary.executed_tests > 0
    && summary.specs.every((entry) => (
      entry.discovered_tests > 0
      && entry.tests_with_results === entry.discovered_tests
      && entry.executed_tests > 0
    ))
    && summary.projects.every((entry) => (
      entry.discovered_tests > 0
      && entry.tests_with_results === entry.discovered_tests
      && entry.executed_tests > 0
    ))
    && summary.stats.unexpected === 0
    && summary.report_errors === 0
    && (!requiresOperatorActions || JSON.stringify(summary.action_scenario_ids) === JSON.stringify(PLAYWRIGHT_OPERATOR_ACTION_SCENARIO_IDS));
}

export function publishPlaywrightExecutionReport({ rawPath, retainedPath, scope }) {
  for (const [value, label] of [[rawPath, 'raw'], [retainedPath, 'retained']]) {
    if (typeof value !== 'string' || !isAbsolute(value) || /[\0\r\n]/.test(value)) {
      throw new Error(`Playwright ${label} execution report path must be one safe absolute path.`);
    }
  }
  if (rawPath === retainedPath) throw new Error('Raw and retained Playwright execution reports must use distinct paths.');
  const reportDirectory = dirname(rawPath);
  if (
    rawPath !== resolve(reportDirectory, PLAYWRIGHT_RAW_EXECUTION_REPORT)
    || retainedPath !== resolve(reportDirectory, PLAYWRIGHT_EXECUTION_REPORT)
  ) throw new Error('Playwright execution report paths must use the exact runner-owned filenames in one directory.');
  let rawMetadata = null;
  try {
    try {
      rawMetadata = lstatSync(rawPath);
    } catch (error) {
      if (error?.code === 'ENOENT') return null;
      throw error;
    }
    if (!rawMetadata.isFile() || rawMetadata.isSymbolicLink()) {
      throw new Error('Raw Playwright execution report must be a regular file.');
    }
    if (rawMetadata.size <= 0 || rawMetadata.size > MAX_PLAYWRIGHT_EXECUTION_REPORT_BYTES) {
      throw new Error('Raw Playwright execution report exceeds its evidence budget.');
    }
    try {
      lstatSync(retainedPath);
      throw new Error('Retained Playwright execution report must not pre-exist publication.');
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    const normalized = normalizePlaywrightJsonReport(JSON.parse(readFileSync(rawPath, 'utf8')), scope);
    const temporaryPath = `${retainedPath}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
    try {
      writeFileSync(temporaryPath, `${JSON.stringify(normalized, null, 2)}\n`, {
        encoding: 'utf8',
        flag: 'wx',
        mode: 0o600,
      });
      renameSync(temporaryPath, retainedPath);
    } finally {
      try {
        unlinkSync(temporaryPath);
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
      }
    }
    const metadata = lstatSync(retainedPath);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size <= 0) {
      throw new Error('Normalized Playwright execution report publication failed.');
    }
    const bytes = readFileSync(retainedPath);
    summarizePlaywrightJsonReport(JSON.parse(bytes.toString('utf8')), scope);
    return {
      sha256: createHash('sha256').update(bytes).digest('hex'),
      size_bytes: metadata.size,
    };
  } finally {
    if (rawMetadata) {
      try {
        if (rawMetadata.isDirectory() && !rawMetadata.isSymbolicLink()) {
          rmSync(rawPath, { recursive: true, force: true });
        } else {
          unlinkSync(rawPath);
        }
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
      }
    }
  }
}

export function runPlaywrightWithExecutionPublication({ runPlaywright, rawPath, retainedPath, scope }) {
  if (typeof runPlaywright !== 'function') throw new Error('Playwright publication supervision requires a run callback.');
  let runError = null;
  try {
    runPlaywright();
  } catch (error) {
    runError = error;
  }
  const publication = publishPlaywrightExecutionReport({ rawPath, retainedPath, scope });
  if (runError) throw runError;
  return publication;
}

function safeCgroupCounter(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function roundedRatio(numerator, denominator) {
  return denominator > 0 ? Number((numerator / denominator).toFixed(6)) : null;
}

export function summarizeCgroupCpuWindow(samples, role) {
  if (!Array.isArray(samples) || !['browser', 'controller'].includes(role)) {
    throw new Error('Cgroup CPU window requires resource samples and a known container role.');
  }
  const observations = samples.flatMap((sample) => {
    const cgroup = sample?.[role]?.cgroup;
    const stat = cgroup?.cpu?.stat;
    const elapsed = sample?.finished_elapsed_ms ?? sample?.elapsed_ms;
    if (!Number.isSafeInteger(elapsed) || elapsed < 0 || !stat || typeof stat !== 'object') return [];
    const counters = {
      usage_usec: safeCgroupCounter(stat.usage_usec),
      nr_periods: safeCgroupCounter(stat.nr_periods),
      nr_throttled: safeCgroupCounter(stat.nr_throttled),
      throttled_usec: safeCgroupCounter(stat.throttled_usec),
    };
    if (Object.values(counters).some((value) => value === null)) return [];
    return [{ elapsed_ms: elapsed, path: cgroup.path || null, counters }];
  });
  if (observations.length < 2) return { available: false, reason: 'insufficient_comparable_samples' };
  const first = observations[0];
  const last = observations.at(-1);
  if (!first.path || first.path !== last.path) return { available: false, reason: 'cgroup_identity_changed' };
  const durationMs = last.elapsed_ms - first.elapsed_ms;
  const delta = Object.fromEntries(Object.keys(first.counters).map((key) => [
    key,
    last.counters[key] - first.counters[key],
  ]));
  if (durationMs <= 0 || Object.values(delta).some((value) => !Number.isSafeInteger(value) || value < 0)) {
    return { available: false, reason: 'non_monotonic_cgroup_counters' };
  }
  const elapsedUsec = durationMs * 1_000;
  return {
    available: true,
    start_elapsed_ms: first.elapsed_ms,
    end_elapsed_ms: last.elapsed_ms,
    duration_ms: durationMs,
    delta,
    ratios: {
      throttled_period_ratio: roundedRatio(delta.nr_throttled, delta.nr_periods),
      throttled_usec_per_elapsed_usec: roundedRatio(delta.throttled_usec, elapsedUsec),
      usage_usec_per_elapsed_usec: roundedRatio(delta.usage_usec, elapsedUsec),
    },
  };
}

export function playwrightBrowserCompletionHealthy(summary) {
  return Boolean(
    summary
    && summary.state?.running === true
    && summary.state.oom_killed === false
    && summary.state.has_runtime_error === false
  );
}

export function playwrightServerReady(logs, wsEndpoint) {
  const endpoint = exactPlaywrightWSEndpoint(wsEndpoint);
  return logs.split(/\r?\n/).some((line) => line.trim() === `Listening on ${endpoint}`);
}

export function parseEnvironment(contents) {
  const entries = new Map();
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = rawLine.indexOf('=');
    if (separator < 1) throw new Error('Runtime environment contains a malformed field.');
    const key = rawLine.slice(0, separator).trim();
    const value = rawLine.slice(separator + 1);
    if (!/^[A-Z][A-Z0-9_]*$/.test(key)) throw new Error(`Runtime environment contains an invalid field name: ${key}`);
    if (entries.has(key)) throw new Error(`Runtime environment contains a duplicate field: ${key}`);
    entries.set(key, value);
  }
  return entries;
}

export function replaceEnvironmentFields(contents, replacements) {
  const pending = new Map(Object.entries(replacements));
  const output = contents.split(/\r?\n/).map((line) => {
    const separator = line.indexOf('=');
    if (separator < 1) return line;
    const key = line.slice(0, separator).trim();
    if (!pending.has(key)) return line;
    const value = pending.get(key);
    pending.delete(key);
    return `${key}=${value}`;
  });
  for (const [key, value] of pending) output.push(`${key}=${value}`);
  return `${output.join('\n').replace(/\n+$/, '')}\n`;
}

export function validateIdentifiers(projectName, controlImage) {
  if (!PROJECT_PATTERN.test(projectName)) throw new Error('Generated Compose project name is malformed.');
  if (!IMAGE_PATTERN.test(controlImage)) throw new Error('Generated control image name is malformed.');
  const projectId = projectName.slice('lomo-code-security-'.length);
  const imageId = controlImage.slice('lomo-kodesec-control:'.length);
  if (projectId !== imageId) throw new Error('Compose project and control image identities do not match.');
}

export function exactScannerImage(value) {
  if (!SCANNER_IMAGE_PATTERN.test(value)) {
    throw new Error('Generated scanner image identity is malformed.');
  }
  return value;
}

export function composeImageInspectArguments(controlImage, scannerImage) {
  if (!IMAGE_PATTERN.test(controlImage)) {
    throw new Error('Generated control image identity is malformed.');
  }
  return ['image', 'inspect', controlImage, exactScannerImage(scannerImage), '--format', '{{json .}}'];
}

export function exactLoopbackBaseURL(value) {
  const parsed = new URL(value);
  if (
    parsed.protocol !== 'http:'
    || parsed.hostname !== '127.0.0.1'
    || !parsed.port
    || parsed.username
    || parsed.password
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash
  ) {
    throw new Error('Compose smoke URL must be an exact 127.0.0.1 HTTP origin with an explicit port.');
  }
  const port = Number.parseInt(parsed.port, 10);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Compose smoke port is outside the allowed range.');
  return parsed.origin;
}

export function composeArguments({ repository, runtimeEnvironment, projectName }, ...command) {
  validateIdentifiers(projectName, `lomo-kodesec-control:${projectName.slice('lomo-code-security-'.length)}`);
  return [
    'compose',
    '--project-name', projectName,
    '--env-file', runtimeEnvironment,
    '--file', `${repository}/docker-compose.yml`,
    ...command,
  ];
}

export function isolatedComposeEnvironment(hostEnvironment, runtimeFields) {
  const environment = { ...hostEnvironment };
  for (const key of ['COMPOSE_FILE', 'COMPOSE_ENV_FILES', 'COMPOSE_PATH_SEPARATOR', 'COMPOSE_PROFILES']) delete environment[key];
  for (const [key, value] of runtimeFields) environment[key] = value;
  environment.COMPOSE_PROFILES = '';
  environment.COMPOSE_PARALLEL_LIMIT = '2';
  return environment;
}

export function sanitizedCommand(args) {
  return ['docker', ...args].map((value) => {
    if (/token|secret|password|authorization|capability/i.test(value)) return '<redacted-argument>';
    return value;
  }).join(' ');
}

export async function availableLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    const timer = setTimeout(() => {
      server.close();
      reject(new Error('Timed out while allocating an isolated loopback port.'));
    }, 5_000);
    timer.unref();
    server.unref();
    server.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        clearTimeout(timer);
        server.close();
        reject(new Error('Could not allocate an isolated loopback port.'));
        return;
      }
      const port = address.port;
      server.close((error) => {
        clearTimeout(timer);
        return error ? reject(error) : resolve(port);
      });
    });
  });
}
