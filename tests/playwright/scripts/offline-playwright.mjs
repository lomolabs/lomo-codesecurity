import { fork, spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes, randomInt } from 'node:crypto';
import {
  closeSync,
  chmodSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { createConnection, createServer } from 'node:net';
import { arch, availableParallelism, cpus, hostname, release } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import {
  PLAYWRIGHT_ALLOWED_PROJECTS,
  PLAYWRIGHT_CONTAINER_IMAGE,
  PLAYWRIGHT_EXECUTION_REPORT,
  PLAYWRIGHT_RAW_EXECUTION_REPORT,
  PLAYWRIGHT_OFFLINE_BROWSER_CPUS,
  PLAYWRIGHT_OFFLINE_CONTROLLER_CPUS,
  PLAYWRIGHT_REMOTE_NODE_MODULES,
  PLAYWRIGHT_HEADED_DISPLAY,
  PLAYWRIGHT_CONTAINER_XAUTHORITY,
  PLAYWRIGHT_CONTAINER_X11_SOCKET,
  exactPlaywrightWSEndpoint,
  isolatedOfflineLocalEnvironment,
  publishPlaywrightExecutionReport,
  offlineBrowserServiceArguments,
  offlineControllerArguments,
  offlinePlaywrightInvocation,
  playwrightExecutionScopeComplete,
  playwrightReferenceCpuEvidence,
  playwrightContainerAbsenceArguments,
  playwrightContainerCleanupArguments,
  playwrightContainerStopArguments,
  playwrightBrowserCompletionHealthy,
  playwrightRunnerKind,
  playwrightServerReady,
  summarizePlaywrightContainerInspect,
  summarizePlaywrightControllerNetworkNamespace,
  summarizePlaywrightJsonReport,
  summarizeCgroupCpuWindow,
  summarizePlaywrightImageInspect,
} from './compose-harness-lib.mjs';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const suiteDirectory = realpathSync(resolve(scriptDirectory, '..'));
const webDistDirectory = resolve(suiteDirectory, '..', '..', 'apps', 'web', 'dist');
const INTERNAL_X11_RELAY_MODE = '--internal-x11-relay';
const internalX11RelayMode = process.argv[2] === INTERNAL_X11_RELAY_MODE;
const requestedHeadedValue = process.env.KODESEC_PLAYWRIGHT_HEADED;
if (requestedHeadedValue !== undefined && requestedHeadedValue !== '0' && requestedHeadedValue !== '1') {
  throw new Error('KODESEC_PLAYWRIGHT_HEADED must be exactly 0 or 1.');
}
const invocation = offlinePlaywrightInvocation(
  internalX11RelayMode ? [] : process.argv.slice(2),
  { headed: !internalX11RelayMode && requestedHeadedValue === '1' },
);
const playwrightArguments = invocation.playwrightArguments;
const snapshotUpdate = invocation.mode === 'snapshot-update';
const RECEIPT_SCHEMA = 'lomo-playwright-offline-runner/v2';
const RESOURCE_SAMPLE_INTERVAL_MS = 10_000;
const LEGACY_MAX_RESOURCE_SAMPLES = 64;
const DEFAULT_CONTROLLER_TIMEOUT_MS = 600_000;
const LEGACY_MAX_CONTROLLER_TIMEOUT_MS = 1_200_000;
const MAX_EVIDENCE_MANIFEST_FILES = 512;
const MAX_EVIDENCE_MANIFEST_BYTES = 128 * 1024 * 1024;
const MAX_EXECUTION_REPORT_BYTES = 32 * 1024 * 1024;
const MAX_DEPENDENCY_METADATA_BYTES = 1024 * 1024;
const MAX_LOCAL_BROWSER_EXECUTABLE_BYTES = 512 * 1024 * 1024;
const FILE_HASH_BUFFER_BYTES = 1024 * 1024;
const LOCAL_RESULT_DIRECTORY_ATTEMPTS = 16;
const LOCAL_CHILD_TERMINATION_GRACE_MS = 2_000;
const X11_RELAY_READY_TIMEOUT_MS = 5_000;
const X11_RELAY_STOP_TIMEOUT_MS = 5_000;
const X11_RELAY_SCHEMA = 'lomo-playwright-x11-relay/v1';
const SIGNAL_EXIT_CODES = Object.freeze({ SIGHUP: 129, SIGINT: 130, SIGTERM: 143 });

export function playwrightControllerTimeoutMs(hostEnvironment = process.env) {
  const raw = hostEnvironment.LOMO_PLAYWRIGHT_CONTROLLER_TIMEOUT_MS;
  if (hostEnvironment.LOMO_PLAYWRIGHT_TIMING_POLICY === 'D-020') {
    const limits = { mac: 600_000, linux: 1_560_000, windows: 2_340_000 };
    const lane = hostEnvironment.LOMO_PLAYWRIGHT_PERFORMANCE_PLATFORM;
    const limit = Object.hasOwn(limits, lane) ? limits[lane] : undefined;
    if (limit === undefined || raw !== undefined && raw !== String(limit)) {
      throw runnerError('controller_timeout_invalid', 'D020 requires one exact reviewed platform/controller budget.');
    }
    return limit;
  }
  if (hostEnvironment.LOMO_PLAYWRIGHT_TIMING_POLICY !== undefined) throw runnerError('controller_timeout_invalid', 'Unknown timing policy.');
  if (raw === undefined) return DEFAULT_CONTROLLER_TIMEOUT_MS;
  if (raw !== String(DEFAULT_CONTROLLER_TIMEOUT_MS) && raw !== String(LEGACY_MAX_CONTROLLER_TIMEOUT_MS)) {
    throw runnerError(
      'controller_timeout_invalid',
      'The Playwright controller timeout must be the native Linux value or its exact 2x nested-virtualization value.',
    );
  }
  return Number(raw);
}

export function playwrightPerformanceBudgetMode(controllerTimeoutMs, hostEnvironment = process.env) {
  if (hostEnvironment.LOMO_PLAYWRIGHT_TIMING_POLICY === 'D-020') {
    if (controllerTimeoutMs !== playwrightControllerTimeoutMs(hostEnvironment)) throw runnerError('performance_budget_mode_invalid', 'D020 timing policy differs.');
    return hostEnvironment.LOMO_PLAYWRIGHT_PERFORMANCE_PLATFORM === 'mac' ? 'blocking' : 'advisory';
  }
  if (controllerTimeoutMs !== DEFAULT_CONTROLLER_TIMEOUT_MS && controllerTimeoutMs !== LEGACY_MAX_CONTROLLER_TIMEOUT_MS) {
    throw runnerError(
      'performance_budget_mode_invalid',
      'Performance budget mode requires the native Linux or exact 2x nested Windows controller timeout.',
    );
  }
  return controllerTimeoutMs === DEFAULT_CONTROLLER_TIMEOUT_MS ? 'blocking' : 'advisory';
}

const CONTROLLER_TIMEOUT_MS = playwrightControllerTimeoutMs();
const MAX_CONTROLLER_TIMEOUT_MS = Math.max(LEGACY_MAX_CONTROLLER_TIMEOUT_MS, CONTROLLER_TIMEOUT_MS);
const QUALIFICATION_TIMING_FACTOR = CONTROLLER_TIMEOUT_MS / DEFAULT_CONTROLLER_TIMEOUT_MS;
const PERFORMANCE_BUDGET_MODE = playwrightPerformanceBudgetMode(CONTROLLER_TIMEOUT_MS);
const CURRENT_TIMING_POLICY = process.env.LOMO_PLAYWRIGHT_TIMING_POLICY === 'D-020';
const MAX_RESOURCE_SAMPLES = CURRENT_TIMING_POLICY
  ? Math.ceil(CONTROLLER_TIMEOUT_MS / RESOURCE_SAMPLE_INTERVAL_MS) + 4 : LEGACY_MAX_RESOURCE_SAMPLES;
const PLAYWRIGHT_VISUAL_BASELINE_ROUTES = Object.freeze([
  'overview',
  'projects',
  'jobs',
  'scans',
  'findings',
  'tools',
  'settings',
]);
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const LOCAL_BROWSER_EXECUTABLE_PATHS = Object.freeze({
  darwin: Object.freeze({
    x64: Object.freeze({
      chromium: Object.freeze([
        'chrome-mac-x64',
        'Google Chrome for Testing.app',
        'Contents',
        'MacOS',
        'Google Chrome for Testing',
      ]),
      'chromium-headless-shell': Object.freeze([
        'chrome-headless-shell-mac-x64',
        'chrome-headless-shell',
      ]),
    }),
    arm64: Object.freeze({
      chromium: Object.freeze([
        'chrome-mac-arm64',
        'Google Chrome for Testing.app',
        'Contents',
        'MacOS',
        'Google Chrome for Testing',
      ]),
      'chromium-headless-shell': Object.freeze([
        'chrome-headless-shell-mac-arm64',
        'chrome-headless-shell',
      ]),
    }),
  }),
  win32: Object.freeze({
    x64: Object.freeze({
      chromium: Object.freeze(['chrome-win64', 'chrome.exe']),
      'chromium-headless-shell': Object.freeze([
        'chrome-headless-shell-win64',
        'chrome-headless-shell.exe',
      ]),
    }),
    arm64: Object.freeze({
      chromium: Object.freeze(['chrome-win64', 'chrome.exe']),
      'chromium-headless-shell': Object.freeze([
        'chrome-headless-shell-win64',
        'chrome-headless-shell.exe',
      ]),
    }),
  }),
});

function runnerError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function boundedStatIdentity(metadata) {
  const numericFields = ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size'];
  if (numericFields.some((field) => !Number.isSafeInteger(metadata?.[field]) || metadata[field] < 0)) {
    throw runnerError('headed_desktop_stat_invalid', 'Headed desktop filesystem identity is not safely representable.');
  }
  return {
    device: String(metadata.dev),
    inode: String(metadata.ino),
    owner_uid: metadata.uid,
    owner_gid: metadata.gid,
    mode: (metadata.mode & 0o7777).toString(8).padStart(4, '0'),
    nlink: metadata.nlink,
    size_bytes: metadata.size,
  };
}

export function linuxHeadedDesktopEvidence({
  environment = process.env,
  uid = process.getuid?.(),
  gid = process.getgid?.(),
  hostnameValue = hostname(),
  lstatPath = lstatSync,
  realpathPath = realpathSync,
} = {}) {
  const headedValue = environment.KODESEC_PLAYWRIGHT_HEADED;
  if (headedValue !== undefined && headedValue !== '0' && headedValue !== '1') {
    throw runnerError('headed_mode_invalid', 'KODESEC_PLAYWRIGHT_HEADED must be exactly 0 or 1.');
  }
  if (headedValue !== '1') {
    return {
      mode: 'headless',
      headed: false,
      display: null,
      hostname: null,
      xauthority: null,
      x11_socket: null,
      transport: null,
      preflight_verified: true,
      terminal_verified: null,
      verified: false,
      postflight_error_code: null,
    };
  }
  if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid < 0) {
    throw runnerError('headed_identity_invalid', 'Headed desktop qualification requires one non-root numeric user identity.');
  }
  if (environment.DISPLAY !== PLAYWRIGHT_HEADED_DISPLAY) {
    throw runnerError('headed_display_invalid', 'Headed desktop qualification requires the exact real DISPLAY=:1 desktop.');
  }
  const xauthorityPath = environment.XAUTHORITY;
  if (
    typeof xauthorityPath !== 'string'
    || !isAbsolute(xauthorityPath)
    || /[\0\r\n,]/.test(xauthorityPath)
    || resolve(xauthorityPath) !== xauthorityPath
  ) {
    throw runnerError('headed_xauthority_invalid', 'Headed desktop qualification requires one canonical absolute Xauthority path.');
  }
  if (
    typeof hostnameValue !== 'string'
    || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(hostnameValue)
  ) {
    throw runnerError('headed_hostname_invalid', 'Headed desktop qualification requires one safe guest hostname.');
  }
  let xauthorityMetadata;
  let socketMetadata;
  try {
    xauthorityMetadata = lstatPath(xauthorityPath);
  } catch {
    throw runnerError('headed_xauthority_unavailable', 'The exact owner Xauthority file is unavailable.');
  }
  if (
    !xauthorityMetadata.isFile()
    || xauthorityMetadata.isSymbolicLink()
    || realpathPath(xauthorityPath) !== xauthorityPath
    || xauthorityMetadata.uid !== uid
    || xauthorityMetadata.gid !== gid
    || (xauthorityMetadata.mode & 0o7777) !== 0o600
    || xauthorityMetadata.nlink !== 1
    || xauthorityMetadata.size < 1
    || xauthorityMetadata.size > 65_536
  ) {
    throw runnerError('headed_xauthority_invalid', 'The exact Xauthority file is not a bounded owner-only regular file.');
  }
  try {
    socketMetadata = lstatPath(PLAYWRIGHT_CONTAINER_X11_SOCKET);
  } catch {
    throw runnerError('headed_x11_socket_unavailable', 'The exact :1 X11 socket is unavailable.');
  }
  if (
    !socketMetadata.isSocket()
    || socketMetadata.isSymbolicLink()
    || realpathPath(PLAYWRIGHT_CONTAINER_X11_SOCKET) !== PLAYWRIGHT_CONTAINER_X11_SOCKET
    || socketMetadata.uid !== uid
    || socketMetadata.gid !== gid
    || socketMetadata.nlink !== 1
  ) {
    throw runnerError('headed_x11_socket_invalid', 'The exact :1 X11 socket is not owned by the qualifying desktop user.');
  }
  return {
    mode: 'headed-real-x11',
    headed: true,
    display: PLAYWRIGHT_HEADED_DISPLAY,
    hostname: hostnameValue,
    xauthority: {
      host_path: xauthorityPath,
      container_path: PLAYWRIGHT_CONTAINER_XAUTHORITY,
      ...boundedStatIdentity(xauthorityMetadata),
      terminal_identity: null,
    },
    x11_socket: {
      host_path: PLAYWRIGHT_CONTAINER_X11_SOCKET,
      container_path: PLAYWRIGHT_CONTAINER_X11_SOCKET,
      ...boundedStatIdentity(socketMetadata),
      terminal_identity: null,
    },
    transport: null,
    preflight_verified: true,
    terminal_verified: null,
    verified: false,
    postflight_error_code: null,
  };
}

function sourceDesktopIdentity(evidence) {
  if (!evidence) return null;
  return {
    host_path: evidence.host_path,
    container_path: evidence.container_path,
    device: evidence.device,
    inode: evidence.inode,
    owner_uid: evidence.owner_uid,
    owner_gid: evidence.owner_gid,
    mode: evidence.mode,
    nlink: evidence.nlink,
    size_bytes: evidence.size_bytes,
  };
}

function desktopIdentityProjection(evidence) {
  return {
    mode: evidence.mode,
    headed: evidence.headed,
    display: evidence.display,
    hostname: evidence.hostname,
    xauthority: sourceDesktopIdentity(evidence.xauthority),
    x11_socket: sourceDesktopIdentity(evidence.x11_socket),
    preflight_verified: evidence.preflight_verified,
  };
}

export function sameLinuxHeadedDesktopEvidence(expected, observed) {
  return JSON.stringify(desktopIdentityProjection(expected))
    === JSON.stringify(desktopIdentityProjection(observed));
}

export function nativeHeadedDesktopEvidence({
  platform,
  environment = process.env,
} = {}) {
  if (!['darwin', 'win32'].includes(platform)) {
    throw runnerError('native_desktop_platform_invalid', 'Native foreground evidence is supported only on macOS and Windows.');
  }
  const headedValue = environment.KODESEC_PLAYWRIGHT_HEADED;
  if (headedValue !== undefined && headedValue !== '0' && headedValue !== '1') {
    throw runnerError('headed_mode_invalid', 'KODESEC_PLAYWRIGHT_HEADED must be exactly 0 or 1.');
  }
  const headed = headedValue === '1';
  return {
    mode: headed ? 'headed-native-foreground' : 'headless',
    headed,
    platform,
    presentation: headed ? 'native-window' : null,
    preflight_verified: true,
    terminal_verified: null,
    verified: false,
    postflight_error_code: null,
    launch_contract: {
      local_process: true,
      playwright_headless: !headed,
      exact_environment_value: headed ? '1' : '0',
    },
  };
}

export function terminalNativeHeadedDesktopEvidence(desktop, {
  controller,
  fullScopeExecuted,
  outcomePassed,
} = {}) {
  if (!desktop || !['darwin', 'win32'].includes(desktop.platform)) {
    throw runnerError('native_desktop_evidence_invalid', 'Native foreground evidence is malformed.');
  }
  if (!desktop.headed) {
    return {
      ...desktop,
      terminal_verified: true,
      verified: false,
      postflight_error_code: 'headed_not_requested',
    };
  }
  const verified = desktop.mode === 'headed-native-foreground'
    && desktop.preflight_verified === true
    && desktop.presentation === 'native-window'
    && desktop.launch_contract?.local_process === true
    && desktop.launch_contract?.playwright_headless === false
    && desktop.launch_contract?.exact_environment_value === '1'
    && controller?.exit_code === 0
    && controller?.signal === null
    && controller?.spawn_error === false
    && controller?.timed_out === false
    && controller?.reaped === true
    && fullScopeExecuted === true
    && outcomePassed === true;
  return {
    ...desktop,
    terminal_verified: verified,
    verified,
    postflight_error_code: verified ? null : 'native_foreground_unproven',
  };
}

function statIdentityMatches(metadata, expected) {
  const observed = boundedStatIdentity(metadata);
  return observed.device === expected?.device
    && observed.inode === expected?.inode
    && observed.owner_uid === expected?.owner_uid
    && observed.owner_gid === expected?.owner_gid
    && observed.mode === expected?.mode
    && observed.nlink === expected?.nlink
    && observed.size_bytes === expected?.size_bytes;
}

function exactRelayPaths(runId) {
  if (typeof runId !== 'string' || !/^[a-f0-9]{12}$/.test(runId)) {
    throw runnerError('headed_relay_run_id_invalid', 'Headed desktop relay requires one generated run identity.');
  }
  const resultsRoot = resolve(suiteDirectory, '.results');
  const relayDirectory = resolve(resultsRoot, `.x11-relay-${runId}`);
  return {
    resultsRoot,
    relayDirectory,
    xauthorityPath: resolve(relayDirectory, 'Xauthority'),
    x11SocketPath: resolve(relayDirectory, 'X1'),
  };
}

function validateRelayDirectory(path, uid, gid) {
  const metadata = lstatSync(path);
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || realpathSync(path) !== path
    || metadata.uid !== uid
    || metadata.gid !== gid
    || (metadata.mode & 0o7777) !== 0o700
  ) {
    throw runnerError('headed_relay_directory_invalid', 'The per-run X11 relay directory is not an owner-only real directory.');
  }
  return metadata;
}

function validateRelaySource(path, expected, kind) {
  const metadata = lstatSync(path);
  const validKind = kind === 'file' ? metadata.isFile() : metadata.isSocket();
  if (
    !validKind
    || metadata.isSymbolicLink()
    || realpathSync(path) !== path
    || !statIdentityMatches(metadata, expected)
  ) {
    throw runnerError(`headed_relay_${kind}_source_changed`, `The real desktop ${kind} identity changed before relay use.`);
  }
  return metadata;
}

async function receiveRelayConfiguration() {
  return new Promise((resolveConfiguration, rejectConfiguration) => {
    const timer = setTimeout(() => {
      rejectConfiguration(runnerError('headed_relay_configuration_timeout', 'The X11 relay did not receive its bounded configuration.'));
    }, X11_RELAY_READY_TIMEOUT_MS);
    process.once('message', (message) => {
      clearTimeout(timer);
      resolveConfiguration(message);
    });
  });
}

async function runInternalX11Relay() {
  let server = null;
  const connections = new Set();
  let stopping = false;
  let terminalCode = 0;
  const finish = (code) => {
    if (stopping) return;
    stopping = true;
    terminalCode = code;
    for (const connection of connections) connection.destroy();
    if (server?.listening) server.close();
  };
  try {
    const configuration = await receiveRelayConfiguration();
    if (
      configuration?.schema !== X11_RELAY_SCHEMA
      || !Number.isSafeInteger(configuration.owner_uid)
      || configuration.owner_uid <= 0
      || !Number.isSafeInteger(configuration.owner_gid)
      || configuration.owner_gid < 0
    ) {
      throw runnerError('headed_relay_configuration_invalid', 'The X11 relay configuration is invalid.');
    }
    const paths = exactRelayPaths(configuration.run_id);
    if (
      configuration.relay_directory !== paths.relayDirectory
      || configuration.xauthority_source !== configuration.xauthority_identity?.host_path
      || configuration.x11_socket_source !== PLAYWRIGHT_CONTAINER_X11_SOCKET
      || configuration.x11_socket_source !== configuration.x11_socket_identity?.host_path
    ) {
      throw runnerError('headed_relay_paths_invalid', 'The X11 relay paths differ from the exact per-run desktop contract.');
    }
    validateRelayDirectory(paths.relayDirectory, configuration.owner_uid, configuration.owner_gid);
    validateRelaySource(configuration.xauthority_source, configuration.xauthority_identity, 'file');
    validateRelaySource(configuration.x11_socket_source, configuration.x11_socket_identity, 'socket');
    if (existsSync(paths.xauthorityPath) || existsSync(paths.x11SocketPath)) {
      throw runnerError('headed_relay_target_exists', 'The generated X11 relay paths already exist.');
    }

    process.umask(0o077);
    const sourceDescriptor = openSync(
      configuration.xauthority_source,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
    );
    let authorityBytes;
    try {
      const openedMetadata = fstatSync(sourceDescriptor);
      if (!statIdentityMatches(openedMetadata, configuration.xauthority_identity)) {
        throw runnerError('headed_relay_file_source_changed', 'The owner Xauthority identity changed while it was opened.');
      }
      authorityBytes = readFileSync(sourceDescriptor);
    } finally {
      closeSync(sourceDescriptor);
    }
    const destinationDescriptor = openSync(
      paths.xauthorityPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW || 0),
      0o600,
    );
    try {
      writeFileSync(destinationDescriptor, authorityBytes);
    } finally {
      closeSync(destinationDescriptor);
    }
    chmodSync(paths.xauthorityPath, 0o600);
    const copiedBytes = readFileSync(paths.xauthorityPath);
    const copyMatches = authorityBytes.length === copiedBytes.length && authorityBytes.equals(copiedBytes);
    authorityBytes.fill(0);
    copiedBytes.fill(0);
    if (!copyMatches) {
      throw runnerError('headed_relay_xauthority_copy_invalid', 'The private Xauthority relay copy could not be verified.');
    }
    const copiedMetadata = lstatSync(paths.xauthorityPath);
    if (
      !copiedMetadata.isFile()
      || copiedMetadata.isSymbolicLink()
      || copiedMetadata.uid !== configuration.owner_uid
      || copiedMetadata.gid !== configuration.owner_gid
      || (copiedMetadata.mode & 0o7777) !== 0o600
      || copiedMetadata.nlink !== 1
      || copiedMetadata.size !== configuration.xauthority_identity.size_bytes
    ) {
      throw runnerError('headed_relay_xauthority_copy_invalid', 'The private Xauthority relay copy has an unsafe identity.');
    }

    server = createServer((client) => {
      try {
        validateRelaySource(configuration.x11_socket_source, configuration.x11_socket_identity, 'socket');
      } catch (error) {
        client.destroy();
        process.send?.({ type: 'failed', code: error.code || 'headed_relay_source_changed' });
        finish(1);
        return;
      }
      const upstream = createConnection({ path: configuration.x11_socket_source });
      connections.add(client);
      connections.add(upstream);
      const closePair = () => {
        connections.delete(client);
        connections.delete(upstream);
        client.destroy();
        upstream.destroy();
      };
      client.once('error', closePair);
      upstream.once('error', closePair);
      client.once('close', () => connections.delete(client));
      upstream.once('close', () => connections.delete(upstream));
      client.pipe(upstream);
      upstream.pipe(client);
    });
    await new Promise((resolveListening, rejectListening) => {
      const rejectInitialError = (error) => {
        rejectListening(runnerError(
          error?.code === 'EADDRINUSE' ? 'headed_relay_target_exists' : 'headed_relay_server_failed',
          'The per-run X11 relay could not listen on its exact private socket.',
        ));
      };
      server.once('error', rejectInitialError);
      server.listen(paths.x11SocketPath, () => {
        server.removeListener('error', rejectInitialError);
        try {
          chmodSync(paths.x11SocketPath, 0o600);
          const socketMetadata = lstatSync(paths.x11SocketPath);
          if (
            !socketMetadata.isSocket()
            || socketMetadata.isSymbolicLink()
            || socketMetadata.uid !== configuration.owner_uid
            || socketMetadata.gid !== configuration.owner_gid
            || (socketMetadata.mode & 0o7777) !== 0o600
            || socketMetadata.nlink !== 1
          ) {
            throw runnerError('headed_relay_socket_invalid', 'The per-run X11 relay socket has an unsafe identity.');
          }
          resolveListening({
            xauthority: boundedStatIdentity(copiedMetadata),
            x11_socket: boundedStatIdentity(socketMetadata),
          });
        } catch (error) {
          rejectListening(error);
        }
      });
    }).then((identities) => {
      process.send?.({
        type: 'ready',
        schema: X11_RELAY_SCHEMA,
        run_id: configuration.run_id,
        xauthority_path: paths.xauthorityPath,
        x11_socket_path: paths.x11SocketPath,
        identities,
      });
    });
    server.on('error', () => {
      process.send?.({ type: 'failed', code: 'headed_relay_server_failed' });
      finish(1);
    });

    await new Promise((resolveStop) => {
      const stop = () => {
        finish(0);
        resolveStop();
      };
      process.once('SIGTERM', stop);
      process.once('SIGINT', stop);
      server.once('close', resolveStop);
    });
  } catch (error) {
    terminalCode = 1;
    process.send?.({ type: 'failed', code: typeof error?.code === 'string' ? error.code : 'headed_relay_failed' });
    finish(1);
  }
  if (process.connected) process.disconnect();
  process.exitCode = terminalCode;
}

function relayIdentity(path, kind, uid, gid) {
  const metadata = lstatSync(path);
  const validKind = kind === 'directory'
    ? metadata.isDirectory()
    : kind === 'file'
      ? metadata.isFile()
      : metadata.isSocket();
  const requiredMode = kind === 'directory' ? 0o700 : 0o600;
  if (
    !validKind
    || metadata.isSymbolicLink()
    || realpathSync(path) !== path
    || metadata.uid !== uid
    || metadata.gid !== gid
    || (metadata.mode & 0o7777) !== requiredMode
    || (kind !== 'directory' && metadata.nlink !== 1)
  ) {
    throw runnerError(`headed_relay_${kind}_invalid`, `The private X11 relay ${kind} has an unsafe identity.`);
  }
  return boundedStatIdentity(metadata);
}

function createHeadedX11Transport(desktop, runId, uid, gid) {
  if (desktop?.headed !== true || desktop.transport !== null) {
    throw runnerError('headed_relay_desktop_invalid', 'The X11 relay requires one verified untransported headed desktop.');
  }
  const paths = exactRelayPaths(runId);
  if (!existsSync(paths.resultsRoot) || realpathSync(paths.resultsRoot) !== paths.resultsRoot) {
    throw runnerError('headed_relay_result_root_invalid', 'The X11 relay result root is unavailable or symlinked.');
  }
  mkdirSync(paths.relayDirectory, { mode: 0o700 });
  const directoryIdentity = relayIdentity(paths.relayDirectory, 'directory', uid, gid);
  const child = fork(fileURLToPath(import.meta.url), [INTERNAL_X11_RELAY_MODE], {
    cwd: suiteDirectory,
    env: { LANG: 'C', LC_ALL: 'C' },
    execArgv: [],
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
  });
  const receipt = {
    schema: X11_RELAY_SCHEMA,
    mode: 'owner-scoped-unix-relay',
    ready: false,
    relay_directory: {
      host_path: paths.relayDirectory,
      initial_identity: directoryIdentity,
      terminal_identity: null,
    },
    xauthority: null,
    x11_socket: null,
    source_identity_verified: false,
    terminal_identity_verified: null,
    terminal_error_code: null,
    child: {
      pid: Number.isSafeInteger(child.pid) ? child.pid : null,
      ready: false,
      exit_code: null,
      signal: null,
      unexpected_exit: false,
      error_code: null,
    },
    cleanup: {
      requested: false,
      xauthority_absent: null,
      x11_socket_absent: null,
      relay_directory_absent: null,
      verified: null,
      error_code: null,
    },
  };
  const state = {
    child,
    paths,
    uid,
    gid,
    receipt,
    stopRequested: false,
    relayFailureCode: null,
    exit: null,
  };
  state.exitPromise = new Promise((resolveExit) => {
    child.once('close', (exitCode, signal) => {
      state.exit = { exitCode, signal };
      receipt.child.exit_code = Number.isInteger(exitCode) ? exitCode : null;
      receipt.child.signal = typeof signal === 'string' ? signal : null;
      receipt.child.unexpected_exit = !state.stopRequested;
      resolveExit(state.exit);
    });
  });
  state.readyPromise = new Promise((resolveReady, rejectReady) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeListener('error', onError);
      if (error) rejectReady(error);
      else resolveReady(state);
    };
    const onError = () => finish(runnerError('headed_relay_spawn_failed', 'The private X11 relay child could not start.'));
    const timer = setTimeout(() => {
      finish(runnerError('headed_relay_ready_timeout', 'The private X11 relay did not become ready in time.'));
    }, X11_RELAY_READY_TIMEOUT_MS);
    child.once('error', onError);
    child.on('message', (message) => {
      if (message?.type === 'failed') {
        state.relayFailureCode = typeof message.code === 'string' ? message.code : 'headed_relay_failed';
        receipt.child.error_code = state.relayFailureCode;
        if (!receipt.ready) finish(runnerError(state.relayFailureCode, 'The private X11 relay failed closed.'));
        return;
      }
      if (message?.type !== 'ready' || settled) return;
      try {
        if (
          message.schema !== X11_RELAY_SCHEMA
          || message.run_id !== runId
          || message.xauthority_path !== paths.xauthorityPath
          || message.x11_socket_path !== paths.x11SocketPath
        ) {
          throw runnerError('headed_relay_ready_invalid', 'The X11 relay returned an invalid ready identity.');
        }
        const xauthorityIdentity = relayIdentity(paths.xauthorityPath, 'file', uid, gid);
        const x11SocketIdentity = relayIdentity(paths.x11SocketPath, 'socket', uid, gid);
        if (
          JSON.stringify(message.identities?.xauthority) !== JSON.stringify(xauthorityIdentity)
          || JSON.stringify(message.identities?.x11_socket) !== JSON.stringify(x11SocketIdentity)
          || xauthorityIdentity.size_bytes !== desktop.xauthority.size_bytes
        ) {
          throw runnerError('headed_relay_ready_invalid', 'The X11 relay ready identity differs from its private filesystem objects.');
        }
        receipt.xauthority = {
          host_path: paths.xauthorityPath,
          container_path: PLAYWRIGHT_CONTAINER_XAUTHORITY,
          initial_identity: xauthorityIdentity,
          terminal_identity: null,
        };
        receipt.x11_socket = {
          host_path: paths.x11SocketPath,
          container_path: PLAYWRIGHT_CONTAINER_X11_SOCKET,
          initial_identity: x11SocketIdentity,
          terminal_identity: null,
        };
        receipt.ready = true;
        receipt.source_identity_verified = true;
        receipt.child.ready = true;
        finish(null);
      } catch (error) {
        finish(error);
      }
    });
    child.send({
      schema: X11_RELAY_SCHEMA,
      run_id: runId,
      relay_directory: paths.relayDirectory,
      owner_uid: uid,
      owner_gid: gid,
      xauthority_source: desktop.xauthority.host_path,
      xauthority_identity: desktop.xauthority,
      x11_socket_source: desktop.x11_socket.host_path,
      x11_socket_identity: desktop.x11_socket,
    }, (error) => {
      if (error) finish(runnerError('headed_relay_configuration_failed', 'The private X11 relay configuration could not be delivered.'));
    });
  });
  return state;
}

function assertHeadedX11TransportRunning(state) {
  if (
    !state
    || state.receipt.ready !== true
    || state.receipt.child.ready !== true
    || state.relayFailureCode
    || state.child.exitCode !== null
    || state.child.signalCode !== null
  ) {
    throw runnerError(
      state?.relayFailureCode || 'headed_relay_not_running',
      'The private X11 relay is not running with its verified ready identity.',
    );
  }
}

function verifyHeadedX11TransportIdentity(state) {
  assertHeadedX11TransportRunning(state);
  const directoryIdentity = relayIdentity(state.paths.relayDirectory, 'directory', state.uid, state.gid);
  const xauthorityIdentity = relayIdentity(state.paths.xauthorityPath, 'file', state.uid, state.gid);
  const x11SocketIdentity = relayIdentity(state.paths.x11SocketPath, 'socket', state.uid, state.gid);
  if (
    directoryIdentity.device !== state.receipt.relay_directory.initial_identity.device
    || directoryIdentity.inode !== state.receipt.relay_directory.initial_identity.inode
    || JSON.stringify(xauthorityIdentity) !== JSON.stringify(state.receipt.xauthority.initial_identity)
    || JSON.stringify(x11SocketIdentity) !== JSON.stringify(state.receipt.x11_socket.initial_identity)
  ) {
    throw runnerError('headed_relay_identity_changed', 'The private X11 relay identity changed during Playwright execution.');
  }
  state.receipt.relay_directory.terminal_identity = directoryIdentity;
  state.receipt.xauthority.terminal_identity = xauthorityIdentity;
  state.receipt.x11_socket.terminal_identity = x11SocketIdentity;
  state.receipt.terminal_identity_verified = true;
  state.receipt.terminal_error_code = null;
}

async function stopAndCleanHeadedX11Transport(state) {
  if (!state) return;
  state.stopRequested = true;
  state.receipt.cleanup.requested = true;
  if (!state.exit && state.child.exitCode === null && state.child.signalCode === null) {
    state.child.kill('SIGTERM');
  }
  if (!state.exit) {
    let stopTimer;
    await Promise.race([
      state.exitPromise,
      new Promise((resolveTimeout) => {
        stopTimer = setTimeout(resolveTimeout, X11_RELAY_STOP_TIMEOUT_MS);
      }),
    ]);
    clearTimeout(stopTimer);
  }
  if (!state.exit && state.child.exitCode === null && state.child.signalCode === null) {
    state.child.kill('SIGKILL');
    await state.exitPromise;
  }
  try {
    const directoryIdentity = relayIdentity(state.paths.relayDirectory, 'directory', state.uid, state.gid);
    if (
      directoryIdentity.device !== state.receipt.relay_directory.initial_identity.device
      || directoryIdentity.inode !== state.receipt.relay_directory.initial_identity.inode
    ) {
      throw runnerError('headed_relay_cleanup_identity_changed', 'The private X11 relay directory changed before cleanup.');
    }
    for (const [path, evidence] of [
      [state.paths.x11SocketPath, state.receipt.x11_socket],
      [state.paths.xauthorityPath, state.receipt.xauthority],
    ]) {
      if (!existsSync(path)) continue;
      const kind = path === state.paths.x11SocketPath ? 'socket' : 'file';
      const identity = relayIdentity(path, kind, state.uid, state.gid);
      if (evidence?.initial_identity && JSON.stringify(identity) !== JSON.stringify(evidence.initial_identity)) {
        throw runnerError('headed_relay_cleanup_identity_changed', 'A private X11 relay object changed before cleanup.');
      }
      unlinkSync(path);
    }
    rmdirSync(state.paths.relayDirectory);
    state.receipt.cleanup.xauthority_absent = !existsSync(state.paths.xauthorityPath);
    state.receipt.cleanup.x11_socket_absent = !existsSync(state.paths.x11SocketPath);
    state.receipt.cleanup.relay_directory_absent = !existsSync(state.paths.relayDirectory);
    state.receipt.cleanup.verified = state.receipt.cleanup.xauthority_absent
      && state.receipt.cleanup.x11_socket_absent
      && state.receipt.cleanup.relay_directory_absent;
    state.receipt.cleanup.error_code = state.receipt.cleanup.verified ? null : 'headed_relay_cleanup_unproven';
  } catch (error) {
    state.receipt.cleanup.xauthority_absent = !existsSync(state.paths.xauthorityPath);
    state.receipt.cleanup.x11_socket_absent = !existsSync(state.paths.x11SocketPath);
    state.receipt.cleanup.relay_directory_absent = !existsSync(state.paths.relayDirectory);
    state.receipt.cleanup.verified = false;
    state.receipt.cleanup.error_code = typeof error?.code === 'string' ? error.code : 'headed_relay_cleanup_unproven';
  }
}

function run(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: options.cwd || suiteDirectory,
    env: options.env || process.env,
    encoding: 'utf8',
    stdio: options.quiet ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    timeout: options.timeout || 30_000,
  });
  if (result.error && !options.allowFailure) {
    throw runnerError(options.errorCode || 'command_spawn_failed', `${options.label || program} could not be started.`);
  }
  if (result.status !== 0 && !options.allowFailure) {
    throw runnerError(options.errorCode || 'command_failed', `${options.label || program} failed with a nonzero status.`);
  }
  return result;
}

function pathIsWithin(parent, candidate) {
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

function ensureSafeDirectory(path, { create = false, platform = process.platform } = {}) {
  if (!existsSync(path)) {
    if (!create) throw runnerError('result_parent_missing', 'Offline Playwright result parent is missing.');
    mkdirSync(path, { mode: 0o700 });
  }
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || !sameResolvedPath(realpathSync(path), path, platform)) {
    throw runnerError('unsafe_result_directory', 'Offline Playwright result directories must be real, non-symlinked directories.');
  }
}

export function createLocalResultDirectory({
  suiteRoot = suiteDirectory,
  mode = invocation.mode,
  platform = process.platform,
  runIdFactory = () => randomBytes(6).toString('hex'),
} = {}) {
  const resolvedSuite = resolve(suiteRoot);
  ensureSafeDirectory(resolvedSuite, { platform });
  const resultsRoot = resolve(resolvedSuite, '.results');
  const modeRoot = resolve(resultsRoot, mode === 'snapshot-update' ? 'offline-update' : 'offline');
  ensureSafeDirectory(resultsRoot, { create: true, platform });
  ensureSafeDirectory(modeRoot, { create: true, platform });
  if (!pathIsWithin(resolvedSuite, resultsRoot) || !pathIsWithin(resultsRoot, modeRoot)) {
    throw runnerError('unsafe_result_directory', 'Offline Playwright result paths escaped the suite result root.');
  }
  for (let attempt = 0; attempt < LOCAL_RESULT_DIRECTORY_ATTEMPTS; attempt += 1) {
    const runId = runIdFactory();
    if (typeof runId !== 'string' || !/^[a-f0-9]{12}$/.test(runId)) {
      throw runnerError('invalid_run_id', 'Offline Playwright run identities must be exactly twelve lowercase hexadecimal characters.');
    }
    const resultDirectory = resolve(modeRoot, runId);
    if (!pathIsWithin(modeRoot, resultDirectory)) {
      throw runnerError('unsafe_result_directory', 'Offline Playwright result paths escaped the generated run root.');
    }
    try {
      mkdirSync(resultDirectory, { mode: 0o700 });
    } catch (error) {
      if (error?.code === 'EEXIST') continue;
      throw error;
    }
    if (!sameResolvedPath(realpathSync(resultDirectory), resultDirectory, platform)) {
      throw runnerError('unsafe_result_directory', 'Offline Playwright run results must not resolve through a symlink.');
    }
    return { runId, resultsRoot, resultDirectory };
  }
  throw runnerError('run_id_collision_budget_exhausted', 'Could not allocate a unique offline Playwright result directory.');
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function boundedDirectoryManifest(root) {
  const entries = [];
  const pending = [''];
  let totalBytes = 0;
  while (pending.length > 0) {
    const relativeDirectory = pending.pop();
    const absoluteDirectory = relativeDirectory ? join(root, relativeDirectory) : root;
    for (const entry of readdirSync(absoluteDirectory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
      if (/[,\0\r\n]/.test(entry.name)) {
        throw runnerError('candidate_manifest_unsafe_name', 'Candidate evidence contains an unsafe filename.');
      }
      const relativePath = relativeDirectory ? join(relativeDirectory, entry.name) : entry.name;
      const absolutePath = join(root, relativePath);
      const metadata = lstatSync(absolutePath);
      if (metadata.isSymbolicLink()) {
        throw runnerError('candidate_manifest_symlink', 'Candidate evidence trees may not contain symlinks.');
      }
      if (metadata.isDirectory()) {
        pending.push(relativePath);
        continue;
      }
      if (!metadata.isFile()) {
        throw runnerError('candidate_manifest_special_file', 'Candidate evidence trees may contain only directories and regular files.');
      }
      totalBytes += metadata.size;
      if (entries.length >= MAX_EVIDENCE_MANIFEST_FILES || totalBytes > MAX_EVIDENCE_MANIFEST_BYTES) {
        throw runnerError('candidate_manifest_too_large', 'Candidate evidence tree exceeds its bounded manifest budget.');
      }
      entries.push({
        path: relativePath.split(sep).join('/'),
        size_bytes: metadata.size,
        sha256: sha256File(absolutePath),
      });
    }
  }
  entries.sort((left, right) => left.path.localeCompare(right.path));
  const digest = createHash('sha256');
  for (const entry of entries) digest.update(`${entry.path}\0${entry.size_bytes}\0${entry.sha256}\n`);
  return {
    sha256: digest.digest('hex'),
    file_count: entries.length,
    total_bytes: totalBytes,
  };
}

function candidateEvidence({
  suiteRoot = suiteDirectory,
  scriptRoot = scriptDirectory,
  webDistRoot = webDistDirectory,
} = {}) {
  const runnerFiles = {
    offline_runner_sha256: sha256File(resolve(scriptRoot, 'offline-playwright.mjs')),
    harness_library_sha256: sha256File(resolve(scriptRoot, 'compose-harness-lib.mjs')),
    playwright_wrapper_sha256: sha256File(resolve(scriptRoot, 'playwright.mjs')),
    playwright_config_sha256: sha256File(resolve(suiteRoot, 'playwright.config.ts')),
    package_manifest_sha256: sha256File(resolve(suiteRoot, 'package.json')),
    package_lock_sha256: sha256File(resolve(suiteRoot, 'package-lock.json')),
    fixture_server_sha256: sha256File(resolve(suiteRoot, 'server.mjs')),
    fixture_server_launcher_sha256: sha256File(resolve(scriptRoot, 'server-launcher.mjs')),
  };
  return {
    runner_files: runnerFiles,
    test_tree: boundedDirectoryManifest(resolve(suiteRoot, 'tests')),
    web_distribution: boundedDirectoryManifest(webDistRoot),
  };
}

export function expectedPlatformBaselinePaths(platform, { headed = true } = {}) {
  if (!['darwin', 'linux', 'win32'].includes(platform)) {
    throw runnerError('unsupported_baseline_platform', 'Playwright visual evidence requires one supported platform suffix.');
  }
  if (typeof headed !== 'boolean') throw runnerError('baseline_mode_invalid', 'Visual baseline mode must be explicit.');
  const suffix = platform === 'darwin' && !headed ? `${platform}-headless` : platform;
  const paths = [];
  for (const route of PLAYWRIGHT_VISUAL_BASELINE_ROUTES) {
    for (const project of PLAYWRIGHT_ALLOWED_PROJECTS) {
      paths.push(`${route}-${project}-${suffix}.png`);
    }
  }
  return paths.sort();
}

export function platformBaselineEvidence({ suiteRoot = suiteDirectory, platform = process.platform, headed = true } = {}) {
  const baselineDirectory = resolve(suiteRoot, 'tests', '__screenshots__', 'foundation.spec.ts');
  if (!existsSync(baselineDirectory)) {
    throw runnerError('platform_baseline_missing', 'The reviewed platform visual baseline directory is missing.');
  }
  const metadata = lstatSync(baselineDirectory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || !sameResolvedPath(realpathSync(baselineDirectory), baselineDirectory, platform)) {
    throw runnerError('platform_baseline_unsafe', 'The reviewed platform visual baseline directory must be real and non-symlinked.');
  }
  const expectedPaths = expectedPlatformBaselinePaths(platform, { headed });
  const suffix = platform === 'darwin' && !headed ? `${platform}-headless` : platform;
  const expectedSet = new Set(expectedPaths);
  const actualPlatformPaths = readdirSync(baselineDirectory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(`-${suffix}.png`))
    .map((entry) => entry.name)
    .sort();
  if (JSON.stringify(actualPlatformPaths) !== JSON.stringify(expectedPaths)) {
    throw runnerError('platform_baseline_incomplete', 'The reviewed platform visual baseline does not match the exact qualification surface.');
  }
  const entries = [];
  let totalBytes = 0;
  for (const relativePath of expectedPaths) {
    if (!expectedSet.has(relativePath) || /[\0\r\n]/.test(relativePath)) {
      throw runnerError('platform_baseline_unsafe_name', 'The reviewed platform visual baseline contains an unsafe name.');
    }
    const absolutePath = resolve(baselineDirectory, relativePath);
    if (!pathIsWithin(baselineDirectory, absolutePath)) {
      throw runnerError('platform_baseline_path_escape', 'The reviewed platform visual baseline escaped its expected directory.');
    }
    const fileMetadata = lstatSync(absolutePath);
    if (!fileMetadata.isFile() || fileMetadata.isSymbolicLink() || fileMetadata.size <= PNG_SIGNATURE.length) {
      throw runnerError('platform_baseline_invalid_file', 'Each reviewed platform visual baseline must be a non-empty regular PNG file.');
    }
    const signature = readFileSync(absolutePath).subarray(0, PNG_SIGNATURE.length);
    if (!signature.equals(PNG_SIGNATURE)) {
      throw runnerError('platform_baseline_invalid_png', 'Each reviewed platform visual baseline must have a PNG signature.');
    }
    totalBytes += fileMetadata.size;
    if (totalBytes > MAX_EVIDENCE_MANIFEST_BYTES) {
      throw runnerError('platform_baseline_too_large', 'The reviewed platform visual baseline exceeds its evidence budget.');
    }
    entries.push({ path: relativePath, size_bytes: fileMetadata.size, sha256: sha256File(absolutePath) });
  }
  const digest = createHash('sha256');
  for (const entry of entries) digest.update(`${entry.path}\0${entry.size_bytes}\0${entry.sha256}\n`);
  const pathDigest = createHash('sha256').update(`${expectedPaths.join('\n')}\n`).digest('hex');
  return {
    platform_suffix: platform,
    ...(platform === 'darwin' ? { rendering_mode: headed ? 'headed' : 'headless' } : {}),
    expected_paths_sha256: pathDigest,
    sha256: digest.digest('hex'),
    file_count: entries.length,
    total_bytes: totalBytes,
    complete: true,
  };
}

function dependencyRelativePath(suiteRoot, path) {
  if (!pathIsWithin(suiteRoot, path)) {
    throw runnerError('playwright_dependency_path_escape', 'Locked Playwright dependency evidence escaped the suite root.');
  }
  return relative(suiteRoot, path).split(sep).join('/');
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function verifiedRegularFileEvidence(path, {
  suiteRoot,
  containmentRoot = null,
  platform,
  missingCode,
  maximumBytes,
  capture = false,
  executable = false,
} = {}) {
  if (containmentRoot && !pathIsWithin(containmentRoot, path)) {
    throw runnerError('playwright_dependency_path_escape', 'Locked Playwright dependency evidence escaped its owned root.');
  }
  let before;
  try {
    before = lstatSync(path, { bigint: true });
  } catch {
    throw runnerError(missingCode, 'Locked local Playwright dependency evidence is incomplete.');
  }
  if (
    !before.isFile()
    || before.isSymbolicLink()
    || before.size <= 0n
    || before.size > BigInt(maximumBytes)
    || (executable && platform !== 'win32' && (before.mode & 0o111n) === 0n)
  ) {
    throw runnerError(
      executable ? 'playwright_browser_executable_unsafe' : 'playwright_dependency_file_unsafe',
      'Locked local Playwright dependency evidence must use bounded regular files.',
    );
  }
  let realPath;
  try {
    realPath = realpathSync(path);
  } catch {
    throw runnerError(
      executable ? 'playwright_browser_executable_unsafe' : 'playwright_dependency_file_unsafe',
      'Locked local Playwright dependency evidence must resolve safely.',
    );
  }
  if (!sameResolvedPath(realPath, path, platform)) {
    throw runnerError(
      executable ? 'playwright_browser_executable_unsafe' : 'playwright_dependency_file_unsafe',
      'Locked local Playwright dependency evidence must not resolve through symlinks.',
    );
  }
  const relativePath = dependencyRelativePath(suiteRoot, path);
  let descriptor;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0));
  } catch {
    throw runnerError(
      executable ? 'playwright_browser_executable_unsafe' : 'playwright_dependency_file_unsafe',
      'Locked local Playwright dependency evidence could not be opened without following links.',
    );
  }
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || !sameFileIdentity(before, opened)) {
      throw runnerError(
        executable ? 'playwright_browser_executable_unsafe' : 'playwright_dependency_file_unsafe',
        'Locked local Playwright dependency identity changed before inspection.',
      );
    }
    const digest = createHash('sha256');
    const chunks = capture ? [] : null;
    const buffer = Buffer.allocUnsafe(Math.min(FILE_HASH_BUFFER_BYTES, Number(opened.size)));
    let totalBytes = 0;
    while (true) {
      const bytesRead = readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      const chunk = buffer.subarray(0, bytesRead);
      digest.update(chunk);
      if (chunks) chunks.push(Buffer.from(chunk));
      totalBytes += bytesRead;
      if (totalBytes > maximumBytes) {
        throw runnerError(
          executable ? 'playwright_browser_executable_unsafe' : 'playwright_dependency_file_unsafe',
          'Locked local Playwright dependency evidence exceeded its inspection bound.',
        );
      }
    }
    const afterDescriptor = fstatSync(descriptor, { bigint: true });
    let afterPath;
    try {
      afterPath = lstatSync(path, { bigint: true });
    } catch {
      throw runnerError(
        executable ? 'playwright_browser_executable_unsafe' : 'playwright_dependency_file_unsafe',
        'Locked local Playwright dependency identity disappeared during inspection.',
      );
    }
    if (
      BigInt(totalBytes) !== opened.size
      || !sameFileIdentity(opened, afterDescriptor)
      || !sameFileIdentity(opened, afterPath)
      || afterPath.isSymbolicLink()
    ) {
      throw runnerError(
        executable ? 'playwright_browser_executable_unsafe' : 'playwright_dependency_file_unsafe',
        'Locked local Playwright dependency identity changed during inspection.',
      );
    }
    const evidence = {
      path: relativePath,
      size_bytes: totalBytes,
      sha256: digest.digest('hex'),
    };
    if (chunks) evidence.contents = Buffer.concat(chunks, totalBytes);
    return evidence;
  } finally {
    closeSync(descriptor);
  }
}

function verifiedJsonEvidence(path, options) {
  const evidence = verifiedRegularFileEvidence(path, {
    ...options,
    maximumBytes: MAX_DEPENDENCY_METADATA_BYTES,
    capture: true,
  });
  let value;
  try {
    value = JSON.parse(evidence.contents.toString('utf8'));
  } catch {
    throw runnerError('playwright_dependency_json_invalid', 'Locked Playwright dependency metadata is malformed.');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw runnerError('playwright_dependency_json_invalid', 'Locked Playwright dependency metadata must be a JSON object.');
  }
  return { ...evidence, contents: undefined, value };
}

function requireSafeDependencyDirectory(path, { suiteRoot, platform, missingCode }) {
  let metadata;
  try {
    metadata = lstatSync(path);
  } catch {
    throw runnerError(missingCode, 'Locked local Playwright dependency directories are incomplete.');
  }
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || !sameResolvedPath(realpathSync(path), path, platform)
  ) {
    throw runnerError('playwright_dependencies_symlinked', 'Locked Playwright dependency directories must be real and non-symlinked.');
  }
  dependencyRelativePath(suiteRoot, path);
}

function resolveManifestFrom(requestPath, packageName, code, platform) {
  const specifier = `${packageName}/package.json`;
  const resolver = createRequire(requestPath);
  let resolvedManifest;
  try {
    resolvedManifest = resolve(resolver.resolve(specifier));
  } catch {
    throw runnerError(code, 'Node could not resolve one exact locked Playwright dependency.');
  }
  const searchPaths = resolver.resolve.paths(specifier);
  if (!Array.isArray(searchPaths)) {
    throw runnerError(code, 'Node did not expose the exact locked Playwright resolution path.');
  }
  let logicalManifest = null;
  for (const searchPath of searchPaths) {
    const candidate = resolve(searchPath, packageName, 'package.json');
    try {
      lstatSync(candidate);
      logicalManifest = candidate;
      break;
    } catch {
      // Node continues to the next package search root when this candidate is absent.
    }
  }
  if (!logicalManifest) {
    throw runnerError(code, 'Node did not expose the logical locked Playwright package path.');
  }
  let logicalRealPath;
  try {
    logicalRealPath = realpathSync(logicalManifest);
  } catch {
    throw runnerError(code, 'The logical locked Playwright package path could not be resolved safely.');
  }
  if (
    !sameResolvedPath(logicalRealPath, logicalManifest, platform)
    || !sameResolvedPath(logicalRealPath, resolvedManifest, platform)
  ) {
    throw runnerError('playwright_dependencies_symlinked', 'Node-resolved Playwright packages must not traverse symlinks.');
  }
  return resolvedManifest;
}

function exactBrowserRegistryEntry(registry, name) {
  if (!Array.isArray(registry.browsers)) {
    throw runnerError('playwright_browser_registry_invalid', 'The exact Playwright browser registry is malformed.');
  }
  const matches = registry.browsers.filter((entry) => entry?.name === name);
  if (matches.length !== 1) {
    throw runnerError('playwright_browser_registry_invalid', 'The exact Playwright browser registry must contain one required Chromium identity.');
  }
  const [entry] = matches;
  if (
    !/^\d+$/.test(entry.revision || '')
    || typeof entry.browserVersion !== 'string'
    || entry.browserVersion.length === 0
    || /[\0\r\n]/.test(entry.browserVersion)
    || entry.installByDefault !== true
  ) {
    throw runnerError('playwright_browser_registry_invalid', 'The exact Playwright Chromium registry identity is invalid.');
  }
  return { revision: entry.revision, browser_version: entry.browserVersion };
}

function localBrowserExecutableTokens(platform, architecture) {
  const platformPaths = LOCAL_BROWSER_EXECUTABLE_PATHS[platform];
  const architecturePaths = platformPaths?.[architecture];
  if (!architecturePaths) {
    throw runnerError('playwright_browser_platform_unsupported', 'The local locked browser executable platform is unsupported.');
  }
  return architecturePaths;
}

export function playwrightDependencyGraphEvidence({
  suiteRoot = suiteDirectory,
  platform = process.platform,
} = {}) {
  const resolvedSuiteRoot = resolve(suiteRoot);
  if (!sameResolvedPath(realpathSync(resolvedSuiteRoot), resolvedSuiteRoot, platform)) {
    throw runnerError('playwright_dependencies_symlinked', 'The local Playwright suite root must not resolve through a symlink.');
  }
  const nodeModulesDirectory = resolve(resolvedSuiteRoot, 'node_modules');
  const cliPath = resolve(nodeModulesDirectory, '@playwright', 'test', 'cli.js');
  const installedManifestPath = resolve(nodeModulesDirectory, '@playwright', 'test', 'package.json');
  const installedLockPath = resolve(nodeModulesDirectory, '.package-lock.json');
  const repositoryManifestPath = resolve(resolvedSuiteRoot, 'package.json');
  const repositoryLockPath = resolve(resolvedSuiteRoot, 'package-lock.json');
  requireSafeDependencyDirectory(nodeModulesDirectory, {
    suiteRoot: resolvedSuiteRoot,
    platform,
    missingCode: 'playwright_dependencies_missing',
  });
  const cliEvidence = verifiedRegularFileEvidence(cliPath, {
    suiteRoot: resolvedSuiteRoot,
    containmentRoot: nodeModulesDirectory,
    platform,
    missingCode: 'playwright_dependencies_missing',
    maximumBytes: MAX_DEPENDENCY_METADATA_BYTES,
  });
  const repositoryManifest = verifiedJsonEvidence(repositoryManifestPath, {
    suiteRoot: resolvedSuiteRoot,
    platform,
    missingCode: 'playwright_dependencies_missing',
  });
  const repositoryLock = verifiedRegularFileEvidence(repositoryLockPath, {
    suiteRoot: resolvedSuiteRoot,
    platform,
    missingCode: 'playwright_dependencies_missing',
    maximumBytes: MAX_DEPENDENCY_METADATA_BYTES,
  });
  const installedManifest = verifiedJsonEvidence(installedManifestPath, {
    suiteRoot: resolvedSuiteRoot,
    containmentRoot: nodeModulesDirectory,
    platform,
    missingCode: 'playwright_dependencies_missing',
  });
  const installedLock = verifiedRegularFileEvidence(installedLockPath, {
    suiteRoot: resolvedSuiteRoot,
    containmentRoot: nodeModulesDirectory,
    platform,
    missingCode: 'playwright_installed_lock_missing',
    maximumBytes: MAX_DEPENDENCY_METADATA_BYTES,
  });
  const playwrightManifestPath = resolveManifestFrom(
    cliPath,
    'playwright',
    'playwright_package_resolution_failed',
    platform,
  );
  const playwrightManifest = verifiedJsonEvidence(playwrightManifestPath, {
    suiteRoot: resolvedSuiteRoot,
    containmentRoot: nodeModulesDirectory,
    platform,
    missingCode: 'playwright_dependencies_missing',
  });
  const playwrightCoreManifestPath = resolveManifestFrom(
    playwrightManifestPath,
    'playwright-core',
    'playwright_core_resolution_failed',
    platform,
  );
  const playwrightCoreManifest = verifiedJsonEvidence(playwrightCoreManifestPath, {
    suiteRoot: resolvedSuiteRoot,
    containmentRoot: nodeModulesDirectory,
    platform,
    missingCode: 'playwright_dependencies_missing',
  });
  const browserRegistryPath = resolve(dirname(playwrightCoreManifestPath), 'browsers.json');
  const browserRegistry = verifiedJsonEvidence(browserRegistryPath, {
    suiteRoot: resolvedSuiteRoot,
    containmentRoot: nodeModulesDirectory,
    platform,
    missingCode: 'playwright_browser_registry_missing',
  });
  const expectedTestVersion = repositoryManifest.value.devDependencies?.['@playwright/test'];
  const expectedPlaywrightVersion = installedManifest.value.dependencies?.playwright;
  const expectedCoreVersion = playwrightManifest.value.dependencies?.['playwright-core'];
  if (
    installedManifest.value.name !== '@playwright/test'
    || playwrightManifest.value.name !== 'playwright'
    || playwrightCoreManifest.value.name !== 'playwright-core'
    || typeof expectedTestVersion !== 'string'
    || expectedTestVersion !== installedManifest.value.version
    || expectedPlaywrightVersion !== playwrightManifest.value.version
    || expectedCoreVersion !== playwrightCoreManifest.value.version
    || installedManifest.value.version !== playwrightManifest.value.version
    || playwrightManifest.value.version !== playwrightCoreManifest.value.version
  ) {
    throw runnerError('playwright_dependency_version_mismatch', 'The resolved Playwright dependency chain does not match its exact declared versions.');
  }
  const chromiumRegistry = exactBrowserRegistryEntry(browserRegistry.value, 'chromium');
  const headlessRegistry = exactBrowserRegistryEntry(browserRegistry.value, 'chromium-headless-shell');
  return {
    package_lock_sha256: repositoryLock.sha256,
    installed_lock_sha256: installedLock.sha256,
    playwright_cli: cliEvidence,
    playwright_test_manifest_path: installedManifest.path,
    playwright_test_manifest_sha256: installedManifest.sha256,
    playwright_test_version: installedManifest.value.version,
    playwright_package_path: playwrightManifest.path,
    playwright_package_manifest_sha256: playwrightManifest.sha256,
    playwright_package_version: playwrightManifest.value.version,
    playwright_core_version: playwrightCoreManifest.value.version,
    playwright_core_package_path: playwrightCoreManifest.path,
    playwright_core_package_manifest_sha256: playwrightCoreManifest.sha256,
    browser_registry_path: browserRegistry.path,
    browser_registry_sha256: browserRegistry.sha256,
    chromium: {
      registry_revision: chromiumRegistry.revision,
      browser_version: chromiumRegistry.browser_version,
    },
    chromium_headless_shell: {
      registry_revision: headlessRegistry.revision,
      browser_version: headlessRegistry.browser_version,
    },
  };
}

export function localDependencyEvidence({
  suiteRoot = suiteDirectory,
  platform = process.platform,
  architecture = arch(),
} = {}) {
  const resolvedSuiteRoot = resolve(suiteRoot);
  const graphEvidence = playwrightDependencyGraphEvidence({
    suiteRoot: resolvedSuiteRoot,
    platform,
  });
  const browserCacheDirectory = resolve(resolvedSuiteRoot, '.browsers');
  const executableTokens = localBrowserExecutableTokens(platform, architecture);
  requireSafeDependencyDirectory(browserCacheDirectory, {
    suiteRoot: resolvedSuiteRoot,
    platform,
    missingCode: 'playwright_browser_cache_missing',
  });
  const browserEvidence = {};
  for (const [name, registryEntry] of [
    ['chromium', graphEvidence.chromium],
    ['chromium-headless-shell', graphEvidence.chromium_headless_shell],
  ]) {
    const installedDirectory = `${name.replaceAll('-', '_')}-${registryEntry.registry_revision}`;
    const executablePath = resolve(browserCacheDirectory, installedDirectory, ...executableTokens[name]);
    browserEvidence[name] = {
      ...registryEntry,
      executable: verifiedRegularFileEvidence(executablePath, {
        suiteRoot: resolvedSuiteRoot,
        containmentRoot: browserCacheDirectory,
        platform,
        missingCode: 'playwright_browser_executable_missing',
        maximumBytes: MAX_LOCAL_BROWSER_EXECUTABLE_BYTES,
        executable: true,
      }),
    };
  }
  return {
    ...graphEvidence,
    browser_cache_path: dependencyRelativePath(resolvedSuiteRoot, browserCacheDirectory),
    browser_selection_claim: 'both-installed-candidates-verified-no-runtime-selection-claim',
    chromium: browserEvidence.chromium,
    chromium_headless_shell: browserEvidence['chromium-headless-shell'],
  };
}

function readExecutionReport(path, scope) {
  if (!existsSync(path)) return null;
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw runnerError('execution_report_not_regular', 'Playwright execution report is not a regular file.');
  }
  if (metadata.size <= 0 || metadata.size > MAX_EXECUTION_REPORT_BYTES) {
    throw runnerError('execution_report_size_invalid', 'Playwright execution report is empty or exceeds its evidence budget.');
  }
  try {
    return summarizePlaywrightJsonReport(JSON.parse(readFileSync(path, 'utf8')), {
      allowedSpecs: scope.specs, allowedProjects: scope.projects,
    });
  } catch (error) {
    if (typeof error?.code === 'string') throw error;
    throw runnerError('execution_report_invalid', 'Playwright execution report is malformed.');
  }
}

function publishNormalizedExecutionReport(resultDirectory, runInvocation = invocation) {
  const rawPath = resolve(resultDirectory, PLAYWRIGHT_RAW_EXECUTION_REPORT);
  const retainedPath = resolve(resultDirectory, PLAYWRIGHT_EXECUTION_REPORT);
  try {
    return publishPlaywrightExecutionReport({
      rawPath,
      retainedPath,
      scope: { allowedSpecs: runInvocation.scope.specs, allowedProjects: runInvocation.scope.projects },
    });
  } catch (error) {
    throw runnerError(
      typeof error?.code === 'string' ? error.code : 'execution_report_invalid',
      'Raw Playwright execution evidence is malformed or outside the repository contract.',
    );
  }
}

function boundedFailureArtifactInventory(artifactsDirectory) {
  if (!existsSync(artifactsDirectory)) {
    return { directory_present: false, file_count: 0, trace_files: 0, screenshot_files: 0, total_bytes: 0 };
  }
  if (!sameResolvedPath(realpathSync(artifactsDirectory), artifactsDirectory)) {
    throw runnerError('failure_artifact_directory_symlinked', 'Playwright failure artifact directory must not resolve through a symlink.');
  }
  const pending = [''];
  let fileCount = 0;
  let traceFiles = 0;
  let screenshotFiles = 0;
  let totalBytes = 0;
  while (pending.length > 0) {
    const relativeDirectory = pending.pop();
    const absoluteDirectory = relativeDirectory ? join(artifactsDirectory, relativeDirectory) : artifactsDirectory;
    for (const entry of readdirSync(absoluteDirectory, { withFileTypes: true })) {
      const relativePath = relativeDirectory ? join(relativeDirectory, entry.name) : entry.name;
      const absolutePath = join(artifactsDirectory, relativePath);
      const metadata = lstatSync(absolutePath);
      if (metadata.isSymbolicLink()) {
        throw runnerError('failure_artifact_symlink', 'Playwright failure artifacts may not contain symlinks.');
      }
      if (metadata.isDirectory()) {
        pending.push(relativePath);
        continue;
      }
      if (!metadata.isFile()) continue;
      fileCount += 1;
      totalBytes += metadata.size;
      if (fileCount > MAX_EVIDENCE_MANIFEST_FILES || totalBytes > MAX_EVIDENCE_MANIFEST_BYTES) {
        throw runnerError('failure_artifact_inventory_too_large', 'Playwright failure artifacts exceed their inspection budget.');
      }
      if (entry.name === 'trace.zip') traceFiles += 1;
      if (/\.png$/i.test(entry.name)) screenshotFiles += 1;
    }
  }
  return {
    directory_present: true,
    file_count: fileCount,
    trace_files: traceFiles,
    screenshot_files: screenshotFiles,
    total_bytes: totalBytes,
  };
}

function atomicWriteReceipt(path, value) {
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  renameSync(temporary, path);
}

export function qualificationScopeComplete(runInvocation, summary, releaseEligible = false) {
  return releaseEligible === true
    && runInvocation.qualificationEligible
    && playwrightExecutionScopeComplete(runInvocation.scope, summary);
}

export function localPlaywrightEnvironment(hostEnvironment, resultDirectory, headed = false) {
  if (typeof resultDirectory !== 'string' || !isAbsolute(resultDirectory) || /[\0\r\n]/.test(resultDirectory)) {
    throw runnerError('invalid_local_result_directory', 'The local Playwright result directory must be one safe absolute path.');
  }
  if (typeof headed !== 'boolean') {
    throw runnerError('headed_mode_invalid', 'Local Playwright headed mode must be one explicit boolean.');
  }
  const currentTiming = hostEnvironment.LOMO_PLAYWRIGHT_TIMING_POLICY === 'D-020';
  const duration = playwrightControllerTimeoutMs(hostEnvironment);
  return {
    ...isolatedOfflineLocalEnvironment(hostEnvironment),
    ...(currentTiming ? { KODESEC_PLAYWRIGHT_TIMING_FACTOR: String(duration / DEFAULT_CONTROLLER_TIMEOUT_MS),
      KODESEC_PLAYWRIGHT_TIMING_POLICY: 'D-020',
      KODESEC_PLAYWRIGHT_PERFORMANCE_PLATFORM: hostEnvironment.LOMO_PLAYWRIGHT_PERFORMANCE_PLATFORM } : {}),
    KODESEC_PLAYWRIGHT_RESULT_DIR: resultDirectory,
    KODESEC_PLAYWRIGHT_HEADED: headed ? '1' : '0',
  };
}

export async function runLocalFallback({
  runInvocation = invocation,
  suiteRoot = suiteDirectory,
  scriptRoot = scriptDirectory,
  webDistRoot = webDistDirectory,
  platform = process.platform,
  architecture = arch(),
  osRelease = release(),
  hostEnvironment = process.env,
  spawnPlaywright = spawn,
  runIdFactory,
  controllerTimeoutMs,
  childTerminationGraceMs = LOCAL_CHILD_TERMINATION_GRACE_MS,
} = {}) {
  if (playwrightRunnerKind(platform) !== 'local') {
    throw runnerError('local_runner_platform_invalid', 'The local Playwright fallback is only available on native non-Linux platforms.');
  }
  const hostBudget = playwrightControllerTimeoutMs(hostEnvironment);
  const currentTiming = hostEnvironment.LOMO_PLAYWRIGHT_TIMING_POLICY === 'D-020';
  if (currentTiming && hostEnvironment.LOMO_PLAYWRIGHT_PERFORMANCE_PLATFORM !== (platform === 'darwin' ? 'mac' : 'windows')) {
    throw runnerError('local_controller_timeout_invalid', 'D020 lane does not match the native local runner.');
  }
  controllerTimeoutMs ??= hostBudget;
  const maximumControllerMs = currentTiming ? hostBudget : MAX_CONTROLLER_TIMEOUT_MS;
  if (!Number.isSafeInteger(controllerTimeoutMs) || controllerTimeoutMs <= 0 || controllerTimeoutMs > maximumControllerMs) {
    throw runnerError('local_controller_timeout_invalid', 'The local Playwright controller timeout must be a positive bounded integer.');
  }
  if (!Number.isSafeInteger(childTerminationGraceMs) || childTerminationGraceMs <= 0 || childTerminationGraceMs > 10_000) {
    throw runnerError('local_termination_grace_invalid', 'The local Playwright termination grace must be a positive bounded integer.');
  }
  const { runId, resultDirectory } = createLocalResultDirectory({
    suiteRoot,
    mode: runInvocation.mode,
    platform,
    runIdFactory,
  });
  const receiptPath = resolve(resultDirectory, 'runner-receipt.json');
  const executionReportPath = resolve(resultDirectory, PLAYWRIGHT_EXECUTION_REPORT);
  const artifactsDirectory = resolve(resultDirectory, 'artifacts');
  const startedAt = new Date();
  const startedMonotonic = performance.now();
  const cpuReference = playwrightReferenceCpuEvidence(availableParallelism(), cpus().length);
  const receipt = {
    schema: RECEIPT_SCHEMA,
    run_id: runId,
    mode: runInvocation.mode,
    qualification_eligible: false,
    playwright_arguments: [...runInvocation.playwrightArguments],
    test_scope: runInvocation.scope,
    started_at: startedAt.toISOString(),
    finished_at: null,
    duration_ms: null,
    system: {
      platform,
      architecture,
      os_release: osRelease,
      cpu_reference: cpuReference,
      ...(currentTiming ? { qualification_timing_policy: 'D-020',
        performance_platform: hostEnvironment.LOMO_PLAYWRIGHT_PERFORMANCE_PLATFORM,
        qualification_timing_factor: hostBudget / DEFAULT_CONTROLLER_TIMEOUT_MS,
        performance_budget_mode: playwrightPerformanceBudgetMode(hostBudget, hostEnvironment),
        controller_timeout_ms: controllerTimeoutMs } : {}),
      selinux: 'not-applicable',
      selinux_mount_contract: 'not-applicable-to-native-local-runner',
      desktop: nativeHeadedDesktopEvidence({ platform, environment: hostEnvironment }),
    },
    runtime: {
      kind: 'local-locked-browser',
      result_location: `.results/${runInvocation.mode === 'snapshot-update' ? 'offline-update' : 'offline'}/${runId}`,
      result_environment_owned: true,
      container_isolation: false,
    },
    dependencies: {
      package_lock_sha256: null,
      installed_lock_sha256: null,
      playwright_cli: null,
      playwright_test_manifest_path: null,
      playwright_test_manifest_sha256: null,
      playwright_test_version: null,
      playwright_package_path: null,
      playwright_package_manifest_sha256: null,
      playwright_package_version: null,
      playwright_core_version: null,
      playwright_core_package_path: null,
      playwright_core_package_manifest_sha256: null,
      browser_registry_path: null,
      browser_registry_sha256: null,
      browser_cache_path: null,
      browser_selection_claim: null,
      chromium: null,
      chromium_headless_shell: null,
    },
    candidate: null,
    baseline: null,
    image: {
      requested_ref: null,
      id: null,
      repo_digests: [],
      architecture: null,
      os: null,
    },
    containers: { browser: null, controller: null },
    resource_sampling: {
      interval_ms: null,
      maximum_samples: 0,
      attempted_samples: 0,
      recorded_samples: 0,
      methodology: {
        repository_phase_signal: 'unavailable',
        cadence_limitation: 'Native local fallback has no outer container or cgroup resource sampler; in-page Playwright timing attachments remain authoritative.',
      },
      samples: [],
    },
    test_execution: {
      report_file: PLAYWRIGHT_EXECUTION_REPORT,
      report_sha256: null,
      report_size_bytes: null,
      report_present: false,
      qualification_scope_complete: null,
      summary: null,
      error_code: null,
    },
    controller: {
      exit_code: null,
      signal: null,
      spawn_error: false,
      timed_out: false,
      reaped: false,
      termination_requested: false,
      termination_signal: null,
      kill_escalated: false,
    },
    cleanup: [],
    outcome: { status: 'preparing', exit_code: null, signal: null, error_code: null },
    failure_artifacts: {
      required: null,
      present: null,
      inventory: null,
      error_code: null,
    },
    failure_artifacts_preserved: null,
  };
  process.stdout.write(`Offline Playwright evidence directory: ${resultDirectory}\n`);
  if (!runInvocation.qualificationEligible || !receipt.system.desktop.headed) {
    process.stderr.write(`NON-QUALIFYING PLAYWRIGHT ${runInvocation.mode.toUpperCase()} RUN: receipt eligibility is false.\n`);
  }

  let playwrightResult = null;
  let playwrightAttempted = false;
  let primaryError = null;
  let activeChild = null;
  let requestedSignal = null;
  let controllerTimedOut = false;
  let controllerTimeout = null;
  let childKillTimer = null;
  let childStopRequested = false;
  let childKillEscalated = false;
  let executionReportPublished = false;
  let executionReportPublicationFailed = false;
  const requestChildStop = () => {
    if (
      !activeChild
      || activeChild.exitCode !== null
      || activeChild.signalCode !== null
    ) return;
    if (!childStopRequested) {
      childStopRequested = true;
      try {
        activeChild.kill('SIGTERM');
      } catch {
        // The close/error observation below remains the authoritative reap result.
      }
    }
    if (!childKillTimer) {
      childKillTimer = setTimeout(() => {
        if (
          activeChild
          && activeChild.exitCode === null
          && activeChild.signalCode === null
        ) {
          childKillEscalated = true;
          try {
            activeChild.kill('SIGKILL');
          } catch {
            // A missing close event will keep the runner from claiming a terminal receipt.
          }
        }
      }, childTerminationGraceMs);
    }
  };
  const signalHandlers = new Map();
  for (const signal of Object.keys(SIGNAL_EXIT_CODES)) {
    const handler = () => {
      if (!requestedSignal) {
        requestedSignal = signal;
        receipt.outcome = {
          status: 'interrupted',
          exit_code: null,
          signal,
          error_code: 'runner_interrupted',
        };
      }
      requestChildStop();
    };
    signalHandlers.set(signal, handler);
    process.on(signal, handler);
  }
  const refreshTestExecutionEvidence = () => {
    // Raw publication failure consumes the private input; preserve that first failure.
    if (executionReportPublicationFailed) return;
    if (!executionReportPublished && existsSync(resolve(resultDirectory, PLAYWRIGHT_RAW_EXECUTION_REPORT))) {
      try {
        const published = publishNormalizedExecutionReport(resultDirectory, runInvocation);
        if (published) {
          receipt.test_execution.report_sha256 = published.sha256;
          receipt.test_execution.report_size_bytes = published.size_bytes;
          executionReportPublished = true;
        }
      } catch (error) {
        executionReportPublicationFailed = true;
        receipt.test_execution.report_present = false;
        receipt.test_execution.summary = null;
        receipt.test_execution.qualification_scope_complete = false;
        receipt.test_execution.error_code = typeof error?.code === 'string'
          ? error.code
          : 'execution_report_invalid';
        return;
      }
    }
    receipt.test_execution.report_present = existsSync(executionReportPath);
    try {
      const summary = readExecutionReport(executionReportPath, runInvocation.scope);
      receipt.test_execution.summary = summary;
      receipt.test_execution.error_code = summary ? null : 'execution_report_missing';
      receipt.test_execution.qualification_scope_complete = qualificationScopeComplete(
        runInvocation,
        summary,
        receipt.qualification_eligible,
      );
    } catch (error) {
      receipt.test_execution.summary = null;
      receipt.test_execution.qualification_scope_complete = false;
      receipt.test_execution.error_code = typeof error?.code === 'string'
        ? error.code
        : 'execution_report_invalid';
    }
    if (receipt.test_execution.report_present && !receipt.test_execution.report_sha256) {
      const metadata = lstatSync(executionReportPath);
      receipt.test_execution.report_sha256 = sha256File(executionReportPath);
      receipt.test_execution.report_size_bytes = metadata.size;
    }
  };
  const refreshFailureArtifactEvidence = () => {
    const required = playwrightAttempted && receipt.outcome.status !== 'passed';
    receipt.failure_artifacts.required = required;
    try {
      const inventory = boundedFailureArtifactInventory(artifactsDirectory);
      const present = inventory.trace_files > 0 || inventory.screenshot_files > 0;
      receipt.failure_artifacts.inventory = inventory;
      receipt.failure_artifacts.present = present;
      receipt.failure_artifacts.error_code = null;
      receipt.failure_artifacts_preserved = required ? present : null;
    } catch (error) {
      receipt.failure_artifacts.inventory = null;
      receipt.failure_artifacts.present = false;
      receipt.failure_artifacts.error_code = typeof error?.code === 'string'
        ? error.code
        : 'failure_artifact_inventory_failed';
      receipt.failure_artifacts_preserved = required ? false : null;
    }
  };

  try {
    if (!existsSync(resolve(webDistRoot, 'index.html'))) {
      throw runnerError('web_distribution_missing', 'Built web distribution is missing.');
    }
    if (!sameResolvedPath(realpathSync(webDistRoot), webDistRoot, platform)) {
      throw runnerError('web_distribution_symlinked', 'Built web distribution must not resolve through a symlink.');
    }
    receipt.candidate = candidateEvidence({ suiteRoot, scriptRoot, webDistRoot });
    receipt.dependencies = localDependencyEvidence({ suiteRoot, platform, architecture });
    receipt.baseline = platformBaselineEvidence({ suiteRoot, platform, headed: receipt.system.desktop.headed });
    receipt.outcome.status = 'running';

    await new Promise((resolveTurn) => setImmediate(resolveTurn));
    if (requestedSignal) throw runnerError('runner_interrupted', 'Runner received a termination signal.');
    const cli = resolve(suiteRoot, 'node_modules', '@playwright', 'test', 'cli.js');
    const environment = localPlaywrightEnvironment(
      hostEnvironment,
      resultDirectory,
      receipt.system.desktop.headed,
    );
    environment.PLAYWRIGHT_BROWSERS_PATH = resolve(suiteRoot, '.browsers');
    playwrightAttempted = true;
    playwrightResult = await new Promise((resolveChild) => {
      let settled = false;
      let spawnError = null;
      const settle = (value) => {
        if (settled) return;
        settled = true;
        resolveChild(value);
      };
      try {
        activeChild = spawnPlaywright(
          process.execPath,
          [cli, 'test', ...runInvocation.playwrightArguments],
          { cwd: suiteRoot, env: environment, stdio: 'inherit' },
        );
      } catch (error) {
        settle({ status: null, signal: null, error, reaped: false });
        return;
      }
      if (!activeChild || typeof activeChild.once !== 'function' || typeof activeChild.kill !== 'function') {
        settle({
          status: null,
          signal: null,
          error: runnerError('playwright_child_invalid', 'The local Playwright child handle is invalid.'),
          reaped: false,
        });
        return;
      }
      activeChild.once('error', (error) => {
        spawnError = error;
        if (!Number.isSafeInteger(activeChild.pid)) {
          settle({ status: null, signal: null, error, reaped: false });
        }
      });
      activeChild.once('close', (exitCode, signal) => {
        settle({
          status: exitCode,
          signal,
          error: spawnError,
          reaped: true,
        });
      });
      controllerTimeout = setTimeout(() => {
        controllerTimedOut = true;
        requestChildStop();
      }, controllerTimeoutMs);
      if (requestedSignal) requestChildStop();
    });
    if (controllerTimeout) {
      clearTimeout(controllerTimeout);
      controllerTimeout = null;
    }
    if (childKillTimer) {
      clearTimeout(childKillTimer);
      childKillTimer = null;
    }
    receipt.controller = {
      exit_code: Number.isInteger(playwrightResult?.status) ? playwrightResult.status : null,
      signal: typeof playwrightResult?.signal === 'string' ? playwrightResult.signal : null,
      spawn_error: Boolean(playwrightResult?.error),
      timed_out: controllerTimedOut,
      reaped: playwrightResult?.reaped === true,
      termination_requested: childStopRequested,
      termination_signal: childStopRequested ? 'SIGTERM' : null,
      kill_escalated: childKillEscalated,
    };
    refreshTestExecutionEvidence();
    if (requestedSignal) throw runnerError('runner_interrupted', 'Runner received a termination signal.');
    if (controllerTimedOut) throw runnerError('controller_timeout', 'Playwright controller exceeded its fixed timeout.');
    if (playwrightResult?.error) {
      throw runnerError('playwright_spawn_failed', 'The local locked Playwright process could not be started.');
    }
    if (playwrightResult?.status !== 0) {
      throw runnerError('playwright_tests_failed', 'The local locked Playwright suite failed.');
    }
    if (!receipt.test_execution.summary) {
      throw runnerError(
        receipt.test_execution.error_code || 'execution_report_missing',
        'Playwright completed without a valid executed-test report.',
      );
    }
    if (
      runInvocation.qualificationEligible
      && !playwrightExecutionScopeComplete(runInvocation.scope, receipt.test_execution.summary)
    ) {
      throw runnerError('qualification_scope_unproven', 'Playwright report does not prove the complete qualification scope.');
    }
    receipt.outcome = { status: 'passed', exit_code: 0, signal: null, error_code: null };
  } catch (error) {
    primaryError = error;
    if (requestedSignal) {
      receipt.outcome = {
        status: 'interrupted',
        exit_code: null,
        signal: requestedSignal,
        error_code: 'runner_interrupted',
      };
    } else {
      receipt.outcome = {
        status: 'failed',
        exit_code: Number.isInteger(playwrightResult?.status) ? playwrightResult.status : 1,
        signal: typeof playwrightResult?.signal === 'string' ? playwrightResult.signal : null,
        error_code: typeof error?.code === 'string' ? error.code : 'runner_failure',
      };
    }
  } finally {
    if (controllerTimeout) clearTimeout(controllerTimeout);
    if (childKillTimer) clearTimeout(childKillTimer);
    refreshTestExecutionEvidence();
    refreshFailureArtifactEvidence();
    const fullScopeExecuted = playwrightExecutionScopeComplete(
      runInvocation.scope,
      receipt.test_execution.summary,
    );
    receipt.system.desktop = terminalNativeHeadedDesktopEvidence(receipt.system.desktop, {
      controller: receipt.controller,
      fullScopeExecuted,
      outcomePassed: receipt.outcome.status === 'passed',
    });
    receipt.qualification_eligible = runInvocation.qualificationEligible
      && receipt.system.desktop.verified === true
      && receipt.system.desktop.terminal_verified === true
      && receipt.outcome.status === 'passed';
    receipt.test_execution.qualification_scope_complete = qualificationScopeComplete(
      runInvocation,
      receipt.test_execution.summary,
      receipt.qualification_eligible,
    );
    receipt.finished_at = new Date().toISOString();
    receipt.duration_ms = Math.max(1, Math.round(performance.now() - startedMonotonic));
    atomicWriteReceipt(receiptPath, receipt);
    for (const [signal, handler] of signalHandlers) process.removeListener(signal, handler);
    process.stdout.write(`Offline Playwright terminal receipt: ${receiptPath}\n`);
  }

  if (primaryError) {
    process.stderr.write(`Offline Playwright failed: ${receipt.outcome.error_code}. Inspect the terminal receipt for verified failure evidence.\n`);
  }
  return {
    exitCode: requestedSignal
      ? SIGNAL_EXIT_CODES[requestedSignal]
      : primaryError ? (receipt.outcome.exit_code || 1) : 0,
    receipt,
    receiptPath,
    resultDirectory,
  };
}

function safeInteger(value) {
  if (value === 'max') return 'max';
  if (!/^\d+$/.test(value || '')) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : value;
}

function parseKeyValueLines(value) {
  if (typeof value !== 'string') return null;
  const parsed = {};
  for (const line of value.split(/\r?\n/)) {
    const [key, raw, ...remaining] = line.trim().split(/\s+/);
    if (!key || raw === undefined || remaining.length > 0 || !/^[a-z0-9_]+$/i.test(key)) continue;
    parsed[key] = safeInteger(raw);
  }
  return parsed;
}

function parsePressure(value) {
  if (typeof value !== 'string') return null;
  const parsed = {};
  for (const line of value.split(/\r?\n/)) {
    const [kind, ...fields] = line.trim().split(/\s+/);
    if (!['some', 'full'].includes(kind)) continue;
    const values = {};
    for (const field of fields) {
      const separator = field.indexOf('=');
      if (separator < 1) continue;
      const key = field.slice(0, separator);
      const raw = field.slice(separator + 1);
      const numeric = Number(raw);
      if (/^(avg10|avg60|avg300|total)$/.test(key) && Number.isFinite(numeric)) values[key] = numeric;
    }
    parsed[kind] = values;
  }
  return parsed;
}

function parseCgroupSnapshot(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const membership = typeof raw.membership === 'string'
    ? raw.membership.split(/\r?\n/).find((line) => line.startsWith('0::'))
    : undefined;
  const cpuMax = typeof raw.cpu_max === 'string' ? raw.cpu_max.split(/\s+/) : [];
  return {
    path: membership && /^0::\/[A-Za-z0-9_.:/-]*$/.test(membership) ? membership.slice(3) : null,
    cpu: {
      max: cpuMax.length === 2 ? { quota: safeInteger(cpuMax[0]), period: safeInteger(cpuMax[1]) } : null,
      stat: parseKeyValueLines(raw.cpu_stat),
      pressure: parsePressure(raw.cpu_pressure),
    },
    memory: {
      current: safeInteger(raw.memory_current),
      max: safeInteger(raw.memory_max),
      peak: safeInteger(raw.memory_peak),
      events: parseKeyValueLines(raw.memory_events),
      pressure: parsePressure(raw.memory_pressure),
    },
    pids: {
      current: safeInteger(raw.pids_current),
      max: safeInteger(raw.pids_max),
      peak: safeInteger(raw.pids_peak),
    },
    io_pressure: parsePressure(raw.io_pressure),
  };
}

function hostPressure() {
  const result = {};
  for (const kind of ['cpu', 'memory', 'io']) {
    try {
      result[kind] = parsePressure(readFileSync(`/proc/pressure/${kind}`, 'utf8'));
    } catch {
      result[kind] = null;
    }
  }
  return result;
}

function selinuxState() {
  try {
    return readFileSync('/sys/fs/selinux/enforce', 'utf8').trim() === '1' ? 'enforcing' : 'permissive';
  } catch {
    return 'not-detected';
  }
}

function parseDockerSize(value) {
  if (typeof value !== 'string') return null;
  const match = value.trim().match(/^([0-9.]+)(B|kB|MB|GB|TB|KiB|MiB|GiB|TiB)$/);
  if (!match) return null;
  const units = {
    B: 1,
    kB: 1_000,
    MB: 1_000_000,
    GB: 1_000_000_000,
    TB: 1_000_000_000_000,
    KiB: 1_024,
    MiB: 1_048_576,
    GiB: 1_073_741_824,
    TiB: 1_099_511_627_776,
  };
  const bytes = Number(match[1]) * units[match[2]];
  return Number.isFinite(bytes) ? Math.round(bytes) : null;
}

function dockerStats(containerNames) {
  if (containerNames.length === 0) {
    return {
      values: new Map(),
      command_exit_code: null,
      command_spawn_error: false,
      requested_containers: 0,
      parsed_containers: 0,
      malformed_lines: 0,
    };
  }
  const result = run('docker', ['stats', '--no-stream', '--format', '{{json .}}', ...containerNames], {
    allowFailure: true,
    quiet: true,
    timeout: 5_000,
  });
  const parsed = new Map();
  let malformedLines = 0;
  if (result.status !== 0 || !result.stdout?.trim()) {
    return {
      values: parsed,
      command_exit_code: result.status,
      command_spawn_error: Boolean(result.error),
      requested_containers: containerNames.length,
      parsed_containers: 0,
      malformed_lines: 0,
    };
  }
  for (const line of result.stdout.trim().split(/\r?\n/)) {
    try {
      const value = JSON.parse(line);
      if (!containerNames.includes(value.Name)) {
        malformedLines += 1;
        continue;
      }
      const memory = typeof value.MemUsage === 'string' ? value.MemUsage.split('/').map((part) => part.trim()) : [];
      parsed.set(value.Name, {
        cpu_percent: typeof value.CPUPerc === 'string' ? Number(value.CPUPerc.replace(/%$/, '')) : null,
        memory_usage_bytes: parseDockerSize(memory[0]),
        memory_limit_bytes: parseDockerSize(memory[1]),
        memory_percent: typeof value.MemPerc === 'string' ? Number(value.MemPerc.replace(/%$/, '')) : null,
        pids: safeInteger(String(value.PIDs ?? '')),
      });
    } catch {
      malformedLines += 1;
    }
  }
  return {
    values: parsed,
    command_exit_code: result.status,
    command_spawn_error: Boolean(result.error),
    requested_containers: containerNames.length,
    parsed_containers: parsed.size,
    malformed_lines: malformedLines,
  };
}

function cgroupSnapshot(cgroupPath) {
  const root = `/sys/fs/cgroup${cgroupPath === '/' ? '' : cgroupPath}`;
  const files = {
    cpu_max: 'cpu.max',
    cpu_stat: 'cpu.stat',
    cpu_pressure: 'cpu.pressure',
    memory_current: 'memory.current',
    memory_max: 'memory.max',
    memory_peak: 'memory.peak',
    memory_events: 'memory.events',
    memory_pressure: 'memory.pressure',
    pids_current: 'pids.current',
    pids_max: 'pids.max',
    pids_peak: 'pids.peak',
    io_pressure: 'io.pressure',
  };
  const raw = { membership: `0::${cgroupPath}` };
  let available = false;
  for (const [field, filename] of Object.entries(files)) {
    try {
      raw[field] = readFileSync(`${root}/${filename}`, 'utf8').trim();
      available = true;
    } catch {
      raw[field] = null;
    }
  }
  return available ? parseCgroupSnapshot(raw) : null;
}

function hostCgroupPath(containerName) {
  const pidResult = run('docker', ['container', 'inspect', '--format', '{{.State.Pid}}', containerName], {
    allowFailure: true,
    quiet: true,
    timeout: 5_000,
  });
  const pid = pidResult.stdout?.trim();
  if (pidResult.status !== 0 || !/^\d{1,12}$/.test(pid || '') || pid === '0') return null;
  try {
    const membership = readFileSync(`/proc/${pid}/cgroup`, 'utf8')
      .split(/\r?\n/)
      .find((line) => line.startsWith('0::'));
    const path = membership?.slice(3);
    const safeSegments = typeof path === 'string'
      && path.split('/').every((segment) => !['.', '..'].includes(segment));
    return safeSegments && path.length <= 512 && /^\/[A-Za-z0-9_.:/-]*$/.test(path) ? path : null;
  } catch {
    return null;
  }
}

function inspectContainerRaw(containerName) {
  const result = run('docker', ['container', 'inspect', '--format', '{{json .}}', containerName], {
    allowFailure: true,
    quiet: true,
    timeout: 5_000,
  });
  if (result.status !== 0 || !result.stdout?.trim()) return null;
  try {
    const parsed = JSON.parse(result.stdout);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function inspectContainer(containerName, expectedTargets) {
  const raw = inspectContainerRaw(containerName);
  if (!raw) return null;
  try {
    return summarizePlaywrightContainerInspect(raw, expectedTargets);
  } catch {
    return null;
  }
}

function validateEffectiveIsolation(role, summary, uid, gid, desktop) {
  if (!summary) throw runnerError(`${role}_inspect_unavailable`, `Effective ${role} container state could not be inspected.`);
  const effective = summary.effective;
  const expectedNetwork = role === 'browser' ? 'none' : 'container:browser-service';
  const commonValid = effective.user === `${uid}:${gid}`
    && summary.state?.running === true
    && effective.image === PLAYWRIGHT_CONTAINER_IMAGE
    && effective.network_mode === expectedNetwork
    && effective.read_only_root === true
    && effective.memory_bytes === 1_073_741_824
    && effective.memory_swap_bytes === 1_073_741_824
    && effective.nano_cpus === (
      role === 'browser'
        ? PLAYWRIGHT_OFFLINE_BROWSER_CPUS
        : PLAYWRIGHT_OFFLINE_CONTROLLER_CPUS
    ) * 1_000_000_000
    && effective.pids_limit === 256
    && effective.cap_drop.includes('ALL')
    && effective.security_opt.some((value) => value.startsWith('no-new-privileges'));
  if (!commonValid) throw runnerError(`${role}_isolation_mismatch`, `Effective ${role} isolation does not match the repository contract.`);
  const headed = desktop?.headed === true;
  if (role === 'browser') {
    const browserDesktopValid = headed
      ? effective.hostname === desktop.hostname
        && effective.environment?.DISPLAY === PLAYWRIGHT_HEADED_DISPLAY
        && effective.environment?.XAUTHORITY === PLAYWRIGHT_CONTAINER_XAUTHORITY
        && effective.environment?.KODESEC_PLAYWRIGHT_HEADED === null
      : effective.environment?.DISPLAY === null
        && effective.environment?.XAUTHORITY === null
        && effective.environment?.KODESEC_PLAYWRIGHT_HEADED === null;
    if (!browserDesktopValid) {
      throw runnerError('browser_desktop_mismatch', 'Effective browser desktop wiring does not match the requested headed mode.');
    }
  } else if (
    effective.environment?.KODESEC_PLAYWRIGHT_HEADED !== (headed ? '1' : '0')
    || effective.environment?.DISPLAY !== null
    || effective.environment?.XAUTHORITY !== null
  ) {
    throw runnerError('controller_desktop_mismatch', 'Effective controller headed-mode signal does not match the browser desktop.');
  }
  const bindMounts = summary.mounts.filter((mount) => mount.type === 'bind');
  const expectedBinds = role === 'browser'
    ? [
      { purpose: 'locked_node_modules', writable: false },
      ...(headed ? [
        { purpose: 'xauthority', writable: false },
        { purpose: 'x11_socket', writable: false },
      ] : []),
    ]
    : [
      { purpose: 'current_results', writable: true },
      ...(snapshotUpdate ? [{ purpose: 'snapshot_baselines', writable: true }] : []),
      { purpose: 'suite', writable: false },
      { purpose: 'web_dist', writable: false },
    ];
  const actualBinds = bindMounts.map(({ purpose, writable }) => ({ purpose, writable }))
    .sort((left, right) => left.purpose.localeCompare(right.purpose));
  expectedBinds.sort((left, right) => left.purpose.localeCompare(right.purpose));
  if (JSON.stringify(actualBinds) !== JSON.stringify(expectedBinds)) {
    throw runnerError(`${role}_mount_mismatch`, `Effective ${role} bind mounts do not match the repository contract.`);
  }
  if (summary.mounts.some((mount) => mount.purpose === 'other') || summary.tmpfs.some((mount) => mount.purpose === 'other')) {
    throw runnerError(`${role}_unexpected_mount`, `Effective ${role} mounts include an unexpected target.`);
  }
  const tmpfsPurposes = summary.tmpfs.map((mount) => mount.purpose).sort();
  const requiredTmpfs = role === 'browser' ? ['temporary'] : ['results_mask', 'temporary'];
  if (JSON.stringify(tmpfsPurposes) !== JSON.stringify(requiredTmpfs)) {
    throw runnerError(`${role}_tmpfs_mismatch`, `Effective ${role} tmpfs mounts do not match the repository contract.`);
  }
}

async function waitForBrowserServer(containerName, wsEndpoint, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const logs = run('docker', ['logs', containerName], {
      allowFailure: true,
      quiet: true,
      timeout: 5_000,
    });
    const boundedLogs = `${logs.stdout || ''}${logs.stderr || ''}`.slice(-4_096);
    if (logs.status === 0 && playwrightServerReady(boundedLogs, wsEndpoint)) return;
    const exists = run('docker', ['container', 'inspect', containerName], {
      allowFailure: true,
      quiet: true,
      timeout: 5_000,
    });
    if (exists.status !== 0) throw runnerError('browser_exited_before_readiness', 'Pinned browser service exited before readiness.');
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw runnerError('browser_readiness_timeout', 'Pinned browser service did not become ready in time.');
}

async function waitForContainerRunning(containerName, expectedTargets, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const raw = inspectContainerRaw(containerName);
    if (raw) {
      let summary;
      try {
        summary = summarizePlaywrightContainerInspect(raw, expectedTargets);
      } catch {
        summary = null;
      }
      if (summary?.state.running === true) return { raw, summary };
      if (['dead', 'exited', 'removing'].includes(summary?.state.status)) {
        throw runnerError('controller_exited_before_running', 'Playwright controller exited before a running state could be proven.');
      }
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  throw runnerError('controller_running_timeout', 'Playwright controller did not reach a running state in time.');
}

function cleanupContainers(targets) {
  const results = [];
  for (const target of targets) {
    if (!target.attempted) {
      results.push({ role: target.role, attempted: false, removal_exit_code: null, absence_query_exit_code: null, absent: null });
      continue;
    }
    const removal = run('docker', playwrightContainerCleanupArguments(target.name), {
      allowFailure: true,
      quiet: true,
      timeout: 30_000,
    });
    const absence = run('docker', playwrightContainerAbsenceArguments(target.name), {
      allowFailure: true,
      quiet: true,
      timeout: 10_000,
    });
    const listed = absence.status === 0
      ? absence.stdout.trim().split(/\r?\n/).filter(Boolean)
      : [];
    results.push({
      role: target.role,
      attempted: true,
      removal_exit_code: removal.status,
      absence_query_exit_code: absence.status,
      absent: absence.status === 0 && listed.length === 0,
    });
  }
  return results;
}

function startController(controllerArguments, onChild) {
  return new Promise((resolveController) => {
    const child = spawn('docker', controllerArguments, {
      cwd: suiteDirectory,
      env: process.env,
      stdio: 'inherit',
    });
    onChild(child);
    let settled = false;
    child.once('error', () => {
      if (settled) return;
      settled = true;
      resolveController({ exitCode: null, signal: null, spawnError: true });
    });
    child.once('close', (exitCode, signal) => {
      if (settled) return;
      settled = true;
      resolveController({ exitCode, signal, spawnError: false });
    });
  });
}

async function runOfflineContainers() {
  const resultsRoot = resolve(suiteDirectory, '.results');
  if (existsSync(resultsRoot) && realpathSync(resultsRoot) !== resultsRoot) {
    throw runnerError('unsafe_result_root', 'Offline Playwright result root must not resolve through a symlink.');
  }
  const runId = randomBytes(6).toString('hex');
  const browserContainerName = `lomo-code-security-${runId}-browser`;
  const controllerContainerName = `lomo-code-security-${runId}-controller`;
  const resultDirectory = resolve(suiteDirectory, '.results', snapshotUpdate ? 'offline-update' : 'offline', runId);
  mkdirSync(resultDirectory, { recursive: true, mode: 0o700 });
  if (realpathSync(resultsRoot) !== resultsRoot || realpathSync(resultDirectory) !== resultDirectory) {
    throw runnerError('unsafe_result_directory', 'Offline Playwright results must not resolve through a symlink.');
  }
  const receiptPath = resolve(resultDirectory, 'runner-receipt.json');
  const startedAt = new Date();
  const startedMonotonic = performance.now();
  const cpuReference = playwrightReferenceCpuEvidence(availableParallelism(), cpus().length);
  const receipt = {
    schema: RECEIPT_SCHEMA,
    run_id: runId,
    mode: invocation.mode,
    qualification_eligible: false,
    playwright_arguments: [...playwrightArguments],
    test_scope: invocation.scope,
    started_at: startedAt.toISOString(),
    finished_at: null,
    duration_ms: null,
    system: {
      platform: process.platform,
      architecture: arch(),
      os_release: release(),
      qualification_timing_factor: QUALIFICATION_TIMING_FACTOR,
      ...(CURRENT_TIMING_POLICY ? { qualification_timing_policy: 'D-020',
        performance_platform: process.env.LOMO_PLAYWRIGHT_PERFORMANCE_PLATFORM } : {}),
      performance_budget_mode: PERFORMANCE_BUDGET_MODE,
      controller_timeout_ms: CONTROLLER_TIMEOUT_MS,
      cpu_reference: cpuReference,
      selinux: selinuxState(),
      selinux_mount_contract: 'pre-labeled-disposable-candidate-required; owner-checkout-is-never-relabeled; labels-are-never-disabled',
      desktop: {
        mode: 'unverified',
        headed: false,
        display: null,
        hostname: null,
        xauthority: null,
        x11_socket: null,
        transport: null,
        preflight_verified: false,
        terminal_verified: null,
        verified: false,
        postflight_error_code: null,
      },
    },
    dependencies: {
      package_lock_sha256: null,
      installed_lock_sha256: null,
      playwright_cli: null,
      playwright_test_manifest_path: null,
      playwright_test_manifest_sha256: null,
      playwright_test_version: null,
      playwright_package_path: null,
      playwright_package_manifest_sha256: null,
      playwright_package_version: null,
      playwright_core_version: null,
      playwright_core_package_path: null,
      playwright_core_package_manifest_sha256: null,
      browser_registry_path: null,
      browser_registry_sha256: null,
      chromium: null,
      chromium_headless_shell: null,
    },
    candidate: null,
    image: {
      requested_ref: PLAYWRIGHT_CONTAINER_IMAGE,
      id: null,
      repo_digests: [],
      architecture: null,
      os: null,
    },
    containers: {
      browser: { name: browserContainerName, start: null, completion: null, final: null, cgroup_path: null },
      controller: {
        name: controllerContainerName,
        start: null,
        final: null,
        cgroup_path: null,
        network_namespace: {
          target_matches_browser: false,
          sandbox_identity_available: false,
          sandbox_matches_browser: null,
          verified: false,
        },
      },
    },
    resource_sampling: {
      interval_ms: RESOURCE_SAMPLE_INTERVAL_MS,
      maximum_samples: MAX_RESOURCE_SAMPLES,
      started_elapsed_ms: null,
      finished_elapsed_ms: null,
      duration_ms: null,
      scheduled_interval_count: 0,
      attempted_samples: 0,
      recorded_samples: 0,
      failed_samples: 0,
      partial_samples: 0,
      missed_interval_count: 0,
      dropped_sample_count: 0,
      methodology: {
        repository_phase_signal: 'unavailable',
        cadence_limitation: 'Ten-second Docker daemon snapshots may overlap in-page measurement windows; Playwright timing attachments remain the route-level authority.',
      },
      host_pressure_start: hostPressure(),
      host_pressure_end: null,
      cgroup_cpu_windows: { browser: null, controller: null },
      samples: [],
    },
    test_execution: {
      report_file: PLAYWRIGHT_EXECUTION_REPORT,
      report_sha256: null,
      report_size_bytes: null,
      report_present: false,
      qualification_scope_complete: null,
      summary: null,
      error_code: null,
    },
    controller: { exit_code: null, signal: null, spawn_error: false, timed_out: false },
    cleanup: [],
    outcome: { status: 'preparing', exit_code: null, signal: null, error_code: null },
    failure_artifacts: {
      required: null,
      present: null,
      inventory: null,
      error_code: null,
    },
    failure_artifacts_preserved: null,
  };
  atomicWriteReceipt(receiptPath, receipt);
  process.stdout.write(`Offline Playwright evidence directory: ${resultDirectory}\n`);
  if (!invocation.qualificationEligible) {
    process.stderr.write(`NON-QUALIFYING PLAYWRIGHT ${invocation.mode.toUpperCase()} RUN: receipt eligibility is false.\n`);
  }

  const nodeModulesDirectory = resolve(suiteDirectory, 'node_modules');
  const snapshotDirectory = snapshotUpdate ? resolve(suiteDirectory, 'tests', '__screenshots__') : undefined;
  const executionReportPath = resolve(resultDirectory, PLAYWRIGHT_EXECUTION_REPORT);
  const artifactsDirectory = resolve(resultDirectory, 'artifacts');
  const expectedTargets = {
    suite: suiteDirectory,
    web_dist: webDistDirectory,
    current_results: resultDirectory,
    snapshot_baselines: snapshotDirectory,
    locked_node_modules: PLAYWRIGHT_REMOTE_NODE_MODULES,
    results_mask: resultsRoot,
    temporary: '/tmp',
    shared_memory: '/dev/shm',
    xauthority: PLAYWRIGHT_CONTAINER_XAUTHORITY,
    x11_socket: PLAYWRIGHT_CONTAINER_X11_SOCKET,
  };
  let browserAttempted = false;
  let controllerAttempted = false;
  let activeController = null;
  let requestedSignal = null;
  let controllerTimedOut = false;
  let controllerResult = null;
  let primaryError = null;
  let sampleTimer = null;
  let samplingWindowStartedMonotonic = null;
  let intervalSamplingStartedMonotonic = null;
  let lastScheduledInterval = 0;
  let controllerTimeout = null;
  let controllerKillTimer = null;
  let executionReportPublished = false;
  let executionReportPublicationFailed = false;
  let headedTransport = null;
  let headedTransportUnexpectedError = null;
  const verifyDesktopPostflight = () => {
    const observed = linuxHeadedDesktopEvidence();
    if (!sameLinuxHeadedDesktopEvidence(receipt.system.desktop, observed)) {
      throw runnerError('headed_desktop_identity_changed', 'The real desktop identity changed during Playwright execution.');
    }
    if (receipt.system.desktop.headed) {
      receipt.system.desktop.xauthority.terminal_identity = sourceDesktopIdentity(observed.xauthority);
      receipt.system.desktop.x11_socket.terminal_identity = sourceDesktopIdentity(observed.x11_socket);
    }
    if (receipt.system.desktop.headed) verifyHeadedX11TransportIdentity(headedTransport);
    receipt.system.desktop.terminal_verified = true;
    receipt.system.desktop.verified = receipt.system.desktop.headed === true;
    receipt.system.desktop.postflight_error_code = receipt.system.desktop.headed
      ? null
      : 'headed_not_requested';
  };

  const updateContainerInspection = (role) => {
    const name = role === 'browser' ? browserContainerName : controllerContainerName;
    return inspectContainer(name, expectedTargets);
  };
  const collectSample = (kind) => {
    receipt.resource_sampling.attempted_samples += 1;
    if (samplingWindowStartedMonotonic === null) {
      samplingWindowStartedMonotonic = performance.now();
      receipt.resource_sampling.started_elapsed_ms = Math.round(samplingWindowStartedMonotonic - startedMonotonic);
    }
    if (receipt.resource_sampling.samples.length >= MAX_RESOURCE_SAMPLES) {
      receipt.resource_sampling.dropped_sample_count += 1;
      return false;
    }
    const sampleStartedMonotonic = performance.now();
    const runningNames = [];
    const inspected = new Map();
    for (const [role, attempted, name] of [
      ['browser', browserAttempted, browserContainerName],
      ['controller', controllerAttempted, controllerContainerName],
    ]) {
      if (!attempted) continue;
      const inspect = updateContainerInspection(role);
      inspected.set(role, inspect);
      if (inspect?.state.running) runningNames.push(name);
    }
    const sample = {
      kind,
      started_elapsed_ms: Math.round(sampleStartedMonotonic - startedMonotonic),
      finished_elapsed_ms: null,
      duration_ms: null,
      elapsed_ms: null,
      host_pressure: hostPressure(),
      docker_stats_collection: null,
      browser: null,
      controller: null,
    };
    for (const [role, attempted, name] of [
      ['browser', browserAttempted, browserContainerName],
      ['controller', controllerAttempted, controllerContainerName],
    ]) {
      if (!attempted) continue;
      const inspect = inspected.get(role);
      const cgroupPath = inspect?.state.running
        ? hostCgroupPath(name)
        : receipt.containers[role].cgroup_path;
      const cgroup = cgroupPath ? cgroupSnapshot(cgroupPath) : null;
      if (!receipt.containers[role].cgroup_path) {
        receipt.containers[role].cgroup_path = cgroupPath || cgroup?.path || null;
      }
      sample[role] = {
        docker_stats: null,
        cgroup,
      };
    }
    const stats = dockerStats(runningNames);
    sample.docker_stats_collection = {
      command_exit_code: stats.command_exit_code,
      command_spawn_error: stats.command_spawn_error,
      requested_containers: stats.requested_containers,
      parsed_containers: stats.parsed_containers,
      malformed_lines: stats.malformed_lines,
    };
    if (
      stats.command_spawn_error
      || (stats.command_exit_code !== null && stats.command_exit_code !== 0)
      || stats.parsed_containers !== stats.requested_containers
      || stats.malformed_lines > 0
    ) receipt.resource_sampling.partial_samples += 1;
    if (sample.browser) sample.browser.docker_stats = stats.values.get(browserContainerName) || null;
    if (sample.controller) sample.controller.docker_stats = stats.values.get(controllerContainerName) || null;
    const sampleFinishedMonotonic = performance.now();
    sample.finished_elapsed_ms = Math.round(sampleFinishedMonotonic - startedMonotonic);
    sample.elapsed_ms = sample.finished_elapsed_ms;
    sample.duration_ms = Math.round(sampleFinishedMonotonic - sampleStartedMonotonic);
    receipt.resource_sampling.samples.push(sample);
    receipt.resource_sampling.recorded_samples = receipt.resource_sampling.samples.length;
    atomicWriteReceipt(receiptPath, receipt);
    return true;
  };
  const attemptSample = (kind) => {
    try {
      return collectSample(kind);
    } catch {
      receipt.resource_sampling.failed_samples += 1;
      try {
        atomicWriteReceipt(receiptPath, receipt);
      } catch {
        // A terminal write is still attempted after cleanup; this counter makes the missed observation explicit.
      }
      return false;
    }
  };
  const recordScheduledInterval = () => {
    if (intervalSamplingStartedMonotonic === null) return;
    const elapsed = performance.now() - intervalSamplingStartedMonotonic;
    const scheduledInterval = Math.max(1, Math.floor(elapsed / RESOURCE_SAMPLE_INTERVAL_MS));
    if (scheduledInterval > lastScheduledInterval + 1) {
      receipt.resource_sampling.missed_interval_count += scheduledInterval - lastScheduledInterval - 1;
    }
    lastScheduledInterval = Math.max(lastScheduledInterval, scheduledInterval);
    receipt.resource_sampling.scheduled_interval_count = lastScheduledInterval;
    attemptSample('interval');
  };
  const finalizeScheduledIntervals = () => {
    if (intervalSamplingStartedMonotonic === null) return;
    const expectedIntervals = Math.floor(
      (performance.now() - intervalSamplingStartedMonotonic) / RESOURCE_SAMPLE_INTERVAL_MS,
    );
    if (expectedIntervals > lastScheduledInterval) {
      receipt.resource_sampling.missed_interval_count += expectedIntervals - lastScheduledInterval;
      lastScheduledInterval = expectedIntervals;
      receipt.resource_sampling.scheduled_interval_count = expectedIntervals;
    }
  };
  const refreshTestExecutionEvidence = () => {
    // Raw publication failure consumes the private input; preserve that first failure.
    if (executionReportPublicationFailed) return;
    if (!executionReportPublished && existsSync(resolve(resultDirectory, PLAYWRIGHT_RAW_EXECUTION_REPORT))) {
      try {
        const published = publishNormalizedExecutionReport(resultDirectory);
        if (published) {
          receipt.test_execution.report_sha256 = published.sha256;
          receipt.test_execution.report_size_bytes = published.size_bytes;
          executionReportPublished = true;
        }
      } catch (error) {
        executionReportPublicationFailed = true;
        receipt.test_execution.report_present = false;
        receipt.test_execution.summary = null;
        receipt.test_execution.qualification_scope_complete = false;
        receipt.test_execution.error_code = typeof error?.code === 'string'
          ? error.code
          : 'execution_report_invalid';
        return;
      }
    }
    receipt.test_execution.report_present = existsSync(executionReportPath);
    try {
      const summary = readExecutionReport(executionReportPath, invocation.scope);
      receipt.test_execution.summary = summary;
      receipt.test_execution.error_code = summary ? null : 'execution_report_missing';
      receipt.test_execution.qualification_scope_complete = qualificationScopeComplete(
        invocation,
        summary,
        receipt.qualification_eligible,
      );
    } catch (error) {
      receipt.test_execution.summary = null;
      receipt.test_execution.qualification_scope_complete = false;
      receipt.test_execution.error_code = typeof error?.code === 'string'
        ? error.code
        : 'execution_report_invalid';
    }
    if (receipt.test_execution.report_present && !receipt.test_execution.report_sha256) {
      const metadata = lstatSync(executionReportPath);
      receipt.test_execution.report_sha256 = sha256File(executionReportPath);
      receipt.test_execution.report_size_bytes = metadata.size;
    }
  };
  const refreshFailureArtifactEvidence = () => {
    const required = controllerAttempted && (
      (Number.isInteger(controllerResult?.exitCode) && controllerResult.exitCode !== 0)
      || controllerTimedOut
      || Boolean(requestedSignal)
    );
    receipt.failure_artifacts.required = required;
    try {
      const inventory = boundedFailureArtifactInventory(artifactsDirectory);
      const present = inventory.trace_files > 0 || inventory.screenshot_files > 0;
      receipt.failure_artifacts.inventory = inventory;
      receipt.failure_artifacts.present = present;
      receipt.failure_artifacts.error_code = null;
      receipt.failure_artifacts_preserved = required ? present : null;
    } catch (error) {
      receipt.failure_artifacts.inventory = null;
      receipt.failure_artifacts.present = false;
      receipt.failure_artifacts.error_code = typeof error?.code === 'string'
        ? error.code
        : 'failure_artifact_inventory_failed';
      receipt.failure_artifacts_preserved = required ? false : null;
    }
  };
  const requestControllerStop = () => {
    if (!activeController || activeController.exitCode !== null || activeController.signalCode !== null) return;
    activeController.kill('SIGTERM');
    if (!controllerKillTimer) {
      controllerKillTimer = setTimeout(() => {
        if (activeController && activeController.exitCode === null && activeController.signalCode === null) {
          activeController.kill('SIGKILL');
        }
      }, 2_000);
    }
  };
  const signalHandlers = new Map();
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    const handler = () => {
      if (requestedSignal) return;
      requestedSignal = signal;
      receipt.outcome = { status: 'interrupted', exit_code: null, signal, error_code: 'runner_interrupted' };
      atomicWriteReceipt(receiptPath, receipt);
      requestControllerStop();
    };
    signalHandlers.set(signal, handler);
    process.on(signal, handler);
  }

  try {
    receipt.system.desktop = linuxHeadedDesktopEvidence();
    if (receipt.system.desktop.headed) {
      headedTransport = createHeadedX11Transport(receipt.system.desktop, runId, process.getuid?.(), process.getgid?.());
      receipt.system.desktop.transport = headedTransport.receipt;
      headedTransport.exitPromise.then(() => {
        if (!headedTransport.stopRequested) {
          headedTransportUnexpectedError = runnerError(
            headedTransport.relayFailureCode || 'headed_relay_exited',
            'The private X11 relay exited before browser qualification completed.',
          );
          requestControllerStop();
        }
      });
      atomicWriteReceipt(receiptPath, receipt);
      await headedTransport.readyPromise;
      assertHeadedX11TransportRunning(headedTransport);
    }
    atomicWriteReceipt(receiptPath, receipt);
    if (!existsSync(resolve(nodeModulesDirectory, '@playwright', 'test', 'cli.js'))) {
      throw runnerError('playwright_dependencies_missing', 'Locked Playwright dependencies are missing.');
    }
    if (realpathSync(nodeModulesDirectory) !== nodeModulesDirectory) {
      throw runnerError('playwright_dependencies_symlinked', 'Locked Playwright dependencies must not resolve through a symlink.');
    }
    if (!existsSync(resolve(webDistDirectory, 'index.html'))) {
      throw runnerError('web_distribution_missing', 'Built web distribution is missing.');
    }
    if (realpathSync(webDistDirectory) !== webDistDirectory) {
      throw runnerError('web_distribution_symlinked', 'Built web distribution must not resolve through a symlink.');
    }
    if (snapshotUpdate && (!existsSync(snapshotDirectory) || realpathSync(snapshotDirectory) !== snapshotDirectory)) {
      throw runnerError('snapshot_directory_invalid', 'Snapshot updates require the exact non-symlinked baseline directory.');
    }
    receipt.candidate = candidateEvidence();
    atomicWriteReceipt(receiptPath, receipt);
    if (invocation.qualificationEligible && !cpuReference.meets_reference_envelope) {
      throw runnerError(
        'insufficient_reference_cpus',
        `Qualification requires at least ${PLAYWRIGHT_OFFLINE_BROWSER_CPUS} available CPUs for the reference browser envelope.`,
      );
    }
    if (!cpuReference.meets_reference_envelope) {
      process.stderr.write(
        `NON-QUALIFYING CPU ENVELOPE: ${cpuReference.available_parallelism}/${cpuReference.reference_browser_cpus} available CPUs.\n`,
      );
    }
    const uid = process.getuid?.();
    const gid = process.getgid?.();
    if (!Number.isSafeInteger(uid) || !Number.isSafeInteger(gid)) {
      throw runnerError('numeric_identity_unavailable', 'Linux isolation requires a numeric host uid and gid.');
    }
    receipt.dependencies = playwrightDependencyGraphEvidence({
      suiteRoot: suiteDirectory,
      platform: process.platform,
    });

    const configuredFixturePort = process.env.KODESEC_PLAYWRIGHT_PORT || '41783';
    if (!/^\d{4,5}$/.test(configuredFixturePort)) {
      throw runnerError('invalid_fixture_port', 'Fixture port must be one explicit decimal port.');
    }
    const fixturePort = Number(configuredFixturePort);
    let wsPort = randomInt(20_000, 60_000);
    while (wsPort === fixturePort) wsPort = randomInt(20_000, 60_000);
    const wsPath = `/${runId}`;
    const wsEndpoint = exactPlaywrightWSEndpoint(`ws://127.0.0.1:${wsPort}${wsPath}`);
    const browserArguments = offlineBrowserServiceArguments({
      suiteDirectory,
      containerName: browserContainerName,
      wsPort,
      wsPath,
      uid,
      gid,
      desktop: receipt.system.desktop.headed ? receipt.system.desktop : null,
    });
    const controllerArguments = offlineControllerArguments({
      suiteDirectory,
      webDistDirectory,
      resultDirectory,
      browserContainerName,
      controllerContainerName,
      wsEndpoint,
      fixturePort,
      uid,
      gid,
      playwrightArguments,
      runnerMode: invocation.mode,
      snapshotDirectory,
      timingFactor: QUALIFICATION_TIMING_FACTOR,
      ...(CURRENT_TIMING_POLICY ? { timingPolicy: 'D-020',
        performancePlatform: process.env.LOMO_PLAYWRIGHT_PERFORMANCE_PLATFORM } : {}),
      headed: receipt.system.desktop.headed,
    });
    const imageResult = run('docker', [
      'image', 'inspect', '--format', '{{json .}}', PLAYWRIGHT_CONTAINER_IMAGE,
    ], {
      allowFailure: true,
      quiet: true,
      timeout: 30_000,
    });
    if (imageResult.status !== 0 || !imageResult.stdout?.trim()) {
      throw runnerError('playwright_image_missing', 'Pinned Playwright image is absent from the prepared offline cache.');
    }
    receipt.image = {
      requested_ref: PLAYWRIGHT_CONTAINER_IMAGE,
      ...summarizePlaywrightImageInspect(JSON.parse(imageResult.stdout)),
    };
    receipt.outcome.status = 'running';
    atomicWriteReceipt(receiptPath, receipt);

    if (headedTransport) assertHeadedX11TransportRunning(headedTransport);
    browserAttempted = true;
    run('docker', browserArguments, {
      quiet: true,
      timeout: 30_000,
      label: 'Pinned Playwright browser service start',
      errorCode: 'browser_start_failed',
    });
    await waitForBrowserServer(browserContainerName, wsEndpoint);
    const browserStartRaw = inspectContainerRaw(browserContainerName);
    const browserStart = browserStartRaw
      ? summarizePlaywrightContainerInspect(browserStartRaw, expectedTargets)
      : null;
    validateEffectiveIsolation('browser', browserStart, uid, gid, receipt.system.desktop);
    receipt.containers.browser.start = browserStart;
    attemptSample('browser-ready');
    if (requestedSignal) throw runnerError('runner_interrupted', 'Runner received a termination signal.');

    controllerAttempted = true;
    controllerTimeout = setTimeout(() => {
      controllerTimedOut = true;
      requestControllerStop();
    }, CONTROLLER_TIMEOUT_MS);
    const controllerPromise = startController(controllerArguments, (child) => {
      activeController = child;
    });
    const controllerObservation = await waitForContainerRunning(controllerContainerName, expectedTargets);
    const controllerStart = controllerObservation.summary;
    receipt.containers.controller.start = controllerStart;
    const browserAtControllerStart = inspectContainerRaw(browserContainerName);
    receipt.containers.controller.network_namespace = summarizePlaywrightControllerNetworkNamespace(
      controllerObservation.raw,
      browserAtControllerStart,
    );
    if (!receipt.containers.controller.network_namespace.verified) {
      throw runnerError(
        'controller_network_namespace_mismatch',
        'Playwright controller does not share the exact browser-service network namespace.',
      );
    }
    validateEffectiveIsolation('controller', controllerStart, uid, gid, receipt.system.desktop);
    attemptSample('controller-running');
    intervalSamplingStartedMonotonic = performance.now();
    sampleTimer = setInterval(recordScheduledInterval, RESOURCE_SAMPLE_INTERVAL_MS);
    controllerResult = await controllerPromise;
    if (headedTransportUnexpectedError) throw headedTransportUnexpectedError;
    if (headedTransport) assertHeadedX11TransportRunning(headedTransport);
    finalizeScheduledIntervals();
    if (sampleTimer) {
      clearInterval(sampleTimer);
      sampleTimer = null;
    }
    intervalSamplingStartedMonotonic = null;
    receipt.controller = {
      exit_code: controllerResult.exitCode,
      signal: controllerResult.signal,
      spawn_error: controllerResult.spawnError,
      timed_out: controllerTimedOut,
    };
    attemptSample('controller-completion');
    const browserCompletion = inspectContainer(browserContainerName, expectedTargets);
    receipt.containers.browser.completion = browserCompletion;
    refreshTestExecutionEvidence();
    atomicWriteReceipt(receiptPath, receipt);
    if (!playwrightBrowserCompletionHealthy(browserCompletion)) {
      throw runnerError(
        'browser_service_unhealthy_at_completion',
        'Pinned browser service was not healthy when the controller completed.',
      );
    }
    if (requestedSignal) throw runnerError('runner_interrupted', 'Runner received a termination signal.');
    if (controllerTimedOut) throw runnerError('controller_timeout', 'Playwright controller exceeded its fixed timeout.');
    if (controllerResult.spawnError) throw runnerError('controller_spawn_failed', 'Playwright controller could not be started.');
    if (controllerResult.exitCode !== 0) throw runnerError('playwright_tests_failed', 'Playwright tests failed.');
    if (!receipt.test_execution.summary) {
      throw runnerError(
        receipt.test_execution.error_code || 'execution_report_missing',
        'Playwright completed without a valid executed-test report.',
      );
    }
    if (
      invocation.qualificationEligible
      && !playwrightExecutionScopeComplete(invocation.scope, receipt.test_execution.summary)
    ) {
      throw runnerError('qualification_scope_unproven', 'Playwright report does not prove the complete qualification scope.');
    }
    verifyDesktopPostflight();
    receipt.outcome = { status: 'passed', exit_code: 0, signal: null, error_code: null };
  } catch (error) {
    primaryError = error;
    if (receipt.outcome.status !== 'interrupted') {
      receipt.outcome = {
        status: 'failed',
        exit_code: controllerResult?.exitCode ?? 1,
        signal: controllerResult?.signal ?? null,
        error_code: typeof error?.code === 'string' ? error.code : 'runner_failure',
      };
    }
  } finally {
    finalizeScheduledIntervals();
    if (sampleTimer) {
      clearInterval(sampleTimer);
      sampleTimer = null;
    }
    if (controllerTimeout) clearTimeout(controllerTimeout);
    if (controllerKillTimer) clearTimeout(controllerKillTimer);
    if (browserAttempted || controllerAttempted) {
      attemptSample('terminal-pre-stop');
    }
    if (samplingWindowStartedMonotonic !== null) {
      const samplingFinishedMonotonic = performance.now();
      receipt.resource_sampling.finished_elapsed_ms = Math.round(samplingFinishedMonotonic - startedMonotonic);
      receipt.resource_sampling.duration_ms = Math.round(
        samplingFinishedMonotonic - samplingWindowStartedMonotonic,
      );
      receipt.resource_sampling.cgroup_cpu_windows = {
        browser: summarizeCgroupCpuWindow(receipt.resource_sampling.samples, 'browser'),
        controller: summarizeCgroupCpuWindow(receipt.resource_sampling.samples, 'controller'),
      };
    }
    const stopResults = new Map();
    for (const [role, attempted, name] of [
      ['controller', controllerAttempted, controllerContainerName],
      ['browser', browserAttempted, browserContainerName],
    ]) {
      if (!attempted) continue;
      const stop = run('docker', playwrightContainerStopArguments(name), {
        allowFailure: true,
        quiet: true,
        timeout: 10_000,
      });
      stopResults.set(role, stop.status);
    }
    if (controllerAttempted) receipt.containers.controller.final = inspectContainer(controllerContainerName, expectedTargets);
    if (browserAttempted) receipt.containers.browser.final = inspectContainer(browserContainerName, expectedTargets);
    receipt.cleanup = cleanupContainers([
      { role: 'controller', name: controllerContainerName, attempted: controllerAttempted },
      { role: 'browser', name: browserContainerName, attempted: browserAttempted },
    ]).map((entry) => ({ ...entry, stop_exit_code: stopResults.get(entry.role) ?? null }));
    let cleanupFailed = receipt.cleanup.some((entry) => {
      if (!entry.attempted || entry.absent !== true) return entry.attempted && entry.absent !== true;
      const container = receipt.containers[entry.role];
      return container.start !== null && (
        entry.stop_exit_code !== 0
        || container.final === null
        || container.final.state.running !== false
      );
    });
    if (cleanupFailed) {
      receipt.outcome = {
        status: 'failed',
        exit_code: 1,
        signal: requestedSignal,
        error_code: 'container_cleanup_unproven',
      };
    }
    refreshTestExecutionEvidence();
    refreshFailureArtifactEvidence();
    if (receipt.system.desktop.terminal_verified !== true) {
      try {
        verifyDesktopPostflight();
      } catch (error) {
        receipt.system.desktop.terminal_verified = false;
        receipt.system.desktop.verified = false;
        receipt.system.desktop.postflight_error_code = typeof error?.code === 'string'
          ? error.code
          : 'headed_desktop_postflight_failed';
        if (!primaryError || receipt.outcome.status === 'passed') {
          primaryError = error;
          receipt.outcome = {
            status: 'failed',
            exit_code: 1,
            signal: requestedSignal,
            error_code: receipt.system.desktop.postflight_error_code,
          };
        }
      }
    }
    if (headedTransport) {
      await stopAndCleanHeadedX11Transport(headedTransport);
      const relayCleanupFailed = headedTransport.receipt.cleanup.verified !== true
        || headedTransport.receipt.child.exit_code !== 0
        || headedTransport.receipt.child.signal !== null
        || headedTransport.receipt.child.unexpected_exit === true;
      if (relayCleanupFailed) {
        cleanupFailed = true;
        receipt.outcome = {
          status: 'failed',
          exit_code: 1,
          signal: requestedSignal,
          error_code: headedTransport.receipt.cleanup.error_code || 'headed_relay_cleanup_unproven',
        };
      }
    }
    receipt.qualification_eligible = invocation.qualificationEligible
      && receipt.outcome.status === 'passed'
      && receipt.system.desktop.headed === true
      && receipt.system.desktop.verified === true
      && receipt.system.desktop.terminal_verified === true;
    receipt.test_execution.qualification_scope_complete = qualificationScopeComplete(
      invocation,
      receipt.test_execution.summary,
      receipt.qualification_eligible,
    );
    receipt.resource_sampling.host_pressure_end = hostPressure();
    receipt.finished_at = new Date().toISOString();
    receipt.duration_ms = Math.round(performance.now() - startedMonotonic);
    atomicWriteReceipt(receiptPath, receipt);
    for (const [signal, handler] of signalHandlers) process.removeListener(signal, handler);
    process.stdout.write(`Offline Playwright terminal receipt: ${receiptPath}\n`);

    if (cleanupFailed) {
      primaryError = runnerError(
        receipt.outcome.error_code || 'container_cleanup_unproven',
        'Exact Playwright container and headed-desktop transport cleanup could not be proven.',
      );
    }
  }

  if (primaryError) {
    process.stderr.write(`Offline Playwright failed: ${receipt.outcome.error_code}. Inspect the terminal receipt for verified failure evidence.\n`);
    if (requestedSignal && receipt.outcome.error_code !== 'container_cleanup_unproven') {
      const signalExitCodes = { SIGHUP: 129, SIGINT: 130, SIGTERM: 143 };
      process.exitCode = signalExitCodes[requestedSignal] || 1;
    } else {
      process.exitCode = 1;
    }
  }
}

function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    return sameResolvedPath(
      realpathSync(process.argv[1]),
      realpathSync(fileURLToPath(import.meta.url)),
      process.platform,
    );
  } catch {
    return false;
  }
}

async function main() {
  if (process.env.KODESEC_PLAYWRIGHT_WS_ENDPOINT) {
    throw new Error('KODESEC_PLAYWRIGHT_WS_ENDPOINT is owned by the repository offline runner and may not be supplied by the host.');
  }
  const runnerKind = playwrightRunnerKind(process.platform);
  if (snapshotUpdate && runnerKind === 'local') {
    throw new Error('The internal offline snapshot-update mode is Linux-only; use the local update wrapper on this platform.');
  }
  if (runnerKind === 'local') {
    const localResult = await runLocalFallback();
    if (localResult.exitCode !== 0) process.exitCode = localResult.exitCode;
  } else {
    await runOfflineContainers();
  }
}

if (isMainModule()) {
  if (internalX11RelayMode) await runInternalX11Relay();
  else await main();
}
