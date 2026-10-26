import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { createConnection } from 'node:net';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import {
  availableLoopbackPort,
  CORE_SERVICES,
  PLAYWRIGHT_CONTAINER_IMAGE,
  PLAYWRIGHT_ALLOWED_PROJECTS,
  PLAYWRIGHT_COMPOSE_SPEC,
  PLAYWRIGHT_EXECUTION_REPORT,
  PLAYWRIGHT_RAW_EXECUTION_REPORT,
  composeArguments,
  composeImageInspectArguments,
  createPlaywrightResultDirectory,
  coreContainerRecoveryReady,
  exactLoopbackBaseURL,
  exactScannerImage,
  isolatedComposeEnvironment,
  parseEnvironment,
  playwrightContainerArguments,
  playwrightExecutionScopeComplete,
  playwrightRunnerKind,
  runPlaywrightWithExecutionPublication,
  replaceEnvironmentFields,
  sanitizedCommand,
  summarizePlaywrightJsonReport,
  unexpectedCoreContainerExitArguments,
  unexpectedCoreContainerExitStatusAccepted,
  validateIdentifiers,
} from './compose-harness-lib.mjs';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const suiteDirectory = realpathSync(resolve(scriptDirectory, '..'));
const repository = realpathSync(resolve(suiteDirectory, '..', '..'));
const { runId, resultDirectory } = createPlaywrightResultDirectory({
  suiteRoot: suiteDirectory,
  resultKind: 'compose',
});
const stateDirectory = resolve(repository, '.kodesec-test', 'playwright-compose', runId);
const stateParent = resolve(repository, '.kodesec-test', 'playwright-compose');
const runtimeEnvironment = resolve(stateDirectory, 'runtime.env');
const fixtureRepository = resolve(stateDirectory, 'fixture', 'repository');
const ledgerFixtureRepository = resolve(fixtureRepository, 'ledger-disposable');
const storageState = resolve(stateDirectory, 'browser-state.json');
const projectName = `lomo-code-security-${runId}`;
const controlImage = `lomo-kodesec-control:${runId}`;
const browserContainerName = `${projectName}-browser`;
let composeStarted = false;
let cleanupStarted = false;
let composeProcessEnvironment = process.env;
let browserContainerAttempted = false;
let browserImagePresentInitially = true;
const OPTIONAL_SERVICES = Object.freeze(['gitea', 'prometheus', 'grafana', 'adminer']);
const OPTIONAL_PORTS = Object.freeze([3000, 2222, 9090, 3001, 8082]);
const OPTIONAL_VOLUMES = Object.freeze(['gitea_data', 'gitea_config', 'prometheus_data', 'grafana_data']);

if (!stateDirectory.startsWith(`${stateParent}${sep}`)) throw new Error('Generated Compose state escaped its private parent.');
validateIdentifiers(projectName, controlImage);

function run(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: options.cwd || repository,
    env: options.env || process.env,
    encoding: 'utf8',
    stdio: options.quiet ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    timeout: options.timeout || 600_000,
  });
  if (result.error) {
    if (options.allowFailure) return result;
    throw result.error;
  }
  if (result.status !== 0 && !options.allowFailure) {
    const command = program === 'docker' ? sanitizedCommand(args) : `${program} <arguments omitted>`;
    const detail = options.quiet ? `: ${(result.stderr || result.stdout || '').trim().slice(0, 600)}` : '';
    throw new Error(`Command failed (${result.status ?? 'signal'}): ${command}${detail}`);
  }
  return result;
}

function compose(...command) {
  return run('docker', composeArguments({ repository, runtimeEnvironment, projectName }, ...command), {
    env: composeProcessEnvironment,
    timeout: 1_800_000,
  });
}

function composeBuild(...command) {
  return run(
    resolve(repository, 'scripts', 'compose-build.sh'),
    ['docker', ...composeArguments({ repository, runtimeEnvironment, projectName }, ...command)],
    { env: composeProcessEnvironment, timeout: 1_800_000 },
  );
}

function applyComponents(componentSet) {
  if (!['all', 'core'].includes(componentSet)) throw new Error('Compose action receipt accepts only full or core reconciliation.');
  run('make', [
    'apply-components',
    `COMPONENTS=${componentSet}`,
    `STATE_DIR=${stateDirectory}`,
    `RUNTIME_ENV=${runtimeEnvironment}`,
  ], { env: composeProcessEnvironment, timeout: 1_800_000 });
}

function optionalContainerStates() {
  return OPTIONAL_SERVICES.map((service) => {
    const name = `${projectName}-${service}-1`;
    const inspected = run('docker', ['container', 'inspect', '--format', '{{json .State}}', name], {
      allowFailure: true,
      quiet: true,
      timeout: 30_000,
    });
    if (inspected.status !== 0) return { service, present: false, running: false, status: 'absent' };
    const state = JSON.parse(inspected.stdout);
    return { service, present: true, running: state.Running === true, status: state.Status };
  });
}

function optionalVolumeEvidence() {
  return OPTIONAL_VOLUMES.map((volume) => {
    const name = `${projectName}_${volume}`;
    const inspected = run('docker', ['volume', 'inspect', '--format', '{{json .}}', name], {
      quiet: true,
      timeout: 30_000,
    });
    const detail = JSON.parse(inspected.stdout);
    if (detail?.Name !== name || detail?.Labels?.['com.docker.compose.project'] !== projectName) {
      throw new Error(`Optional volume identity is outside the generated Compose project: ${volume}.`);
    }
    return { volume, name: detail.Name, created_at: detail.CreatedAt };
  });
}

function loopbackPortOpen(port) {
  return new Promise((resolveOpen) => {
    const socket = createConnection({ host: '127.0.0.1', port });
    const finish = (open) => {
      socket.destroy();
      resolveOpen(open);
    };
    socket.setTimeout(1_000, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

async function waitForOptionalPorts(expectedOpen, timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const states = await Promise.all(OPTIONAL_PORTS.map((port) => loopbackPortOpen(port)));
    if (states.every((open) => open === expectedOpen)) {
      return OPTIONAL_PORTS.map((port, index) => ({ port, open: states[index] }));
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 500));
  }
  throw new Error(`Optional loopback listeners did not become ${expectedOpen ? 'ready' : 'closed'} before timeout.`);
}

function cleanup() {
  if (cleanupStarted) return;
  cleanupStarted = true;
  let teardownSucceeded = !composeStarted;
  if (composeStarted) {
    const teardown = run('docker', composeArguments(
      { repository, runtimeEnvironment, projectName },
      'down', '--volumes', '--remove-orphans', '--rmi', 'local', '--timeout', '15',
    ), { allowFailure: true, env: composeProcessEnvironment, timeout: 120_000 });
    teardownSucceeded = teardown.status === 0;
    if (teardownSucceeded) {
      const imageCleanup = run('docker', ['image', 'rm', controlImage], { allowFailure: true, quiet: true, timeout: 60_000 });
      if (imageCleanup.status !== 0) {
        const imageStillExists = run('docker', ['image', 'inspect', controlImage], {
          allowFailure: true,
          quiet: true,
          timeout: 30_000,
        });
        if (imageStillExists.status === 0) {
          process.stderr.write(`Project containers and volumes were removed, but image cleanup must be checked for ${controlImage}.\n`);
        }
      }
    } else {
      process.stderr.write(`Compose teardown failed for ${projectName}; owner-only recovery state was retained at ${stateDirectory}\n`);
    }
  }
  if (browserContainerAttempted) {
    run('docker', ['container', 'rm', '--force', browserContainerName], {
      allowFailure: true,
      quiet: true,
      timeout: 30_000,
    });
  }
  if (browserContainerAttempted && !browserImagePresentInitially) {
    const imageCleanup = run('docker', ['image', 'rm', PLAYWRIGHT_CONTAINER_IMAGE], {
      allowFailure: true,
      quiet: true,
      timeout: 60_000,
    });
    if (imageCleanup.status !== 0) {
      const imageStillExists = run('docker', ['image', 'inspect', PLAYWRIGHT_CONTAINER_IMAGE], {
        allowFailure: true,
        quiet: true,
        timeout: 30_000,
      });
      if (imageStillExists.status === 0) {
        process.stderr.write(`The browser image was absent initially but cleanup must be checked for ${PLAYWRIGHT_CONTAINER_IMAGE}.\n`);
      }
    }
  }
  if (teardownSucceeded && stateDirectory.startsWith(`${stateParent}${sep}`)) rmSync(stateDirectory, { recursive: true, force: true });
}

for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.once(signal, () => {
    cleanup();
    process.kill(process.pid, signal);
  });
}

function configureRuntime(port) {
  const initialized = readFileSync(runtimeEnvironment, 'utf8');
  const updated = replaceEnvironmentFields(initialized, {
    COMPOSE_PROJECT_NAME: projectName,
    KODESEC_CONTROL_IMAGE: controlImage,
    CONTROL_PORT: String(port),
    KODESEC_REPO_ROOT: fixtureRepository,
    KODESEC_ALLOWED_ROOTS: fixtureRepository,
    KODESEC_AI_MODE: 'off',
    KODESEC_AUTO_TRIAGE_LIMIT: '0',
  });
  writeFileSync(runtimeEnvironment, updated, { encoding: 'utf8', mode: 0o600 });
  chmodSync(runtimeEnvironment, 0o600);
  const fields = parseEnvironment(updated);
  validateIdentifiers(fields.get('COMPOSE_PROJECT_NAME') || '', fields.get('KODESEC_CONTROL_IMAGE') || '');
  exactScannerImage(fields.get('KODESEC_SCANNER_IMAGE') || '');
  if (fields.get('CONTROL_PORT') !== String(port)) throw new Error('Runtime control port was not isolated.');
  if (fields.get('KODESEC_REPO_ROOT') !== fixtureRepository || fields.get('KODESEC_ALLOWED_ROOTS') !== fixtureRepository) {
    throw new Error('Runtime source boundary does not match the generated fixture.');
  }
  return fields;
}

async function waitForHealth(baseURL, timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;
  let lastStatus = 'not reachable';
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseURL}/healthz`, { redirect: 'error', signal: AbortSignal.timeout(3_000) });
      lastStatus = `HTTP ${response.status}`;
      if (response.ok) {
        const health = await response.json();
        if (health?.ok === true && health?.db === true && health?.scanner === true && health?.worker === true) return;
        lastStatus = 'HTTP 200 with an unhealthy dependency';
      }
    } catch (error) {
      lastStatus = error instanceof Error ? error.name : 'network error';
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 500));
  }
  throw new Error(`Control plane did not become healthy before timeout (${lastStatus}).`);
}

function recoveryState(service) {
  const containerName = `${projectName}-${service}-1`;
  const result = run('docker', ['container', 'inspect', '--format', '{{json .}}', containerName], {
    quiet: true,
    timeout: 30_000,
  });
  const inspect = JSON.parse(result.stdout);
  const state = inspect?.State;
  const snapshot = {
    id: inspect?.Id,
    name: inspect?.Name,
    restartCount: inspect?.RestartCount,
    running: state?.Running,
    health: state?.Health?.Status,
  };
  if (
    typeof snapshot.id !== 'string'
    || !/^[a-f0-9]{64}$/.test(snapshot.id)
    || snapshot.name !== `/${containerName}`
    || !Number.isSafeInteger(snapshot.restartCount)
    || snapshot.restartCount < 0
    || typeof snapshot.running !== 'boolean'
    || !['starting', 'healthy', 'unhealthy'].includes(snapshot.health)
  ) throw new Error(`Invalid recovery state for ${service}.`);
  return snapshot;
}

async function waitForRestart(service, before, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const after = recoveryState(service);
    if (coreContainerRecoveryReady(before, after)) return after;
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error(`${service} did not restart healthy after an internally signalled process exit.`);
}

async function verifyForcedRecovery(baseURL, service) {
  const before = recoveryState(service);
  const started = performance.now();
  const containerName = `${projectName}-${service}-1`;
  const exitResult = run('docker', unexpectedCoreContainerExitArguments(containerName), {
    allowFailure: service === 'postgres',
    timeout: 30_000,
  });
  if (exitResult.error) throw exitResult.error;
  if (exitResult.signal) throw new Error(`${service} recovery command was interrupted by an unexpected signal.`);
  if (!unexpectedCoreContainerExitStatusAccepted(containerName, exitResult.status)) {
    throw new Error(`${service} recovery command returned unexpected status ${exitResult.status ?? 'signal'}.`);
  }
  // The signal is delivered asynchronously. Prove Docker observed the exit
  // before accepting a health response that may have raced ahead of it.
  const restarted = await waitForRestart(service, before);
  await waitForHealth(baseURL);
  const after = recoveryState(service);
  if (
    !coreContainerRecoveryReady(before, after)
    || after.restartCount !== restarted.restartCount
  ) {
    throw new Error(
      `${service} restart evidence regressed after recovery: ${JSON.stringify({ before, restarted, after })}`,
    );
  }
  return Math.round(performance.now() - started);
}

async function apiRequest(baseURL, path, { method = 'GET', capability, data, idempotencyKey, operator } = {}) {
  const headers = { Accept: 'application/json', Origin: baseURL };
  if (capability) headers.Authorization = `Bearer ${capability}`;
  if (operator) {
    headers.Cookie = operator.cookie;
    if (method !== 'GET') headers['X-CSRF-Token'] = operator.csrfToken;
  }
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
  if (data !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(`${baseURL}${path}`, {
    method,
    headers,
    body: data === undefined ? undefined : JSON.stringify(data),
    redirect: 'error',
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`${method} ${path} failed with HTTP ${response.status}.`);
  return response.json();
}

async function seedState(baseURL, operator) {
  const enrollment = await apiRequest(baseURL, '/v1/auth/ide/enrollments', {
    method: 'POST',
    data: {
      client_name: 'Repository Playwright Compose smoke',
      client_slot: `ks1_${'c'.repeat(43)}`,
      expected_active_generation: 0,
    },
  });
  const capability = typeof enrollment.capability === 'string' ? enrollment.capability : '';
  if (!capability.startsWith('kc1.')) throw new Error('The isolated IDE capability was not issued.');
  if (!/^ker1_[A-Za-z0-9_-]{24}$/.test(enrollment.request_id)) {
    throw new Error('The isolated IDE enrollment request identity was invalid.');
  }
  const approved = await apiRequest(
    baseURL,
    `/v1/auth/ide/enrollments/${encodeURIComponent(enrollment.request_id)}/decision`,
    {
      method: 'POST',
      operator,
      data: {
        decision: 'approved',
        expected_revision: enrollment.revision,
        expected_generation: enrollment.generation,
      },
    },
  );
  if (approved.state !== 'approved') throw new Error('The isolated IDE enrollment was not approved.');
  const activated = await apiRequest(baseURL, '/v1/auth/ide/activate', {
    method: 'POST',
    capability,
  });
  if (activated.generation !== enrollment.generation) throw new Error('The isolated IDE capability was not activated.');

  const tools = await apiRequest(baseURL, '/v1/scanner/tools', { operator });
  for (const tool of tools) {
    await apiRequest(baseURL, `/v1/scanner/tools/${encodeURIComponent(tool.id)}`, {
      method: 'PATCH', operator, data: { enabled: tool.id === 'sast-lite' },
    });
  }
  const project = await apiRequest(baseURL, '/v1/projects', {
    method: 'POST',
    capability,
    data: {
      name: 'Generated Compose Smoke Project',
      repo_path: fixtureRepository,
      default_branch: 'main',
    },
  });
  const scan = await apiRequest(baseURL, '/v1/scans', {
    method: 'POST',
    capability,
    idempotencyKey: `compose-${runId}-scan`,
    data: { project_id: project.id, mode: 'full', use_ai: false },
  });
  const deadline = Date.now() + 60_000;
  let storedScan = scan;
  while (!['completed', 'partial', 'failed'].includes(storedScan.status) && Date.now() < deadline) {
    await new Promise((resolveWait) => setTimeout(resolveWait, 250));
    storedScan = await apiRequest(baseURL, `/v1/scans/${scan.id}`, { capability });
  }
  if (storedScan.status !== 'completed') throw new Error(`Generated scan reached unexpected state: ${storedScan.status}.`);
  return { capability, projectId: project.id, scanId: scan.id };
}

async function createBrowserState(baseURL, bootstrapToken) {
  if (!bootstrapToken) throw new Error('Generated browser bootstrap material is missing.');
  const { request } = await import('playwright');
  const context = await request.newContext({ baseURL, extraHTTPHeaders: { Origin: baseURL } });
  try {
    const response = await context.post('/v1/auth/bootstrap', { data: { bootstrap_token: bootstrapToken } });
    if (!response.ok()) throw new Error(`Browser bootstrap failed with HTTP ${response.status()}.`);
    const payload = await response.json();
    const state = await context.storageState({ path: storageState });
    chmodSync(storageState, 0o600);
    const cookie = state.cookies.map((item) => `${item.name}=${item.value}`).join('; ');
    const csrfToken = typeof payload.csrf_token === 'string' ? payload.csrf_token : '';
    if (!cookie || !csrfToken) throw new Error('Browser operator session was not persisted exactly.');
    return { cookie, csrfToken };
  } finally {
    await context.dispose();
  }
}

async function verifyPersistence(baseURL, seeded) {
  const project = await apiRequest(baseURL, '/v1/projects/resolve', {
    method: 'POST',
    capability: seeded.capability,
    data: { repo_path: fixtureRepository },
  });
  const scan = await apiRequest(baseURL, `/v1/scans/${seeded.scanId}`, { capability: seeded.capability });
  if (project.id !== seeded.projectId) throw new Error('Generated project was not durable across service recovery.');
  if (!scan || scan.status !== 'completed') throw new Error('Completed generated scan was not durable across service recovery.');
}

async function verifyPostRecoveryWork(baseURL, seeded) {
  const scan = await apiRequest(baseURL, '/v1/scans', {
    method: 'POST',
    capability: seeded.capability,
    idempotencyKey: `compose-${runId}-post-recovery-scan`,
    data: { project_id: seeded.projectId, mode: 'full', use_ai: false },
  });
  const deadline = Date.now() + 60_000;
  let storedScan = scan;
  while (!['completed', 'partial', 'failed'].includes(storedScan.status) && Date.now() < deadline) {
    await new Promise((resolveWait) => setTimeout(resolveWait, 250));
    storedScan = await apiRequest(baseURL, `/v1/scans/${scan.id}`, { capability: seeded.capability });
  }
  if (storedScan.status !== 'completed') {
    throw new Error(`Post-recovery scan reached unexpected state: ${storedScan.status}.`);
  }
}

async function verifyFullToCoreHostReconciliation(baseURL, seeded, operator) {
  applyComponents('all');
  const fullPorts = await waitForOptionalPorts(true);
  const fullContainers = optionalContainerStates();
  if (!fullContainers.every((container) => container.present && container.running && container.status === 'running')) {
    throw new Error(`Full component profile did not start every optional service: ${JSON.stringify(fullContainers)}.`);
  }
  const volumesBeforeCore = optionalVolumeEvidence();

  applyComponents('core');
  const corePorts = await waitForOptionalPorts(false);
  const coreContainers = optionalContainerStates();
  if (coreContainers.some((container) => container.present || container.running)) {
    throw new Error(`Core component profile left an optional service container present: ${JSON.stringify(coreContainers)}.`);
  }
  const volumesAfterCore = optionalVolumeEvidence();
  if (JSON.stringify(volumesAfterCore) !== JSON.stringify(volumesBeforeCore)) {
    throw new Error('Core component reconciliation replaced or removed an optional persistent volume.');
  }
  await waitForHealth(baseURL);
  await verifyPersistence(baseURL, seeded);
  await verifyPostRecoveryWork(baseURL, seeded);
  const config = await apiRequest(baseURL, '/v1/config', { operator });
  if (
    config.component_monitoring_enabled !== false
    || config.component_git_proxy_enabled !== false
    || config.component_db_admin_enabled !== false
    || config.component_apply_command !== 'make apply-components COMPONENTS=core'
  ) throw new Error('Dashboard component preference did not remain on the lean core profile.');
  const optionalComponents = Array.isArray(config.components)
    ? config.components.filter((component) => component?.required !== true)
    : [];
  if (
    optionalComponents.length === 0
    || optionalComponents.some((component) => (
      component.desired_state !== 'disabled'
      || !['disabled', 'not_observed'].includes(component.observed_state)
      || /errno|name or service not known/iu.test(component.message || '')
    ))
  ) throw new Error('Dashboard did not present stopped optional services as neutral desired-off state.');
  return {
    schema: 'lomo-compose-component-reconciliation/v1',
    full: { command: 'make apply-components COMPONENTS=all', containers: fullContainers, listeners: fullPorts },
    core: { command: 'make apply-components COMPONENTS=core', containers: coreContainers, listeners: corePorts },
    volumes_preserved: volumesAfterCore,
    dashboard: {
      apply_command: config.component_apply_command,
      optional_components: optionalComponents.map((component) => ({
        id: component.id,
        desired_state: component.desired_state,
        observed_state: component.observed_state,
      })),
    },
    core_health_ready: true,
    post_core_scan_completed: true,
  };
}

function runBrowserSuite(baseURL) {
  if (playwrightRunnerKind(process.platform) === 'local') {
    run(process.execPath, [resolve(suiteDirectory, 'scripts', 'playwright.mjs'), 'test'], {
      cwd: suiteDirectory,
      env: {
        ...process.env,
        KODESEC_PLAYWRIGHT_MODE: 'compose',
        KODESEC_COMPOSE_BASE_URL: baseURL,
        KODESEC_COMPOSE_STORAGE_STATE: storageState,
        KODESEC_PLAYWRIGHT_RESULT_DIR: resultDirectory,
      },
      timeout: 600_000,
    });
    return;
  }
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  browserImagePresentInitially = run('docker', ['image', 'inspect', PLAYWRIGHT_CONTAINER_IMAGE], {
    allowFailure: true,
    quiet: true,
    timeout: 30_000,
  }).status === 0;
  browserContainerAttempted = true;
  run('docker', playwrightContainerArguments({
    suiteDirectory,
    resultDirectory,
    storageState,
    baseURL,
    containerName: browserContainerName,
    uid,
    gid,
  }), { cwd: suiteDirectory, timeout: 600_000 });
}

async function main() {
  const metrics = {
    run_id: runId,
    build_and_startup_ms: 0,
    seed_scan_ms: 0,
    post_recovery_scan_ms: 0,
    forced_recovery_ms: {},
    resources: [],
    images: [],
  };
  mkdirSync(fixtureRepository, { recursive: true, mode: 0o700 });
  chmodSync(fixtureRepository, 0o755);
  writeFileSync(
    resolve(fixtureRepository, 'generated.js'),
    'export function evaluateGeneratedInput(generatedInput) {\n  return eval(generatedInput);\n}\n',
    { encoding: 'utf8', mode: 0o644 },
  );
  mkdirSync(ledgerFixtureRepository, { recursive: true, mode: 0o700 });
  chmodSync(ledgerFixtureRepository, 0o755);
  writeFileSync(
    resolve(ledgerFixtureRepository, 'ledger-generated.js'),
    'export function evaluateLedgerInput(ledgerInput) {\n  return eval(ledgerInput);\n}\n',
    { encoding: 'utf8', mode: 0o644 },
  );
  run(resolve(repository, 'scripts', 'init-runtime.sh'), [], {
    env: {
      ...process.env,
      KODESEC_STATE_DIR: stateDirectory,
      KODESEC_RUNTIME_ENV: runtimeEnvironment,
      KODESEC_ALLOW_TEST_STATE: '1',
    },
    timeout: 60_000,
  });
  const port = await availableLoopbackPort();
  const baseURL = exactLoopbackBaseURL(`http://127.0.0.1:${port}`);
  const fields = configureRuntime(port);
  composeProcessEnvironment = isolatedComposeEnvironment(process.env, fields);

  composeStarted = true;
  const startupStarted = performance.now();
  composeBuild('up', '--detach', '--build', ...CORE_SERVICES);
  await waitForHealth(baseURL);
  metrics.build_and_startup_ms = Math.round(performance.now() - startupStarted);
  const operator = await createBrowserState(baseURL, fields.get('KODESEC_BOOTSTRAP_TOKEN'));
  const scanStarted = performance.now();
  const seeded = await seedState(baseURL, operator);
  metrics.seed_scan_ms = Math.round(performance.now() - scanStarted);

  for (const service of ['scanner', 'api', 'api-ingress', 'postgres']) {
    metrics.forced_recovery_ms[service] = await verifyForcedRecovery(baseURL, service);
  }
  await verifyPersistence(baseURL, seeded);
  const recoveryScanStarted = performance.now();
  await verifyPostRecoveryWork(baseURL, seeded);
  metrics.post_recovery_scan_ms = Math.round(performance.now() - recoveryScanStarted);

  const containerNames = CORE_SERVICES.map((service) => `${projectName}-${service}-1`);
  const stats = run('docker', ['stats', '--no-stream', '--format', '{{json .}}', ...containerNames], {
    quiet: true,
    timeout: 30_000,
  });
  metrics.resources = stats.stdout.trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
  const imageData = run('docker', composeImageInspectArguments(
    controlImage,
    fields.get('KODESEC_SCANNER_IMAGE') || '',
  ), { quiet: true, timeout: 30_000 });
  metrics.images = imageData.stdout.trim().split(/\r?\n/).filter(Boolean).map((line) => {
    const image = JSON.parse(line);
    return { id: image.Id, repo_tags: image.RepoTags, size_bytes: image.Size };
  });
  writeFileSync(resolve(resultDirectory, 'compose-metrics.json'), `${JSON.stringify(metrics, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });

  const publishedExecutionReport = runPlaywrightWithExecutionPublication({
    runPlaywright: () => runBrowserSuite(baseURL),
    rawPath: resolve(resultDirectory, PLAYWRIGHT_RAW_EXECUTION_REPORT),
    retainedPath: resolve(resultDirectory, PLAYWRIGHT_EXECUTION_REPORT),
    scope: {
      allowedSpecs: [PLAYWRIGHT_COMPOSE_SPEC],
      allowedProjects: PLAYWRIGHT_ALLOWED_PROJECTS,
    },
  });
  if (!publishedExecutionReport) {
    throw new Error('Compose Playwright completed without raw execution evidence.');
  }
  const executionSummary = summarizePlaywrightJsonReport(JSON.parse(readFileSync(
    resolve(resultDirectory, PLAYWRIGHT_EXECUTION_REPORT),
    'utf8',
  )), {
    allowedSpecs: [PLAYWRIGHT_COMPOSE_SPEC],
    allowedProjects: PLAYWRIGHT_ALLOWED_PROJECTS,
  });
  if (!playwrightExecutionScopeComplete({
    specs: [PLAYWRIGHT_COMPOSE_SPEC],
    projects: PLAYWRIGHT_ALLOWED_PROJECTS,
  }, executionSummary)) {
    throw new Error('Compose Playwright execution evidence does not cover its exact qualification scope.');
  }
  metrics.component_reconciliation = await verifyFullToCoreHostReconciliation(baseURL, seeded, operator);
  writeFileSync(
    resolve(resultDirectory, 'component-reconciliation-receipt.json'),
    `${JSON.stringify(metrics.component_reconciliation, null, 2)}\n`,
    { encoding: 'utf8', mode: 0o600 },
  );
  metrics.browser_execution_report = publishedExecutionReport;
  writeFileSync(resolve(resultDirectory, 'compose-metrics.json'), `${JSON.stringify(metrics, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  process.stdout.write(`Compose smoke passed; browser artifacts: ${resultDirectory}\n`);
}

try {
  await main();
} finally {
  cleanup();
}
