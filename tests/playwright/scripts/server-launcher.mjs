import { spawn } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const suiteDirectory = realpathSync(resolve(scriptDirectory, '..'));
const serverPath = resolve(suiteDirectory, 'server.mjs');
const TERMINATION_GRACE_MS = 2_000;
const SIGNAL_EXIT_CODES = Object.freeze({ SIGHUP: 129, SIGINT: 130, SIGTERM: 143 });

export function sanitizedFixtureServerEnvironment(hostEnvironment) {
  const port = hostEnvironment?.KODESEC_PLAYWRIGHT_PORT;
  if (typeof port !== 'string' || !/^\d{4,5}$/.test(port)) {
    throw new Error('Fixture server launcher requires one explicit decimal port.');
  }
  const numericPort = Number(port);
  if (!Number.isInteger(numericPort) || numericPort < 1024 || numericPort > 65535) {
    throw new Error('Fixture server launcher port is outside the allowed range.');
  }
  return { KODESEC_PLAYWRIGHT_PORT: String(numericPort) };
}

export function fixtureServerSpawnOptions(hostEnvironment) {
  return {
    cwd: suiteDirectory,
    env: sanitizedFixtureServerEnvironment(hostEnvironment),
    stdio: 'inherit',
  };
}

function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

async function main() {
  const child = spawn(process.execPath, [serverPath], fixtureServerSpawnOptions(process.env));
  let requestedSignal = null;
  let killTimer = null;
  const requestStop = (signal) => {
    if (requestedSignal) return;
    requestedSignal = signal;
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.kill('SIGTERM');
    if (!killTimer) {
      killTimer = setTimeout(() => {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      }, TERMINATION_GRACE_MS);
    }
  };
  const handlers = new Map();
  for (const signal of Object.keys(SIGNAL_EXIT_CODES)) {
    const handler = () => requestStop(signal);
    handlers.set(signal, handler);
    process.on(signal, handler);
  }
  // Playwright owns the write end of this pipe even when its web server is
  // detached. Losing that owner must stop our exact child after CLI death.
  const ownerClosed = () => requestStop('SIGTERM');
  for (const event of ['end', 'close', 'error']) process.stdin.on(event, ownerClosed);
  process.stdin.resume();
  const result = await new Promise((resolveChild) => {
    let spawnError = false;
    child.once('error', () => { spawnError = true; });
    child.once('close', (exitCode, signal) => resolveChild({ exitCode, signal, spawnError }));
  });
  if (killTimer) clearTimeout(killTimer);
  for (const [signal, handler] of handlers) process.removeListener(signal, handler);
  for (const event of ['end', 'close', 'error']) process.stdin.removeListener(event, ownerClosed);
  // A live parent's writer must not keep this launcher alive after its child
  // has been reaped. Close only our own read endpoint.
  process.stdin.pause();
  process.stdin.destroy();
  if (requestedSignal) process.exitCode = SIGNAL_EXIT_CODES[requestedSignal];
  else if (result.spawnError) process.exitCode = 1;
  else if (Number.isInteger(result.exitCode)) process.exitCode = result.exitCode;
  else process.exitCode = result.signal ? 1 : 0;
}

if (isMainModule()) await main();
