import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { snapshotUpdateRunnerArguments } from './compose-harness-lib.mjs';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const suiteDirectory = resolve(scriptDirectory, '..');
const extraArguments = process.argv.slice(2);
if (process.env.KODESEC_PLAYWRIGHT_WS_ENDPOINT) {
  throw new Error('KODESEC_PLAYWRIGHT_WS_ENDPOINT is runner-owned and may not be supplied to snapshot updates.');
}

const command = snapshotUpdateRunnerArguments({
  platform: process.platform,
  scriptsDirectory: scriptDirectory,
  extraArguments,
});
const result = spawnSync(process.execPath, [command.runner, ...command.arguments], {
  cwd: suiteDirectory,
  env: process.env,
  stdio: 'inherit',
});

if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
