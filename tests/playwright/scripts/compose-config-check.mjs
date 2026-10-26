import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const suiteDirectory = resolve(scriptDirectory, '..');
const stateDirectory = mkdtempSync(join(tmpdir(), 'lomo-compose-config-'));
const storageState = resolve(stateDirectory, 'storage-state.json');
writeFileSync(storageState, '{"cookies":[],"origins":[]}\n', { encoding: 'utf8', mode: 0o600 });

try {
  const result = spawnSync(process.execPath, [resolve(scriptDirectory, 'playwright.mjs'), 'test', '--list'], {
    cwd: suiteDirectory,
    env: {
      ...process.env,
      KODESEC_PLAYWRIGHT_MODE: 'compose',
      KODESEC_COMPOSE_BASE_URL: 'http://127.0.0.1:43123',
      KODESEC_COMPOSE_STORAGE_STATE: storageState,
      KODESEC_PLAYWRIGHT_RESULT_DIR: resolve(stateDirectory, 'results'),
    },
    stdio: 'inherit',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exitCode = result.status ?? 1;
} finally {
  rmSync(stateDirectory, { recursive: true, force: true });
}
