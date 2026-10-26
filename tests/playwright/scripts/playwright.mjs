import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const suiteDirectory = resolve(scriptDirectory, '..');
const cli = resolve(suiteDirectory, 'node_modules', '@playwright', 'test', 'cli.js');
const containerMode = process.env.KODESEC_PLAYWRIGHT_BROWSER_CONTAINER === '1';
if (containerMode && process.env.PLAYWRIGHT_BROWSERS_PATH !== '/ms-playwright') {
  throw new Error('The Playwright browser container must use its pinned /ms-playwright browser tree.');
}
const browsers = containerMode ? '/ms-playwright' : resolve(suiteDirectory, '.browsers');
const result = spawnSync(process.execPath, [cli, ...process.argv.slice(2)], {
  cwd: suiteDirectory,
  env: { ...process.env, PLAYWRIGHT_BROWSERS_PATH: browsers },
  stdio: 'inherit',
});

if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
