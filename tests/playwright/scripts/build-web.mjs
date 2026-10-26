import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, '..', '..', '..');
const webDirectory = resolve(repositoryRoot, 'apps', 'web');
const port = Number.parseInt(process.env.KODESEC_PLAYWRIGHT_PORT || '41783', 10);

if (!Number.isInteger(port) || port < 1024 || port > 65535) {
  throw new Error(`Invalid KODESEC_PLAYWRIGHT_PORT: ${process.env.KODESEC_PLAYWRIGHT_PORT}`);
}

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const install = spawnSync(npm, ['ci', '--ignore-scripts'], {
  cwd: webDirectory,
  stdio: 'inherit',
});
if (install.error) throw install.error;
if (install.status !== 0) process.exit(install.status ?? 1);

const result = spawnSync(npm, ['run', 'build'], {
  cwd: webDirectory,
  env: { ...process.env, VITE_API_BASE_URL: `http://127.0.0.1:${port}` },
  stdio: 'inherit',
});

if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
