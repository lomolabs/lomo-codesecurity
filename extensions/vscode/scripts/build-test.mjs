import { execFileSync } from 'node:child_process';
import { rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const extensionRoot = resolve(scriptDirectory, '..');
const compiler = resolve(extensionRoot, 'node_modules', 'typescript', 'bin', 'tsc');

await rm(resolve(extensionRoot, 'dist'), { force: true, recursive: true });
execFileSync(process.execPath, [compiler, '-p', resolve(extensionRoot, 'tsconfig.test.json')], {
  cwd: extensionRoot,
  stdio: 'inherit',
});
