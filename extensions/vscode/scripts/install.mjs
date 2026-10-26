import { spawnSync } from 'node:child_process';
import { closeSync, constants, fstatSync, lstatSync, openSync, opendirSync, readFileSync, readSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, resolve, win32 } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const extensionRoot = resolve(dirname(scriptPath), '..');
const repoRoot = resolve(extensionRoot, '..', '..');
const manifest = JSON.parse(readFileSync(resolve(extensionRoot, 'package.json'), 'utf8'));

export class InstallationInspectionError extends Error {
  code = 'installation_inspection_refused';
}

function metadataJson(path, accountOwned = false) {
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink()) throw new Error('VS Code installation metadata must be an ordinary file.');
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
  try {
    const item = fstatSync(descriptor);
    if (!item.isFile() || item.nlink !== 1 || item.size > 256 * 1024 || item.dev !== before.dev || item.ino !== before.ino
      || accountOwned && process.platform !== 'win32' && (item.uid !== process.getuid() || (item.mode & 0o022))) {
      throw new Error('VS Code installation metadata is unsafe or exceeds its bound.');
    }
    const buffer = Buffer.alloc(256 * 1024 + 1);
    let size = 0;
    while (size < buffer.length) {
      const count = readSync(descriptor, buffer, size, buffer.length - size, null);
      if (count === 0) break;
      size += count;
    }
    const content = buffer.subarray(0, size);
    if (content.length !== item.size || content.length > 256 * 1024) throw new Error('VS Code installation metadata changed while reading.');
    return JSON.parse(content.toString('utf8'));
  } finally { closeSync(descriptor); }
}

function absoluteStoragePath(value) {
  if (typeof value !== 'string' || !isAbsolute(value) || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new InstallationInspectionError('Select an explicit absolute VS Code extensions directory without control characters.');
  }
  return resolve(value);
}

export function extensionStorageRoot({ cli, extensionsDirectory, environment = process.env,
  platform = process.platform, home = homedir() }) {
  if (environment.VSCODE_DEV) throw new InstallationInspectionError('Source startup cannot verify a development VS Code layout. Select an installed VS Code application.');
  if (extensionsDirectory !== undefined) return absoluteStoragePath(extensionsDirectory);
  if (environment.VSCODE_EXTENSIONS) return absoluteStoragePath(environment.VSCODE_EXTENSIONS);
  // Match the official CLI's environmentService/configurePortable precedence.
  // Read only the selected application's product metadata, never profile state.
  const selected = realpathSync(cli);
  let appRoot;
  if (platform === 'darwin' && basename(dirname(selected)) === 'bin') appRoot = dirname(dirname(selected));
  else if (platform === 'linux' && basename(dirname(selected)) === 'bin') appRoot = resolve(dirname(dirname(selected)), 'resources/app');
  else throw new InstallationInspectionError('The selected VS Code wrapper has no verified application layout. Select its official bin/code CLI or an explicit extensions directory.');
  if (!lstatSync(resolve(appRoot, 'out/cli.js')).isFile()) throw new Error('The selected VS Code application CLI is unavailable.');
  const product = metadataJson(resolve(appRoot, 'product.json'));
  const component = (value) => typeof value === 'string' && /^[.A-Za-z0-9_-]+$/u.test(value) && value !== '.' && value !== '..';
  if (!component(product.dataFolderName) || !component(product.applicationName)
    || product.portable !== undefined && !component(product.portable)) throw new Error('The selected VS Code product has invalid extension-storage metadata.');
  const application = platform === 'darwin' ? dirname(dirname(dirname(appRoot))) : dirname(dirname(appRoot));
  const portable = environment.VSCODE_PORTABLE ? absoluteStoragePath(environment.VSCODE_PORTABLE)
    : platform === 'darwin' ? resolve(dirname(application), product.portable || `${product.applicationName}-portable-data`)
      : resolve(application, 'data');
  if (!Object.hasOwn(product, 'target') && lstatSync(portable, { throwIfNoEntry: false })) return resolve(portable, 'extensions');
  return resolve(absoluteStoragePath(home), product.dataFolderName, 'extensions');
}

export function findInstalledExtension(root, identity, version) {
  root = absoluteStoragePath(root);
  const storage = lstatSync(root, { throwIfNoEntry: false });
  if (!storage) return null;
  if (!storage.isDirectory() || storage.isSymbolicLink() || realpathSync(root) !== root
    || process.platform !== 'win32' && (storage.uid !== process.getuid() || (storage.mode & 0o022))) {
    throw new Error('The selected VS Code extensions directory has unsafe ownership or links.');
  }
  // Match VS Code's ExtensionKey directory naming before reading manifests.
  // Unrelated extensions (for example GitLens) can have much larger manifests;
  // their contents do not establish the requested package's identity.
  // https://github.com/microsoft/vscode/blob/main/src/vs/platform/extensionManagement/common/extensionManagementUtil.ts
  const packageName = `${identity}-${version}`;
  const packageNames = new Set([packageName, ...[
    'win32-x64', 'win32-arm64', 'linux-x64', 'linux-arm64', 'linux-armhf',
    'alpine-x64', 'alpine-arm64', 'darwin-x64', 'darwin-arm64', 'web', 'universal', 'unknown',
  ].map((platform) => `${packageName}-${platform}`)]);
  const candidates = [];
  const directory = opendirSync(root);
  try {
    for (let count = 0, entry; (entry = directory.readSync()) !== null; count += 1) {
      if (count >= 512) throw new Error('The selected VS Code extension inventory exceeds its 512-entry bound.');
      const location = resolve(root, entry.name);
      const item = lstatSync(location);
      if (item.isSymbolicLink()) throw new Error('The selected VS Code extension inventory contains an unsafe linked entry.');
      if (!item.isDirectory()) continue;
      if (process.platform !== 'win32' && (item.uid !== process.getuid() || (item.mode & 0o022))) throw new Error('The selected VS Code extension package has unsafe ownership.');
      if (!packageNames.has(entry.name)) continue;
      const packagePath = resolve(location, 'package.json');
      if (!lstatSync(packagePath, { throwIfNoEntry: false })) continue;
      const installed = metadataJson(packagePath, true);
      if (`${installed.publisher}.${installed.name}` === identity && installed.version === version) candidates.push(location);
    }
  } finally { directory.closeSync(); }
  if (candidates.length > 1) throw new Error('The exact VS Code extension identity has ambiguous installed packages. No package was guessed.');
  return candidates[0] || null;
}

export function inspectInstalledExtension({ cli, profile, userDataDirectory, extensionsDirectory }) {
  const arguments_ = selectionArguments(cli, profile, userDataDirectory, extensionsDirectory);
  const listed = runCli(cli, [...arguments_, '--list-extensions', '--show-versions'], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000, maxBuffer: 1024 * 1024,
  });
  if (listed.error || listed.signal) throw new Error('The selected VS Code profile could not be inspected.');
  if (listed.status !== 0) return { status: 'missing' };
  const identity = `${manifest.publisher}.${manifest.name}`;
  const memberships = listed.stdout.split(/\r?\n/u).filter((line) => line.startsWith(`${identity}@`));
  if (memberships.length !== 1 || memberships[0] !== `${identity}@${manifest.version}`) return { status: 'missing' };
  const location = findInstalledExtension(extensionStorageRoot({ cli, extensionsDirectory }), identity, manifest.version);
  return location ? { status: 'verified', identity: memberships[0], location } : { status: 'missing' };
}

export function installCompletionMessage(profile) {
  return `Installed Lomo CodeSecurity into the VS Code profile "${profile}". Open or switch to that profile to start CodeSecurity. If it is already open, run Developer: Reload Window.`;
}

// Read the selected installation's official wrapper as data. Its one bounded
// invocation names the bundled CLI; the wrapper is never executed.
function officialWindowsCommand(path) {
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size < 1 || before.size > 2048) {
    throw new Error('The selected VS Code command wrapper is unavailable or unsafe.');
  }
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const observed = fstatSync(descriptor);
    if (!observed.isFile() || observed.nlink !== 1 || observed.size !== before.size
      || observed.dev !== before.dev || observed.ino !== before.ino) {
      throw new Error('The selected VS Code command wrapper changed while reading.');
    }
    const bytes = Buffer.alloc(observed.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(descriptor, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
    }
    if (length !== observed.size) throw new Error('The selected VS Code command wrapper changed while reading.');
    return bytes.subarray(0, length).toString('utf8');
  } finally { closeSync(descriptor); }
}

export function parseOfficialWindowsCli(executable, command) {
  const root = win32.dirname(executable);
  const lines = command.replace(/\r\n/gu, '\n').trimEnd().split('\n');
  const invocation = lines.length === 7
    && /^"%~dp0\.\.\\Code\.exe" "%~dp0\.\.\\((?:[a-f0-9]{10,40}\\)?resources\\app\\out\\cli\.js)" %\*$/u.exec(lines[4]);
  if (!invocation || lines[0] !== '@echo off' || lines[1] !== 'setlocal'
    || lines[2] !== 'set VSCODE_DEV=' || lines[3] !== 'set ELECTRON_RUN_AS_NODE=1'
    || lines[5] !== 'IF %ERRORLEVEL% NEQ 0 EXIT /b %ERRORLEVEL%' || lines[6] !== 'endlocal') {
    throw new Error('The selected VS Code command wrapper does not name one official bundled CLI.');
  }
  return win32.join(root, invocation[1]);
}

function officialWindowsCli(executable) {
  const root = win32.dirname(executable);
  const bin = win32.join(root, 'bin');
  const binEntry = lstatSync(bin);
  if (!binEntry.isDirectory() || binEntry.isSymbolicLink()) {
    throw new Error('The selected VS Code command directory is unsafe.');
  }
  const bundled = parseOfficialWindowsCli(executable, officialWindowsCommand(win32.join(bin, 'code.cmd')));
  const relative = win32.relative(root, bundled);
  const parts = relative.split('\\');
  for (let index = 0; index < parts.length - 1; index += 1) {
    const path = win32.join(root, ...parts.slice(0, index + 1));
    const entry = lstatSync(path);
    if (!entry.isDirectory() || entry.isSymbolicLink()) {
      throw new Error('The selected VS Code bundled CLI directory is unsafe.');
    }
  }
  const entry = lstatSync(bundled);
  if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1) {
    throw new Error('The selected VS Code bundled CLI is unavailable or unsafe.');
  }
  return bundled;
}

export function vscodeCliInvocation(cli, arguments_, platform = process.platform, environment = process.env,
  resolveWindowsCli = officialWindowsCli) {
  if (typeof cli !== 'string' || !cli || /[\u0000-\u001f\u007f]/u.test(cli)
    || !Array.isArray(arguments_) || arguments_.some((argument) => typeof argument !== 'string' || argument.includes('\0'))) {
    throw new Error('VS Code CLI requires one executable and explicit argument strings.');
  }
  if (platform !== 'win32') return { executable: cli, arguments: [...arguments_], environment };
  if (!/^[A-Za-z]:\\/u.test(cli) || win32.normalize(cli) !== cli
    || /[<>:"/|?*]/u.test(cli.slice(3)) || cli.slice(3).split('\\').some((part) => !part || /[. ]$/u.test(part))) {
    throw new Error('On Windows select the exact local-drive Code.exe or bin\\code.cmd path with VSCODE_CLI.');
  }
  const name = win32.basename(cli).toLowerCase();
  let executable;
  if (name === 'code.exe') executable = cli;
  else if (name === 'code.cmd' && win32.basename(win32.dirname(cli)).toLowerCase() === 'bin') {
    executable = win32.join(win32.dirname(win32.dirname(cli)), 'Code.exe');
  } else throw new Error('On Windows select the official Code.exe or bin\\code.cmd entry point.');
  // Match the official code.cmd invocation without a command shell. CLI flags
  // are handled by the bundled CLI, not mistaken for Electron window flags.
  const childEnvironment = Object.fromEntries(Object.entries(environment).filter(
    ([key]) => !['ELECTRON_RUN_AS_NODE', 'VSCODE_DEV'].includes(key.toUpperCase()),
  ));
  childEnvironment.ELECTRON_RUN_AS_NODE = '1';
  return {
    executable,
    arguments: [resolveWindowsCli(executable), ...arguments_],
    environment: childEnvironment,
  };
}

function runCli(cli, arguments_, options) {
  const invocation = vscodeCliInvocation(cli, arguments_);
  if (process.platform === 'win32') {
    for (const path of [invocation.executable, invocation.arguments[0]]) {
      const metadata = lstatSync(path);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
        throw new Error('The selected Windows VS Code executable or bundled CLI is unavailable or unsafe.');
      }
    }
  }
  return spawnSync(invocation.executable, invocation.arguments, { ...options, env: invocation.environment });
}

export function ensureNamedProfile(cli, profileArguments, profileWorkspace) {
  if (profileWorkspace !== undefined) {
    if (typeof profileWorkspace !== 'string' || profileWorkspace.length > 4096
      || !isAbsolute(profileWorkspace) || /[\u0000-\u001f\u007f]/u.test(profileWorkspace)) {
      throw new Error('Profile startup requires an exact absolute workspace directory or .code-workspace file.');
    }
    const metadata = lstatSync(profileWorkspace);
    if (metadata.isSymbolicLink() || realpathSync(profileWorkspace) !== profileWorkspace
      || !metadata.isDirectory() && !(metadata.isFile() && metadata.nlink === 1 && profileWorkspace.endsWith('.code-workspace'))) {
      throw new Error('Profile startup requires an existing canonical workspace directory or .code-workspace file without links.');
    }
  }
  // The extension-management CLI only resolves existing profiles. A normal
  // window launch is the supported way to create a missing empty profile.
  const probe = (timeout = 5000) => {
    const result = runCli(cli, [...profileArguments, '--list-extensions'], {
      stdio: ['ignore', 'ignore', 'ignore'], timeout,
    });
    if (result.error || result.signal) {
      throw new Error('The selected VS Code CLI could not check profile readiness. No extension was installed.');
    }
    return result.status === 0;
  };
  if (probe()) return;
  console.log('Opening the selected VS Code profile to establish readiness…');
  // Source startup already owns an exact workspace. Put it in this first
  // window so the final public CLI open can focus it, rather than leaving an
  // empty setup window with a second copy of the same IDE event connection.
  // Never use --reuse-window: that can replace an unrelated last-active window.
  const launched = runCli(cli, [...profileArguments, '--new-window', ...(profileWorkspace ? [profileWorkspace] : [])], {
    stdio: ['ignore', 'ignore', 'ignore'], timeout: 15000,
  });
  if (launched.error || launched.signal || launched.status !== 0) {
    throw new Error('VS Code could not open the selected profile. Check that exact application; no extension was installed.');
  }
  // Poll an authoritative public predicate, not elapsed time or process exit.
  // Bound both process count and wall time; never launch a second window here.
  const deadline = Date.now() + 15000;
  const pause = new Int32Array(new SharedArrayBuffer(4));
  for (let attempt = 0; attempt < 8 && Date.now() < deadline; attempt += 1) {
    if (probe(Math.max(1, Math.min(5000, deadline - Date.now())))) return;
    if (attempt < 7 && Date.now() < deadline) {
      Atomics.wait(pause, 0, 0, Math.min(250, deadline - Date.now()));
    }
  }
  throw new Error('The selected VS Code profile did not become ready within the startup bound. Keep that window available, resolve its startup problem, then retry installation; no settings or authentication were reset.');
}

function selectionArguments(cli, profile, userDataDirectory, extensionsDirectory) {
  if (typeof cli !== 'string' || !cli || cli.includes('\0')) {
    throw new Error('VSCODE_CLI must name one executable.');
  }
  if (
    typeof profile !== 'string'
    || !profile
    || profile !== profile.trim()
    || profile.length > 128
    || /[\u0000-\u001f\u007f]/u.test(profile)
  ) {
    throw new Error('VSCODE_PROFILE must be a non-empty profile name without control characters.');
  }
  const directoryArguments = [];
  for (const [flag, directory] of [
    ['--user-data-dir', userDataDirectory],
    ['--extensions-dir', extensionsDirectory],
  ]) {
    if (directory === undefined) continue;
    if (typeof directory !== 'string' || !isAbsolute(directory) || /[\u0000-\u001f\u007f]/u.test(directory)) {
      throw new Error(`${flag} must be an explicit absolute directory without control characters.`);
    }
    directoryArguments.push(flag, directory);
  }
  return [...directoryArguments, '--profile', profile];
}

export function installVsix({
  cli = 'code', profile = 'Lomo CodeSecurity', userDataDirectory, extensionsDirectory,
  outputDirectory = resolve(repoRoot, '.kodesec-test', 'vscode'),
  profileWorkspace,
} = {}) {
  const profileArguments = selectionArguments(cli, profile, userDataDirectory, extensionsDirectory);
  const candidate = resolve(outputDirectory, `code-security-${manifest.version}.vsix`);
  const metadata = lstatSync(candidate);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    throw new Error('Invalid packaged VSIX.');
  }
  ensureNamedProfile(cli, profileArguments, profileWorkspace);
  const installed = runCli(cli, [...profileArguments, '--install-extension', candidate, '--force'], {
    stdio: 'inherit', timeout: process.platform === 'win32' ? 156_000 : process.platform === 'linux' ? 78_000 : 60_000,
  });
  if (installed.error || installed.signal || installed.status !== 0) {
    throw new Error('The selected VS Code profile could not install this exact VSIX. Existing profile settings and authentication were not reset.');
  }
  console.log(installCompletionMessage(profile));
  return candidate;
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const selection = {
    cli: process.env.VSCODE_CLI || 'code',
    profile: process.env.VSCODE_PROFILE || 'Lomo CodeSecurity',
    userDataDirectory: process.env.VSCODE_USER_DATA_DIR || undefined,
    extensionsDirectory: process.env.VSCODE_EXTENSIONS_DIR || undefined,
  };
  if (process.argv[2] === '--inspect-installed' && process.argv.length === 3) {
    try { process.stdout.write(`${JSON.stringify(inspectInstalledExtension(selection))}\n`); }
    catch (error) {
      process.stderr.write(`${error instanceof InstallationInspectionError ? error.message : 'The selected VS Code installation could not be verified safely. Check its official CLI and exact extensions directory; no profile was reset.'}\n`);
      process.exitCode = 1;
    }
  } else if (process.argv.length === 2) installVsix({ ...selection, profileWorkspace: process.env.VSCODE_PROFILE_WORKSPACE });
  else throw new Error('Unsupported source installer action.');
}
