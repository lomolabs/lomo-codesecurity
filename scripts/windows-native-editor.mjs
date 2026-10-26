// Native phase of the explicit WSL source launcher. Only public installation
// metadata arrives on stdin; the fixed PowerShell caller owns ACL admission.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureNamedProfile, findInstalledExtension, installVsix, vscodeCliInvocation } from '../extensions/vscode/scripts/install.mjs';

const manifest = JSON.parse(readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '../extensions/vscode/package.json'), 'utf8'));
const compatibility = JSON.parse(readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '../extensions/vscode/test/ui/compatibility-lock.json'), 'utf8'));

export function remoteWslDependency(lock = compatibility) {
  const entries = Array.isArray(lock?.extensions) ? lock.extensions.filter((entry) => entry?.name === 'remote-wsl') : [];
  const entry = entries?.[0];
  if (lock?.schema !== 'lomo-vscode-compatibility-lock/v1' || entries?.length !== 1
    || entry.publisher !== 'ms-vscode-remote' || !/^\d+\.\d+\.\d+$/u.test(entry.version)
    || entry.identity !== `ms-vscode-remote.remote-wsl@${entry.version}`
    || !/^\^1\.\d+\.\d+$/u.test(entry.vscode_engine)
    || !/^[a-f0-9]{64}$/u.test(entry.sha256) || !Number.isSafeInteger(entry.bytes)
    || entry.bytes < 1 || entry.bytes > 16 * 1024 * 1024
    || entry.asset_url !== `https://marketplace.visualstudio.com/_apis/public/gallery/publishers/ms-vscode-remote/vsextensions/remote-wsl/${entry.version}/vspackage`) {
    throw new Error('The reviewed Remote WSL dependency pin is missing or invalid.');
  }
  return entry;
}

export function nativeEditorArguments(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)
    || Object.keys(request).sort().join(',') !== 'cli,distro,editor,extensionsDirectory,outputDirectory,phase,profile,userDataDirectory,workspace,wslExecutable'
    || !['preflight', 'inspect', 'install', 'prepare-remote', 'open'].includes(request.phase)
    || !['native', 'remote-wsl'].includes(request.editor)
    || request.phase === 'prepare-remote' && request.editor !== 'remote-wsl'
    || request.editor === 'remote-wsl' && ['inspect', 'install'].includes(request.phase)
    || (request.editor === 'native' ? request.wslExecutable !== null : typeof request.wslExecutable !== 'string'
      || !/^[A-Za-z]:\\[^\u0000-\u001f\u007f]+\\wsl[.]exe$/u.test(request.wslExecutable))
    || typeof request.distro !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(request.distro)
    || ['cli', 'extensionsDirectory', 'outputDirectory', 'profile', 'userDataDirectory', 'workspace'].some(
      (key) => typeof request[key] !== 'string' || !request[key] || /[\u0000-\u001f\u007f]/u.test(request[key]),
    )) throw new Error('Invalid native editor request.');
  return ['--user-data-dir', request.userDataDirectory, '--extensions-dir', request.extensionsDirectory, '--profile', request.profile];
}

export function remoteWslFolderUri(distro, workspace) {
  if (typeof distro !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(distro)
    || typeof workspace !== 'string' || workspace.length < 2 || workspace.length > 4096
    || !workspace.startsWith('/') || posix.normalize(workspace) !== workspace
    || /[\\\u0000-\u001f\u007f]/u.test(workspace)) throw new Error('Invalid exact Remote WSL folder.');
  return `vscode-remote://wsl+${distro}${workspace.split('/').map(encodeURIComponent).join('/')}`;
}

export function remoteWslTransportIdentity(output) {
  const selected = output.trim().split(/\r?\n/u).filter((line) => line.startsWith('ms-vscode-remote.remote-wsl@'));
  if (selected.length === 0) return null;
  if (selected.length !== 1 || !/^ms-vscode-remote\.remote-wsl@\d+\.\d+\.\d+$/u.test(selected[0])) {
    throw new Error('The exact profile returned an invalid WSL transport identity.');
  }
  return selected[0];
}

export function remoteWslDefaultAccount(request, execute = spawnSync) {
  // No --user: the same explicit distro default is used by wsl+DISTRO. The
  // isolated Python command reads only numeric UID and the passwd home field.
  const result = execute(request.wslExecutable, ['--distribution', request.distro, '--exec', 'python3', '-I', '-c',
    'import os,pwd;print(os.getuid());print(pwd.getpwuid(os.getuid()).pw_dir)'], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000, maxBuffer: 4096,
  });
  const output = nativeCliResult(result);
  const lines = output.replace(/\r?\n$/u, '').split(/\r?\n/u);
  if (lines.length !== 2 || !/^(0|[1-9][0-9]{0,9})$/u.test(lines[0]) || Number(lines[0]) > 4294967294
    || !lines[1].startsWith('/') || posix.normalize(lines[1]) !== lines[1]
    || /[\u0000-\u001f\u007f]/u.test(lines[1])) throw new Error('The selected WSL default account could not be verified.');
  return { uid: Number(lines[0]), home: lines[1] };
}

export function nativeCliResult(result, optional = false) {
  if (!result || result.error || result.signal || !Number.isInteger(result.status) || result.status < 0) {
    throw new Error('The native VS Code CLI could not complete its bounded operation.');
  }
  if (result.status !== 0) {
    if (optional) return null;
    throw new Error('The native VS Code CLI refused the requested operation.');
  }
  if (typeof result.stdout !== 'string' || Buffer.byteLength(result.stdout) > 64 * 1024) {
    throw new Error('The native VS Code CLI returned invalid bounded output.');
  }
  return result.stdout;
}

export function requireNativeEditorVersion(output, engine = manifest.engines.vscode) {
  const observed = /^(\d+)\.(\d+)\.(\d+)$/u.exec(output.split(/\r?\n/u)[0]);
  const minimum = /^\^(\d+)\.(\d+)\.(\d+)$/u.exec(engine);
  if (!observed || !minimum || observed[1] !== minimum[1]
    || Number(observed[2]) < Number(minimum[2])
    || (observed[2] === minimum[2] && Number(observed[3]) < Number(minimum[3]))) {
    throw new Error('The selected native VS Code version does not meet the extension engine requirement. Select a supported VS Code version.');
  }
  return observed[0];
}

function cliOutput(request, arguments_, optional = false) {
  const invocation = vscodeCliInvocation(request.cli, arguments_);
  const action = arguments_[nativeEditorArguments(request).length];
  return nativeCliResult(spawnSync(invocation.executable, invocation.arguments, {
    env: invocation.environment, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    timeout: action === '--install-extension' || action === '--new-window' ? 156_000 : 120_000,
    maxBuffer: 64 * 1024,
  }), optional);
}

export function runNativeEditor(request, {
  platform = process.platform, execute = cliOutput, profileExists = existsSync, ensureProfile = ensureNamedProfile,
  defaultAccount = remoteWslDefaultAccount, locateInstalled = findInstalledExtension, install = installVsix,
} = {}) {
  if (platform !== 'win32') throw new Error('The native editor phase requires Windows.');
  const arguments_ = nativeEditorArguments(request);
  const version = requireNativeEditorVersion(execute(request, ['--version']));
  const wslDependency = request.editor === 'remote-wsl' ? remoteWslDependency() : undefined;
  if (wslDependency) requireNativeEditorVersion(version, wslDependency.vscode_engine);
  const inspectRemoteProfile = () => {
    const listed = execute(request, [...arguments_, '--list-extensions', '--show-versions']);
    if (listed.trim().split(/\r?\n/u).some((line) => line.startsWith(`${manifest.publisher}.${manifest.name}@`))) {
      throw new Error('Remote WSL startup requires this exact local profile to contain no local Lomo extension. Use the existing profile\'s ordinary owner-approved remote setup; no native enrollment or extension removal was attempted.');
    }
    return remoteWslTransportIdentity(listed);
  };
  // Never create/open a local Lomo host before the intended remote first owner.
  // A missing private directory cannot contain this profile; existing state
  // must pass the official profile-specific listing, not an error-as-absence.
  let remoteTransport;
  if (wslDependency && (request.phase !== 'preflight' || profileExists(request.userDataDirectory))) {
    if (request.phase !== 'prepare-remote') remoteTransport = inspectRemoteProfile();
  }
  if (request.phase === 'preflight') return {
    phase: 'preflight', status: 'ready', version, wsl_account: wslDependency ? defaultAccount(request) : null,
  };
  if (request.phase === 'prepare-remote') {
    ensureProfile(request.cli, arguments_);
    let transport = inspectRemoteProfile();
    if (transport !== wslDependency.identity) {
      // Normal signed/version-qualified Marketplace installation in this exact
      // private profile. The Lomo package is only staged by the caller.
      execute(request, [...arguments_, '--install-extension', wslDependency.identity, '--force']);
      transport = inspectRemoteProfile();
      if (transport !== wslDependency.identity) throw new Error('The selected profile did not expose the exact pinned Microsoft WSL transport.');
    }
    return { phase: 'prepare-remote', status: 'ready', transport_identity: transport };
  }
  if (request.phase === 'open') {
    if (request.editor === 'remote-wsl') {
      const uri = remoteWslFolderUri(request.distro, request.workspace);
      const transport = remoteTransport;
      if (transport !== wslDependency.identity) throw new Error('The selected profile no longer exposes its exact pinned Microsoft WSL transport.');
      execute(request, [...arguments_, '--new-window', '--folder-uri', uri]);
      return { phase: 'open', status: 'remote-install-pending', remote_authority: `wsl+${request.distro}`, transport_identity: transport };
    }
    execute(request, [...arguments_, '--new-window', request.workspace]);
    return { phase: 'open', status: 'dispatched' };
  }
  if (request.phase === 'install') {
    install({
      cli: request.cli, profile: request.profile,
      userDataDirectory: request.userDataDirectory, extensionsDirectory: request.extensionsDirectory,
      outputDirectory: request.outputDirectory,
      profileWorkspace: request.workspace,
    });
  }
  const identity = `${manifest.publisher}.${manifest.name}@${manifest.version}`;
  const listed = execute(request, [...arguments_, '--list-extensions', '--show-versions'], request.phase === 'inspect');
  if (listed === null) return { phase: 'inspect', status: 'unverified' };
  const installed = listed.trim().split(/\r?\n/u);
  if (installed.filter((value) => value.startsWith(`${manifest.publisher}.${manifest.name}@`)).join('\n') !== identity) {
    if (request.phase === 'inspect') return { phase: 'inspect', status: 'unverified' };
    throw new Error('The native profile did not expose the exact installed extension identity.');
  }
  const location = locateInstalled(request.extensionsDirectory, `${manifest.publisher}.${manifest.name}`, manifest.version);
  if (!location) throw new Error('The native profile did not expose one exact installed extension package.');
  return { phase: request.phase, status: request.phase === 'install' ? 'installed' : 'verified', location, identity };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const input = readFileSync(0);
    if (input.length > 16 * 1024) throw new Error('Oversized native editor request.');
    const result = runNativeEditor(JSON.parse(input.toString('utf8')));
    console.log(`LOMO_NATIVE_EDITOR_RESULT:${JSON.stringify(result)}`);
  } catch {
    console.error('The exact native editor operation failed. Existing profile settings and credentials were not reset.');
    process.exitCode = 1;
  }
}
