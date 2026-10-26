#!/usr/bin/env python3
"""Explicit WSL backend startup, preserving the existing Windows editor profile.

From Windows: wsl.exe -d DISTRO --cd /ext4/checkout --exec python3
scripts/start-lomo-windows.py --distro DISTRO --checkout /ext4/checkout
--editor native

Add --source-vsix, --code and --workspace only for development/QA installation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PureWindowsPath
import pwd
import re
import signal
import stat
import subprocess
import sys
from threading import Event

from source_provenance import STANDARD_BUILD_INPUT_PATHS, SourceProvenanceError, resolve_source_provenance

REPO = Path(__file__).resolve().parent.parent


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), REPO / 'scripts' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


startup = load_script('start-lomo')
handoff = load_script('publish-windows-first-owner')


class WindowsStartupError(RuntimeError):
    """Actionable refusal with no subprocess or credential material."""


def local_windows_path(value):
    return isinstance(value, str) and 4 <= len(value) <= 4096 and bool(re.match(r'^[A-Za-z]:\\', value)) \
        and str(PureWindowsPath(value)) == value and not re.search(r'[<>:"/|?*\x00-\x1f\x7f]', value[3:]) \
        and all(part not in {'', '.', '..'} and not part.endswith(('.', ' ')) for part in value[3:].split('\\'))


def validate_options(options):
    if options.editor not in {'native', 'remote-wsl'}:
        raise WindowsStartupError('Choose native or remote-wsl explicitly; no editor mode is inferred.')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', options.distro):
        raise WindowsStartupError('Select one exact installed WSL distribution name.')
    if sys.platform != 'linux' or 'microsoft' not in Path('/proc/sys/kernel/osrelease').read_text().lower() \
            or os.environ.get('WSL_DISTRO_NAME') != options.distro:
        raise WindowsStartupError('Run this entry through wsl.exe -d with the exact selected distribution; no default distribution is inferred.')
    if not options.checkout.is_absolute() or options.checkout != options.checkout.resolve(strict=True) or options.checkout != REPO:
        raise WindowsStartupError('Select the exact canonical ext4 product checkout containing this launcher.')
    fs_type = startup.command(['stat', '-f', '-c', '%T', str(REPO)]).stdout.decode().strip()
    if fs_type != 'ext2/ext3':
        raise WindowsStartupError('Build the product in the selected WSL ext4 filesystem, not a Windows/UNC mount or another filesystem.')
    if options.source_vsix and (not local_windows_path(options.code) or PureWindowsPath(options.code).name != 'Code.exe'):
        raise WindowsStartupError('Select the exact signed native local-drive Code.exe entry point.')
    if options.editor == 'native':
        if (options.source_vsix or options.workspace is not None) and not local_windows_path(options.workspace):
            raise WindowsStartupError('Native mode requires an exact local-drive source workspace; UNC workspaces are not native snapshots.')
    else:
        workspace = Path(options.workspace) if options.workspace is not None else None
        if options.source_vsix and workspace is None:
            raise WindowsStartupError('Source-VSIX mode requires an explicit workspace.')
        if workspace is not None and (not workspace.is_absolute() or str(workspace) != options.workspace or len(options.workspace) > 4096 \
                or re.search(r'[\\\x00-\x1f\x7f]', options.workspace) or not workspace.is_dir() \
                or workspace != workspace.resolve(strict=True) or workspace == Path('/') \
                or startup.command(['stat', '-f', '-c', '%T', str(workspace)]).stdout.decode().strip() != 'ext2/ext3'):
            raise WindowsStartupError('Remote WSL requires one existing canonical ext4 source folder in the selected distro, not a Windows or UNC path.')
        # A reused official WSL server does not inherit a newly launched
        # Windows process environment. Do not claim a custom-state handoff.
        account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        default_state = account_home / '.local/state/lomo-kodesec'
        if not account_home.is_absolute() or account_home != account_home.resolve() \
                or os.environ.get('HOME') != str(account_home) \
                or os.environ.get('XDG_STATE_HOME') not in (None, str(account_home / '.local/state')) \
                or os.environ.get('KODESEC_STATE_DIR') not in (None, str(default_state)) \
                or options.state_dir.absolute() != default_state:
            raise WindowsStartupError('Remote WSL setup supports only this account\'s default POSIX state directory. Custom HOME/XDG/runtime handoff is not supported; no state was copied or editor mode substituted.')
    if not options.profile or options.profile != options.profile.strip() or len(options.profile) > 128 \
            or any(ord(char) < 32 or ord(char) == 127 for char in options.profile):
        raise WindowsStartupError('Select one non-empty native editor profile name without control characters.')


def native_path(path):
    value = startup.command(['wslpath', '-w', str(path)]).stdout.decode('utf-8').rstrip('\r\n')
    if not value or '\n' in value or '\r' in value:
        raise WindowsStartupError('WSL could not map the exact public installer file to Windows.')
    return value


NATIVE_HELPER_PATHS = (
    'scripts/windows-native-editor.mjs',
    'extensions/vscode/scripts/install.mjs',
    'extensions/vscode/package.json',
    'extensions/vscode/test/ui/compatibility-lock.json',
)

def native_helper_hashes():
    # The Windows child cannot load modules from the WSL UNC namespace. Admit
    # only this fixed public import closure for private, temporary local staging.
    digests = {}
    for relative in NATIVE_HELPER_PATHS:
        path = REPO / relative
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= 256 * 1024:
            raise WindowsStartupError('The exact native editor helper is unsafe or exceeds its bound.')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        try:
            observed = os.fstat(descriptor)
            if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1 or observed.st_size != before.st_size \
                    or (observed.st_dev, observed.st_ino) != (before.st_dev, before.st_ino):
                raise WindowsStartupError('The exact native editor helper changed during admission.')
            chunks = []
            remaining = observed.st_size + 1
            while remaining:
                part = os.read(descriptor, remaining)
                if not part:
                    break
                chunks.append(part)
                remaining -= len(part)
            content = b''.join(chunks)
            if len(content) != observed.st_size:
                raise WindowsStartupError('The exact native editor helper changed during admission.')
            digests[relative] = hashlib.sha256(content).hexdigest()
        finally:
            os.close(descriptor)
    return digests


def native_phase(executable, request):
    program = handoff.STORAGE_SCRIPT.read_text(encoding='utf-8') + '\n' \
        + (REPO / 'scripts/start-lomo-windows.ps1').read_text(encoding='utf-8')
    if len(program.encode()) > 32 * 1024:
        raise WindowsStartupError('The native startup program exceeds its reviewed bound.')
    result = subprocess.run([executable, '-NoProfile', '-NonInteractive', '-Command', program],
        input=json.dumps(request, separators=(',', ':')), encoding='utf-8', capture_output=True,
        timeout=390, check=False)
    if result.returncode or len(result.stdout.encode()) > 16 * 1024:
        raise WindowsStartupError('Native startup was refused. Check that the selected signed VS Code meets the extension version requirement, the workspace exists, and installer/profile permissions are account-private. Existing credentials and permissions were not reset.')
    response = json.loads(result.stdout, object_pairs_hook=handoff.no_duplicate_fields)
    keys = {'phase', 'status', 'user_data', 'extensions', 'wsl_account'} if request['phase'] == 'preflight' \
        else {'phase', 'result', 'user_data', 'extensions'}
    if not isinstance(response, dict) or set(response) != keys or response['phase'] != request['phase'] \
            or not local_windows_path(response['user_data']) or not local_windows_path(response['extensions']):
        raise WindowsStartupError('Native startup returned invalid public metadata.')
    if request['phase'] == 'preflight' and response['status'] != 'ready':
        raise WindowsStartupError('Native startup preflight did not pass.')
    if request['phase'] == 'preflight':
        account = response['wsl_account']
        if request['editor'] == 'remote-wsl':
            if not isinstance(account, dict) or set(account) != {'uid', 'home'} \
                    or type(account['uid']) is not int or account['uid'] != os.getuid() \
                    or account['home'] != pwd.getpwuid(os.getuid()).pw_dir:
                raise WindowsStartupError('Remote WSL opens the selected distro\'s default account, which does not match this launcher account and home. Start setup as that existing default account; no distro default, runtime or profile was changed.')
        elif account is not None:
            raise WindowsStartupError('Native startup returned unexpected WSL account metadata.')
    return response


def launch(options):
    validate_options(options)
    state = options.state_dir.absolute()
    startup.private_directory(state)
    state = state.resolve()
    if state == REPO or REPO in state.parents:
        raise WindowsStartupError('Runtime state must be outside the product checkout.')
    backend = [sys.executable, str(REPO / 'scripts/start-lomo.py'), '--browser-only', '--state-dir', str(state)]
    if not options.source_vsix:
        if options.check:
            checked = startup.command([*backend, '--check', '--json'], optional=True, timeout=600)
            report = json.loads(checked.stdout)
            if not isinstance(report, dict) or report.get('schema_version') != 1 or report.get('status') not in {'passed', 'failed'} \
                    or (checked.returncode == 0) != (report['status'] == 'passed'):
                raise WindowsStartupError('The backend prerequisite report is invalid; no editor or runtime was changed.')
            report['editor_workflow'] = {'mode': options.editor, 'distro': options.distro,
                'profile': 'existing', 'installation_verified': False,
                'next_action': 'Install Lomo in the selected native or WSL extension host and run CodeSecurity: Connect / Review IDE Access.'}
            if options.json:
                print(json.dumps(report, sort_keys=True))
            elif checked.returncode:
                for check in report.get('checks', []):
                    if check.get('status') == 'failed':
                        print(check.get('message', 'Backend prerequisite failed.'))
            else:
                print('WSL backend prerequisites passed; the temporary source-free Docker storage probe was removed. Existing editor installation and connection still require verification.')
            if checked.returncode:
                raise SystemExit(checked.returncode)
        else:
            startup.command([*backend, *(['--publish-windows-owner'] if options.editor == 'native' else [])], capture=False, timeout=10140)
            print('The backend is ready. Keep your existing VS Code profile. Install Lomo in the native Windows host or the selected WSL window, then run CodeSecurity: Connect / Review IDE Access. No extension was replaced and no workspace trust was granted.')
        return
    included = [*STANDARD_BUILD_INPUT_PATHS, '.env.example', 'extensions/vscode',
        'scripts/start-lomo.py', 'scripts/start-lomo-windows.py', 'scripts/start-lomo-windows.ps1',
        'scripts/windows-native-editor.mjs', 'scripts/windows-installer-storage.ps1',
        'scripts/init-runtime.sh', 'scripts/runtime-compose.py', 'scripts/source_roots.py',
        'scripts/authorize-source.py', 'scripts/publish-first-owner-bootstrap.py',
        'scripts/publish-windows-first-owner.py', 'scripts/publish-windows-first-owner.ps1']
    provenance = resolve_source_provenance(REPO, included_paths=included)
    startup.node_build_preflight()
    startup.executable('npm')
    executable = handoff.native_powershell()
    runtime = state / 'runtime.env'
    values = startup.read_runtime(runtime) if runtime.exists() or runtime.is_symlink() else None
    if values and values['CONTROL_PORT'] != '8080':
        raise WindowsStartupError('Automatic Windows editor startup requires control port 8080; configure a different origin through the explicit manual workflow.')
    request = {'phase': 'preflight', 'editor': options.editor, 'distro': options.distro, 'checkout': str(REPO),
        'state_dir': str(state), 'code': options.code, 'workspace': options.workspace,
        'profile': options.profile, 'installation_id': values['KODESEC_INSTALLATION_ID'] if values else None,
        'native_script': native_path(REPO / 'scripts/windows-native-editor.mjs'),
        'native_helper_hashes': native_helper_hashes(), 'vsix_path': None, 'vsix_sha256': None}
    admitted = native_phase(executable, request)
    if options.check:
        startup.command([*backend, '--check'], capture=False, timeout=600)
        print('Selected Windows editor and WSL backend preflights passed. No editor, authority, build or runtime was created; remote installation and pairing are not inferred.')
        return
    startup.command([*backend, *(['--publish-windows-owner'] if options.editor == 'native' else [])], capture=False, timeout=10140)
    values = startup.read_runtime(runtime)
    if values['CONTROL_PORT'] != '8080':
        raise WindowsStartupError('The initialized backend origin changed; no native editor was installed or opened.')
    if resolve_source_provenance(REPO, included_paths=included) != provenance:
        raise WindowsStartupError('Source changed during backend startup; no native extension was installed.')
    receipt_path = state / 'windows-source-launch.json'
    previous = json.loads(startup.private_bytes(receipt_path, 16384)) if receipt_path.exists() or receipt_path.is_symlink() else {}
    if not isinstance(previous, dict):
        raise WindowsStartupError('The existing Windows startup receipt is invalid.')
    manifest = json.loads((REPO / 'extensions/vscode/package.json').read_bytes())
    candidate = REPO / '.kodesec-test/vscode' / f"code-security-{manifest['version']}.vsix"
    package_admission = startup.reusable_extension_source(candidate, provenance, previous.get('extension', {}))
    if package_admission is None:
        startup.command([startup.executable('make'), '-C', str(REPO), 'vscode-package'], capture=False, timeout=2340)
        package_admission = (provenance, hashlib.sha256(startup.read_vsix_bytes(candidate)).hexdigest())
    package_source, admitted_digest = package_admission
    payload = startup.vsix_payload(candidate, admitted_digest)
    if resolve_source_provenance(REPO, included_paths=included) != provenance:
        raise WindowsStartupError('Source changed during extension packaging; no native extension was installed.')
    request.update(phase='inspect', installation_id=values['KODESEC_INSTALLATION_ID'],
        native_script=native_path(REPO / 'scripts/windows-native-editor.mjs'), vsix_path=native_path(candidate),
        vsix_sha256=admitted_digest)
    expected_identity = f"{manifest['publisher']}.{manifest['name']}@{manifest['version']}"

    def installed_matches(observed, phase):
        if observed['user_data'] != admitted['user_data'] or observed['extensions'] != admitted['extensions']:
            raise WindowsStartupError('The native account/profile paths changed during startup.')
        result = observed['result']
        if phase == 'inspect' and result == {'phase': 'inspect', 'status': 'unverified'}:
            return False
        if not isinstance(result, dict) or set(result) != {'phase', 'status', 'location', 'identity'} \
                or result['phase'] != phase or result['status'] != ('installed' if phase == 'install' else 'verified') \
                or result['identity'] != expected_identity or not local_windows_path(result['location']) \
                or PureWindowsPath(result['location']).parent != PureWindowsPath(observed['extensions']):
            raise WindowsStartupError('The native installed extension does not match this exact profile and package.')
        mapped = startup.command(['wslpath', '-u', result['location']]).stdout.decode().rstrip('\r\n')
        return startup.installed_extension_matches(Path(mapped), payload)

    staged = None
    expected_transport = None
    if options.editor == 'remote-wsl':
        dependencies = json.loads((REPO / 'extensions/vscode/test/ui/compatibility-lock.json').read_bytes())
        matching = [entry for entry in dependencies['extensions'] if entry.get('name') == 'remote-wsl']
        if len(matching) != 1:
            raise WindowsStartupError('The reviewed Remote WSL transport pin is missing or ambiguous.')
        expected_transport = matching[0]['identity']
        request['phase'] = 'prepare-remote'
        installed = native_phase(executable, request)
        staged = installed['result']
        expected_stage = PureWindowsPath(admitted['user_data']).parent / 'package' / candidate.name
        if installed['user_data'] != admitted['user_data'] or installed['extensions'] != admitted['extensions'] \
                or not isinstance(staged, dict) or set(staged) != {'phase', 'status', 'transport_identity', 'vsix_path', 'vsix_sha256'} \
                or staged['phase'] != 'prepare-remote' or staged['status'] != 'staged' \
                or staged['transport_identity'] != expected_transport or not local_windows_path(staged['vsix_path']) \
                or PureWindowsPath(staged['vsix_path']) != expected_stage or staged['vsix_sha256'] != request['vsix_sha256']:
            raise WindowsStartupError('The exact Remote WSL package staging was not confirmed; no remote window was opened.')
    else:
        installed = native_phase(executable, request)
        if not installed_matches(installed, 'inspect'):
            request['phase'] = 'install'
            installed = native_phase(executable, request)
            if not installed_matches(installed, 'install'):
                raise WindowsStartupError('The native installed extension bytes differ from the exact source-built VSIX. No workspace was opened.')
    if resolve_source_provenance(REPO, included_paths=included) != provenance:
        raise WindowsStartupError('Source changed before native workspace launch; reopen only after a matching source start.')
    startup.read_vsix_bytes(candidate, admitted_digest)
    request['phase'] = 'open'
    opened = native_phase(executable, request)
    result = opened['result']
    remote_pending = options.editor == 'remote-wsl' and isinstance(result, dict) \
        and set(result) == {'phase', 'status', 'remote_authority', 'transport_identity'} \
        and result['phase'] == 'open' and result['status'] == 'remote-install-pending' \
        and result['remote_authority'] == f'wsl+{options.distro}' \
        and result['transport_identity'] == expected_transport \
        and isinstance(result['transport_identity'], str) \
        and re.fullmatch(r'ms-vscode-remote[.]remote-wsl@[0-9]+[.][0-9]+[.][0-9]+', result['transport_identity'])
    if (not remote_pending and not (options.editor == 'native' and result == {'phase': 'open', 'status': 'dispatched'})) \
            or opened['user_data'] != installed['user_data'] or opened['extensions'] != installed['extensions']:
        raise WindowsStartupError('The exact selected workspace launch was not confirmed by its CLI.')
    startup.write_receipt(receipt_path, {'v': 1, **provenance.to_record(),
        'installation_id': values['KODESEC_INSTALLATION_ID'], 'distro': options.distro, 'state_dir': str(state),
        'profile': options.profile, 'user_data': installed['user_data'], 'extensions': installed['extensions'],
        'vsix_sha256': request['vsix_sha256'], 'editor': options.editor,
        'extension': {**package_source.to_record(),
            'vsix_sha256': request['vsix_sha256'], 'version': manifest['version']},
        **({'staged_extension_identity': expected_identity, 'staged_vsix_path': staged['vsix_path']}
            if remote_pending else {'extension_identity': expected_identity}),
        **({'remote_installation': 'pending', 'remote_authority': result['remote_authority'],
            'transport_identity': result['transport_identity']} if remote_pending else {})})
    if remote_pending:
        print(f'Remote WSL window requested for {options.distro}. Lomo was NOT installed locally. In the WSL: {options.distro} window, choose Extensions: Install from VSIX…, then Show Local, select the staged Windows package "{staged["vsix_path"]}", and choose Install. Follow the ordinary VSIX/workspace-trust prompts. Remote installation, pairing and host placement remain PENDING until the WSL extension is running. Repeat startup never treats this receipt as a remote installation pass.')
    else:
        print('Native VS Code launch dispatched with the verified source-built extension. Use its normal trust/enrollment prompts; no trust policy was changed. CLI completion is not foreground or Windows release acceptance.')


def keep_backend_session():
    """Keep this foreground WSL invocation alive without changing host settings."""
    stopped = Event()
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for sig in previous:
            signal.signal(sig, lambda _signal, _frame: stopped.set())
        print('Keep this terminal open while using Lomo. WSL systemd services alone do not keep the distro running. Ctrl+C releases this session; it does not delete containers or data. Run the same startup command to resume.', flush=True)
        stopped.wait()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--distro', required=True)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--state-dir', type=Path, default=startup.default_state())
    parser.add_argument('--editor', required=True, choices=('native', 'remote-wsl'))
    parser.add_argument('--code')
    parser.add_argument('--workspace')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--source-vsix', action='store_true', help='Explicit development/QA extension build and isolated editor setup.')
    mode.add_argument('--browser-only', action='store_true', help='Alias for the default backend-only workflow.')
    parser.add_argument('--profile', default='Lomo CodeSecurity')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--json', action='store_true', help='Emit a versioned backend prerequisite report with --check.')
    options = parser.parse_args()
    if options.json and (not options.check or options.source_vsix):
        parser.error('--json requires backend-only --check')
    try:
        launch(options)
        if not options.check:
            keep_backend_session()
    except (WindowsStartupError, startup.StartupError, handoff.HandoffError, SourceProvenanceError) as error:
        if options.json:
            report = startup.PrerequisiteReport()
            report.begin('windows_context')
            print(json.dumps(report.result(error), sort_keys=True))
            raise SystemExit(1) from None
        raise SystemExit(str(error)) from None
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        message = 'Windows source startup could not validate its bounded metadata or prerequisites. Completed backend state was retained; no credential or global policy was reset.'
        if options.json:
            report = startup.PrerequisiteReport()
            report.begin('windows_context')
            print(json.dumps(report.result(WindowsStartupError(message)), sort_keys=True))
            raise SystemExit(1) from None
        raise SystemExit(message) from None


if __name__ == '__main__':
    main()
