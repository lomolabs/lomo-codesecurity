from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from kodesec_scanner import main as scanner
from kodesec_scanner.external import ToolRunResult
from kodesec_scanner import external


def configure(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, 'settings', SimpleNamespace(
        allowed_root_list=[str(tmp_path)], max_files=5000, max_file_bytes=1024 * 1024,
        artifact_dir=str(tmp_path / 'artifacts'), source_snapshot_dir=str(tmp_path / 'snapshots'),
        scratch_dir=str(tmp_path / 'scratch'), tool_cache_dir=str(tmp_path / 'cache'),
        tool_lock_path=str(tmp_path / 'tools.json'), rules_lock_path=str(tmp_path / 'rules.json'),
        external_tool_timeout=30, validate_storage_boundaries=lambda: None))
    dimension = SimpleNamespace(model_dump=lambda **kw: {'state': 'ready'})
    ready = SimpleNamespace(ready=True, binary=dimension, data=dimension, rules=dimension, execution=dimension)
    monkeypatch.setattr(scanner, 'scanner_runtime_context', lambda **kw: SimpleNamespace(
        runtime_by_id={name: {'available': True} for name in ('gitleaks', 'checkov')},
        readiness_by_id={name: ready for name in ('gitleaks', 'checkov')}, tools=None))


def capture(repo, owned):
    owned.mkdir()
    return scanner._capture_target_directory(repo, None, owned,
        scanner.ExecutionControl.with_timeout(10), gitleaks_whole_root=True)


def scan(repo, tools=('gitleaks',), **kwargs):
    return scanner._execute_scan(scanner.ScanRequest(scan_id=123, repo_path=str(repo),
        mode='full', enabled_tools=list(tools), **kwargs), scanner.ExecutionControl.with_timeout(10))


def test_gitleaks_directory_capture_policy_remains_bound_to_reviewed_pin():
    root = next(parent for parent in Path(__file__).resolve().parents
                if (parent / 'scanner-tools.lock.json').is_file())
    lock = json.loads((root / 'scanner-tools.lock.json').read_text())
    assert next(tool for tool in lock['tools'] if tool['id'] == 'gitleaks')['version'] == '8.30.1'


def test_complete_capture_preserves_binary_controls_and_previously_lite_excluded_source(tmp_path, monkeypatch):
    configure(tmp_path, monkeypatch)
    repo = tmp_path / 'repo'
    contents = {'app.py': b'print(1)\n', '.gitleaksignore': b'fingerprint\n',
        '.gitleaks.toml': b'[allowlist]\nregexes=[".*"]\n', 'asset.bin': bytes(range(256)),
        'vendor/code.py': b'print(2)\n', 'node_modules/a.js': b'code\n',
        '.kodesec-data/code.py': b'code\n', 'case-sensitive/.GIT/code.py': b'code\n'}
    for name, data in contents.items():
        destination = repo / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    for name in ('.git/objects/large', 'nested/.git/config'):
        destination = repo / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b'x' * 20)
    (repo / 'empty').mkdir()
    result = capture(repo, tmp_path / 'owned')
    assert result.complete
    assert result.captured_files == len(contents)
    assert result.captured_bytes == sum(map(len, contents.values()))
    assert (result.root / 'empty').is_dir()
    assert not (result.root / '.git').exists()
    assert not (result.root / 'nested/.git').exists()
    for name, data in contents.items():
        assert (result.root / name).read_bytes() == data
    expected = hashlib.sha256(b'lomo-gitleaks-captured-inventory/v1\0')
    # Inventory order follows deterministic depth-first directory enumeration.
    def walk(relative):
        for child in sorted((repo / relative).iterdir()):
            name = child.relative_to(repo).as_posix()
            if child.is_dir():
                if child.name != '.git':
                    expected.update(scanner.canonical_json_bytes({'kind': 'directory', 'path': name}) + b'\n')
                    walk(name)
            else:
                data = child.read_bytes()
                expected.update(scanner.canonical_json_bytes({'kind': 'file', 'path': name,
                    'size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}) + b'\n')
    walk('')
    assert result.inventory_sha256 == expected.hexdigest()


def test_empty_root_ignore_directory_is_retained_for_refusal(tmp_path, monkeypatch):
    configure(tmp_path, monkeypatch)
    repo = tmp_path / 'repo'
    (repo / '.gitleaksignore').mkdir(parents=True)
    result = capture(repo, tmp_path / 'owned')
    assert (result.root / '.gitleaksignore').is_dir()
    absent = tmp_path / 'absent'
    absent.mkdir()
    absent_result = capture(absent, tmp_path / 'absent-owned')
    assert result.inventory_sha256 != absent_result.inventory_sha256


@pytest.mark.parametrize('kind', ['file', 'directory'])
def test_captured_root_ignore_still_refuses_without_native_execution(tmp_path, monkeypatch, kind):
    configure(tmp_path, monkeypatch)
    repo = tmp_path / 'repo'
    repo.mkdir()
    (repo / 'app.py').write_text('print(1)\n')
    ignore = repo / '.gitleaksignore'
    if kind == 'file':
        ignore.write_text('fingerprint\n')
    else:
        ignore.mkdir()
    calls = []
    monkeypatch.setattr(external, '_invoke_run_command', lambda *args, **kwargs: calls.append(args))
    result = scan(repo)
    assert result.status == 'partial'
    assert result.summary['external_runs'][0]['error'] == 'source_control_unsupported:gitleaks'
    assert result.summary['gitleaks_source_capture']['complete']
    assert calls == []
    assert ignore.exists()


def test_mutable_scan_uses_frozen_gitleaks_view_and_other_scanners_keep_original_view(tmp_path, monkeypatch):
    configure(tmp_path, monkeypatch)
    repo = tmp_path / 'repo'
    (repo / 'vendor').mkdir(parents=True)
    (repo / 'app.py').write_text('print(1)\n')
    (repo / 'vendor/app.py').write_text('print(2)\n')
    calls = {}
    def run(tool, source, *args):
        calls[tool] = source
        if tool == 'gitleaks':
            assert source != repo
            (repo / '.gitleaksignore').write_text('late suppression\n')
            (repo / 'app.py').write_text('changed\n')
            assert not (source / '.gitleaksignore').exists()
            assert (source / 'app.py').read_text() == 'print(1)\n'
            assert (source / 'vendor/app.py').read_text() == 'print(2)\n'
        return ToolRunResult(scanner=tool, status='completed', exit_code=0)
    monkeypatch.setattr(scanner, 'run_external_tool', run)
    result = scan(repo, ('gitleaks', 'checkov', 'sast-lite'))
    assert result.status == 'completed'
    assert calls['checkov'] == repo
    assert result.summary['source_coverage']['eligible_files'] == 1
    receipt = result.summary['gitleaks_source_capture']
    assert receipt['complete'] and len(receipt['inventory_sha256']) == 64
    assert receipt['directory_exclusion_policy'] == 'gitleaks-8.30.1-dotgit'
    assert list((tmp_path / 'scratch').iterdir()) == []


@pytest.mark.parametrize('bound,expected', [
    ('files', 'capture_file_limit_exceeded'), ('file_bytes', 'capture_file_too_large'),
    ('total_bytes', 'capture_total_bytes_exceeded'), ('symlink', 'capture_entry_unsupported_type')])
def test_incomplete_whole_capture_never_invokes_native_gitleaks(tmp_path, monkeypatch, bound, expected):
    configure(tmp_path, monkeypatch)
    repo = tmp_path / 'repo'
    repo.mkdir()
    (repo / 'a.bin').write_bytes(b'12345')
    (repo / 'b.bin').write_bytes(b'12345')
    if bound == 'files':
        scanner.settings.max_files = 1
    elif bound == 'file_bytes':
        monkeypatch.setattr(scanner, 'MAX_DIRECTORY_CAPTURE_FILE_BYTES', 4)
    elif bound == 'total_bytes':
        monkeypatch.setattr(scanner, 'MAX_DIRECTORY_CAPTURE_BYTES', 5)
    else:
        (repo / 'linked').symlink_to(repo / 'a.bin')
    calls = []
    monkeypatch.setattr(scanner, 'run_external_tool', lambda *args: calls.append(args))
    result = scan(repo)
    assert result.status == 'partial'
    assert calls == []
    assert result.summary['external_runs'][0]['status'] == 'failed'
    assert result.summary['external_runs'][0]['error'] == 'source_capture_incomplete'
    assert expected in result.summary['gitleaks_source_capture']['reason_counts']
    assert f'source_coverage: {expected}' in result.summary['errors']
    assert list((tmp_path / 'scratch').iterdir()) == []


def test_whole_capture_detects_directory_addition_during_enumeration(tmp_path, monkeypatch):
    configure(tmp_path, monkeypatch)
    repo = tmp_path / 'repo'
    repo.mkdir()
    (repo / 'app.py').write_text('print(1)\n')
    original = scanner.os.listdir
    def changed(descriptor):
        names = original(descriptor)
        (repo / '.gitleaksignore').write_text('late\n')
        return names
    monkeypatch.setattr(scanner.os, 'listdir', changed)
    with pytest.raises(scanner.SourceBoundaryError, match='changed during immutable capture'):
        capture(repo, tmp_path / 'owned')


def test_whole_capture_detects_file_mutation_during_copy(tmp_path, monkeypatch):
    configure(tmp_path, monkeypatch)
    repo = tmp_path / 'repo'
    repo.mkdir()
    (repo / 'app.py').write_text('print(1)\n')
    original = scanner.os.read
    changed = False
    def read(descriptor, count):
        nonlocal changed
        data = original(descriptor, count)
        if data and not changed:
            changed = True
            (repo / 'app.py').write_text('changed\n')
        return data
    monkeypatch.setattr(scanner.os, 'read', read)
    with pytest.raises(scanner.SourceBoundaryError, match='changed during immutable capture'):
        capture(repo, tmp_path / 'owned')


def test_whole_capture_rejects_directory_replacement_before_open(tmp_path, monkeypatch):
    configure(tmp_path, monkeypatch)
    repo = tmp_path / 'repo'
    (repo / 'child').mkdir(parents=True)
    (repo / 'child/app.py').write_text('print(1)\n')
    replacement = tmp_path / 'replacement'
    replacement.mkdir()
    (replacement / 'app.py').write_text('changed\n')
    original = scanner.os.open
    changed = False
    def opened(path, flags, *args, **kwargs):
        nonlocal changed
        if path == 'child' and not changed:
            changed = True
            (repo / 'child').rename(tmp_path / 'retained-child')
            replacement.rename(repo / 'child')
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(scanner.os, 'open', opened)
    with pytest.raises(scanner.SourceBoundaryError, match='changed before immutable capture'):
        capture(repo, tmp_path / 'owned')


@pytest.mark.parametrize('target', ['file', 'directory', 'sealed', 'without_gitleaks'])
def test_existing_non_mutable_root_routes_do_not_add_gitleaks_capture(tmp_path, monkeypatch, target):
    configure(tmp_path, monkeypatch)
    digest = 'a' * 64
    repo = tmp_path / ('snapshots/generations/' + digest + '/source' if target == 'sealed' else 'repo')
    (repo / 'src').mkdir(parents=True)
    (repo / 'src/app.py').write_text('print(1)\n')
    calls = []
    monkeypatch.setattr(scanner, 'run_external_tool', lambda tool, source, *args:
        calls.append(source) or ToolRunResult(scanner=tool, status='completed', exit_code=0))
    kwargs = {'source_snapshot_digest': digest} if target == 'sealed' else ({'target_kind': target,
        'target_path': 'src/app.py' if target == 'file' else 'src'} if target in ('file', 'directory') else {})
    result = scan(repo, ('checkov',) if target == 'without_gitleaks' else ('gitleaks',), **kwargs)
    assert result.status == 'completed'
    assert 'gitleaks_source_capture' not in result.summary
    if target in ('sealed', 'without_gitleaks'):
        assert calls == [repo]
