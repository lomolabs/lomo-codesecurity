#!/usr/bin/env python3
"""Collect bounded local support evidence without starting or changing services."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MAX_OUTPUT = 64 * 1024
ERROR_MARKER = re.compile(
    r'(?i)(?:^|[^a-z])(?:error|exception|failed|fatal|timeout|timed_out|deadline_exceeded|oom|killed)(?:$|[^a-z])'
    r'|[A-Za-z]+Error\b')
SERVICES = frozenset(('api', 'api-ingress', 'worker', 'scanner', 'scanner-updater',
    'advisor-connector', 'postgres', 'schema-init', 'prometheus', 'grafana', 'gitea', 'adminer'))
GRYPE_REASONS = frozenset(('files', 'import_metadata', 'import_checksum', 'file', 'changed',
    'size', 'deadline', 'cancelled', 'schema', 'integrity', 'data', 'database'))
GRYPE_PHASES = frozenset(('file_admission', 'physical_hash', 'sqlite_schema', 'sqlite_integrity',
    'logical_rows', 'final_fence'))
RUNTIME_COMPONENTS = frozenset(('none', 'bearer-rules', 'grype-db', 'opengrep-reviewed-rules',
    'trivy-checks', 'trivy-db', 'trivy-java-db'))


def scanner_failure_summaries(lines: list[str]) -> list[dict]:
    """Keep fixed diagnostic enums/counters, never arbitrary exception detail."""
    summaries = []
    for line in lines:
        runtime = re.search(r'scanner runtime cache verification failed target=(active|previous_good) '
            r'component_id=([a-z_-]+) state=(timed_out|failed|invalid) '
            r'phase=(queued|validating|hashing) elapsed_ms=([0-9]{1,6})(?: |$)', line)
        if runtime:
            if runtime[2] in RUNTIME_COMPONENTS and int(runtime[5]) <= 900_000:
                summaries.append({'component': runtime[2], 'error_class': 'RuntimeCacheVerification',
                    'target': runtime[1], 'reason': runtime[3], 'phase': runtime[4],
                    'validation_elapsed_ms': int(runtime[5])})
            if len(summaries) == 32:
                break
            continue
        if 'scanner lifecycle operation failed ' not in line or 'component_id=grype-db ' not in line:
            continue
        failure = re.search(r'\berror_type=GrypeContentValidationError detail=grype_validation_([a-z_]+)(?: |$)', line)
        if failure is None or failure[1] not in GRYPE_REASONS:
            continue
        item = {'component': 'grype-db', 'error_class': 'GrypeContentValidationError', 'reason': failure[1]}
        timing = re.search(r'\bvalidation_phase=([a-z_]+) phase_elapsed_ms=([0-9]{1,7}) '
            r'validation_elapsed_ms=([0-9]{1,7}) timing_capped=(True|False)(?: |$)', line)
        if (timing and timing[1] in GRYPE_PHASES
                and 0 <= int(timing[2]) <= int(timing[3]) <= 2_700_000):
            item.update(phase=timing[1], phase_elapsed_ms=int(timing[2]),
                validation_elapsed_ms=int(timing[3]), timing_capped=timing[4] == 'True')
        summaries.append(item)
        if len(summaries) == 32:
            break
    return summaries


def redact(text: str, values: dict[str, str]) -> str:
    # Exact runtime values cover generated credentials before pattern-based cleanup.
    sensitive_word = r'(?:password|passwd|secret|token|cookie|authorization|bootstrap|csrf|api[_-]?key|credentials?|private[_-]?key)'
    public_keys = {"KODESEC_INSTALLATION_ID", "COMPOSE_PROJECT_NAME", "KODESEC_SOURCE_COMMIT",
        "KODESEC_SOURCE_TREE", "KODESEC_SOURCE_DIGEST"}
    private_values = {value for key, value in values.items() if key not in public_keys
        and (len(value) >= 8 or re.search(sensitive_word + r'|(?:^|_)key$', key, re.I))}
    for value in sorted(private_values - {""}, key=len, reverse=True):
        text = text.replace(value, '[runtime value]')
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|\Z)', '[private key]', text)
    text = re.sub(r'(?i)\b(?:https?|ssh|postgres(?:ql)?|redis)://[^\s<>"\']+', '[url]', text)
    text = re.sub(r'(?i)\b(?:bearer|basic)\s+\S+', '[authorization]', text)
    sensitive_key = r'[a-z0-9_-]{0,64}' + sensitive_word + r'[a-z0-9_-]{0,64}'
    # Quoted JSON values may start on the following line; consume their full value.
    text = re.sub(r'(?is)["\']' + sensitive_key + r'["\']\s*:\s*"(?:\\.|[^"\\])*(?:"|\Z)', '[sensitive field]', text)
    text = re.sub(r'(?im)^.*' + sensitive_word + r'[^\r\n:=]{0,80}[=:].*$', '[sensitive field]', text)
    text = re.sub(r'\b(?:ks1_|kbm1_|gh[pousr]_|github_pat_|sk-)[A-Za-z0-9_-]+', '[credential]', text)
    text = re.sub(r'(?i)(?:[a-z]:[\\/](?:Users|Documents and Settings)[\\/]|/(?:Users|home|root|workspace|sources|repos)/)[^\s"\'<>]+', '[private path]', text)
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[email]', text)
    # Strip terminal controls, retaining tabs/newlines for readable logs.
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', text)


def capture(argv: list[str], deadline: float, timeout: float = 5) -> dict:
    """Drain a single owned process group within byte and whole-collection limits."""
    remaining = min(timeout, deadline - time.monotonic())
    if remaining <= 0:
        return {'status': 'not_collected', 'reason': 'collection_deadline'}
    if not shutil.which(argv[0]):
        return {'status': 'unavailable', 'reason': 'executable_missing'}
    started = time.monotonic()
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError as error:
        return {'status': 'unavailable', 'reason': type(error).__name__}
    output = bytearray()
    reason = None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            left = min(started + remaining, deadline) - time.monotonic()
            if left <= 0:
                reason = 'timeout'
                break
            for key, _ in selector.select(min(left, .1)):
                block = os.read(key.fileobj.fileno(), 8192)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                room = MAX_OUTPUT - len(output)
                output.extend(block[:room])
                if len(block) > room:
                    reason = 'output_limit'
                    break
            if reason:
                break
        if not reason:
            try:
                process.wait(timeout=max(.01, min(started + remaining, deadline) - time.monotonic()))
            except subprocess.TimeoutExpired:
                reason = 'timeout'
    finally:
        selector.close()
        if reason:
            # Only the CLI session created above, never a container or service.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            reason = 'cleanup_unconfirmed'
        process.stdout.close()
    return {'status': reason or ('ok' if process.returncode == 0 else 'failed'),
        'returncode': process.returncode, 'elapsed_ms': round((time.monotonic() - started) * 1000),
        'captured_bytes': len(output), 'text': output.decode('utf-8', errors='replace')}


def read_runtime(path: Path) -> tuple[dict, str]:
    spec = importlib.util.spec_from_file_location('support_runtime', ROOT / 'scripts/runtime-compose.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.read_runtime(path), 'read'
    except SystemExit:
        return {}, 'missing_or_invalid_owner_only_configuration'


def collect(runtime: Path, *, include_logs: bool = False, runner=capture) -> tuple[dict, dict[str, bytes]]:
    started = datetime.now(timezone.utc)
    deadline = time.monotonic() + 90
    values, runtime_status = read_runtime(runtime)
    files: dict[str, bytes] = {}
    observations = {}

    def run(name, argv, timeout=5):
        result = runner(argv, deadline, timeout)
        raw = result.pop('text', '')
        text = redact(raw, values)
        files[f'{name}.txt'] = text.encode()
        observations[name] = result
        return raw, result

    system = {'os': platform.system(), 'release': platform.release(), 'architecture': platform.machine(),
        'python': platform.python_version(), 'runtime_configuration': runtime_status}
    try:
        usage = shutil.disk_usage(runtime.parent if runtime.parent.exists() else ROOT)
        system['state_filesystem_free_bytes'] = usage.free
    except OSError:
        system['state_filesystem_free_bytes'] = None
    for name, argv in [('git-version', ['git', '--version']), ('make-version', ['make', '--version']),
        ('docker-version', ['docker', 'version', '--format', '{{json .}}']),
        ('compose-version', ['docker', 'compose', 'version']), ('buildx-version', ['docker', 'buildx', 'version'])]:
        run(name, argv)
    run('source-revision', ['git', '-C', str(ROOT), 'rev-parse', 'HEAD'])
    run('source-identity', [sys.executable, str(ROOT / 'scripts/source_provenance.py'), '--json'])
    for lock in ('scanner-tools.lock.json', 'scanner-rules.lock.json'):
        path = ROOT / lock
        if path.is_file():
            system[lock + '_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    project = values.get('COMPOSE_PROJECT_NAME', '')
    installation = values.get('KODESEC_INSTALLATION_ID', '')
    if re.fullmatch(r'[a-f0-9]{12}', installation) and project == f'lomo-code-security-{installation}':
        system['installation_id'] = installation
        # List only this installation; never enumerate other Docker projects.
        raw, result = run('containers', ['docker', 'ps', '-a', '--no-trunc', '--filter',
            f'label=com.docker.compose.project={project}', '--format', '{{.ID}}'])
        ids = raw.splitlines()
        valid_ids = len(ids) == len(set(ids)) and all(re.fullmatch(r'[a-f0-9]{64}', item) for item in ids)
        if result['status'] == 'ok' and (len(ids) > 24 or not valid_ids):
            observations['container-details'] = {'status': 'not_collected',
                'reason': 'container_inventory_bound' if len(ids) > 24 else 'container_inventory_invalid',
                'observed_count': len(ids), 'maximum_count': 24}
        if result['status'] == 'ok' and len(ids) <= 24 and valid_ids:
            for container in ids:
                # Do not collect Env, mounts, command arguments or health-check output.
                metadata_format = '{{json .Id}} {{json .Image}} {{json .State.Status}} {{json .State.ExitCode}} {{json .State.OOMKilled}} {{json .RestartCount}} {{json (index .Config.Labels "com.docker.compose.service")}} {{json (index .Config.Labels "com.docker.compose.project")}}'
                raw, result = run('container-' + container[:12], ['docker', 'inspect', '--format', metadata_format, container])
                # Revalidate labels before collecting this exact container's logs.
                try:
                    # JSONDecoder consumes each exact field; labels must match before logs.
                    decoder = json.JSONDecoder()
                    fields = []
                    tail = raw.strip()
                    while tail:
                        value, end = decoder.raw_decode(tail)
                        fields.append(value)
                        tail = tail[end:].lstrip()
                    admitted = (len(fields) == 8 and fields[0] == container
                        and fields[6] in SERVICES and fields[7] == project)
                except (ValueError, TypeError):
                    admitted = False
                if result['status'] != 'ok' or not admitted:
                    observations['logs-' + container[:12]] = {'status': 'not_collected', 'reason': 'identity_unverified'}
                    continue
                since = (started - timedelta(minutes=15)).isoformat()
                until = started.isoformat()
                logs, log_result = run('logs-' + container[:12], ['docker', 'logs', '--timestamps', '--since', since,
                    '--until', until, '--tail', '200', container])
                logs = redact(logs, values)
                log_result['log_text_included'] = include_logs and log_result['status'] == 'ok'
                if not log_result['log_text_included']:
                    # Default privacy boundary: error classes/counts/fingerprints, not
                    # arbitrary messages that can contain source or unknown secrets.
                    lines = logs.splitlines()
                    classes = sorted(set(re.findall(r'\b(?:TimeoutError|ConnectionError|ValueError|RuntimeError|PermissionError|OSError|HTTPError|CancelledError|IntegrityError)\b', logs)))
                    summary = {'lines_in_bounded_window': len(lines), 'error_classes': classes,
                        'error_marker_lines': sum(bool(ERROR_MARKER.search(line)) for line in lines),
                        'scanner_failures': scanner_failure_summaries(lines),
                        'redacted_text_sha256': hashlib.sha256(logs.encode()).hexdigest(),
                        'text_included': False, 'since': since, 'until': until,
                        'tail_limit': 200, 'byte_limit': MAX_OUTPUT,
                        'history_completeness': 'not_asserted; Docker rotation and tail limits may omit lines'}
                    files['logs-' + container[:12] + '.txt'] = (json.dumps(summary, indent=2) + '\n').encode()
    else:
        observations['containers'] = {'status': 'not_collected', 'reason': 'installation_identity_unavailable'}
    manifest = {'schema': 'lomo-support-bundle/v1', 'started_at': started.isoformat(),
        'finished_at': datetime.now(timezone.utc).isoformat(), 'system': system,
        'redacted_log_text_included': include_logs, 'observations': observations,
        'scope': 'read-only; no upload, startup, repair, source, database or profile export',
        'limits': {'workflow_seconds': 90, 'command_seconds': 5, 'command_bytes': MAX_OUTPUT,
            'services': 24, 'log_tail_lines': 200, 'log_lookback_minutes': 15}}
    return manifest, files


def write_bundle(output: Path, manifest: dict, files: dict[str, bytes]) -> None:
    manifest['files'] = {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        for name, data in sorted(files.items())}
    files = {**files, 'manifest.json': (json.dumps(manifest, indent=2) + '\n').encode(),
        'README.txt': b'Local Lomo support evidence. Review before sharing. Nothing was uploaded.\n'
            b'Default logs contain summaries only. Opt-in redacted text may still contain private custom messages.\n'
            b'Missing, truncated and timed-out observations are gaps, not proof of health.\n'}
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as stream, tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-env', type=Path, required=True)
    parser.add_argument('--include-log-text', action='store_true', help='Include bounded redacted service text; review before sharing')
    args = parser.parse_args()
    if os.name != 'posix':
        parser.error('Run this command in the selected backend WSL distro on Windows.')
    directory = Path(tempfile.mkdtemp(prefix='lomo-support-'))
    output = directory / 'support-bundle.tar.gz'
    manifest, files = collect(args.runtime_env, include_logs=args.include_log_text)
    write_bundle(output, manifest, files)
    print(f'Support bundle: {output}')
    print('Read-only collection complete. Review the manifest and files before sharing; nothing was uploaded.')


if __name__ == '__main__':
    main()
