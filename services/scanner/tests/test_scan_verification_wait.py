from pathlib import Path
from types import SimpleNamespace

import pytest

from kodesec_scanner import tools, external
from kodesec_scanner.external import ExecutionControl, RunCancelled, RunDeadlineExceeded


@pytest.fixture
def runtime(monkeypatch):
    calls = []
    locks = SimpleNamespace(value=SimpleNamespace(tools=[SimpleNamespace(
        id='fixture', requirements=[SimpleNamespace(required=True)])]), sha256='a' * 64)
    rules = SimpleNamespace(value=object(), sha256='b' * 64)
    monkeypatch.setattr(tools, 'load_tool_lock', lambda _path: locks)
    monkeypatch.setattr(tools, 'load_rules_lock', lambda _path: rules)
    monkeypatch.setattr(tools, 'validate_runtime_lock_contract', lambda _value: None)
    monkeypatch.setattr(tools, 'external_tool_ids', lambda: {'fixture'})
    monkeypatch.setattr(tools, 'tool_runtime_state', lambda _id: calls.append('binary') or {'status': 'ready'})
    monkeypatch.setattr(tools, 'evaluate_tool_readiness', lambda _t, _r, resolved, _b:
        [SimpleNamespace(tool_id='fixture', ready=resolved.state == 'ready')])
    def state(status, reference='same'):
        return SimpleNamespace(state=status, pointer=SimpleNamespace(active=reference), generation=None)
    return calls, state


def context(resolver, wait=None, control=None, requested=None):
    return tools.scanner_runtime_context(tool_lock_path=Path('tools'), rules_lock_path=Path('rules'),
        cache_root=Path('cache'), resolver=resolver, requested_tools={'fixture'} if requested is None else requested,
        verification_wait=wait, checkpoint=control.checkpoint if control else None)


def test_scan_waits_for_exact_cache_before_binary_readiness(runtime):
    calls, state = runtime
    snapshots = iter([state('verifying'), state('verifying'), state('ready')])
    arguments = []
    def resolve(_root, **kwargs):
        calls.append('resolve'); arguments.append(kwargs); return next(snapshots)
    control = ExecutionControl.with_timeout(1)
    deadline = control.deadline_monotonic
    result = context(resolve, lambda: calls.append('wait'), control)
    assert result.readiness_by_id['fixture'].ready
    assert calls == ['resolve', 'wait', 'resolve', 'wait', 'resolve', 'binary']
    assert all(row['tool_lock_sha256'] == 'a' * 64 and row['rules_lock_sha256'] == 'b' * 64 for row in arguments)
    assert control.deadline_monotonic == deadline


@pytest.mark.parametrize('terminal', ['invalid', 'unavailable', 'verification_timeout', 'verification_failed'])
def test_terminal_verification_failure_is_not_retried_or_made_ready(runtime, terminal):
    calls, state = runtime
    snapshots = iter([state('verifying'), state(terminal)])
    result = context(lambda *_a, **_k: next(snapshots), lambda: calls.append('wait'), ExecutionControl.with_timeout(1))
    assert calls == ['wait', 'binary']
    assert result.resolved.state == terminal and not result.readiness_by_id['fixture'].ready


@pytest.mark.parametrize('interrupt', ['cancel', 'deadline'])
def test_wait_obeys_original_cancel_and_deadline_without_readiness_publication(runtime, interrupt, monkeypatch):
    calls, state = runtime
    now = [0.0]
    monkeypatch.setattr(external, 'time', SimpleNamespace(monotonic=lambda: now[0]))
    control = ExecutionControl.with_timeout(1)
    def wait():
        if interrupt == 'cancel': control.cancel_event.set()
        else: now[0] = 2.0
    with pytest.raises(RunCancelled if interrupt == 'cancel' else RunDeadlineExceeded):
        context(lambda *_a, **_k: state('verifying'), wait, control)
    assert calls == []


def test_changed_active_generation_is_not_silently_adopted(runtime):
    calls, state = runtime
    snapshots = iter([state('verifying'), state('ready', 'replacement')])
    result = context(lambda *_a, **_k: next(snapshots), lambda: None, ExecutionControl.with_timeout(1))
    assert result.resolved is None and not result.readiness_by_id['fixture'].ready


@pytest.mark.parametrize('requested', [set(), {'unrelated'}])
def test_tools_without_required_cache_do_not_wait(runtime, requested):
    calls, state = runtime
    def forbidden(): raise AssertionError('unneeded verification wait')
    result = context(lambda *_a, **_k: state('verifying'), forbidden, ExecutionControl.with_timeout(1), requested)
    assert result.resolved.state == 'verifying' and calls == ['binary']


def test_status_reader_remains_nonblocking(runtime):
    calls, state = runtime
    result = context(lambda *_a, **_k: state('verifying'))
    assert result.resolved.state == 'verifying' and calls == ['binary']
