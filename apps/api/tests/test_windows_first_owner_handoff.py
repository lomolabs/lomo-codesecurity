"""Producer unit checks; these are not Windows ACL/foreground acceptance."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("windows_first_owner_handoff", ROOT / "scripts/publish-windows-first-owner.py")
assert SPEC and SPEC.loader
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


@pytest.fixture
def installer(tmp_path):
    state = (tmp_path / "state").resolve()
    state.mkdir(mode=0o700)
    token = "a" * 43
    unrelated = "never-forward-this-installation-secret"
    runtime = state / "runtime.env"
    runtime.write_text(f"KODESEC_INSTALLATION_ID=123456abcdef\nCONTROL_PORT=8180\nKODESEC_BOOTSTRAP_TOKEN={token}\nKODESEC_INSTALLATION_SECRET={unrelated}\n")
    runtime.chmod(0o600)
    payload = {"v": 1, "installation_id": "123456abcdef", "control_origin": "http://127.0.0.1:8180", "bootstrap_token": token}
    artifact = state / handoff.FILE_NAME
    artifact.write_text(json.dumps(payload))
    artifact.chmod(0o600)
    return state, runtime, artifact, payload, unrelated


def test_windows_handoff_forwards_only_existing_exact_authority_and_preserves_inputs(installer):
    state, runtime, artifact, payload, unrelated = installer
    before = (runtime.read_bytes(), artifact.read_bytes())
    request = handoff.handoff_request(state, runtime)
    assert request == {"installation_id": payload["installation_id"], "control_origin": payload["control_origin"], "bootstrap": payload}
    assert unrelated not in json.dumps(request)
    assert (runtime.read_bytes(), artifact.read_bytes()) == before
    # Missing means consumed/unavailable; runtime's token never regenerates it.
    artifact.unlink()
    assert handoff.handoff_request(state, runtime)["bootstrap"] is None
    assert not artifact.exists()


@pytest.mark.parametrize("change", ["origin", "installation", "token", "extra", "boolean_version", "duplicate"])
def test_windows_handoff_refuses_mismatched_or_malformed_existing_authority(installer, change):
    state, runtime, artifact, payload, _ = installer
    if change == "origin": payload["control_origin"] = "http://127.0.0.1:8080"
    elif change == "installation": payload["installation_id"] = "abcdef123456"
    elif change == "token": payload["bootstrap_token"] = "b" * 43
    elif change == "extra": payload["runtime_secret"] = "never-forward"
    elif change == "boolean_version": payload["v"] = True
    text = json.dumps(payload)
    if change == "duplicate": text = text[:-1] + ',"v":1}'
    artifact.write_text(text)
    with pytest.raises(handoff.HandoffError):
        handoff.handoff_request(state, runtime)
    assert artifact.read_text() == text


@pytest.mark.parametrize("change", ["runtime_mode", "artifact_mode", "artifact_link", "artifact_hardlink", "artifact_size", "state_alias"])
def test_windows_handoff_refuses_unsafe_input_storage(installer, change, tmp_path):
    state, runtime, artifact, _, _ = installer
    if change == "runtime_mode": runtime.chmod(0o644)
    elif change == "artifact_mode": artifact.chmod(0o644)
    elif change == "artifact_link":
        target = state / "other"
        artifact.rename(target)
        artifact.symlink_to(target)
    elif change == "artifact_hardlink": (state / "alias").hardlink_to(artifact)
    elif change == "artifact_size": artifact.write_text("x" * 2049)
    elif change == "state_alias":
        alias = tmp_path / "state-alias"
        alias.symlink_to(state, target_is_directory=True)
        state, runtime = alias, alias / "runtime.env"
    with pytest.raises((handoff.HandoffError, OSError)):
        handoff.handoff_request(state, runtime)


@pytest.mark.parametrize("status", ["published", "retained", "unavailable"])
def test_windows_handoff_transport_uses_stdin_and_checks_receipt_identity(installer, monkeypatch, status):
    state, runtime, _, _, unrelated = installer
    request = handoff.handoff_request(state, runtime)
    calls = []
    def run(argv, **options):
        calls.append((argv, options))
        return subprocess.CompletedProcess(argv, 0, json.dumps({"status": status, "installation_id": request["installation_id"], "control_origin": request["control_origin"]}), "")
    monkeypatch.setattr(handoff.subprocess, "run", run)
    assert handoff.publish(request, "/approved/system/powershell.exe") == status
    argv, options = calls[0]
    assert argv[1:4] == ["-NoProfile", "-NonInteractive", "-Command"]
    assert request["bootstrap"]["bootstrap_token"] not in repr(argv)
    assert unrelated not in options["input"]
    assert json.loads(options["input"]) == request
    assert options["timeout"] == 30
    assert "-ExecutionPolicy" not in argv and "shell" not in options


def test_windows_handoff_never_exposes_subprocess_error_and_refuses_wrong_receipt(installer, monkeypatch):
    state, runtime, _, payload, _ = installer
    request = handoff.handoff_request(state, runtime)
    secret = payload["bootstrap_token"]
    monkeypatch.setattr(handoff.subprocess, "run", lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, secret, secret))
    with pytest.raises(handoff.HandoffError) as caught:
        handoff.publish(request, "/approved/system/powershell.exe")
    assert secret not in str(caught.value)
    response = {"status": "retained", "installation_id": "abcdef123456", "control_origin": payload["control_origin"]}
    monkeypatch.setattr(handoff.subprocess, "run", lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, json.dumps(response), ""))
    with pytest.raises(handoff.HandoffError, match="invalid receipt"):
        handoff.publish(request, "/approved/system/powershell.exe")


def test_windows_handoff_refuses_non_wsl_execution(monkeypatch):
    monkeypatch.setattr(handoff.sys, "platform", "darwin")
    with pytest.raises(handoff.HandoffError, match="inside Windows WSL"):
        handoff.native_powershell()


def test_windows_handoff_fixed_native_program_retains_creation_and_replay_fences():
    # Source guard only. Actual .NET/NTFS ACL execution belongs to Windows QA.
    program = handoff.native_program()
    assert "LocalApplicationData" in program
    assert "[IO.FileMode]::CreateNew" in program
    assert "$acl.SetAccessRuleProtection($true, $false)" in program
    assert "'S-1-5-18','S-1-5-32-544'" in program
    assert "[IO.FileAttributes]::ReparsePoint" in program
    assert "Write-Record $marker $record" in program
    assert program.index("state='reserved'") < program.index("$destination = New-PrivateFile $artifact")
    assert program.index("$record.state = 'published'") > program.index("Write-Record $destination $request.bootstrap")
    assert "if (Test-Path -LiteralPath $artifact) { Refuse-Handoff }" in program
    assert "Set-Acl" not in program and "ExecutionPolicy" not in program
    assert "Write-Host" not in program and "Start-Transcript" not in program
