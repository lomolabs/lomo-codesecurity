from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import pytest

from kodesec_scanner.release_signature import CosignTrust, SignatureVerificationError, verify_blob
from kodesec_scanner import release_signature as module

REAL_IMMUTABLE_EXECUTABLE = module._immutable_executable


@pytest.fixture(autouse=True)
def synthetic_image_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    # Test executables are disposable scripts, not immutable image payloads.
    monkeypatch.setattr(module, "_immutable_executable", lambda path: True)


def setup_inputs(tmp_path: Path, body: str = "sys.exit(0)") -> tuple[Path, Path, CosignTrust]:
    tmp_path = tmp_path.resolve()
    artifact, bundle, root, binary = (tmp_path / name for name in ("artifact", "bundle", "root", "cosign"))
    artifact.write_bytes(b'{"release":"fixture"}')
    bundle.write_bytes(b"fixture bundle")
    root.write_bytes(b"fixture trust root")
    binary.write_text(f"#!{sys.executable}\nimport sys, os\n" + body + "\n")
    binary.chmod(0o700)
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    return artifact, bundle, CosignTrust(binary, digest(binary), root, digest(root),
        "https://github.com/example/fixture/.github/workflows/data.yml@refs/heads/main",
        "https://token.actions.githubusercontent.com")


def test_signature_fixed_offline_command_returns_exact_bytes_without_output(tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    artifact, bundle, trust = setup_inputs(tmp_path, """from pathlib import Path
assert sys.argv[1:3] == ['verify-blob', '--offline']
assert '--trusted-root' in sys.argv and '--certificate-identity' in sys.argv
assert '--certificate-oidc-issuer' in sys.argv
assert not any('regexp' in value or 'insecure' in value or 'ignore' in value for value in sys.argv)
assert sys.stdin.read() == ''
assert 'HTTPS_PROXY' not in os.environ and 'GITHUB_TOKEN' not in os.environ
assert Path(sys.argv[-1]).read_bytes() == b'{"release":"fixture"}'
print('private signature output')
print('private stderr', file=sys.stderr)
""")
    expected = artifact.read_bytes()
    proof = verify_blob(artifact, bundle, trust)
    artifact.write_bytes(b"replacement")
    assert proof.artifact == expected
    assert proof.sha256 == hashlib.sha256(expected).hexdigest()
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("case,code", [("binary", "executable"), ("root", "trust"), ("symlink", "file"), ("signature", "signature")])
def test_signature_refuses_untrusted_inputs(tmp_path: Path, case: str, code: str) -> None:
    artifact, bundle, trust = setup_inputs(tmp_path, "sys.exit(2)" if case == "signature" else "sys.exit(0)")
    if case == "binary":
        trust.executable.write_bytes(b"replacement")
    elif case == "root":
        trust.trusted_root.write_bytes(b"replacement")
    elif case == "symlink":
        link = artifact.with_name("link")
        link.symlink_to(artifact)
        artifact = link
    with pytest.raises(SignatureVerificationError) as raised:
        verify_blob(artifact, bundle, trust)
    assert raised.value.code == code


def test_signature_timeout_and_cancellation_stop_owned_process(tmp_path: Path) -> None:
    artifact, bundle, trust = setup_inputs(tmp_path, "import time\ntime.sleep(30)")
    with pytest.raises(SignatureVerificationError, match="timeout"):
        verify_blob(artifact, bundle, trust, timeout_seconds=0.05)
    cancellation = RuntimeError("test cancellation")
    checks = 0
    def checkpoint() -> None:
        nonlocal checks
        checks += 1
        if checks == 3:
            raise cancellation
    with pytest.raises(RuntimeError) as raised:
        verify_blob(artifact, bundle, trust, checkpoint=checkpoint)
    assert raised.value is cancellation


def test_signature_missing_trust_never_executes(tmp_path: Path) -> None:
    artifact, bundle, trust = setup_inputs(tmp_path)
    with pytest.raises(SignatureVerificationError, match="trust"):
        verify_blob(artifact, bundle, trust._replace(certificate_identity=""))


def test_signature_refuses_mutable_executable_filesystem(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact, bundle, trust = setup_inputs(tmp_path)
    monkeypatch.setattr(module, "_immutable_executable", REAL_IMMUTABLE_EXECUTABLE)
    assert REAL_IMMUTABLE_EXECUTABLE(trust.executable) is False
    with pytest.raises(SignatureVerificationError, match="executable"):
        verify_blob(artifact, bundle, trust)
