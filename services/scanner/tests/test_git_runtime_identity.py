"""Immutable Git evidence must not survive a changed scanner build."""
import pytest

from kodesec_scanner import tools


@pytest.mark.parametrize("kind", ["git", "source-sha256"])
def test_identity_binds_verified_build_source_and_executable(tmp_path, monkeypatch, kind):
    build = tmp_path / "build-identity"
    package = tmp_path / "package"
    package.mkdir()
    source = package / "tools.py"
    source.write_text("# bounded synthetic adapter\n")
    monkeypatch.setattr(tools, "BUILD_IDENTITY_PATH", build)
    monkeypatch.setattr(tools, "__file__", str(source))
    assert tools._runtime_identity("checkov", "a" * 64) is None
    build.write_text("scanner:" + ("a" * 40 + ":" + "b" * 40 if kind == "git" else "source-sha256:" + "a" * 64) + "\n")
    initial = tools._runtime_identity("checkov", "a" * 64)
    assert initial is not None and len(initial) == 64
    assert tools._runtime_identity("checkov", "b" * 64) != initial
    source.write_text("# changed synthetic adapter\n")
    changed = tools._runtime_identity("checkov", "a" * 64)
    assert changed != initial
    build.write_text("scanner:" + ("c" * 40 + ":" + "d" * 40 if kind == "git" else "source-sha256:" + "c" * 64) + "\n")
    assert tools._runtime_identity("checkov", "a" * 64) != changed
    build.write_text("unverified")
    assert tools._runtime_identity("checkov", "a" * 64) is None


@pytest.mark.parametrize("value", [
    "scanner:source-sha256:" + "a" * 63,
    "scanner:source-sha256:" + "a" * 65,
    "scanner:source-sha256:" + "A" * 64,
    "scanner:source-sha256:" + "a" * 64 + ":extra",
    "scanner:source-sha256:" + "a" * 40 + ":" + "b" * 40,
    "control:source-sha256:" + "a" * 64,
    "scanner:sha256:" + "a" * 64,
    "scanner:" + "a" * 64,
    "scanner:" + "a" * 40 + ":" + "b" * 39,
    "scanner:git:" + "a" * 40 + ":" + "b" * 40,
])
def test_runtime_identity_rejects_malformed_or_mixed_source_identity(tmp_path, monkeypatch, value):
    build = tmp_path / "build-identity"
    build.write_text(value + "\n")
    monkeypatch.setattr(tools, "BUILD_IDENTITY_PATH", build)
    monkeypatch.setattr(tools, "scanner_package_identity", lambda: pytest.fail("invalid build identity reached package hashing"))
    assert tools._runtime_identity("checkov", "a" * 64) is None
