from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from kodesec_scanner import main as scanner
from kodesec_scanner.external import ToolRunResult


def _symlink(link: Path, target: Path, *, target_is_directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _init_repo(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "Source Boundary Test")
    _git(repo, "config", "user.email", "source-boundary@example.invalid")
    _git(repo, "config", "commit.gpgsign", "false")


def _configure_scan_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        scanner,
        "settings",
        SimpleNamespace(
            allowed_root_list=[str(tmp_path)],
            max_files=100,
            max_file_bytes=1024 * 1024,
            artifact_dir=str(tmp_path / "artifacts"),
            source_snapshot_dir=str(tmp_path / "source-snapshots"),
            scratch_dir=str(tmp_path / "scratch"),
            tool_cache_dir=str(tmp_path / "tool-cache"),
            tool_lock_path=str(tmp_path / "scanner-tools.lock.json"),
            rules_lock_path=str(tmp_path / "scanner-rules.lock.json"),
            external_tool_timeout=30,
            validate_storage_boundaries=lambda: None,
        ),
    )
    monkeypatch.setattr(
        scanner,
        "scanner_runtime_context",
        lambda **_kwargs: SimpleNamespace(
            runtime_by_id={},
            readiness_by_id={},
            tools=None,
        ),
    )


def test_repo_symlink_cannot_escape_an_allowed_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    linked_repo = allowed / "linked-repo"
    _symlink(linked_repo, outside, target_is_directory=True)
    monkeypatch.setattr(scanner, "settings", SimpleNamespace(allowed_root_list=[str(allowed)]))

    with pytest.raises(scanner.SourceBoundaryError, match="configured source boundary"):
        scanner._ensure_allowed(linked_repo)


@pytest.mark.parametrize("target_kind", [None, "directory"])
@pytest.mark.parametrize("sealed", [False, True])
def test_valid_snapshot_request_keeps_tracked_source_universe(tmp_path, monkeypatch, target_kind, sealed):
    _configure_scan_execution(tmp_path, monkeypatch)
    digest = "a" * 64
    repo = (tmp_path / "source-snapshots/generations" / digest / "source"
            if sealed else tmp_path / "repo")
    for name in ("app.py", "ignored.py", "vendor/secret.py", ".kodesec-source/hidden.py"):
        source = repo / "docs" / name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("print(1)\n")
    (repo / "docs/.gitignore").write_text("ignored.py\nvendor/\n")
    result = scanner._execute_scan(scanner.ScanRequest(
        scan_id=99, repo_path=str(repo), mode="full", target_kind=target_kind,
        target_path="docs" if target_kind == "directory" else None,
        source_snapshot_digest=digest if sealed else None, enabled_tools=["sast-lite"],
    ), scanner.ExecutionControl.with_timeout(10))
    assert result.status == "completed"
    coverage = result.summary["source_coverage"]
    assert coverage["complete"]
    assert coverage["eligible_files"] == (4 if sealed else 2)
    assert coverage["read_files"] == (4 if sealed else 2)
    if target_kind == "directory":
        assert result.summary["source_capture"]["captured_files"] == (5 if sealed else 3)
    assert list((tmp_path / "scratch").iterdir()) == []


@pytest.mark.parametrize("digest", [None, "b" * 64])
def test_invalid_snapshot_binding_never_enables_sealed_policy(tmp_path, monkeypatch, digest):
    _configure_scan_execution(tmp_path, monkeypatch)
    repo = tmp_path / "source-snapshots/generations" / ("a" * 64) / "source"
    (repo / "vendor").mkdir(parents=True)
    (repo / "vendor/secret.py").write_text("print(1)\n")
    calls = []
    monkeypatch.setattr(scanner, "_execute_scan_in_scratch", lambda *args, **kwargs: calls.append(kwargs))
    with pytest.raises(scanner.SourceBoundaryError):
        scanner._execute_scan(scanner.ScanRequest(scan_id=100, repo_path=str(repo), mode="full",
            source_snapshot_digest=digest, enabled_tools=["sast-lite"]),
            scanner.ExecutionControl.with_timeout(10))
    assert calls == []
    assert not (tmp_path / "scratch").exists()


def test_sealed_directory_keeps_capture_and_analysis_bounds_distinct(tmp_path, monkeypatch):
    _configure_scan_execution(tmp_path, monkeypatch)
    digest = "a" * 64
    repo = tmp_path / "source-snapshots/generations" / digest / "source"
    selected = repo / "docs/vendor"
    selected.mkdir(parents=True)
    (selected / "large.py").write_bytes(b"x" * (1_048_576 + 1))
    (selected / "asset.png").write_bytes(b"x" * (8_388_608 + 1))
    result = scanner._execute_scan(scanner.ScanRequest(scan_id=101, repo_path=str(repo), mode="full",
        source_snapshot_digest=digest, target_kind="directory", target_path="docs",
        enabled_tools=["sast-lite"]), scanner.ExecutionControl.with_timeout(10))
    assert result.status == "partial"
    assert result.summary["source_capture"]["reason_counts"] == {"capture_file_too_large": 1}
    assert result.summary["source_capture"]["captured_files"] == 1
    assert result.summary["source_coverage"]["reason_counts"] == {"eligible_file_too_large": 1}
    assert list((tmp_path / "scratch").iterdir()) == []


def test_sealed_directory_still_enforces_aggregate_capture_bound(tmp_path, monkeypatch):
    _configure_scan_execution(tmp_path, monkeypatch)
    monkeypatch.setattr(scanner, "MAX_DIRECTORY_CAPTURE_BYTES", 10)
    digest = "a" * 64
    repo = tmp_path / "source-snapshots/generations" / digest / "source"
    selected = repo / "docs/vendor"
    selected.mkdir(parents=True)
    (selected / "a.py").write_bytes(b"print(1)\n")
    (selected / "b.py").write_bytes(b"print(2)\n")
    result = scanner._execute_scan(scanner.ScanRequest(scan_id=102, repo_path=str(repo), mode="full",
        source_snapshot_digest=digest, target_kind="directory", target_path="docs",
        enabled_tools=["sast-lite"]), scanner.ExecutionControl.with_timeout(10))
    assert result.status == "partial"
    assert result.summary["source_capture"]["captured_bytes"] == 9
    assert result.summary["source_capture"]["reason_counts"] == {"capture_total_bytes_exceeded": 1}
    assert result.summary["source_coverage"]["reason_counts"] == {"eligible_file_capture_total_bytes_exceeded": 1}
    assert list((tmp_path / "scratch").iterdir()) == []


def test_sealed_directory_still_enforces_file_count_bound(tmp_path, monkeypatch):
    _configure_scan_execution(tmp_path, monkeypatch)
    scanner.settings.max_files = 1
    digest = "a" * 64
    repo = tmp_path / "source-snapshots/generations" / digest / "source"
    selected = repo / "docs/vendor"
    selected.mkdir(parents=True)
    for name in ("a.py", "b.py"):
        (selected / name).write_text("print(1)\n")
    result = scanner._execute_scan(scanner.ScanRequest(scan_id=103, repo_path=str(repo), mode="full",
        source_snapshot_digest=digest, target_kind="directory", target_path="docs",
        enabled_tools=["sast-lite"]), scanner.ExecutionControl.with_timeout(10))
    assert result.status == "partial"
    assert result.summary["source_capture"]["captured_files"] == 1
    assert result.summary["source_capture"]["reason_counts"] == {"capture_file_limit_exceeded": 1}
    assert result.summary["source_coverage"]["reason_counts"] == {"eligible_file_limit_exceeded": 1}
    assert list((tmp_path / "scratch").iterdir()) == []


def test_directory_capture_preserves_large_assets_without_expanding_eligible_code(tmp_path, monkeypatch):
    _configure_scan_execution(tmp_path, monkeypatch)
    repo = tmp_path / "repo"
    selected = repo / "docs"
    selected.mkdir(parents=True)
    asset = b"\x89PNG\r\n\x1a\n" + b"x" * (5_800_000 - 8)
    (selected / "image.png").write_bytes(asset)
    (selected / "app.py").write_text("print(1)\n")
    owned = tmp_path / "owned-capture"
    owned.mkdir()
    captured = scanner._capture_target_directory(repo, "docs", owned, scanner.ExecutionControl.with_timeout(10))
    assert captured.complete
    assert captured.captured_files == 2
    assert (captured.root / "docs/image.png").read_bytes() == asset
    assert captured.source_coverage.eligible_files == 1
    assert captured.as_receipt()["max_file_bytes"] == 1_048_576
    assert captured.as_receipt()["max_capture_file_bytes"] == 8_388_608
    oversized_code = b"x" * (1_048_576 + 1)
    (selected / "large.py").write_bytes(oversized_code)
    with_code = tmp_path / "owned-code-capture"
    with_code.mkdir()
    retained = scanner._capture_target_directory(repo, "docs", with_code, scanner.ExecutionControl.with_timeout(10))
    assert retained.complete
    assert retained.captured_files == 3
    assert (retained.root / "docs/large.py").read_bytes() == oversized_code
    result = scanner._execute_scan(scanner.ScanRequest(scan_id=98, repo_path=str(repo), mode="full",
        target_path="docs", target_kind="directory", enabled_tools=["sast-lite"]),
        scanner.ExecutionControl.with_timeout(10))
    assert result.status == "partial"
    assert result.summary["source_coverage"]["reason_counts"] == {"eligible_file_too_large": 1}
    assert result.summary["source_capture"]["complete"]
    assert result.summary["source_capture"]["reason_counts"] == {}
    assert result.summary["source_capture"]["captured_bytes"] == len(asset) + len(b"print(1)\n") + len(oversized_code)
    assert list((tmp_path / "scratch").iterdir()) == []


@pytest.mark.parametrize("size", [8_388_608, 8_388_609])
def test_directory_capture_regular_file_bound_is_exact(tmp_path, monkeypatch, size):
    _configure_scan_execution(tmp_path, monkeypatch)
    repo = tmp_path / "repo"
    selected = repo / "docs"
    selected.mkdir(parents=True)
    content = b"x" * size
    (selected / "asset.png").write_bytes(content)
    owned = tmp_path / "capture"
    owned.mkdir()
    captured = scanner._capture_target_directory(repo, "docs", owned, scanner.ExecutionControl.with_timeout(10))
    assert captured.complete == (size <= 8_388_608)
    if captured.complete:
        assert (captured.root / "docs/asset.png").read_bytes() == content
        assert captured.captured_bytes == size
    else:
        assert captured.reason_counts() == {"capture_file_too_large": 1}
        assert captured.captured_bytes == 0
        assert not (captured.root / "docs/asset.png").exists()


def test_snapshot_source_requires_the_exact_generation_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    source_snapshot_dir = tmp_path / "source-snapshots"
    source = source_snapshot_dir / "generations" / digest / "source"
    source.mkdir(parents=True)
    (source / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    monkeypatch.setattr(
        scanner,
        "settings",
        SimpleNamespace(
            allowed_root_list=[str(source_snapshot_dir / "generations")],
            source_snapshot_dir=str(source_snapshot_dir),
        ),
    )

    admitted = scanner._ensure_allowed(source)
    scanner._ensure_snapshot_binding(admitted, digest)
    with pytest.raises(scanner.SourceBoundaryError, match="requires an immutable snapshot digest"):
        scanner._ensure_snapshot_binding(admitted, None)
    with pytest.raises(scanner.SourceBoundaryError, match="digest is unavailable"):
        scanner._ensure_snapshot_binding(admitted, "b" * 64)


def test_mounted_source_rejects_snapshot_digest_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    snapshot_root = tmp_path / "source-snapshots"
    snapshot_root.mkdir()
    monkeypatch.setattr(
        scanner,
        "settings",
        SimpleNamespace(
            allowed_root_list=[str(tmp_path)],
            source_snapshot_dir=str(snapshot_root),
        ),
    )

    with pytest.raises(scanner.SourceBoundaryError, match="digest is unavailable"):
        scanner._ensure_snapshot_binding(scanner._ensure_allowed(repo), "a" * 64)


@pytest.mark.parametrize("name", ["exposed.py", "node_modules"])
def test_walk_refuses_file_and_skipped_directory_symlink_escapes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / ("secret.py" if name.endswith(".py") else "dependencies")
    if name.endswith(".py"):
        outside.write_text("password = 'outside-secret-value'\n", encoding="utf-8")
    else:
        outside.mkdir()
        (outside / "secret.py").write_text("password = 'outside-secret-value'\n", encoding="utf-8")
    _symlink(repo / name, outside, target_is_directory=outside.is_dir())
    monkeypatch.setattr(scanner, "settings", SimpleNamespace(max_files=100))

    with pytest.raises(scanner.SourceBoundaryError, match="escapes or cannot be resolved"):
        scanner._walk_files(repo)


def test_walk_resolves_internal_links_and_deduplicates_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "source.py"
    source.write_text("print('safe')\n", encoding="utf-8")
    _symlink(repo / "alias.py", source)
    monkeypatch.setattr(scanner, "settings", SimpleNamespace(max_files=100))

    coverage = scanner._walk_files(repo)

    assert coverage.selected_files == [source.resolve()]
    assert coverage.eligible_files == 1
    assert coverage.complete


def test_scan_files_rechecks_each_candidate_at_read_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_scan_execution(tmp_path, monkeypatch)
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("print('outside')\n", encoding="utf-8")
    coverage = scanner.SourceCoverage(
        selected_files=[outside],
        eligible_files=1,
    )

    with pytest.raises(scanner.SourceBoundaryError, match="escapes or cannot be resolved"):
        scanner._scan_files(repo, coverage, {"sast-lite"})


def test_external_only_scan_reads_source_without_running_internal_rules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_scan_execution(tmp_path, monkeypatch)
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "main.py"
    source.write_text("print('external-only')\n", encoding="utf-8")
    coverage = scanner.SourceCoverage(selected_files=[source], eligible_files=1)

    def unexpected_internal_scan(*_args: object) -> list[object]:
        raise AssertionError("external-only requests must not execute internal rules")

    monkeypatch.setattr(scanner, "scan_text_file", unexpected_internal_scan)

    assert scanner._scan_files(repo, coverage, set()) == []
    assert coverage.read_files == 1
    assert coverage.complete


@pytest.mark.parametrize("replacement", ["leaf", "ancestor"])
def test_workspace_read_rejects_symlink_swap_after_canonical_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str,
) -> None:
    _configure_scan_execution(tmp_path, monkeypatch)
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    (repo / "src").mkdir(parents=True)
    outside.mkdir()
    source = repo / "src/source.js"
    source.write_text("safe();\n")
    (outside / "source.js").write_text("eval(outside_bytes);\n")
    original = scanner._resolve_candidate
    swapped = False

    def resolve_then_swap(root, candidate):
        nonlocal swapped
        resolved = original(root, candidate)
        assert not swapped
        swapped = True
        if replacement == "leaf":
            source.unlink()
            _symlink(source, outside / "source.js")
        else:
            (repo / "src").rename(repo / "retained")
            _symlink(repo / "src", outside, target_is_directory=True)
        return resolved

    monkeypatch.setattr(scanner, "_resolve_candidate", resolve_then_swap)
    coverage = scanner.SourceCoverage(selected_files=[source], eligible_files=1)
    assert scanner._scan_files(repo, coverage, {"sast-lite"}, scanner.ExecutionControl.with_timeout(10)) == []
    assert swapped and coverage.read_files == 0 and coverage.unreadable_files == 1
    assert not coverage.complete


def test_selected_directory_scan_never_authorizes_private_capture_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_scan_execution(tmp_path, monkeypatch)
    repo = tmp_path / "repo"
    (repo / "docs").mkdir(parents=True)
    (repo / "docs/source.py").write_text("print('bounded capture')\n")
    scanner.settings.allowed_root_list = [str(repo)]
    result = scanner._execute_scan(scanner.ScanRequest(scan_id=87, repo_path=str(repo),
        target_kind="directory", target_path="docs", enabled_tools=["sast-lite"]),
        scanner.ExecutionControl.with_timeout(10))
    assert result.status == "completed"
    assert result.summary["source_coverage"]["complete"]
    assert result.summary["source_coverage"]["read_files"] == 1
    assert scanner.settings.allowed_root_list == [str(repo)]
    assert list((tmp_path / "scratch").iterdir()) == []


def test_disabled_secret_family_does_not_run_entropy_or_build_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_scan_execution(tmp_path, monkeypatch)
    from kodesec_scanner import rules

    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "main.js"
    source.write_text(
        'const password = "demo-demo-demo-demo";\n'
        '// token: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n'
        'const value = eval(payload);\n', encoding="utf-8",
    )
    coverage = scanner.SourceCoverage(selected_files=[source], eligible_files=1)

    def unexpected_entropy(_value: str) -> float:
        raise AssertionError("disabled secrets-lite must not calculate entropy")

    original_finding = rules.Finding

    def enabled_finding_only(**fields: object) -> scanner.Finding:
        assert fields["scanner"] == "sast-lite", "disabled family must not construct findings"
        return original_finding(**fields)

    monkeypatch.setattr(rules, "_entropy", unexpected_entropy)
    monkeypatch.setattr(rules, "Finding", enabled_finding_only)
    findings = scanner._scan_files(repo, coverage, {"sast-lite"})
    assert [finding.rule_id for finding in findings] == ["sast.javascript_eval"]
    assert coverage.read_files == 1 and coverage.complete


def test_lite_cancellation_during_a_token_stops_the_same_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_scan_execution(tmp_path, monkeypatch)
    from kodesec_scanner import rules

    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "main.py"
    source.write_text(
        '# token: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n',
        encoding="utf-8",
    )
    coverage = scanner.SourceCoverage(selected_files=[source], eligible_files=1)
    control = scanner.ExecutionControl.with_timeout(10)
    original_entropy = rules._entropy

    def cancel_during_entropy(value: str) -> float:
        control.cancel_event.set()
        return original_entropy(value)

    monkeypatch.setattr(rules, "_entropy", cancel_during_entropy)
    with pytest.raises(scanner.RunCancelled):
        scanner._scan_files(repo, coverage, {"secrets-lite"}, control)


def test_scan_reports_source_escape_as_a_typed_boundary_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("print('outside')\n", encoding="utf-8")
    _symlink(repo / "exposed.py", outside)
    monkeypatch.setattr(
        scanner,
        "settings",
        SimpleNamespace(
            allowed_root_list=[str(tmp_path)],
            max_files=100,
            source_snapshot_dir=str(tmp_path / "source-snapshots"),
            scratch_dir=str(tmp_path / "scratch"),
            validate_storage_boundaries=lambda: None,
        ),
    )

    with pytest.raises(scanner.SourceBoundaryError, match="escapes or cannot be resolved"):
        scanner._execute_scan(
            scanner.ScanRequest(
                scan_id=1,
                repo_path=str(repo),
                enabled_tools=["sast-lite"],
            ),
            scanner.ExecutionControl.with_timeout(10),
        )



def test_option_shaped_ref_is_rejected_before_git_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def unexpected_git(_repo: Path, args: list[str], timeout: int = 20) -> str:
        calls.append(args)
        return ""

    monkeypatch.setattr(scanner, "_git", unexpected_git)

    files, error = scanner._changed_files(tmp_path, "--output=/tmp/should-not-exist", "HEAD")

    assert files == []
    assert error == "incremental_diff_planning_failed"
    assert calls == []


def test_incremental_planning_error_does_not_return_path_or_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "fixture-credential"

    def failed_git(*_args, **_kwargs):
        raise RuntimeError(f"{tmp_path}/private password={secret}")

    monkeypatch.setattr(scanner, "_git", failed_git)
    files, error = scanner._changed_files(tmp_path, "base", "head")
    assert files == []
    assert error == "incremental_diff_planning_failed"
    assert str(tmp_path) not in error
    assert secret not in error


def test_diff_uses_resolved_commits_hardened_flags_and_nul_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    unusual = repo / "line\nbreak.py"
    unusual.write_text("print('safe')\n", encoding="utf-8")
    commits = iter(["a" * 40, "b" * 40])
    diff_args: list[str] = []

    def fake_git(_repo: Path, args: list[str], timeout: int = 20) -> str:
        if args[0] == "check-ref-format":
            return f"{args[-1]}\n"
        if args[0] == "rev-parse":
            return f"{next(commits)}\n"
        assert args[0] == "diff"
        diff_args.extend(args)
        return "line\nbreak.py\0"

    monkeypatch.setattr(scanner, "_git", fake_git)

    files, error = scanner._changed_files(repo, "base", "head")

    assert error is None
    assert files == [unusual.resolve()]
    assert "--no-ext-diff" in diff_args
    assert "--no-textconv" in diff_args
    assert "-z" in diff_args
    assert diff_args[-3:] == ["a" * 40, "b" * 40, "--"]
    assert "base" not in diff_args
    assert "head" not in diff_args


def test_diff_output_cannot_escape_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(
        scanner,
        "_resolve_git_commit",
        lambda _repo, ref: "a" * 40 if ref == "base" else "b" * 40,
    )
    monkeypatch.setattr(scanner, "_git", lambda _repo, args, timeout=20: "../outside.py\0")

    with pytest.raises(scanner.SourceBoundaryError, match="escapes or cannot be resolved"):
        scanner._changed_files(repo, "base", "head")


def test_repo_external_diff_driver_is_never_executed_and_newline_name_is_preserved(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    marker = tmp_path / "external-diff-ran"
    driver = tmp_path / "hostile-diff.sh"
    driver.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 0\n", encoding="utf-8")
    driver.chmod(0o700)
    (repo / ".gitattributes").write_text("*.py diff=hostile\n", encoding="utf-8")
    _git(repo, "config", "diff.hostile.command", str(driver))
    _git(repo, "add", ".gitattributes")
    _git(repo, "commit", "--quiet", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    unusual = repo / "line\nbreak.py"
    unusual.write_text("print('changed')\n", encoding="utf-8")
    _git(repo, "add", "--", "line\nbreak.py")
    _git(repo, "commit", "--quiet", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")

    files, error = scanner._changed_files(repo, base, head)

    assert error is None
    assert files == [unusual.resolve()]
    assert not marker.exists()


def test_incremental_request_runs_one_truthful_full_source_view(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    vulnerable = repo / "unchanged_vulnerable.py"
    vulnerable.write_text(
        'import subprocess\nsubprocess.run("fixture", shell=True)\n',
        encoding="utf-8",
    )
    changed = repo / "changed_benign.py"
    changed.write_text("print('base')\n", encoding="utf-8")
    _git(repo, "add", "--", vulnerable.name, changed.name)
    _git(repo, "commit", "--quiet", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    changed.write_text("print('head')\n", encoding="utf-8")
    _git(repo, "add", "--", changed.name)
    _git(repo, "commit", "--quiet", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")
    _configure_scan_execution(tmp_path, monkeypatch)

    result = scanner._execute_scan(
        scanner.ScanRequest(
            scan_id=1,
            repo_path=str(repo),
            mode="incremental_diff",
            base_ref=base,
            head_ref=head,
            enabled_tools=["sast-lite"],
        ),
        scanner.ExecutionControl.with_timeout(10),
    )

    assert result.status == "completed"
    assert {finding.file_path for finding in result.findings} == {
        "unchanged_vulnerable.py"
    }
    assert result.summary["requested_mode"] == "incremental_diff"
    assert result.summary["effective_mode"] == "full"
    assert result.summary["changed_files_count"] is None
    assert result.summary["files_considered"] == 2
    assert result.summary["warnings"] == [
        scanner.INCREMENTAL_MODE_FALLBACK_WARNING
    ]
    assert result.summary["errors"] == []
    assert result.summary["source_coverage"] == {
        "complete": True,
        "eligible_files": 2,
        "selected_files": 2,
        "read_files": 2,
        "omitted_files": 0,
        "max_files": 100,
        "max_file_bytes": 1024 * 1024,
        "reason_counts": {},
    }


def test_full_request_preserves_full_mode_without_fallback_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "vulnerable.py").write_text(
        'import subprocess\nsubprocess.run("fixture", shell=True)\n',
        encoding="utf-8",
    )
    _configure_scan_execution(tmp_path, monkeypatch)

    result = scanner._execute_scan(
        scanner.ScanRequest(
            scan_id=2,
            repo_path=str(repo),
            mode="full",
            enabled_tools=["sast-lite"],
        ),
        scanner.ExecutionControl.with_timeout(10),
    )

    assert result.status == "completed"
    assert result.summary["requested_mode"] == "full"
    assert result.summary["effective_mode"] == "full"
    assert result.summary["changed_files_count"] is None
    assert result.summary["files_considered"] == 1
    assert result.summary["warnings"] == []
    assert result.summary["errors"] == []
    assert result.summary["source_coverage"] == {
        "complete": True,
        "eligible_files": 1,
        "selected_files": 1,
        "read_files": 1,
        "omitted_files": 0,
        "max_files": 100,
        "max_file_bytes": 1024 * 1024,
        "reason_counts": {},
    }


def test_exact_file_target_scans_and_stages_only_the_selected_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    selected = repo / "k8s" / "deployment.yaml"
    selected.parent.mkdir(parents=True)
    selected.write_text("privileged: true\n", encoding="utf-8")
    (repo / "unselected.py").write_text(
        'import subprocess\nsubprocess.run("fixture", shell=True)\n',
        encoding="utf-8",
    )
    _configure_scan_execution(tmp_path, monkeypatch)

    result = scanner._execute_scan(
        scanner.ScanRequest(
            scan_id=21,
            repo_path=str(repo),
            mode="full",
            target_path="k8s/deployment.yaml",
            target_kind="file",
            enabled_tools=["iac-lite", "sast-lite"],
        ),
        scanner.ExecutionControl.with_timeout(10),
    )

    assert result.status == "completed"
    assert {finding.file_path for finding in result.findings} == {
        "k8s/deployment.yaml"
    }
    assert result.summary["files_considered"] == 1
    assert result.summary["scope"] == {
        "kind": "file",
        "target_path": "k8s/deployment.yaml",
    }

    staging = tmp_path / "file-staging"
    staging.mkdir()
    staged_root = scanner._stage_target_file(
        repo,
        "k8s/deployment.yaml",
        staging,
    )
    assert [
        path.relative_to(staged_root).as_posix()
        for path in staged_root.rglob("*")
        if path.is_file()
    ] == ["k8s/deployment.yaml"]
    assert not (staged_root / "unselected.py").exists()

    with pytest.raises(ValueError, match="mode=full"):
        scanner.ScanRequest(
            scan_id=22,
            repo_path=str(repo),
            mode="incremental_diff",
            target_path="k8s/deployment.yaml",
            target_kind="file",
            enabled_tools=["iac-lite"],
        )


def test_exact_file_descriptor_walk_is_anchored_across_parent_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    selected_parent = repo / "nested"
    selected_parent.mkdir(parents=True)
    (selected_parent / "app.py").write_text("print('approved')\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_text("print('outside')\n", encoding="utf-8")
    monkeypatch.setattr(
        scanner,
        "settings",
        SimpleNamespace(
            allowed_root_list=[str(tmp_path)],
            max_file_bytes=1024 * 1024,
        ),
    )
    original_open = scanner.os.open
    swapped = False

    def swap_parent_before_leaf_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "app.py" and dir_fd is not None and not swapped:
            selected_parent.rename(repo / "opened-parent")
            _symlink(selected_parent, outside, target_is_directory=True)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(scanner.os, "open", swap_parent_before_leaf_open)

    logical_path, content = scanner._read_target_file(repo, "nested/app.py")

    assert swapped is True
    assert logical_path == repo / "nested" / "app.py"
    assert content == b"print('approved')\n"
    assert logical_path.read_bytes() == b"print('outside')\n"


def test_exact_file_descriptor_walk_rejects_authorized_repo_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = tmp_path / "allowed"
    repo = allowed / "team" / "repo"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("print('approved')\n", encoding="utf-8")
    outside_team = tmp_path / "outside-team"
    outside_repo = outside_team / "repo"
    outside_repo.mkdir(parents=True)
    (outside_repo / "app.py").write_text("print('outside')\n", encoding="utf-8")
    monkeypatch.setattr(
        scanner,
        "settings",
        SimpleNamespace(
            allowed_root_list=[str(allowed)],
            max_file_bytes=1024 * 1024,
        ),
    )
    original_open = scanner.os.open
    swapped = False

    def swap_repo_ancestor_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "team" and dir_fd is not None and not swapped:
            (allowed / "team").rename(allowed / "opened-team")
            _symlink(allowed / "team", outside_team, target_is_directory=True)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(scanner.os, "open", swap_repo_ancestor_before_open)

    with pytest.raises(scanner.SourceBoundaryError, match="must not traverse a symbolic link"):
        scanner._read_target_file(repo, "app.py")

    assert swapped is True


def test_exact_file_read_rejects_same_inode_same_size_mutation_before_any_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    selected = repo / "app.py"
    approved = b"print('approved source')\n"
    changed = b"print('changed! source')\n"
    assert len(approved) == len(changed)
    selected.write_bytes(approved)
    before_inode = selected.stat().st_ino
    _configure_scan_execution(tmp_path, monkeypatch)
    original_read = scanner.os.read
    mutated = False

    def mutate_same_inode_after_first_read(descriptor: int, count: int) -> bytes:
        nonlocal mutated
        content = original_read(descriptor, count)
        if content and not mutated:
            before = selected.stat()
            with selected.open("r+b") as handle:
                handle.write(changed)
                handle.flush()
            scanner.os.utime(
                selected,
                ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
            )
            mutated = True
        return content

    monkeypatch.setattr(scanner.os, "read", mutate_same_inode_after_first_read)

    with pytest.raises(scanner.SourceBoundaryError, match="changed while it was being read"):
        scanner._execute_scan(
            scanner.ScanRequest(
                scan_id=23,
                repo_path=str(repo),
                mode="full",
                target_path="app.py",
                target_kind="file",
                enabled_tools=["iac-lite", "sast-lite"],
            ),
            scanner.ExecutionControl.with_timeout(10),
        )

    assert mutated is True
    assert selected.stat().st_ino == before_inode
    assert not (tmp_path / "artifacts" / "scans" / "23").exists()
    assert not (tmp_path / "scratch" / "23").exists()


def test_directory_target_scans_and_stages_only_the_selected_subtree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    selected = repo / "infra"
    selected.mkdir(parents=True)
    (selected / "main.tf").write_text(
        'resource "aws_security_group" "open" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n',
        encoding="utf-8",
    )
    manifest = selected / "requirements.txt"
    manifest.write_text("fixture-package==1.0\n", encoding="utf-8")
    sibling = repo / "sibling.py"
    sibling.write_text(
        'import subprocess\nsubprocess.run("fixture", shell=True)\n',
        encoding="utf-8",
    )
    _symlink(selected / "linked-sibling.py", sibling)
    _configure_scan_execution(tmp_path, monkeypatch)
    scanner.settings.max_file_bytes = 128
    (selected / "oversized.tf").write_bytes(b"x" * 129)
    ready_dimension = SimpleNamespace(
        model_dump=lambda **_kwargs: {
            "state": "ready",
            "reason": None,
            "component_ids": [],
        }
    )
    readiness = SimpleNamespace(
        ready=True,
        binary=ready_dimension,
        data=ready_dimension,
        rules=ready_dimension,
        execution=ready_dimension,
    )
    monkeypatch.setattr(
        scanner,
        "scanner_runtime_context",
        lambda **_kwargs: SimpleNamespace(
            runtime_by_id={
                "gitleaks": {
                    "id": "gitleaks",
                    "available": True,
                    "status": "verified",
                    "installed_version": "fixture-1",
                }
            },
            readiness_by_id={"gitleaks": readiness},
            tools=None,
        ),
    )

    internal_roots: list[Path] = []
    original_scan_text_file = scanner.scan_text_file

    def record_internal_root(
        root: Path,
        path: Path,
        text: str,
        **options: object,
    ) -> list[scanner.Finding]:
        internal_roots.append(root)
        return original_scan_text_file(root, path, text, **options)

    monkeypatch.setattr(scanner, "scan_text_file", record_internal_root)
    external_evidence: dict[str, object] = {}

    def record_external_capture(
        tool_id: str,
        source_root: Path,
        request_scratch: Path,
        _publish_root: Path,
        _cache_root: Path,
        _timeout: int,
        _control: scanner.ExecutionControl,
        _inputs: dict[str, Path],
    ) -> ToolRunResult:
        external_evidence["tool_id"] = tool_id
        external_evidence["root"] = source_root
        external_evidence["files"] = sorted(
            path.relative_to(source_root).as_posix()
            for path in source_root.rglob("*")
            if path.is_file()
        )
        source_root.relative_to(request_scratch)

        # Mutating the live source after capture cannot change either scanner's
        # input. The external scanner consumes the exact tree already used by
        # the internal scanner.
        (selected / "main.tf").write_text("resource \"changed\" {}\n", encoding="utf-8")
        manifest.write_text("changed-package==9.9\n", encoding="utf-8")
        external_evidence["main"] = (source_root / "infra" / "main.tf").read_text(
            encoding="utf-8"
        )
        external_evidence["manifest"] = (
            source_root / "infra" / "requirements.txt"
        ).read_text(encoding="utf-8")
        return ToolRunResult(scanner=tool_id, status="completed", exit_code=0)

    monkeypatch.setattr(scanner, "run_external_tool", record_external_capture)

    result = scanner._execute_scan(
        scanner.ScanRequest(
            scan_id=24,
            repo_path=str(repo),
            mode="full",
            target_path="infra",
            target_kind="directory",
            enabled_tools=["gitleaks", "iac-lite"],
        ),
        scanner.ExecutionControl.with_timeout(10),
    )

    assert result.status == "partial"
    assert {finding.file_path for finding in result.findings} == {"infra/main.tf"}
    assert result.summary["files_considered"] == 2
    assert result.summary["scope"] == {
        "kind": "directory",
        "target_path": "infra",
    }
    assert result.summary["source_coverage"]["reason_counts"] == {
        "eligible_file_too_large": 1,
    }
    assert result.summary["source_capture"] == {
        "complete": False,
        "captured_files": 3,
        "captured_bytes": len(
            b'resource "aws_security_group" "open" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
        )
        + len(b"fixture-package==1.0\n") + 129,
        "omitted_files": 1,
        "max_files": 100,
        "max_file_bytes": 128,
        "max_total_bytes": 64 * 1024 * 1024,
        "max_capture_file_bytes": 8 * 1024 * 1024,
        "reason_counts": {
            "capture_entry_unsupported_type": 1,
        },
    }
    assert external_evidence == {
        "tool_id": "gitleaks",
        "root": internal_roots[0],
        "files": ["infra/main.tf", "infra/oversized.tf", "infra/requirements.txt"],
        "main": 'resource "aws_security_group" "open" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n',
        "manifest": "fixture-package==1.0\n",
    }
    assert internal_roots == [external_evidence["root"]]
    assert result.summary["external_runs"][0]["status"] == "completed"
    assert list((tmp_path / "scratch").iterdir()) == []

    with pytest.raises(ValueError, match="both target_path and target_kind"):
        scanner.ScanRequest(
            scan_id=25,
            repo_path=str(repo),
            target_path="infra",
            enabled_tools=["iac-lite"],
        )


def test_directory_capture_cancellation_interrupts_read_and_cleans_scratch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    selected = repo / "infra"
    selected.mkdir(parents=True)
    (selected / "large.py").write_bytes(b"x" * (128 * 1024))
    _configure_scan_execution(tmp_path, monkeypatch)
    control = scanner.ExecutionControl.with_timeout(10)
    original_read = scanner.os.read
    cancelled = False

    def cancel_after_first_chunk(descriptor: int, count: int) -> bytes:
        nonlocal cancelled
        content = original_read(descriptor, count)
        if content and not cancelled:
            control.cancel_event.set()
            cancelled = True
        return content

    monkeypatch.setattr(scanner.os, "read", cancel_after_first_chunk)

    with pytest.raises(scanner.RunCancelled, match="cancellation requested"):
        scanner._execute_scan(
            scanner.ScanRequest(
                scan_id=26,
                repo_path=str(repo),
                mode="full",
                target_path="infra",
                target_kind="directory",
                enabled_tools=["sast-lite"],
            ),
            control,
        )

    assert cancelled is True
    assert list((tmp_path / "scratch").iterdir()) == []
    assert not (tmp_path / "artifacts" / "scans" / "26").exists()


def test_directory_capture_prunes_generated_trees_and_bounds_total_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    selected = repo / "infra"
    selected.mkdir(parents=True)
    for skipped_name in (".git", ".kodesec-local", "node_modules"):
        skipped = selected / skipped_name
        skipped.mkdir()
        (skipped / "cache.py").write_bytes(b"x" * 64)
    (selected / "a.py").write_bytes(b"print(1)\n")
    (selected / "z.js").write_bytes(b"eval(x)\n")
    (selected / "zz.py").write_bytes(b"x\n")
    _configure_scan_execution(tmp_path, monkeypatch)
    monkeypatch.setattr(scanner, "MAX_DIRECTORY_CAPTURE_BYTES", 17)

    result = scanner._execute_scan(
        scanner.ScanRequest(
            scan_id=27,
            repo_path=str(repo),
            mode="full",
            target_path="infra",
            target_kind="directory",
            enabled_tools=["sast-lite"],
        ),
        scanner.ExecutionControl.with_timeout(10),
    )

    assert result.status == "partial"
    assert result.summary["files_considered"] == 2
    assert result.summary["errors"] == [
        "source_coverage: eligible_file_capture_total_bytes_exceeded",
        "source_coverage: capture_total_bytes_exceeded",
    ]
    assert result.summary["source_coverage"] == {
        "complete": False,
        "eligible_files": 3,
        "selected_files": 2,
        "read_files": 2,
        "omitted_files": 1,
        "max_files": 100,
        "max_file_bytes": 1024 * 1024,
        "reason_counts": {
            "eligible_file_capture_total_bytes_exceeded": 1,
        },
    }
    assert result.summary["source_capture"] == {
        "complete": False,
        "captured_files": 2,
        "captured_bytes": 17,
        "omitted_files": 1,
        "max_files": 100,
        "max_file_bytes": 1024 * 1024,
        "max_total_bytes": 17,
        "max_capture_file_bytes": 8 * 1024 * 1024,
        "reason_counts": {"capture_total_bytes_exceeded": 1},
    }
    assert {finding.file_path for finding in result.findings} == {"infra/z.js"}
    assert list((tmp_path / "scratch").iterdir()) == []


def test_full_scan_reports_eligible_file_limit_as_partial_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for name in ("a_vulnerable.py", "b_vulnerable.py"):
        (repo / name).write_text(
            'import subprocess\nsubprocess.run("fixture", shell=True)\n',
            encoding="utf-8",
        )
    _configure_scan_execution(tmp_path, monkeypatch)
    scanner.settings.max_files = 1

    result = scanner._execute_scan(
        scanner.ScanRequest(
            scan_id=3,
            repo_path=str(repo),
            mode="full",
            enabled_tools=["sast-lite"],
        ),
        scanner.ExecutionControl.with_timeout(10),
    )

    assert result.status == "partial"
    assert {finding.file_path for finding in result.findings} == {
        "a_vulnerable.py"
    }
    assert result.summary["errors"] == [
        "source_coverage: eligible_file_limit_exceeded"
    ]
    assert result.summary["source_coverage"] == {
        "complete": False,
        "eligible_files": 2,
        "selected_files": 1,
        "read_files": 1,
        "omitted_files": 1,
        "max_files": 1,
        "max_file_bytes": 1024 * 1024,
        "reason_counts": {"eligible_file_limit_exceeded": 1},
    }


def test_full_scan_reports_oversized_eligible_source_as_partial_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "oversized.py").write_text("x" * 9, encoding="utf-8")
    _configure_scan_execution(tmp_path, monkeypatch)
    scanner.settings.max_file_bytes = 8

    result = scanner._execute_scan(
        scanner.ScanRequest(
            scan_id=4,
            repo_path=str(repo),
            enabled_tools=["sast-lite"],
        ),
        scanner.ExecutionControl.with_timeout(10),
    )

    assert result.status == "partial"
    assert result.findings == []
    assert result.summary["errors"] == [
        "source_coverage: eligible_file_too_large"
    ]
    assert result.summary["source_coverage"]["read_files"] == 0
    assert result.summary["source_coverage"]["reason_counts"] == {
        "eligible_file_too_large": 1
    }


def test_full_scan_reports_unreadable_eligible_source_without_disclosing_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "private-source.py"
    source.write_text("print('fixture')\n", encoding="utf-8")
    _configure_scan_execution(tmp_path, monkeypatch)
    original_read_text = scanner._read_text

    def unreadable(reader, relative_path: str) -> tuple[str | None, str]:
        if relative_path == source.relative_to(repo).as_posix():
            return None, "eligible_file_unreadable"
        return original_read_text(reader, relative_path)

    monkeypatch.setattr(scanner, "_read_text", unreadable)

    result = scanner._execute_scan(
        scanner.ScanRequest(
            scan_id=5,
            repo_path=str(repo),
            enabled_tools=["sast-lite"],
        ),
        scanner.ExecutionControl.with_timeout(10),
    )

    assert result.status == "partial"
    assert result.summary["errors"] == [
        "source_coverage: eligible_file_unreadable"
    ]
    assert source.name not in " ".join(result.summary["errors"])
    assert result.summary["source_coverage"]["reason_counts"] == {
        "eligible_file_unreadable": 1
    }
