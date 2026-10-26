from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/grype-db-lock-candidate.py"
IMAGE_ID = "sha256:" + "1" * 64
INVOCATION_ID = "a" * 32


def _load_cli():
    spec = importlib.util.spec_from_file_location("grype_db_lock_candidate_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cli = _load_cli()


@pytest.mark.parametrize("reason", ["deadline", "integrity"])
def test_logical_candidate_preserves_timeout_without_claiming_corruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason: str,
) -> None:
    from kodesec_scanner import cache_manifest

    monkeypatch.setattr(cache_manifest, "collect_canonical_tree",
        lambda *args, **kwargs: SimpleNamespace(files=[]))

    def fail(*args, **kwargs):
        raise cache_manifest.GrypeContentValidationError(reason)

    monkeypatch.setattr(cache_manifest, "verify_grype_logical_content", fail)
    expected = "installed_tree_validation_timeout" if reason == "deadline" else "installed_tree_invalid"
    with pytest.raises(cli.CandidateError, match="^" + expected + "$") as caught:
        cli.collect_grype_installed_content(tmp_path)
    assert cli._inner_failure_code("import", caught.value) == ("timeout" if reason == "deadline" else "tree")


class Identity:
    uid = 501
    gid = 20


def _listing(**changes: object) -> bytes:
    entry = {
        "status": "active",
        "schemaVersion": "v6.1.9",
        "built": "2026-08-20T06:17:08Z",
        "path": "vulnerability-db_v6.1.9_2026-08-20T00:15:42Z_1787206628.tar.zst",
        "checksum": "sha256:" + "2" * 64,
    }
    entry.update(changes)
    return json.dumps(entry, separators=(",", ":")).encode()


def test_listing_is_exact_and_binds_a_safe_relative_archive() -> None:
    listing = cli.parse_listing(_listing())
    assert set(listing) == cli.LISTING_FIELDS
    assert cli.resolve_archive_url(listing["path"]) == (
        "https://grype.anchore.io/databases/v6/"
        "vulnerability-db_v6.1.9_2026-08-20T00:15:42Z_1787206628.tar.zst"
    )
    for mutation in (
        {"extra": "x"},
        {"status": "deprecated"},
        {"checksum": "2" * 64},
        {"schemaVersion": "v7.0.0"},
    ):
        with pytest.raises(cli.CandidateError):
            cli.parse_listing(_listing(**mutation))
    with pytest.raises(cli.CandidateError, match="listing_shape_invalid"):
        cli.parse_listing(b"[" + _listing() + b"]")


@pytest.mark.parametrize(
    ("mode", "error", "code"),
    [
        ("preflight", "tool_manifest_invalid", "validation"),
        ("fetch", "http_request_failed", "network"),
        ("fetch", "listing_shape_invalid", "listing"),
        ("fetch", "archive_checksum_mismatch", "archive"),
        ("import", "candidate_cache_invalid", "input"),
        ("import", "command_failed", "command"),
        ("import", "grype_status_invalid", "status"),
        ("import", "installed_tree_unsafe", "tree"),
        ("import", "installed_tree_validation_timeout", "timeout"),
        ("canary", "command_failed", "command"),
        ("canary", "canary_output_invalid", "output"),
        ("canary", "canary_semantics_invalid", "semantics"),
        ("canary", "installed_tree_unsafe", "tree"),
    ],
)
def test_inner_failure_codes_are_phase_local_and_non_sensitive(
    mode: str, error: str, code: str
) -> None:
    assert cli._inner_failure_code(mode, cli.CandidateError(error)) == code


def test_internal_failure_emits_only_exact_allowlisted_marker(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(_args: object) -> dict[str, object]:
        raise cli.CandidateError("listing_shape_invalid:secret-never-echoed")

    monkeypatch.setattr(cli, "inner_fetch", fail)
    assert (
        cli.main(
            [
                "internal-fetch",
                "--invocation-id",
                INVOCATION_ID,
                "--output-dir",
                "/run/kodesec-grype-review/output",
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "kodesec_candidate_failure/v1 fetch listing\n"
    assert "secret" not in captured.err


def test_shared_host_accepts_only_exact_grype_failure_contract() -> None:
    host = cli._load_hardened_host()
    for mode, codes in cli.INNER_FAILURE_CODES.items():
        assert codes == host.GRYPE_INNER_FAILURE_CODES[mode]
        for code in codes:
            marker = f"kodesec_candidate_failure/v1 {mode} {code}\n".encode()
            assert (
                host._inner_failure_status(
                    ("docker", "run", f"internal-{mode}"),
                    returncode=2,
                    stdout=b"",
                    stderr=marker,
                )
                == f"{mode}_{code}"
            )
    assert (
        host._inner_failure_status(
            ("docker", "run", "internal-fetch"),
            returncode=2,
            stdout=b"",
            stderr=b"kodesec_candidate_failure/v1 fetch invented\n",
        )
        is None
    )
    assert (
        host._inner_failure_status(
            ("docker", "run", "fetch", "internal-fetch"),
            returncode=2,
            stdout=b"",
            stderr=b"kodesec_candidate_failure/v1 fetch validation\n",
        )
        is None
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://evil.invalid/vulnerability-db_v6.1.9_x.tar.zst",
        "/databases/v6/vulnerability-db_v6.1.9_x.tar.zst",
        "../vulnerability-db_v6.1.9_x.tar.zst",
        "nested/vulnerability-db_v6.1.9_x.tar.zst",
        "vulnerability-db_v6.1.9_x.tar.zst?changed=1",
        "other.tar.zst",
        "vulnerability-db_v6.1.9_x.tar.zst#fragment",
    ],
)
def test_archive_path_rejects_redirectable_or_unsafe_forms(value: str) -> None:
    with pytest.raises(cli.CandidateError):
        cli.resolve_archive_url(value)


def _mounts(argv: tuple[str, ...]) -> list[str]:
    return [argv[index + 1] for index, value in enumerate(argv) if value == "--mount"]


def test_phase_argv_enforces_network_and_source_blind_import(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    archive = output / "vulnerability-db.tar.zst"
    archive.write_bytes(b"archive")
    database = output / "candidate-db"
    database.mkdir(mode=0o700)
    build_receipt = tmp_path / "scanner-build-receipt.json"
    build_receipt.write_bytes(b"{}\n")
    common = {
        "image_id": IMAGE_ID,
        "identity": Identity(),
        "invocation_id": INVOCATION_ID,
        "output_dir": output,
        "producer_sha256": "3" * 64,
        "build_receipt_path": build_receipt,
        "build_receipt_file_sha256": hashlib.sha256(b"{}\n").hexdigest(),
        "source_commit": "4" * 40,
    }

    def run_identity(phase: str) -> SimpleNamespace:
        name = f"kodesec-grype-db-{INVOCATION_ID}-{phase}"
        return SimpleNamespace(name=name, cidfile=tmp_path / f"{name}.cid")

    preflight = cli.phase_argv("preflight", run_identity=run_identity("preflight"), **common)
    fetch = cli.phase_argv("fetch", run_identity=run_identity("fetch"), **common)
    imported = cli.phase_argv("import", run_identity=run_identity("import"), **common)
    canary = cli.phase_argv("canary", run_identity=run_identity("canary"), **common)

    for argv in (preflight, fetch, imported, canary):
        assert argv[:3] == ("docker", "run", "--rm")
        assert "--read-only" in argv
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges" in argv
        assert "--pull=never" in argv
        assert argv.count("--cidfile") == 1
        assert f"--user={Identity.uid}:{Identity.gid}" in argv
        assert all(f"--env={key}=" in argv for key in cli.PROXY_KEYS)
    assert "--network=bridge" in fetch
    assert all("--network=none" in argv for argv in (preflight, imported, canary))
    import_tmpfs = f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=4g,mode=0700,uid={Identity.uid},gid={Identity.gid}"
    default_tmpfs = f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=0700,uid={Identity.uid},gid={Identity.gid}"
    assert import_tmpfs in imported
    assert all(default_tmpfs in argv for argv in (preflight, fetch, canary))
    assert all(import_tmpfs not in argv for argv in (preflight, fetch, canary))

    imported_text = "\0".join(imported)
    assert str(cli.POSITIVE_FIXTURE_PATH) not in imported_text
    assert str(cli.ZERO_FIXTURE_PATH) not in imported_text
    assert len(_mounts(preflight)) == 3
    assert len(_mounts(imported)) == 3
    assert all(value.endswith(",readonly") for value in _mounts(imported)[:2])
    assert not _mounts(imported)[2].endswith(",readonly")
    assert all(value.endswith(",readonly") for value in _mounts(canary))


def test_final_receipt_proposes_exactly_six_mutable_fields() -> None:
    def receipt(schema: str, **values: object) -> dict[str, object]:
        return {
            "schema": schema,
            "receipt_sha256": "4" * 64,
            "invocation_id": INVOCATION_ID,
            **values,
        }

    installed_content = {
        "hash_algorithm": "kodesec-canonical-tree-v1",
        "sha256": "8" * 64,
        "file_count": 2,
        "size_bytes": 456,
        "volatile_paths": [],
    }

    preflight = receipt(
        "kodesec.grype-db-lock-candidate-preflight/v1",
        current_lock_sha256="5" * 64,
        baked_lock_sha256="5" * 64,
        producer_sha256="6" * 64,
    )
    fetch = receipt(
        "kodesec.grype-db-lock-candidate-fetch/v1",
        listing={
            "entry": {
                "schemaVersion": "v6.1.9",
                "built": "2026-08-20T06:17:08Z",
            }
        },
        archive={
            "resolved_url": "https://grype.anchore.io/databases/v6/reviewed.tar.zst",
            "sha256": "7" * 64,
            "size_bytes": 123,
        },
    )
    installed = receipt(
        "kodesec.grype-db-lock-candidate-import/v1",
        archive={"sha256": "7" * 64, "size_bytes": 123},
        status={
            "schemaVersion": "v6.1.9",
            "built": "2026-08-20T06:17:08Z",
        },
        installed_content={**installed_content, "hash_algorithm": "kodesec-grype-v6-logical-tree-v1", "sha256": "b" * 64},
        physical_content=installed_content,
    )
    canary = receipt(
        "kodesec.grype-db-lock-candidate-canary/v1",
        candidate_tree=installed_content,
        canaries=[{"id": "positive"}, {"id": "zero"}],
    )
    final = cli.build_final(
        commit="9" * 40,
        build={"schema": cli.BUILD_RECEIPT_SCHEMA, "receipt_sha256": "a" * 64},
        preflight=preflight,
        fetch=fetch,
        imported=installed,
        canary=canary,
    )
    assert final["authoritative"] is False
    assert final["component_id"] == "grype-db"
    assert set(final["proposed_replacement"]) == cli.PROPOSED_FIELDS
    assert "id" not in final["proposed_replacement"]
    assert final["proposed_replacement"]["installed_content"]["hash_algorithm"] == "kodesec-grype-v6-logical-tree-v1"


@pytest.mark.parametrize("mismatch", ["archive", "tree", "invocation"])
def test_final_receipt_rejects_cross_phase_identity_mismatch(mismatch: str) -> None:
    installed_content = {
        "hash_algorithm": "kodesec-canonical-tree-v1",
        "sha256": "8" * 64,
        "file_count": 2,
        "size_bytes": 456,
        "volatile_paths": [],
    }
    common = {
        "receipt_sha256": "4" * 64,
        "invocation_id": INVOCATION_ID,
    }
    preflight = {
        **common,
        "schema": "kodesec.grype-db-lock-candidate-preflight/v1",
        "current_lock_sha256": "5" * 64,
        "baked_lock_sha256": "5" * 64,
        "producer_sha256": "6" * 64,
    }
    fetch = {
        **common,
        "schema": "kodesec.grype-db-lock-candidate-fetch/v1",
        "listing": {"entry": {"schemaVersion": "v6.1.9", "built": "2026-08-20T06:17:08Z"}},
        "archive": {
            "resolved_url": "https://grype.anchore.io/databases/v6/reviewed.tar.zst",
            "sha256": "7" * 64,
            "size_bytes": 123,
        },
    }
    imported = {
        **common,
        "schema": "kodesec.grype-db-lock-candidate-import/v1",
        "archive": {"sha256": "7" * 64, "size_bytes": 123},
        "status": {"schemaVersion": "v6.1.9", "built": "2026-08-20T06:17:08Z"},
        "installed_content": {**installed_content, "hash_algorithm": "kodesec-grype-v6-logical-tree-v1", "sha256": "b" * 64},
        "physical_content": installed_content,
    }
    canary = {
        **common,
        "schema": "kodesec.grype-db-lock-candidate-canary/v1",
        "candidate_tree": installed_content,
        "canaries": [],
    }
    if mismatch == "archive":
        imported["archive"] = {"sha256": "9" * 64, "size_bytes": 123}
    elif mismatch == "tree":
        canary["candidate_tree"] = {**installed_content, "sha256": "9" * 64}
    else:
        canary["invocation_id"] = "b" * 32
    with pytest.raises(cli.CandidateError, match="mismatch"):
        cli.build_final(
            commit="9" * 40,
            build={"schema": cli.BUILD_RECEIPT_SCHEMA, "receipt_sha256": "a" * 64},
            preflight=preflight,
            fetch=fetch,
            imported=imported,
            canary=canary,
        )


def test_producer_is_build_bound_but_not_in_scanner_copy_allowlists() -> None:
    builder_source = (ROOT / "scripts/scanner-build-receipt.py").read_text()
    trivy_source = (ROOT / "scripts/trivy-db-lock-candidate.py").read_text()
    assert '"scripts/grype-db-lock-candidate.py"' in builder_source
    assert '"scripts/grype-db-lock-candidate.py"' in trivy_source
    dockerfile = (ROOT / "services/scanner/Dockerfile").read_text()
    assert "grype-db-lock-candidate" not in dockerfile
    assert not (ROOT / "services/scanner/kodesec_scanner/grype_db_lock_candidate.py").exists()


def test_pinned_tools_may_emit_bounded_non_authoritative_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=b"deterministic output", stderr=b"progress\n"
        ),
    )
    assert cli._run(("tool",), environment={}) == b"deterministic output"
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=b"",
            stderr=b"x" * (cli.MAX_COMMAND_STDERR_BYTES + 1),
        ),
    )
    with pytest.raises(cli.CandidateError, match="command_failed"):
        cli._run(("tool",), environment={})


def test_source_revalidation_rechecks_commit_producer_and_build_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = object()
    inputs = {"files": [{"path": cli.PRODUCER_RELATIVE_PATH}]}
    host = SimpleNamespace(
        require_host_identity=lambda: identity,
        _collect_build_inputs=lambda *, identity: inputs,
    )
    monkeypatch.setattr(cli, "_git_clean_commit", lambda: "1" * 40)
    monkeypatch.setattr(cli, "sha256_file", lambda _path: "2" * 64)
    cli._revalidate_source(
        host,
        {"inputs_after": inputs},
        commit="1" * 40,
        producer_sha256="2" * 64,
    )
    with pytest.raises(cli.CandidateError, match="source_binding_changed"):
        cli._revalidate_source(
            host,
            {"inputs_after": inputs},
            commit="3" * 40,
            producer_sha256="2" * 64,
        )


def test_canary_digest_is_exactly_runtime_semantic_contract() -> None:
    scanner_package = str(ROOT / "services/scanner")
    if scanner_package not in sys.path:
        sys.path.insert(0, scanner_package)
    from kodesec_scanner.updater import canonical_canary_output_sha256

    identifiers = ["CVE-2025-0001", "GHSA-aaaa-bbbb-cccc"]
    fixture_sha256 = "d" * 64
    observed = cli.semantic_canary_sha256(
        canary_id="sbom-vulnerabilities-positive",
        fixture_sha256=fixture_sha256,
        result_count=3,
        rule_ids=identifiers,
    )
    expected = canonical_canary_output_sha256(
        canary_id="sbom-vulnerabilities-positive",
        fixture_sha256=fixture_sha256,
        exit_code=0,
        result_count=3,
        rule_ids=identifiers,
    )
    assert observed == expected


def test_grype_canary_semantics_are_strict_and_bounded() -> None:
    payload = {
        "matches": [
            {"vulnerability": {"id": "CVE-2025-0001"}},
            {"vulnerability": {"id": "CVE-2025-0001"}},
            {"vulnerability": {"id": "GHSA-aaaa-bbbb-cccc"}},
        ]
    }
    assert cli.grype_result_semantics(payload) == (
        3,
        ["CVE-2025-0001", "GHSA-aaaa-bbbb-cccc"],
    )
    for invalid in (
        {"matches": [{}]},
        {"matches": [{"vulnerability": {"id": " padded "}}]},
        {"matches": [{"vulnerability": {"id": "CVE-1\n"}}]},
    ):
        with pytest.raises(cli.CandidateError):
            cli.grype_result_semantics(invalid)
    with pytest.raises(cli.CandidateError, match="count"):
        cli.grype_result_semantics(
            {
                "matches": [
                    {"vulnerability": {"id": "CVE-2025-0001"}}
                    for _ in range(cli.MAX_CANARY_RESULTS + 1)
                ]
            }
        )


def test_shared_owned_container_contract_is_exact_for_grype(tmp_path: Path) -> None:
    host = cli._load_hardened_host()
    lifecycle = tmp_path / "lifecycle"
    lifecycle.mkdir(mode=0o700)
    imported = host._docker_run_identity(
        invocation_id=INVOCATION_ID,
        mode="import",
        lifecycle_dir=lifecycle,
        component_id="grype-db",
    )
    assert imported.name == f"kodesec-grype-db-{INVOCATION_ID}-import"
    assert "--no-trunc" in host._container_list_argv(imported.name)
    with pytest.raises(host.CandidateCliError, match="docker_mode_invalid"):
        host._docker_run_identity(
            invocation_id=INVOCATION_ID,
            mode="import",
            lifecycle_dir=lifecycle,
            component_id="trivy-db",
        )
    trivy_import_name = f"kodesec-trivy-db-{INVOCATION_ID}-import"
    with pytest.raises(host.CandidateCliError, match="docker_run_identity_invalid"):
        host.DockerRunIdentity(
            name=trivy_import_name,
            cidfile=lifecycle / f"{trivy_import_name}.cid",
        )
    with pytest.raises(host.CandidateCliError, match="docker_run_identity_invalid"):
        host._container_list_argv(trivy_import_name)


def test_run_phase_delegates_to_hardened_owned_lifecycle() -> None:
    class HostError(RuntimeError):
        pass

    class HostUncertain(HostError):
        pass

    run_identity = SimpleNamespace(name="owned", cidfile=Path("/private/tmp/owned.cid"))
    identity = Identity()
    calls: list[tuple[tuple[str, ...], object, object, int]] = []

    def run_owned(argv, *, run_identity, identity, timeout_seconds):
        calls.append((tuple(argv), run_identity, identity, timeout_seconds))
        return SimpleNamespace(stdout=b"{}\n", stderr=b"")

    host = SimpleNamespace(
        DockerProcessCleanupUncertain=HostUncertain,
        CandidateCliError=HostError,
        run_owned_container=run_owned,
        _receipt_stdout=lambda completed, *, label: completed.stdout,
    )
    assert cli._run_phase(
        host,
        ("docker", "run"),
        run_identity=run_identity,
        identity=identity,
        phase="fetch",
    ) == b"{}\n"
    assert calls == [(("docker", "run"), run_identity, identity, 900)]

    def uncertain(*_args, **_kwargs):
        raise HostUncertain("docker_process_forensic_state_preserved:/private/tmp/lifecycle")

    host.run_owned_container = uncertain
    with pytest.raises(cli.DockerProcessCleanupUncertain, match="forensic_state_preserved"):
        cli._run_phase(
            host,
            ("docker", "run"),
            run_identity=run_identity,
            identity=identity,
            phase="fetch",
        )

    for message in (
        "docker_container_cleanup_uncertain",
        "docker_container_preabsence_unproven",
        "docker_cidfile_identity_invalid",
        "docker_lifecycle_directory_cleanup_uncertain:/private/tmp/lifecycle",
    ):
        def candidate_error(*_args, _message=message, **_kwargs):
            raise HostError(_message)

        host.run_owned_container = candidate_error
        with pytest.raises(cli.DockerProcessCleanupUncertain, match=message.split(":", 1)[0]):
            cli._run_phase(
                host,
                ("docker", "run"),
                run_identity=run_identity,
                identity=identity,
                phase="fetch",
            )

    def ordinary_failure(*_args, **_kwargs):
        raise HostError("fetch_inner_validation_failed")

    host.run_owned_container = ordinary_failure
    with pytest.raises(cli.CandidateError) as failure:
        cli._run_phase(
            host,
            ("docker", "run"),
            run_identity=run_identity,
            identity=identity,
            phase="fetch",
        )
    assert type(failure.value) is cli.CandidateError
