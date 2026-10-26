from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/trivy-db-lock-candidate.py"
IMAGE_ID = "sha256:" + "1" * 64
INVOCATION_ID = "a" * 32
BUILD_INVOCATION_ID = "d" * 32


def _load_cli():
    spec = importlib.util.spec_from_file_location("trivy_db_lock_candidate_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cli = _load_cli()
PROVENANCE = cli.SourceProvenance(commit="a" * 40, tree="b" * 40)


def test_build_contract_is_shared_with_receipt_producer() -> None:
    producer_path = ROOT / "scripts/scanner-build-receipt.py"
    spec = importlib.util.spec_from_file_location(
        "scanner_build_receipt_contract_test", producer_path
    )
    assert spec is not None and spec.loader is not None
    producer = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = producer
    spec.loader.exec_module(producer)

    assert cli.BUILD_ARGS is producer.BUILD_ARGS
    assert cli.BUILD_COPY_FILES is producer.COPY_FILES
    assert cli.BUILD_COPY_ROOTS is producer.COPY_ROOTS
    assert cli.BUILD_COPY_SINGLE_FILES is producer.COPY_SINGLE_FILES
    assert "scripts/scanner_build_contract.py" in cli.BUILD_INPUT_FILES
    assert cli.BUILD_INPUT_FILES == producer.BUILD_INPUT_FILES


def test_unsupported_host_imports_safely_and_fails_before_candidate_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli.platform, "machine", lambda: "aarch64")
    spec = importlib.util.spec_from_file_location("trivy_db_lock_candidate_unsupported", SCRIPT)
    assert spec is not None and spec.loader is not None
    unsupported = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = unsupported
    spec.loader.exec_module(unsupported)

    assert unsupported.REVIEW_TARGET is None
    with pytest.raises(unsupported.CandidateCliError, match="host_identity_mismatch"):
        unsupported.require_review_build_host()
    with pytest.raises(unsupported.CandidateCliError, match="host_identity_mismatch"):
        unsupported.orchestrate(
            Path("/not-read/build-receipt.json"),
            Path("/not-created/output"),
            identity=unsupported.require_host_identity(),
        )


@pytest.fixture(autouse=True)
def _isolate_authorized_runtime(monkeypatch: pytest.MonkeyPatch):
    cli._ACTIVE_RUNTIME = None
    monkeypatch.setattr(cli.platform, "system", lambda: cli.REVIEW_TARGET.host_system)
    monkeypatch.setattr(cli.platform, "machine", lambda: cli.REVIEW_TARGET.host_machine)
    monkeypatch.setattr(
        cli, "resolve_source_provenance", lambda _root, _paths: PROVENANCE
    )

    def activate(_receipt, _path, *, identity):
        del identity
        cli._ACTIVE_RUNTIME = object()
        return cli._ACTIVE_RUNTIME

    monkeypatch.setattr(cli, "_activate_build_runtime", activate)
    yield
    cli._ACTIVE_RUNTIME = None


def _build_security_config(invocation_id: str = BUILD_INVOCATION_ID):
    return {
        "Entrypoint": None,
        "Cmd": list(cli.BUILD_EXPECTED_CMD),
        "User": "kodesec",
        "WorkingDir": "/app",
        "Volumes": None,
        "Env": [
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "LANG=C.UTF-8",
            "GPG_KEY=public-upstream-key",
            "PYTHON_VERSION=3.12.0",
            "PYTHON_SHA256=" + "2" * 64,
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONUNBUFFERED=1",
            "PIP_NO_CACHE_DIR=1",
        ],
        "Labels": {
            cli.BUILD_OWNERSHIP_LABEL_KEY: invocation_id,
            **PROVENANCE.labels("scanner"),
        },
    }


def _build_receipt(tmp_path: Path) -> Path:
    identity = cli.require_host_identity()
    directory = tmp_path / "build-receipt"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    (directory / ".docker-runtime").mkdir(mode=0o700)
    path = directory / cli.BUILD_RECEIPT_NAME
    inputs = cli._collect_build_inputs(identity=identity)
    producer = next(
        item
        for item in inputs["files"]
        if item["path"] == cli.BUILD_PRODUCER_RELATIVE_PATH
    )
    tag = f"lomo-kodesec-scanner:trivy-review-{BUILD_INVOCATION_ID}"
    context = directory / cli.BUILD_STAGED_CONTEXT_NAME
    argv = cli._expected_build_argv(
        tag=tag,
        iidfile=directory / ".scanner-build.iid",
        context_dir=context,
        provenance=PROVENANCE,
    )
    staged_files = [
        {
            "path": item["path"],
            "mode": "0400",
            "size_bytes": item["size_bytes"],
            "sha256": item["sha256"],
            "identity_sha256": item["identity_sha256"],
        }
        for item in inputs["files"]
    ]
    staged_context = {
        "hash_algorithm": "kodesec-scanner-staged-context-v1",
        "sha256": hashlib.sha256(
            cli._canonical_json_bytes(
                [
                    {key: item[key] for key in ("path", "mode", "size_bytes", "sha256")}
                    for item in staged_files
                ]
            )
        ).hexdigest(),
        "identity_sha256": hashlib.sha256(
            cli._canonical_json_bytes(
                [
                    {
                        "path": item["path"],
                        "identity_sha256": item["identity_sha256"],
                    }
                    for item in staged_files
                ]
            )
        ).hexdigest(),
        "file_count": len(staged_files),
        "size_bytes": sum(item["size_bytes"] for item in staged_files),
        "files": staged_files,
    }
    receipt = {
        "schema": cli.BUILD_RECEIPT_SCHEMA,
        "authoritative": False,
        "invocation_id": BUILD_INVOCATION_ID,
        "producer": {
            "path": cli.BUILD_PRODUCER_RELATIVE_PATH,
            "sha256": producer["sha256"],
        },
        "host_execution_identity": {
            "uid": identity.uid,
            "gid": identity.gid,
            "system": cli.REVIEW_TARGET.host_system,
            "machine": cli.REVIEW_TARGET.host_machine,
        },
        "docker_runtime": {
            "observation_receipt": {
                "path": str(tmp_path / "docker-runtime-observation.json"),
                "sha256": "7" * 64,
                "receipt_sha256": "8" * 64,
            },
            "observation": {
                "schema": "kodesec.docker-runtime-observation/v1",
                "sha256": "9" * 64,
            },
            "execution": {
                "schema": "kodesec.docker-runtime-execution/v1",
                "environment": {},
            },
        },
        "build": {
            "platform": cli.BUILD_PLATFORM,
            "network": cli.BUILD_NETWORK,
            "pull": True,
            "no_cache": True,
            "context": str(context),
            "dockerfile": str(context / cli.BUILD_DOCKERFILE),
            "tag": tag,
            "source": {
                "commit": PROVENANCE.commit,
                "tree": PROVENANCE.tree,
                "build_identity": PROVENANCE.labels("scanner")[
                    cli.BUILD_IDENTITY_LABEL
                ],
            },
            "args": [
                {"name": key, "value": value}
                for key, value in (*PROVENANCE.build_args(), *cli.BUILD_ARGS)
            ],
            "argv": argv,
            "argv_sha256": hashlib.sha256(cli._canonical_json_bytes(argv)).hexdigest(),
        },
        "inputs_before": inputs,
        "inputs_after": inputs,
        "staged_context": staged_context,
        "image": {
            "id": IMAGE_ID,
            "os": "linux",
            "architecture": cli.BUILD_ARCHITECTURE,
            "owned_tag": tag,
            "security_config": _build_security_config(),
        },
        "lifecycle": {
            "tag_absent_before": True,
            "tag_held_for_consumer": True,
            "iidfile_absent_before": True,
            "iidfile_removed": True,
            "staged_context_removed": True,
            "runtime_snapshots_held_for_consumer": True,
        },
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        cli._canonical_json_bytes(receipt)
    ).hexdigest()
    path.write_bytes(cli._canonical_json_bytes(receipt))
    path.chmod(0o600)
    return path


def _main_argv(tmp_path: Path, output: Path) -> list[str]:
    return [
        "--build-receipt",
        str(_build_receipt(tmp_path)),
        "--output-dir",
        str(output),
    ]


def _inputs(tmp_path: Path, component_id: str = "trivy-db"):
    tmp_path.chmod(0o700)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    support_trivy_db = None
    if component_id == "trivy-java-db":
        support_trivy_db = tmp_path / "support-trivy-db"
        support_trivy_db.mkdir(mode=0o500)
        support_trivy_db.chmod(0o500)
    return cli.ReviewInputs(
        image_id=IMAGE_ID,
        architecture="arm64",
        output_dir=output,
        identity=cli.require_host_identity(),
        invocation_id=INVOCATION_ID,
        component_id=component_id,
        support_trivy_db=support_trivy_db,
    )


def _mounts(argv: tuple[str, ...]) -> list[str]:
    return [argv[index + 1] for index, value in enumerate(argv) if value == "--mount"]


def _assert_hardened(argv: tuple[str, ...], *, network: str, identity=None) -> None:
    identity = identity or cli.require_host_identity()
    assert argv[0:3] == ("docker", "run", "--rm")
    assert "--read-only" in argv
    assert "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges" in argv
    assert "--pids-limit=64" in argv
    assert f"--user={identity.uid}:{identity.gid}" in argv
    assert "--entrypoint=/usr/local/bin/python" in argv
    assert sum(value.startswith("--user=") for value in argv) == 1
    assert "--pull=never" in argv
    assert f"--network={network}" in argv
    assert (
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=0700,"
        f"uid={identity.uid},gid={identity.gid}"
    ) in argv
    expected_tmpfs_count = 3 if network == "none" and "canary" in argv else 2
    assert sum(value.startswith("--tmpfs=") for value in argv) == expected_tmpfs_count
    assert (
        "--tmpfs=/run/kodesec-scratch:rw,noexec,nosuid,nodev,size=64m,"
        f"mode=0700,uid={identity.uid},gid={identity.gid}"
    ) in argv
    assert {
        "--env=HTTP_PROXY=",
        "--env=HTTPS_PROXY=",
        "--env=ALL_PROXY=",
        "--env=NO_PROXY=",
        "--env=http_proxy=",
        "--env=https_proxy=",
        "--env=all_proxy=",
        "--env=no_proxy=",
    }.issubset(argv)
    assert sum(value.startswith("--network=") for value in argv) == 1
    assert all("source=" in value and "target=" in value for value in _mounts(argv))
    image_index = argv.index(IMAGE_ID)
    assert argv[image_index + 1 : image_index + 7] == (
        "-I",
        "-B",
        "-X",
        "pycache_prefix=/run/kodesec-scratch/pycache",
        "-m",
        "kodesec_scanner.trivy_db_lock_candidate",
    )


def test_exact_preflight_argv_is_network_none_and_mounts_only_reviewed_inputs(
    tmp_path: Path,
) -> None:
    inputs = _inputs(tmp_path)
    argv = cli.preflight_argv(inputs)
    _assert_hardened(argv, network="none")
    mounts = _mounts(argv)
    assert len(mounts) == 3
    assert all(value.endswith(",readonly") for value in mounts)
    assert str(cli.CURRENT_LOCK_PATH.resolve()) in mounts[0]
    assert str(cli.POSITIVE_FIXTURE_PATH.resolve()) in mounts[1]
    assert str(cli.ZERO_FIXTURE_PATH.resolve()) in mounts[2]
    assert str(inputs.output_dir) not in "\0".join(argv)
    assert argv[-19:] == (
        "preflight",
        "--current-lock",
        "/run/kodesec-review/current-lock.json",
        "--baked-lock",
        "/usr/local/share/kodesec/locks/scanner-tools.lock.json",
        "--trivy-path",
        "/usr/local/bin/trivy",
        "--trivy-version",
        "0.73.0",
        "--expected-architecture",
        "arm64",
        "--tool-manifest",
        "/usr/local/share/kodesec/tool-manifest.json",
        "--positive-fixture",
        "/run/kodesec-review/positive",
        "--zero-fixture",
        "/run/kodesec-review/zero",
        "--invocation-id",
        INVOCATION_ID,
    )


def test_fetch_argv_has_egress_and_only_one_empty_private_output_mount(
    tmp_path: Path,
) -> None:
    inputs = _inputs(tmp_path)
    argv = cli.fetch_argv(inputs)
    _assert_hardened(argv, network="bridge")
    mounts = _mounts(argv)
    assert mounts == [
        f"type=bind,source={inputs.output_dir},target=/run/kodesec-review/output"
    ]
    joined = "\0".join(argv)
    assert str(cli.CURRENT_LOCK_PATH) not in joined
    assert str(cli.POSITIVE_FIXTURE_PATH) not in joined
    assert str(cli.ZERO_FIXTURE_PATH) not in joined
    assert argv[-11:] == (
        "fetch",
        "--registry",
        "ghcr.io",
        "--repository",
        "aquasecurity/trivy-db",
        "--reference",
        "2",
        "--output-dir",
        "/run/kodesec-review/output",
        "--invocation-id",
        INVOCATION_ID,
    )


def test_canary_argv_is_network_none_and_all_mounts_are_read_only(
    tmp_path: Path,
) -> None:
    inputs = _inputs(tmp_path)
    candidate_db = inputs.output_dir / "candidate-db"
    candidate_db.mkdir(mode=0o500)
    argv = cli.canary_argv(inputs)
    _assert_hardened(argv, network="none")
    mounts = _mounts(argv)
    assert len(mounts) == 4
    assert all(value.endswith(",readonly") for value in mounts)
    assert (
        "--tmpfs=/run/kodesec-review/candidate-cache:"
        "rw,noexec,nosuid,nodev,size=64m,mode=0700,"
        f"uid={inputs.identity.uid},gid={inputs.identity.gid}"
    ) in argv
    assert str(candidate_db) in mounts[1]
    assert str(cli.POSITIVE_FIXTURE_PATH.resolve()) in mounts[2]
    assert str(cli.ZERO_FIXTURE_PATH.resolve()) in mounts[3]
    assert argv[-11:] == (
        "canary",
        "--current-lock",
        "/run/kodesec-review/current-lock.json",
        "--candidate-db",
        "/run/kodesec-review/candidate-cache/db",
        "--positive-fixture",
        "/run/kodesec-review/positive",
        "--zero-fixture",
        "/run/kodesec-review/zero",
        "--invocation-id",
        INVOCATION_ID,
    )


def test_java_profile_argv_uses_fixed_image_canary_and_java_cache_child(
    tmp_path: Path,
) -> None:
    inputs = _inputs(tmp_path, component_id="trivy-java-db")

    preflight = cli.preflight_argv(inputs)
    _assert_hardened(preflight, network="none")
    assert len(_mounts(preflight)) == 2
    assert str(cli.POSITIVE_FIXTURE_PATH) not in "\0".join(preflight)
    assert (
        "--component-id",
        "trivy-java-db",
        "--current-lock",
    ) == preflight[-20:-17]
    assert cli.JAVA_POSITIVE_FIXTURE_IN_IMAGE in preflight

    fetch = cli.fetch_argv(inputs)
    _assert_hardened(fetch, network="bridge")
    assert len(_mounts(fetch)) == 1
    component_index = fetch.index("--component-id")
    assert (
        "--component-id",
        "trivy-java-db",
        "--registry",
        "ghcr.io",
        "--repository",
        "aquasecurity/trivy-java-db",
        "--reference",
        "1",
    ) == fetch[component_index : component_index + 8]

    candidate_db = inputs.output_dir / "candidate-db"
    candidate_db.mkdir(mode=0o500)
    canary = cli.canary_argv(inputs)
    _assert_hardened(canary, network="none")
    mounts = _mounts(canary)
    assert len(mounts) == 4
    assert all(value.endswith(",readonly") for value in mounts)
    assert str(cli.POSITIVE_FIXTURE_PATH) not in "\0".join(canary)
    assert "/run/kodesec-review/candidate-cache/java-db" in canary
    assert "/run/kodesec-review/candidate-cache/db" in canary
    assert "--support-trivy-db" in canary
    assert cli.JAVA_POSITIVE_FIXTURE_IN_IMAGE in canary
    with pytest.raises(cli.CandidateCliError, match="support_trivy_db_invalid"):
        cli.ReviewInputs(
            image_id=IMAGE_ID,
            architecture="arm64",
            output_dir=inputs.output_dir,
            identity=inputs.identity,
            invocation_id=INVOCATION_ID,
            component_id="trivy-java-db",
        )
    with pytest.raises(cli.CandidateCliError, match="component_id_invalid"):
        cli.ReviewInputs(
            image_id=IMAGE_ID,
            architecture="arm64",
            output_dir=inputs.output_dir,
            identity=inputs.identity,
            invocation_id=INVOCATION_ID,
            component_id="../trivy-java-db",
            support_trivy_db=inputs.support_trivy_db,
        )


def test_output_and_candidate_paths_fail_closed(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    fresh = tmp_path / "fresh"
    assert cli.require_new_private_output(fresh) == fresh
    fresh.mkdir(mode=0o700)
    with pytest.raises(cli.CandidateCliError, match="output_dir_exists"):
        cli.require_new_private_output(fresh)
    with pytest.raises(cli.CandidateCliError, match="output_dir_invalid"):
        cli.require_new_private_output(Path("relative"))

    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    with pytest.raises(cli.CandidateCliError, match="output_parent_not_private"):
        cli.require_new_private_output(public / "candidate")

    output = tmp_path / "bounded"
    output.mkdir(mode=0o700)
    inputs = cli.ReviewInputs(
        IMAGE_ID,
        "amd64",
        output,
        cli.require_host_identity(),
        INVOCATION_ID,
    )
    (output / "unexpected").write_bytes(b"x")
    with pytest.raises(cli.CandidateCliError, match="private_directory_not_empty"):
        cli.fetch_argv(inputs)
    (output / "unexpected").unlink()
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (output / "candidate-db").symlink_to(outside, target_is_directory=True)
    with pytest.raises(cli.CandidateCliError, match="candidate_db_invalid"):
        cli.canary_argv(inputs)


@pytest.mark.parametrize(
    ("uid", "gid"),
    [
        (0, 20),
        (502, 0),
        (-1, 20),
        (502, -1),
        (True, 20),
        (502, False),
        (cli.MAX_CONTAINER_ID + 1, 20),
        (502, cli.MAX_CONTAINER_ID + 1),
    ],
)
def test_host_identity_rejects_root_noninteger_and_out_of_range_ids(
    uid: int, gid: int
) -> None:
    with pytest.raises(cli.CandidateCliError, match="invoking_identity_invalid"):
        cli.require_host_identity(uid=uid, gid=gid)


def test_linux_host_identity_drives_user_and_private_tmpfs_options(
    tmp_path: Path,
) -> None:
    identity = cli.HostIdentity(uid=4242, gid=4343)
    inputs = cli.ReviewInputs(
        image_id=IMAGE_ID,
        architecture="amd64",
        output_dir=tmp_path / "unused",
        identity=identity,
        invocation_id=INVOCATION_ID,
    )
    argv = cli.preflight_argv(inputs)
    _assert_hardened(argv, network="none", identity=identity)
    assert "--user=1000:1000" not in argv


def test_private_paths_must_match_the_validated_invoking_owner(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    current = cli.require_host_identity()
    foreign_uid = 1 if current.uid != 1 else 2
    foreign = cli.HostIdentity(uid=foreign_uid, gid=current.gid)
    new_output = tmp_path / "new-output"
    with pytest.raises(cli.CandidateCliError, match="output_parent_not_private"):
        cli.require_new_private_output(new_output, identity=foreign)

    existing = tmp_path / "existing"
    existing.mkdir(mode=0o700)
    with pytest.raises(cli.CandidateCliError, match="private_directory_invalid"):
        cli._require_private_directory(existing, empty=True, identity=foreign)
    assert (
        cli._require_private_directory(existing, empty=True, identity=current)
        == existing
    )


def test_mount_rejects_delimiter_escape(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    hostile = tmp_path / "comma,path"
    hostile.mkdir(mode=0o700)
    with pytest.raises(cli.CandidateCliError, match="mount_source_unsafe"):
        cli._mount(hostile, "/fixed", readonly=True)


def test_image_inspect_requires_exact_typed_local_linux_identity() -> None:
    valid = json.dumps(
        {
            "Id": IMAGE_ID,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {"Volumes": None},
            "extra": "ok",
        },
        separators=(",", ":"),
    ).encode()
    assert cli.parse_image_inspect(valid, expected_id=IMAGE_ID) == "amd64"

    for raw, message in (
        (
            f'{{"Id":"{IMAGE_ID}","Id":"{IMAGE_ID}","Os":"linux","Architecture":"amd64","Config":{{"Volumes":null}}}}'.encode(),
            "duplicate_key",
        ),
        (
            f'{{"Id":"{IMAGE_ID}","Os":"linux","Architecture":"amd64","Config":{{"Volumes":null}},"x":NaN}}'.encode(),
            "nonfinite",
        ),
        (
            f'{{"Id":"{IMAGE_ID}","Os":"linux","Architecture":"amd64","Config":{{"Volumes":null}},"x":1e400}}'.encode(),
            "nonfinite",
        ),
        (
            json.dumps(
                {
                    "Id": True,
                    "Os": "linux",
                    "Architecture": "amd64",
                    "Config": {"Volumes": None},
                }
            ).encode(),
            "shape_invalid",
        ),
        (
            json.dumps(
                {
                    "Id": IMAGE_ID,
                    "Os": "linux",
                    "Config": {"Volumes": None},
                    "extra": "x",
                }
            ).encode(),
            "shape_invalid",
        ),
    ):
        with pytest.raises(cli.CandidateCliError, match=message):
            cli.parse_image_inspect(raw, expected_id=IMAGE_ID)

    mismatch = json.dumps(
        {
            "Id": "sha256:" + "2" * 64,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {"Volumes": None},
        }
    ).encode()
    with pytest.raises(cli.CandidateCliError, match="identity_mismatch"):
        cli.parse_image_inspect(mismatch, expected_id=IMAGE_ID)

    implicit_volume = json.dumps(
        {
            "Id": IMAGE_ID,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {"Volumes": {"/unreviewed": {}}},
        },
        separators=(",", ":"),
    ).encode()
    with pytest.raises(cli.CandidateCliError, match="shape_invalid"):
        cli.parse_image_inspect(implicit_volume, expected_id=IMAGE_ID)


@pytest.mark.parametrize("descriptor", [1, 2])
def test_bounded_process_rejects_output_prospectively(
    monkeypatch: pytest.MonkeyPatch, descriptor: int
) -> None:
    monkeypatch.setattr(cli, "MAX_DOCKER_OUTPUT_BYTES", 64)
    with pytest.raises(cli.DockerProcessCleanupUncertain, match="completion_uncertain"):
        cli._run_bounded_process(
            (
                sys.executable,
                "-c",
                f"import os; os.write({descriptor}, b'x' * 65)",
            ),
            timeout_seconds=5,
        )


def test_bounded_process_captures_both_streams_and_rejects_status() -> None:
    completed = cli._run_bounded_process(
        (
            sys.executable,
            "-c",
            "import os; os.write(1,b'out'); os.write(2,b'err')",
        ),
        timeout_seconds=5,
    )
    assert completed.stdout == b"out"
    assert completed.stderr == b"err"
    with pytest.raises(cli.CandidateCliError, match="docker_status_failed"):
        cli._run_bounded_process(
            (sys.executable, "-c", "raise SystemExit(7)"), timeout_seconds=5
        )


@pytest.mark.parametrize(
    ("mode", "code"),
    [
        (mode, code)
        for mode, codes in cli.INNER_FAILURE_CODES.items()
        for code in sorted(codes)
    ],
)
def test_bounded_process_translates_only_allowlisted_inner_failure_marker(
    mode: str, code: str
) -> None:
    marker = f"kodesec_candidate_failure/v1 {mode} {code}\n".encode()
    program = f"import os; os.write(2, {marker!r}); raise SystemExit(2)"
    with pytest.raises(cli.CandidateCliError) as captured:
        cli._run_bounded_process(
            (sys.executable, "-c", program, mode), timeout_seconds=5
        )
    assert str(captured.value) == f"{mode}_{code}"


@pytest.mark.parametrize(
    ("argv", "returncode", "stdout", "stderr"),
    [
        (
            ("docker", "run", "preflight"),
            1,
            b"",
            b"kodesec_candidate_failure/v1 preflight architecture\n",
        ),
        (
            ("docker", "run", "preflight"),
            2,
            b"partial",
            b"kodesec_candidate_failure/v1 preflight architecture\n",
        ),
        (
            ("docker", "run", "preflight"),
            2,
            b"",
            b"kodesec_candidate_failure/v1 fetch validation\n",
        ),
        (
            ("docker", "run", "preflight"),
            2,
            b"",
            b"kodesec_candidate_failure/v1 preflight invented\n",
        ),
        (
            ("docker", "run", "preflight"),
            2,
            b"",
            b"kodesec_candidate_failure/v1 preflight architecture\nextra\n",
        ),
        (("docker", "run", "preflight"), 2, b"", b"candidate_validation_failed\n"),
        (
            ("docker", "run", "preflight", "fetch"),
            2,
            b"",
            b"kodesec_candidate_failure/v1 preflight architecture\n",
        ),
        (
            ("docker", "run", "canary"),
            2,
            b"",
            b"kodesec_candidate_failure/v1 canary validation\n",
        ),
    ],
)
def test_inner_failure_marker_rejects_malformed_or_ambiguous_output(
    argv: tuple[str, ...], returncode: int, stdout: bytes, stderr: bytes
) -> None:
    assert (
        cli._inner_failure_status(
            argv, returncode=returncode, stdout=stdout, stderr=stderr
        )
        is None
    )


def test_bounded_process_malformed_marker_is_generic_and_never_echoed() -> None:
    marker = b"kodesec_candidate_failure/v1 preflight architecture\nsecret\n"
    program = f"import os; os.write(2, {marker!r}); raise SystemExit(2)"
    with pytest.raises(cli.CandidateCliError) as captured:
        cli._run_bounded_process(
            (sys.executable, "-c", program, "preflight"), timeout_seconds=5
        )
    assert str(captured.value) == "docker_status_failed"
    assert "secret" not in str(captured.value)


def test_run_docker_refuses_nonfixed_prefix_and_invalid_timeout() -> None:
    with pytest.raises(cli.CandidateCliError, match="docker_argv_invalid"):
        cli.run_docker(("not-docker",))
    with pytest.raises(ValueError, match="hard bound"):
        cli.run_docker(("docker", "version"), timeout_seconds=0)


def test_candidate_bounded_runner_reaps_setup_interrupt_and_reports_uncertainty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = os.fdopen(stdout_read, "rb", buffering=0)
            self.stderr = os.fdopen(stderr_read, "rb", buffering=0)
            self.alive = True
            self.terminate_calls = 0

        def poll(self):
            return None if self.alive else -15

        def terminate(self):
            self.terminate_calls += 1
            self.alive = False
            os.close(stdout_write)
            os.close(stderr_write)

        def kill(self):
            self.alive = False

        def wait(self, *, timeout):
            del timeout
            return -15

    process = FakeProcess()
    process.pid = 12345
    monkeypatch.setattr(cli.subprocess, "Popen", lambda *_args, **_kwargs: process)
    kill_calls: list[int] = []

    def killpg(_pid, signal_number):
        kill_calls.append(signal_number)
        process.alive = False
        os.close(stdout_write)
        os.close(stderr_write)

    monkeypatch.setattr(cli.os, "killpg", killpg)
    monkeypatch.setattr(
        cli.os,
        "set_blocking",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            KeyboardInterrupt("injected setup interrupt")
        ),
    )
    with pytest.raises(cli.DockerProcessCleanupUncertain, match="completion_uncertain"):
        cli._run_bounded_process(("docker", "run"), timeout_seconds=1)
    assert kill_calls == [cli.signal.SIGTERM]
    assert process.poll() == -15
    assert process.stdout.closed
    assert process.stderr.closed


def test_candidate_bounded_runner_kill_wait_failure_is_cleanup_uncertain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = os.fdopen(stdout_read, "rb", buffering=0)
            self.stderr = os.fdopen(stderr_read, "rb", buffering=0)

        def poll(self):
            return None

        def terminate(self):
            raise SystemExit("injected terminate interrupt")

        def kill(self):
            raise KeyboardInterrupt("injected kill interrupt")

        def wait(self, *, timeout):
            del timeout
            raise RuntimeError("injected wait failure")

    process = FakeProcess()
    monkeypatch.setattr(cli.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        cli.os,
        "set_blocking",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("injected setup failure")
        ),
    )
    with pytest.raises(cli.DockerProcessCleanupUncertain, match="cleanup_uncertain"):
        cli._run_bounded_process(("docker", "run"), timeout_seconds=1)
    os.close(stdout_write)
    os.close(stderr_write)


def _owned_run_fixture(tmp_path: Path):
    inputs = _inputs(tmp_path)
    lifecycle = tmp_path / "lifecycle"
    lifecycle.mkdir(mode=0o700)
    lifecycle.chmod(0o700)
    run_identity = cli._docker_run_identity(
        invocation_id=INVOCATION_ID,
        mode="preflight",
        lifecycle_dir=lifecycle,
    )
    argv = cli.preflight_argv(inputs, run_identity=run_identity)
    return inputs, run_identity, argv


@pytest.mark.parametrize(
    "failure",
    [
        "docker_status_failed",
        "docker_execution_timed_out",
        "docker_output_oversized",
        "docker_execution_failed",
    ],
)
def test_owned_container_force_removes_and_proves_absence_after_primary_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    inputs, run_identity, argv = _owned_run_fixture(tmp_path)
    control_calls: list[tuple[str, ...]] = []

    def primary(_argv, *, timeout_seconds):
        assert timeout_seconds == 120
        if failure != "docker_execution_failed":
            run_identity.cidfile.write_bytes(b"c" * 64)
        raise cli.CandidateCliError(failure)

    def control(command, *, timeout_seconds=cli.DOCKER_CONTROL_TIMEOUT_SECONDS):
        assert timeout_seconds == cli.DOCKER_CONTROL_TIMEOUT_SECONDS
        control_calls.append(tuple(command))
        return cli.CompletedDocker(b"", b"")

    monkeypatch.setattr(cli, "run_docker", primary)
    monkeypatch.setattr(cli, "run_docker_control", control)
    with pytest.raises(cli.CandidateCliError, match=failure):
        cli.run_owned_container(
            argv,
            run_identity=run_identity,
            identity=inputs.identity,
            timeout_seconds=120,
        )
    assert [command[1:3] for command in control_calls] == [
        ("container", "ls"),
        ("rm", "--force"),
        ("container", "ls"),
    ]
    assert not run_identity.cidfile.exists()


def test_owned_container_success_requires_exact_cidfile_then_removes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs, run_identity, argv = _owned_run_fixture(tmp_path)
    result = cli.CompletedDocker(b"receipt\n", b"")

    def primary(_argv, *, timeout_seconds):
        assert timeout_seconds == 120
        run_identity.cidfile.write_bytes(b"d" * 64)
        return result

    monkeypatch.setattr(cli, "run_docker", primary)
    monkeypatch.setattr(
        cli,
        "run_docker_control",
        lambda *_args, **_kwargs: cli.CompletedDocker(b"", b""),
    )
    assert (
        cli.run_owned_container(
            argv,
            run_identity=run_identity,
            identity=inputs.identity,
            timeout_seconds=120,
        )
        == result
    )
    assert not run_identity.cidfile.exists()


@pytest.mark.parametrize("interrupt_type", [KeyboardInterrupt, SystemExit])
def test_owned_container_interrupt_still_forces_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupt_type: type[BaseException],
) -> None:
    inputs, run_identity, argv = _owned_run_fixture(tmp_path)
    controls: list[tuple[str, ...]] = []

    def primary(_argv, *, timeout_seconds):
        del timeout_seconds
        run_identity.cidfile.write_bytes(b"e" * 64)
        raise interrupt_type()

    def control(command, **_kwargs):
        controls.append(tuple(command))
        return cli.CompletedDocker(b"", b"")

    monkeypatch.setattr(cli, "run_docker", primary)
    monkeypatch.setattr(cli, "run_docker_control", control)
    with pytest.raises(interrupt_type):
        cli.run_owned_container(
            argv,
            run_identity=run_identity,
            identity=inputs.identity,
            timeout_seconds=120,
        )
    assert [item[1:3] for item in controls] == [
        ("container", "ls"),
        ("rm", "--force"),
        ("container", "ls"),
    ]
    assert not run_identity.cidfile.exists()


def test_owned_container_cleanup_interrupt_is_deferred_until_absence_is_proven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs, run_identity, argv = _owned_run_fixture(tmp_path)
    controls = 0

    def primary(_argv, **_kwargs):
        run_identity.cidfile.write_bytes(b"f" * 64)
        return cli.CompletedDocker(b"ok", b"")

    def control(command, **_kwargs):
        nonlocal controls
        controls += 1
        if tuple(command)[1:3] == ("rm", "--force"):
            raise KeyboardInterrupt()
        return cli.CompletedDocker(b"", b"")

    monkeypatch.setattr(cli, "run_docker", primary)
    monkeypatch.setattr(cli, "run_docker_control", control)
    with pytest.raises(KeyboardInterrupt):
        cli.run_owned_container(
            argv,
            run_identity=run_identity,
            identity=inputs.identity,
            timeout_seconds=120,
        )
    assert controls == 3
    assert not run_identity.cidfile.exists()


@pytest.mark.parametrize(
    ("listing", "message"),
    [
        (cli.CompletedDocker((b"1" * 64) + b"\n", b""), "preexisting"),
        (cli.CompletedDocker(b"garbage\n", b""), "preabsence_unproven"),
        (cli.CompletedDocker(b"", b"warning"), "preabsence_unproven"),
    ],
)
def test_owned_container_rejects_present_or_ambiguous_preexisting_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    listing,
    message: str,
) -> None:
    inputs, run_identity, argv = _owned_run_fixture(tmp_path)
    monkeypatch.setattr(cli, "run_docker_control", lambda *_args, **_kwargs: listing)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("primary Docker run must not execute")

    monkeypatch.setattr(cli, "run_docker", forbidden)
    with pytest.raises(cli.CandidateCliError, match=message):
        cli.run_owned_container(
            argv,
            run_identity=run_identity,
            identity=inputs.identity,
            timeout_seconds=120,
        )


def test_owned_container_rejects_existing_cidfile_and_mismatched_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs, run_identity, argv = _owned_run_fixture(tmp_path)
    wrong = tuple(
        "kodesec-trivy-db-" + ("b" * 32) + "-preflight"
        if item == run_identity.name
        else item
        for item in argv
    )
    monkeypatch.setattr(
        cli,
        "run_docker_control",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("control must not execute")
        ),
    )
    with pytest.raises(cli.CandidateCliError, match="owned_argv_invalid"):
        cli.run_owned_container(
            wrong,
            run_identity=run_identity,
            identity=inputs.identity,
            timeout_seconds=120,
        )

    run_identity.cidfile.write_bytes(b"a" * 64)
    with pytest.raises(cli.CandidateCliError, match="cidfile_exists"):
        cli.run_owned_container(
            argv,
            run_identity=run_identity,
            identity=inputs.identity,
            timeout_seconds=120,
        )


def test_owned_container_accepts_rm_failure_only_with_canonical_absence_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs, run_identity, argv = _owned_run_fixture(tmp_path)
    calls = 0

    def primary(_argv, **_kwargs):
        run_identity.cidfile.write_bytes(b"7" * 64)
        return cli.CompletedDocker(b"ok", b"")

    def control(command, **_kwargs):
        nonlocal calls
        calls += 1
        if tuple(command)[1:3] == ("rm", "--force"):
            raise cli.CandidateCliError("docker_status_failed")
        return cli.CompletedDocker(b"", b"")

    monkeypatch.setattr(cli, "run_docker", primary)
    monkeypatch.setattr(cli, "run_docker_control", control)
    assert cli.run_owned_container(
        argv,
        run_identity=run_identity,
        identity=inputs.identity,
        timeout_seconds=120,
    ) == cli.CompletedDocker(b"ok", b"")
    assert calls == 3
    assert not run_identity.cidfile.exists()


@pytest.mark.parametrize(
    "post_listing",
    [
        cli.CompletedDocker((b"2" * 64) + b"\n", b""),
        cli.CompletedDocker(b"malformed", b""),
        cli.CompletedDocker(b"", b"daemon warning"),
    ],
)
def test_owned_container_blocks_when_post_cleanup_absence_is_unproven(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    post_listing,
) -> None:
    inputs, run_identity, argv = _owned_run_fixture(tmp_path)
    list_calls = 0

    def primary(_argv, **_kwargs):
        run_identity.cidfile.write_bytes(b"8" * 64)
        return cli.CompletedDocker(b"ok", b"")

    def control(command, **_kwargs):
        nonlocal list_calls
        if tuple(command)[1:3] == ("container", "ls"):
            list_calls += 1
            if list_calls == 2:
                return post_listing
        return cli.CompletedDocker(b"", b"")

    monkeypatch.setattr(cli, "run_docker", primary)
    monkeypatch.setattr(cli, "run_docker_control", control)
    with pytest.raises(cli.CandidateCliError, match="cleanup_uncertain"):
        cli.run_owned_container(
            argv,
            run_identity=run_identity,
            identity=inputs.identity,
            timeout_seconds=120,
        )
    assert run_identity.cidfile.exists()


@pytest.mark.parametrize("cidfile_kind", ["missing", "invalid", "symlink", "hardlink"])
def test_owned_container_rejects_missing_or_unsafe_success_cidfile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cidfile_kind: str,
) -> None:
    inputs, run_identity, argv = _owned_run_fixture(tmp_path)

    def primary(_argv, **_kwargs):
        if cidfile_kind == "invalid":
            run_identity.cidfile.write_bytes(b"not-a-container-id")
        elif cidfile_kind == "symlink":
            target = tmp_path / "target"
            target.write_bytes(b"9" * 64)
            run_identity.cidfile.symlink_to(target)
        elif cidfile_kind == "hardlink":
            target = run_identity.cidfile.parent / "other"
            target.write_bytes(b"9" * 64)
            run_identity.cidfile.hardlink_to(target)
        return cli.CompletedDocker(b"ok", b"")

    monkeypatch.setattr(cli, "run_docker", primary)
    monkeypatch.setattr(
        cli,
        "run_docker_control",
        lambda *_args, **_kwargs: cli.CompletedDocker(b"", b""),
    )
    message = "cidfile_missing" if cidfile_kind == "missing" else "identity_invalid"
    with pytest.raises(cli.CandidateCliError, match=message):
        cli.run_owned_container(
            argv,
            run_identity=run_identity,
            identity=inputs.identity,
            timeout_seconds=120,
        )


def _inner_receipts(tmp_path: Path, *, stale_core: bool = False):
    core = cli._candidate_core()
    current, canaries = core._trivy_requirement_contract(cli.CURRENT_LOCK_PATH)
    implementation_bundle = core.implementation_bundle_evidence(
        Path(core.__file__).resolve(strict=True).parent,
        expected_uid=cli.require_host_identity().uid,
    )
    if stale_core:
        implementation_bundle = dict(implementation_bundle)
        stale_files = [dict(item) for item in implementation_bundle["files"]]
        stale_files[0]["sha256"] = "f" * 64
        implementation_bundle["files"] = stale_files
        implementation_bundle["sha256"] = hashlib.sha256(
            core.canonical_json_bytes(stale_files)
        ).hexdigest()
    preflight = core._seal_receipt(
        {
            "schema": "kodesec.trivy-db-lock-candidate-preflight/v1",
            "invocation_id": INVOCATION_ID,
            "current_lock_sha256": current.sha256,
            "baked_lock_sha256": current.sha256,
            "scanner": {
                "architecture": cli.BUILD_ARCHITECTURE,
                "trivy_version": "0.73.0",
                "trivy_executable_path": "/usr/local/bin/trivy",
                "trivy_executable_sha256": "1" * 64,
                "tool_manifest_sha256": "2" * 64,
                "implementation_bundle": implementation_bundle,
            },
            "current_canaries": canaries,
        }
    )
    observed = datetime.now(UTC).replace(microsecond=0)
    updated = observed - timedelta(hours=1)
    next_update = observed + timedelta(hours=20)

    def timestamp(value: datetime) -> str:
        return value.isoformat().replace("+00:00", "Z")

    metadata_raw = json.dumps(
        {
            "Version": 2,
            "UpdatedAt": timestamp(updated),
            "NextUpdate": timestamp(next_update),
            "DownloadedAt": core.RAW_TRIVY_DOWNLOADED_AT,
        },
        separators=(",", ":"),
    ).encode()
    records = [
        core.CacheFileRecord(
            path="metadata.json",
            size_bytes=len(metadata_raw),
            sha256=hashlib.sha256(metadata_raw).hexdigest(),
        ),
        core.CacheFileRecord(
            path="trivy.db",
            size_bytes=8,
            sha256=hashlib.sha256(b"database").hexdigest(),
        ),
    ]
    tree = {
        "hash_algorithm": core.CANONICAL_TREE_HASH_ALGORITHM,
        "sha256": core.canonical_tree_sha256(records),
        "file_count": 2,
        "size_bytes": sum(item.size_bytes for item in records),
    }
    fetch = core._seal_receipt(
        {
            "schema": "kodesec.trivy-db-lock-candidate-fetch/v1",
            "invocation_id": INVOCATION_ID,
            "source": {
                "discovery_ref": core.TRIVY_DB_DISCOVERY_REF,
                "token_endpoint": core.TOKEN_URL,
            },
            "oci": {
                "manifest_sha256": "3" * 64,
                "created_at": "2026-08-13T12:00:00Z",
                "layer_sha256": "4" * 64,
                "layer_size_bytes": 5,
                "config_sha256": core.EMPTY_CONFIG_DIGEST.removeprefix("sha256:"),
            },
            "metadata": {
                "updated_at": timestamp(updated),
                "next_update": timestamp(next_update),
                "downloaded_at": core.RAW_TRIVY_DOWNLOADED_AT,
                "observed_at": timestamp(observed),
                "size_bytes": len(metadata_raw),
                "sha256": hashlib.sha256(metadata_raw).hexdigest(),
                "maximum_age_seconds": core.TRIVY_DB_MAX_AGE_SECONDS,
                "minimum_remaining_seconds": core.MINIMUM_REMAINING_SECONDS,
            },
            "installed_records": [item.model_dump(mode="json") for item in records],
            "installed_tree": tree,
        }
    )
    by_id = {item["id"]: item for item in canaries}
    canary = core._seal_receipt(
        {
            "schema": "kodesec.trivy-db-lock-candidate-canary/v1",
            "invocation_id": INVOCATION_ID,
            "current_lock_sha256": current.sha256,
            "candidate_tree": tree,
            "canaries": [
                {
                    "canary_id": "source-vulnerabilities-positive",
                    "fixture_sha256": by_id["source-vulnerabilities-positive"][
                        "fixture_sha256"
                    ],
                    "exit_code": 0,
                    "result_count": 1,
                    "ids": ["CVE-1"],
                    "command_sha256": core._trivy_canary_command_sha256(
                        "source-vulnerabilities-positive"
                    ),
                    "result_sha256": "6" * 64,
                    "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                },
                {
                    "canary_id": "source-vulnerabilities-zero",
                    "fixture_sha256": by_id["source-vulnerabilities-zero"][
                        "fixture_sha256"
                    ],
                    "exit_code": 0,
                    "result_count": 0,
                    "ids": [],
                    "command_sha256": core._trivy_canary_command_sha256(
                        "source-vulnerabilities-zero"
                    ),
                    "result_sha256": "8" * 64,
                    "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                },
            ],
        }
    )
    return core, preflight, fetch, canary, metadata_raw


def _fake_docker_runner(tmp_path: Path, *, stale_core: bool = False):
    core, preflight, fetch, canary, metadata_raw = _inner_receipts(
        tmp_path, stale_core=stale_core
    )
    calls: list[str] = []
    lifecycle_calls: list[tuple[str, ...]] = []
    build_tag = f"lomo-kodesec-scanner:trivy-review-{BUILD_INVOCATION_ID}"
    build_tag_present = True

    def run(argv, *, timeout_seconds=cli.MAX_DOCKER_TIMEOUT_SECONDS):
        del timeout_seconds
        if argv[1:3] == ("image", "inspect"):
            calls.append("inspect")
            return cli.CompletedDocker(
                stdout=json.dumps(
                    {
                        "Id": IMAGE_ID,
                        "Os": "linux",
                        "Architecture": cli.BUILD_ARCHITECTURE,
                        "RepoTags": [build_tag],
                        "RepoDigests": [],
                        "Config": _build_security_config(),
                    },
                    separators=(",", ":"),
                ).encode(),
                stderr=b"",
            )
        mode = next(
            value for value in ("preflight", "fetch", "canary") if value in argv
        )
        invocation_id = argv[argv.index("--invocation-id") + 1]
        name = argv[argv.index("--name") + 1]
        cidfile = Path(argv[argv.index("--cidfile") + 1])
        assert name == f"kodesec-trivy-db-{invocation_id}-{mode}"
        assert cidfile.name == f"{name}.cid"
        cidfile.write_bytes(b"b" * 64)
        active_receipt = {
            "preflight": preflight,
            "fetch": fetch,
            "canary": canary,
        }[mode]
        if active_receipt["invocation_id"] != invocation_id:
            active_receipt = dict(active_receipt)
            active_receipt["invocation_id"] = invocation_id
            unsigned = dict(active_receipt)
            unsigned.pop("receipt_sha256")
            active_receipt["receipt_sha256"] = hashlib.sha256(
                core.canonical_json_bytes(unsigned)
            ).hexdigest()
        calls.append(mode)
        if mode == "preflight":
            return cli.CompletedDocker(core.canonical_json_bytes(active_receipt), b"")
        output = tmp_path / "candidate-output"
        if mode == "fetch":
            database = output / "candidate-db"
            database.mkdir(mode=0o700)
            (database / "metadata.json").write_bytes(metadata_raw)
            (database / "trivy.db").write_bytes(b"database")
            for path in database.iterdir():
                path.chmod(0o400)
            database.chmod(0o500)
            layer = output / "layer.tar.gz"
            layer.write_bytes(b"layer")
            layer.chmod(0o400)
            core.write_private_evidence_receipt(
                output / "fetch-receipt.json",
                active_receipt,
                schema="kodesec.trivy-db-lock-candidate-fetch/v1",
                fields={
                    "schema",
                    "invocation_id",
                    "source",
                    "oci",
                    "metadata",
                    "installed_records",
                    "installed_tree",
                },
            )
            return cli.CompletedDocker(core.canonical_json_bytes(active_receipt), b"")
        return cli.CompletedDocker(core.canonical_json_bytes(active_receipt), b"")

    def control(argv, *, timeout_seconds=cli.DOCKER_CONTROL_TIMEOUT_SECONDS):
        nonlocal build_tag_present
        assert timeout_seconds == cli.DOCKER_CONTROL_TIMEOUT_SECONDS
        command = tuple(argv)
        lifecycle_calls.append(command)
        if command[1:3] == ("image", "ls"):
            reference_filters = [
                item for item in command if item.startswith("--filter=reference=")
            ]
            label_filters = [
                item for item in command if item.startswith("--filter=label=")
            ]
            if label_filters:
                if build_tag_present:
                    return cli.CompletedDocker((IMAGE_ID + "\n").encode(), b"")
                return cli.CompletedDocker(b"", b"")
            if reference_filters and build_tag_present:
                return cli.CompletedDocker(f"{build_tag}|{IMAGE_ID}\n".encode(), b"")
            if not reference_filters and build_tag_present:
                return cli.CompletedDocker((IMAGE_ID + "\n").encode(), b"")
            return cli.CompletedDocker(b"", b"")
        if command[1:3] == ("image", "rm"):
            assert command[-1] == IMAGE_ID
            build_tag_present = False
            return cli.CompletedDocker((IMAGE_ID + "\n").encode(), b"")
        if command[1:3] == ("container", "ls"):
            return cli.CompletedDocker(b"", b"")
        assert command[1:3] == ("rm", "--force")
        return cli.CompletedDocker((command[-1] + "\n").encode(), b"")

    return run, control, calls, lifecycle_calls


def test_main_orchestrates_exact_receipts_without_real_docker_or_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "candidate-output"
    fake, control, calls, lifecycle_calls = _fake_docker_runner(tmp_path)
    monkeypatch.setattr(cli, "run_docker", fake)
    monkeypatch.setattr(cli, "run_docker_control", control)
    assert cli.main(_main_argv(tmp_path, output)) == 0
    assert calls == [
        "inspect",
        "inspect",
        "preflight",
        "inspect",
        "inspect",
        "fetch",
        "canary",
        "inspect",
    ]
    container_lifecycle = [
        command
        for command in lifecycle_calls
        if command[1:3] in {("container", "ls"), ("rm", "--force")}
    ]
    assert [command[1:3] for command in container_lifecycle] == [
        ("container", "ls"),
        ("rm", "--force"),
        ("container", "ls"),
    ] * 3
    assert [command[1:3] for command in lifecycle_calls].count(("image", "rm")) == 1
    image_lifecycle = [
        command[1:3]
        for command in lifecycle_calls
        if command[1:3] in {("image", "ls"), ("image", "rm")}
    ]
    remove_index = image_lifecycle.index(("image", "rm"))
    assert image_lifecycle[remove_index + 1 :] == [("image", "ls")] * 9
    final_path = output / "candidate-receipt.json"
    assert capsys.readouterr().out.strip() == str(final_path)
    final = json.loads(final_path.read_text())
    assert final["authoritative"] is False
    assert final["scanner_image"]["implementation_bundle"] == (
        cli._candidate_core().implementation_bundle_evidence(
            Path(cli._candidate_core().__file__).resolve(strict=True).parent,
            expected_uid=cli.require_host_identity().uid,
        )
    )
    assert final["scanner_image"]["host_cli_sha256"] == cli._stable_source_sha256(
        Path(cli.__file__).resolve(strict=True), label="host_candidate_cli"
    )
    assert final["host_execution_identity"] == {
        "uid": cli.require_host_identity().uid,
        "gid": cli.require_host_identity().gid,
    }
    build_receipt = json.loads(
        (tmp_path / "build-receipt" / cli.BUILD_RECEIPT_NAME).read_text()
    )
    assert final["build_receipt"] == {
        "schema": cli.BUILD_RECEIPT_SCHEMA,
        "receipt_sha256": build_receipt["receipt_sha256"],
    }
    assert set(final["evidence_receipts"]) == {"preflight", "fetch", "canary"}
    for label in ("preflight", "fetch", "canary"):
        sibling = json.loads((output / f"{label}-receipt.json").read_text())
        assert final["evidence_receipts"][label] == {
            "schema": sibling["schema"],
            "receipt_sha256": sibling["receipt_sha256"],
        }
    assert not any(tmp_path.glob(".kodesec-trivy-db-*.docker"))
    assert {item.name for item in output.iterdir()} == {
        "candidate-db",
        "layer.tar.gz",
        "fetch-receipt.json",
        "preflight-receipt.json",
        "canary-receipt.json",
        "candidate-receipt.json",
    }


def test_stale_image_core_aborts_before_fetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "candidate-output"
    fake, control, calls, _ = _fake_docker_runner(tmp_path, stale_core=True)
    monkeypatch.setattr(cli, "run_docker", fake)
    monkeypatch.setattr(cli, "run_docker_control", control)
    assert cli.main(_main_argv(tmp_path, output)) == 2
    assert [item for item in calls if item != "inspect"] == ["preflight"]
    assert capsys.readouterr().err.strip() == "implementation_bundle_image_mismatch"
    assert not output.exists()
    assert not any(tmp_path.glob(".kodesec-trivy-db-*.docker"))


def test_preflight_failure_marker_survives_normal_container_and_output_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "candidate-output"
    fake, control, calls, _ = _fake_docker_runner(tmp_path)

    def marked_preflight(argv, *, timeout_seconds=cli.MAX_DOCKER_TIMEOUT_SECONDS):
        completed = fake(argv, timeout_seconds=timeout_seconds)
        if "preflight" in argv:
            raise cli.CandidateCliError("preflight_trivy_binary")
        return completed

    monkeypatch.setattr(cli, "run_docker", marked_preflight)
    monkeypatch.setattr(cli, "run_docker_control", control)
    assert cli.main(_main_argv(tmp_path, output)) == 2
    assert [item for item in calls if item != "inspect"] == ["preflight"]
    assert capsys.readouterr().err.strip() == "preflight_trivy_binary"
    assert not output.exists()
    assert not any(tmp_path.glob(".kodesec-trivy-db-*.docker"))


def test_cross_run_canary_receipt_is_rejected_and_output_is_rolled_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "candidate-output"
    fake, control, calls, _ = _fake_docker_runner(tmp_path)
    core = cli._candidate_core()

    def mixed_run(argv, *, timeout_seconds=cli.MAX_DOCKER_TIMEOUT_SECONDS):
        completed = fake(argv, timeout_seconds=timeout_seconds)
        if "canary" not in argv:
            return completed
        receipt = json.loads(completed.stdout)
        receipt.pop("receipt_sha256")
        receipt["invocation_id"] = "b" * 32
        return cli.CompletedDocker(
            core.canonical_json_bytes(core._seal_receipt(receipt)), b""
        )

    monkeypatch.setattr(cli, "run_docker", mixed_run)
    monkeypatch.setattr(cli, "run_docker_control", control)
    assert cli.main(_main_argv(tmp_path, output)) == 2
    assert [item for item in calls if item != "inspect"] == [
        "preflight",
        "fetch",
        "canary",
    ]
    assert capsys.readouterr().err.strip() == "cross_receipt_identity_mismatch"
    assert not output.exists()
    assert not any(tmp_path.glob(".kodesec-trivy-db-*.docker"))


def test_fetch_freshness_failure_after_extraction_rolls_back_all_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "candidate-output"
    fake, control, calls, _ = _fake_docker_runner(tmp_path)
    core = cli._candidate_core()

    def stale_fetch(argv, *, timeout_seconds=cli.MAX_DOCKER_TIMEOUT_SECONDS):
        completed = fake(argv, timeout_seconds=timeout_seconds)
        if "fetch" not in argv:
            return completed
        receipt = json.loads(completed.stdout)
        receipt.pop("receipt_sha256")
        receipt["metadata"]["observed_at"] = "2000-01-01T00:00:00Z"
        stale = core._seal_receipt(receipt)
        raw = core.canonical_json_bytes(stale)
        disk_receipt = output / "fetch-receipt.json"
        disk_receipt.chmod(0o600)
        disk_receipt.write_bytes(raw)
        disk_receipt.chmod(0o600)
        return cli.CompletedDocker(raw, b"")

    monkeypatch.setattr(cli, "run_docker", stale_fetch)
    monkeypatch.setattr(cli, "run_docker_control", control)
    assert cli.main(_main_argv(tmp_path, output)) == 2
    assert [item for item in calls if item != "inspect"] == ["preflight", "fetch"]
    assert capsys.readouterr().err.strip() == "fetch_receipt_invalid"
    assert not output.exists()
    assert not any(tmp_path.glob(".kodesec-trivy-db-*.docker"))


def test_canary_process_failure_rolls_back_fetched_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "candidate-output"
    fake, control, calls, _ = _fake_docker_runner(tmp_path)

    def failed_canary(argv, *, timeout_seconds=cli.MAX_DOCKER_TIMEOUT_SECONDS):
        completed = fake(argv, timeout_seconds=timeout_seconds)
        if "canary" in argv:
            raise cli.CandidateCliError("docker_status_failed")
        return completed

    monkeypatch.setattr(cli, "run_docker", failed_canary)
    monkeypatch.setattr(cli, "run_docker_control", control)
    assert cli.main(_main_argv(tmp_path, output)) == 2
    assert [item for item in calls if item != "inspect"] == [
        "preflight",
        "fetch",
        "canary",
    ]
    assert capsys.readouterr().err.strip() == "docker_status_failed"
    assert not output.exists()
    assert not any(tmp_path.glob(".kodesec-trivy-db-*.docker"))


def test_final_receipt_write_failure_rolls_back_all_sibling_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "candidate-output"
    fake, control, calls, _ = _fake_docker_runner(tmp_path)
    core = cli._candidate_core()

    def fail_final(*_args, **_kwargs):
        raise OSError("injected final publication failure")

    monkeypatch.setattr(cli, "run_docker", fake)
    monkeypatch.setattr(cli, "run_docker_control", control)
    monkeypatch.setattr(core, "write_private_receipt", fail_final)
    assert cli.main(_main_argv(tmp_path, output)) == 2
    assert [item for item in calls if item != "inspect"] == [
        "preflight",
        "fetch",
        "canary",
    ]
    assert capsys.readouterr().err.strip() == "final_receipt_publication_failed"
    assert not output.exists()
    assert not any(tmp_path.glob(".kodesec-trivy-db-*.docker"))


def test_container_cleanup_uncertainty_preserves_named_cidfile_forensics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "candidate-output"
    fake, base_control, calls, _ = _fake_docker_runner(tmp_path)
    fetch_lists = 0

    def uncertain_control(command, **kwargs):
        nonlocal fetch_lists
        rendered = tuple(command)
        if rendered[1:3] == ("container", "ls") and any(
            item.endswith("-fetch$") for item in rendered
        ):
            fetch_lists += 1
            if fetch_lists == 2:
                return cli.CompletedDocker((b"a" * 64) + b"\n", b"")
        return base_control(command, **kwargs)

    monkeypatch.setattr(cli, "run_docker", fake)
    monkeypatch.setattr(cli, "run_docker_control", uncertain_control)
    assert cli.main(_main_argv(tmp_path, output)) == 2
    assert [item for item in calls if item != "inspect"] == ["preflight", "fetch"]
    error = capsys.readouterr().err.strip()
    assert error.startswith("docker_lifecycle_directory_cleanup_uncertain:")
    lifecycle = Path(error.split(":", 1)[1])
    assert lifecycle.is_dir()
    assert [item.suffix for item in lifecycle.iterdir()] == [".cid"]
    assert not output.exists()


def test_late_daemon_publication_preserves_output_lifecycle_and_cid_forensics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "candidate-output"
    fake, base_control, calls, _ = _fake_docker_runner(tmp_path)
    fetch_absence_queries = 0
    delayed_container_name: str | None = None

    def uncertain_fetch(argv, *, timeout_seconds=cli.MAX_DOCKER_TIMEOUT_SECONDS):
        command = tuple(argv)
        if "fetch" not in command:
            return fake(command, timeout_seconds=timeout_seconds)
        calls.append("fetch")
        cidfile = Path(command[command.index("--cidfile") + 1])
        cidfile.write_bytes(b"e" * 64)
        raise cli.DockerProcessCleanupUncertain("docker_process_completion_uncertain")

    def late_publish_control(command, **kwargs):
        nonlocal fetch_absence_queries, delayed_container_name
        rendered = tuple(command)
        if rendered[1:3] == ("container", "ls") and any(
            item.endswith("-fetch$") for item in rendered
        ):
            fetch_absence_queries += 1
            if fetch_absence_queries == 2:
                # The cleanup query observes absence, but the daemon publishes
                # the fixed-name container immediately afterward.
                name_filter = next(
                    item for item in rendered if item.startswith("name=^/")
                )
                delayed_container_name = name_filter.removeprefix(
                    "name=^/"
                ).removesuffix("$")
                return cli.CompletedDocker(b"", b"")
            if fetch_absence_queries > 2:
                return cli.CompletedDocker((b"f" * 64) + b"\n", b"")
        return base_control(rendered, **kwargs)

    monkeypatch.setattr(cli, "run_docker", uncertain_fetch)
    monkeypatch.setattr(cli, "run_docker_control", late_publish_control)
    assert cli.main(_main_argv(tmp_path, output)) == 75
    error = capsys.readouterr().err.strip()
    assert error.startswith("docker_process_forensic_state_preserved:")
    lifecycle = Path(error.split(":", 1)[1])
    assert delayed_container_name is not None
    lifecycle_prefix = lifecycle.name.removeprefix(".").removesuffix(".docker")
    assert delayed_container_name == f"{lifecycle_prefix}-fetch"
    assert output.is_dir()
    assert not (output / "candidate-receipt.json").exists()
    assert lifecycle.is_dir()
    cidfiles = list(lifecycle.glob("*.cid"))
    assert len(cidfiles) == 1
    assert cidfiles[0].name == f"{delayed_container_name}.cid"
    assert cidfiles[0].read_bytes() == b"e" * 64
    # No third absence query may erase or overstate the late-publication race.
    assert fetch_absence_queries == 2


def test_output_cleanup_uncertainty_preserves_exact_forensic_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "candidate-output"
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    fake, control, calls, _ = _fake_docker_runner(tmp_path)

    def hostile_fetch(argv, *, timeout_seconds=cli.MAX_DOCKER_TIMEOUT_SECONDS):
        completed = fake(argv, timeout_seconds=timeout_seconds)
        if "fetch" in argv:
            (output / "hostile-link").symlink_to(outside, target_is_directory=True)
            raise cli.CandidateCliError("docker_status_failed")
        return completed

    monkeypatch.setattr(cli, "run_docker", hostile_fetch)
    monkeypatch.setattr(cli, "run_docker_control", control)
    assert cli.main(_main_argv(tmp_path, output)) == 2
    assert [item for item in calls if item != "inspect"] == ["preflight", "fetch"]
    assert capsys.readouterr().err.strip() == "output_cleanup_uncertain"
    assert output.is_dir()
    assert (output / "hostile-link").is_symlink()
    assert outside.is_dir()


def test_receipt_stdout_requires_one_exact_canonical_line() -> None:
    with pytest.raises(cli.CandidateCliError, match="stream_invalid"):
        cli._receipt_stdout(cli.CompletedDocker(b"{}\n\n", b""), label="test")
    with pytest.raises(cli.CandidateCliError, match="stream_invalid"):
        cli._receipt_stdout(cli.CompletedDocker(b"{}\n", b"warning"), label="test")


def test_inner_failure_marker_and_allowlists_are_mirrored_exactly() -> None:
    core = cli._candidate_core()
    assert core._INNER_FAILURE_MARKER.encode("ascii") == cli.INNER_FAILURE_MARKER
    assert core._INNER_FAILURE_CODES == cli.INNER_FAILURE_CODES


@pytest.mark.parametrize(
    ("mode", "validator"),
    [
        ("preflight", "validate_preflight_receipt"),
        ("fetch", "validate_fetch_receipt"),
        ("canary", "validate_canary_receipt"),
    ],
)
def test_real_inner_stdout_bridges_to_host_canonical_receipt_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
    mode: str,
    validator: str,
) -> None:
    core, preflight, fetch, canary, _ = _inner_receipts(tmp_path)
    receipt = {
        "preflight": preflight,
        "fetch": fetch,
        "canary": canary,
    }[mode]

    class Parser:
        @staticmethod
        def parse_args(_argv):
            return type("Arguments", (), {"mode": mode})()

    monkeypatch.setattr(core, "_inner_parser", lambda: Parser())
    monkeypatch.setattr(core, f"run_{mode}", lambda **_kwargs: receipt)
    # The mode-specific branch accesses arguments before calling its producer;
    # use a namespace whose missing attributes resolve to inert sentinels.
    Parser.parse_args = staticmethod(
        lambda _argv: type(
            "Arguments",
            (),
            {
                "mode": mode,
                "current_lock": Path("/run/kodesec-review/current-lock.json"),
                "baked_lock": Path(
                    "/usr/local/share/kodesec/locks/scanner-tools.lock.json"
                ),
                "trivy_path": Path("/usr/local/bin/trivy"),
                "tool_manifest": Path("/usr/local/share/kodesec/tool-manifest.json"),
                "positive_fixture": Path("/run/kodesec-review/positive"),
                "zero_fixture": Path("/run/kodesec-review/zero"),
                "expected_architecture": "arm64",
                "registry": "ghcr.io",
                "repository": "aquasecurity/trivy-db",
                "reference": "2",
                "output_dir": Path("/run/kodesec-review/output"),
                "candidate_db": Path("/run/kodesec-review/candidate-cache/db"),
                "invocation_id": INVOCATION_ID,
            },
        )()
    )
    assert core.inner_main([]) == 0
    captured = capsysbinary.readouterr()
    canonical = core.canonical_json_bytes(receipt)
    assert canonical.endswith(b"\n")
    assert b"\n" not in canonical[:-1]
    assert captured.out == canonical
    assert captured.err == b""
    bridged = cli._receipt_stdout(
        cli.CompletedDocker(captured.out, captured.err), label=mode
    )
    assert bridged == canonical
    validated = getattr(core, validator)(bridged)
    if mode == "fetch":
        assert validated[0]["receipt_sha256"] == receipt["receipt_sha256"]
    elif mode == "canary":
        assert validated[0]["receipt_sha256"] == receipt["receipt_sha256"]
    else:
        assert validated["receipt_sha256"] == receipt["receipt_sha256"]


def test_real_inner_failure_uses_only_stderr_and_cannot_bridge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    core, _, _, _, _ = _inner_receipts(tmp_path)

    class Parser:
        @staticmethod
        def parse_args(_argv):
            return type(
                "Arguments",
                (),
                {
                    "mode": "fetch",
                    "registry": "ghcr.io",
                    "repository": "aquasecurity/trivy-db",
                    "reference": "2",
                    "output_dir": Path("/run/kodesec-review/output"),
                    "invocation_id": INVOCATION_ID,
                },
            )()

    def fail_fetch(**_kwargs):
        raise core.CandidateValidationError("injected")

    monkeypatch.setattr(core, "_inner_parser", lambda: Parser())
    monkeypatch.setattr(core, "run_fetch", fail_fetch)
    assert core.inner_main([]) == 2
    captured = capsysbinary.readouterr()
    assert captured.out == b""
    assert captured.err == b"kodesec_candidate_failure/v1 fetch validation\n"
    with pytest.raises(cli.CandidateCliError, match="stream_invalid"):
        cli._receipt_stdout(
            cli.CompletedDocker(captured.out, captured.err), label="fetch"
        )


@pytest.mark.parametrize(
    "code", sorted(cli.INNER_FAILURE_CODES["preflight"] - {"unexpected"})
)
def test_real_inner_preflight_marker_contains_only_allowlisted_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
    code: str,
) -> None:
    core, _, _, _, _ = _inner_receipts(tmp_path)

    class Parser:
        @staticmethod
        def parse_args(_argv):
            return type("Arguments", (), {"mode": "preflight"})()

    def fail_preflight(**_kwargs):
        raise core._InnerFailure("preflight", code, "/private/secret detail")

    monkeypatch.setattr(core, "_inner_parser", lambda: Parser())
    monkeypatch.setattr(core, "run_preflight", fail_preflight)
    Parser.parse_args = staticmethod(
        lambda _argv: type(
            "Arguments",
            (),
            {
                "mode": "preflight",
                "current_lock": Path("ignored"),
                "baked_lock": Path("ignored"),
                "trivy_path": Path("ignored"),
                "tool_manifest": Path("ignored"),
                "positive_fixture": Path("ignored"),
                "zero_fixture": Path("ignored"),
                "expected_architecture": "arm64",
                "invocation_id": INVOCATION_ID,
            },
        )()
    )
    assert core.inner_main([]) == 2
    captured = capsysbinary.readouterr()
    assert captured.out == b""
    assert captured.err == f"kodesec_candidate_failure/v1 preflight {code}\n".encode()
    assert b"secret" not in captured.err


def test_real_inner_unclassified_oserror_is_unexpected_without_detail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    core, _, _, _, _ = _inner_receipts(tmp_path)

    class Parser:
        @staticmethod
        def parse_args(_argv):
            return type(
                "Arguments",
                (),
                {
                    "mode": "fetch",
                    "registry": "ghcr.io",
                    "repository": "aquasecurity/trivy-db",
                    "reference": "2",
                    "output_dir": Path("ignored"),
                    "invocation_id": INVOCATION_ID,
                },
            )()

    def fail_fetch(**_kwargs):
        raise OSError("/private/secret diagnostic")

    monkeypatch.setattr(core, "_inner_parser", lambda: Parser())
    monkeypatch.setattr(core, "run_fetch", fail_fetch)
    assert core.inner_main([]) == 2
    captured = capsysbinary.readouterr()
    assert captured.out == b""
    assert captured.err == b"kodesec_candidate_failure/v1 fetch unexpected\n"
    assert b"secret" not in captured.err


def test_real_inner_preflight_raw_oserror_is_unexpected_without_detail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    core, _, _, _, _ = _inner_receipts(tmp_path)

    class Parser:
        @staticmethod
        def parse_args(_argv):
            return type(
                "Arguments",
                (),
                {
                    "mode": "preflight",
                    "current_lock": Path("ignored"),
                    "baked_lock": Path("ignored"),
                    "trivy_path": Path("ignored"),
                    "tool_manifest": Path("ignored"),
                    "positive_fixture": Path("ignored"),
                    "zero_fixture": Path("ignored"),
                    "expected_architecture": "arm64",
                    "invocation_id": INVOCATION_ID,
                },
            )()

    def fail_preflight(**_kwargs):
        with core._inner_failure_phase("preflight", "current_lock"):
            raise OSError("/private/secret operational diagnostic")

    monkeypatch.setattr(core, "_inner_parser", lambda: Parser())
    monkeypatch.setattr(core, "run_preflight", fail_preflight)
    assert core.inner_main([]) == 2
    captured = capsysbinary.readouterr()
    assert captured.out == b""
    assert captured.err == b"kodesec_candidate_failure/v1 preflight unexpected\n"
    assert b"secret" not in captured.err


@pytest.mark.parametrize(
    "code", sorted(cli.INNER_FAILURE_CODES["canary"] - {"unexpected"})
)
def test_real_inner_canary_marker_contains_only_allowlisted_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
    code: str,
) -> None:
    core, _, _, _, _ = _inner_receipts(tmp_path)

    class Parser:
        @staticmethod
        def parse_args(_argv):
            return type(
                "Arguments",
                (),
                {
                    "mode": "canary",
                    "current_lock": Path("ignored"),
                    "candidate_db": Path("ignored"),
                    "positive_fixture": Path("ignored"),
                    "zero_fixture": Path("ignored"),
                    "invocation_id": INVOCATION_ID,
                },
            )()

    def fail_canary(**_kwargs):
        raise core._InnerFailure("canary", code, "/private/secret detail")

    monkeypatch.setattr(core, "_inner_parser", lambda: Parser())
    monkeypatch.setattr(core, "run_canary", fail_canary)
    assert core.inner_main([]) == 2
    captured = capsysbinary.readouterr()
    assert captured.out == b""
    assert captured.err == f"kodesec_candidate_failure/v1 canary {code}\n".encode()
    assert b"secret" not in captured.err


def test_real_inner_canary_raw_oserror_is_unexpected_without_detail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    core, _, _, _, _ = _inner_receipts(tmp_path)

    class Parser:
        @staticmethod
        def parse_args(_argv):
            return type(
                "Arguments",
                (),
                {
                    "mode": "canary",
                    "current_lock": Path("ignored"),
                    "candidate_db": Path("ignored"),
                    "positive_fixture": Path("ignored"),
                    "zero_fixture": Path("ignored"),
                    "invocation_id": INVOCATION_ID,
                },
            )()

    def fail_canary(**_kwargs):
        with core._inner_failure_phase("canary", "output"):
            raise OSError("/private/secret operational diagnostic")

    monkeypatch.setattr(core, "_inner_parser", lambda: Parser())
    monkeypatch.setattr(core, "run_canary", fail_canary)
    assert core.inner_main([]) == 2
    captured = capsysbinary.readouterr()
    assert captured.out == b""
    assert captured.err == b"kodesec_candidate_failure/v1 canary unexpected\n"
    assert b"secret" not in captured.err


def test_build_receipt_rejects_forgery_duplicate_json_and_replay(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    identity = cli.require_host_identity()

    forged_root = tmp_path / "forged"
    forged_root.mkdir(mode=0o700)
    forged_root.chmod(0o700)
    forged = _build_receipt(forged_root)
    value = json.loads(forged.read_bytes())
    value["image"]["architecture"] = (
        "arm64" if cli.BUILD_ARCHITECTURE == "amd64" else "amd64"
    )
    forged.write_bytes(cli._canonical_json_bytes(value))
    forged.chmod(0o600)
    with pytest.raises(cli.CandidateCliError, match="identity_invalid"):
        cli.validate_build_receipt(forged, identity=identity)

    duplicate_root = tmp_path / "duplicate"
    duplicate_root.mkdir(mode=0o700)
    duplicate_root.chmod(0o700)
    duplicate = _build_receipt(duplicate_root)
    raw = duplicate.read_bytes()
    duplicate.write_bytes(b'{"schema":"forged",' + raw[1:])
    duplicate.chmod(0o600)
    with pytest.raises(cli.CandidateCliError, match="duplicate_key"):
        cli.validate_build_receipt(duplicate, identity=identity)

    source_root = tmp_path / "source"
    source_root.mkdir(mode=0o700)
    source_root.chmod(0o700)
    source = _build_receipt(source_root)
    replay_parent = tmp_path / "replay" / "build-receipt"
    replay_parent.mkdir(mode=0o700, parents=True)
    replay_parent.parent.chmod(0o700)
    replay_parent.chmod(0o700)
    (replay_parent / ".docker-runtime").mkdir(mode=0o700)
    replay = replay_parent / cli.BUILD_RECEIPT_NAME
    replay.write_bytes(source.read_bytes())
    replay.chmod(0o600)
    with pytest.raises(cli.CandidateCliError, match="invocation_mismatch"):
        cli.validate_build_receipt(replay, identity=identity)


def test_build_receipt_accepts_reviewed_native_linux_amd64_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = cli.scanner_review_build_target("Linux", "x86_64")
    monkeypatch.setattr(cli, "REVIEW_TARGET", target)
    monkeypatch.setattr(cli, "BUILD_PLATFORM", target.image_platform)
    monkeypatch.setattr(cli, "BUILD_ARCHITECTURE", target.image_architecture)
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli.platform, "machine", lambda: "x86_64")
    tmp_path.chmod(0o700)

    path = _build_receipt(tmp_path)

    receipt = cli.validate_build_receipt(path, identity=cli.require_host_identity())
    assert receipt["host_execution_identity"] == {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "system": "Linux",
        "machine": "amd64",
    }
    assert receipt["build"]["platform"] == "linux/amd64"
    assert receipt["image"]["architecture"] == "amd64"


def test_build_receipt_rejects_resealed_staged_context_drift(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = _build_receipt(tmp_path)
    receipt = json.loads(path.read_bytes())
    receipt["staged_context"]["files"][0]["sha256"] = "f" * 64
    receipt.pop("receipt_sha256")
    receipt["receipt_sha256"] = hashlib.sha256(
        cli._canonical_json_bytes(receipt)
    ).hexdigest()
    path.write_bytes(cli._canonical_json_bytes(receipt))
    path.chmod(0o600)
    with pytest.raises(cli.CandidateCliError, match="staged_context_invalid"):
        cli.validate_build_receipt(path, identity=cli.require_host_identity())


def test_built_image_rejects_foreign_digest_and_extra_tag(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = _build_receipt(tmp_path)
    receipt = json.loads(path.read_bytes())
    tag = receipt["build"]["tag"]
    base = {
        "Id": IMAGE_ID,
        "Os": "linux",
        "Architecture": cli.BUILD_ARCHITECTURE,
        "RepoTags": [tag],
        "RepoDigests": [],
        "Config": _build_security_config(),
    }
    for key, value in (
        ("RepoTags", [tag, "foreign:alias"]),
        ("RepoDigests", ["foreign@example.invalid:sha256:" + "f" * 64]),
    ):
        hostile = dict(base)
        hostile[key] = value
        with pytest.raises(cli.CandidateCliError, match="identity_mismatch"):
            cli.parse_built_image_inspect(json.dumps(hostile).encode(), receipt=receipt)


def test_built_image_accepts_exact_local_repo_digest(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    receipt = json.loads(_build_receipt(tmp_path).read_bytes())
    observed = {
        "Id": IMAGE_ID,
        "Os": "linux",
        "Architecture": cli.BUILD_ARCHITECTURE,
        "RepoTags": [receipt["build"]["tag"]],
        "RepoDigests": [f"lomo-kodesec-scanner@{IMAGE_ID}"],
        "Config": _build_security_config(),
    }

    assert (
        cli.parse_built_image_inspect(json.dumps(observed).encode(), receipt=receipt)
        == receipt["image"]
    )
    cli._parse_cleanup_build_image(
        cli.CompletedDocker(json.dumps(observed).encode(), b""),
        receipt=receipt,
        allow_untagged=False,
    )
    untagged = dict(observed)
    untagged["RepoTags"] = []
    cli._parse_cleanup_build_image(
        cli.CompletedDocker(json.dumps(untagged).encode(), b""),
        receipt=receipt,
        allow_untagged=True,
    )


@pytest.mark.parametrize("volumes", [None, {}])
def test_built_image_accepts_docker_omitted_nullable_config_fields(
    tmp_path: Path, volumes: object
) -> None:
    tmp_path.chmod(0o700)
    receipt = json.loads(_build_receipt(tmp_path).read_bytes())
    config = _build_security_config()
    del config["Entrypoint"]
    if volumes is None:
        del config["Volumes"]
    else:
        config["Volumes"] = volumes
    observed = {
        "Id": IMAGE_ID,
        "Os": "linux",
        "Architecture": cli.BUILD_ARCHITECTURE,
        "RepoTags": [receipt["build"]["tag"]],
        "RepoDigests": [],
        "Config": config,
    }

    assert (
        cli.parse_built_image_inspect(json.dumps(observed).encode(), receipt=receipt)
        == receipt["image"]
    )

    cli._parse_cleanup_build_image(
        cli.CompletedDocker(json.dumps(observed).encode(), b""),
        receipt=receipt,
        allow_untagged=False,
    )


@pytest.mark.parametrize("field", ["Cmd", "User", "WorkingDir", "Env", "Labels"])
def test_built_image_rejects_omitted_nonnullable_config_fields(
    tmp_path: Path, field: str
) -> None:
    tmp_path.chmod(0o700)
    receipt = json.loads(_build_receipt(tmp_path).read_bytes())
    config = _build_security_config()
    del config[field]
    observed = {
        "Id": IMAGE_ID,
        "Os": "linux",
        "Architecture": cli.BUILD_ARCHITECTURE,
        "RepoTags": [receipt["build"]["tag"]],
        "RepoDigests": [],
        "Config": config,
    }

    with pytest.raises(cli.CandidateCliError, match="security_config_invalid"):
        cli.parse_built_image_inspect(json.dumps(observed).encode(), receipt=receipt)
    with pytest.raises(cli.CandidateCliError, match="security_config_invalid"):
        cli._parse_cleanup_build_image(
            cli.CompletedDocker(json.dumps(observed).encode(), b""),
            receipt=receipt,
            allow_untagged=False,
        )


def test_build_security_config_receipt_exactness_and_raw_unsafe_fields() -> None:
    receipt_config = _build_security_config()
    for field in ("Entrypoint", "Volumes"):
        incomplete = dict(receipt_config)
        del incomplete[field]
        with pytest.raises(cli.CandidateCliError, match="security_config_invalid"):
            cli._normalize_build_security_config(
                incomplete,
                invocation_id=BUILD_INVOCATION_ID,
                provenance=PROVENANCE,
                exact=True,
            )

    for field, hostile in (("Entrypoint", ["/bin/sh"]), ("Volumes", {"/unsafe": {}})):
        config = dict(receipt_config)
        config[field] = hostile
        with pytest.raises(cli.CandidateCliError, match="security_config_invalid"):
            cli._normalize_build_security_config(
                config,
                invocation_id=BUILD_INVOCATION_ID,
                provenance=PROVENANCE,
                exact=False,
            )


def test_source_drift_after_preflight_aborts_before_candidate_egress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tmp_path.chmod(0o700)
    build_receipt = _build_receipt(tmp_path)
    output = tmp_path / "candidate-output"
    fake, control, calls, _ = _fake_docker_runner(tmp_path)
    original_collect = cli._collect_build_inputs
    count = 0

    def drifting_collect(*, identity):
        nonlocal count
        count += 1
        manifest = original_collect(identity=identity)
        if count >= 3:
            manifest = dict(manifest)
            manifest["sha256"] = "f" * 64
        return manifest

    monkeypatch.setattr(cli, "run_docker", fake)
    monkeypatch.setattr(cli, "run_docker_control", control)
    monkeypatch.setattr(cli, "_collect_build_inputs", drifting_collect)
    assert (
        cli.main(
            [
                "--build-receipt",
                str(build_receipt),
                "--output-dir",
                str(output),
            ]
        )
        == 2
    )
    assert [item for item in calls if item != "inspect"] == ["preflight"]
    assert capsys.readouterr().err.strip() == (
        "build_source_binding_changed_before_egress"
    )
    assert not output.exists()


def test_candidate_commit_occurs_only_after_image_cleanup_proofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "candidate-output"
    fake, control, _, lifecycle_calls = _fake_docker_runner(tmp_path)
    core = cli._candidate_core()
    original_publish = core.write_private_receipt
    checked = False

    def checked_publish(path, receipt):
        nonlocal checked
        assert not path.exists()
        image_events = [
            command[1:3]
            for command in lifecycle_calls
            if command[1:3] in {("image", "ls"), ("image", "rm")}
        ]
        remove_index = image_events.index(("image", "rm"))
        assert image_events[remove_index + 1 :] == [("image", "ls")] * 9
        checked = True
        original_publish(path, receipt)

    monkeypatch.setattr(cli, "run_docker", fake)
    monkeypatch.setattr(cli, "run_docker_control", control)
    monkeypatch.setattr(core, "write_private_receipt", checked_publish)
    assert cli.main(_main_argv(tmp_path, output)) == 0
    assert checked is True
    assert (output / "candidate-receipt.json").is_file()


def test_late_iid_reappearance_blocks_commit_and_removes_candidate_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "candidate-output"
    fake, base_control, _, _ = _fake_docker_runner(tmp_path)
    removed = False

    def reappearing_id_control(argv, **kwargs):
        nonlocal removed
        command = tuple(argv)
        completed = base_control(command, **kwargs)
        if command[1:3] == ("image", "rm"):
            removed = True
        if (
            removed
            and command[1:3] == ("image", "ls")
            and not any(item.startswith("--filter=") for item in command)
        ):
            return cli.CompletedDocker((IMAGE_ID + "\n").encode(), b"")
        return completed

    monkeypatch.setattr(cli, "run_docker", fake)
    monkeypatch.setattr(cli, "run_docker_control", reappearing_id_control)
    assert cli.main(_main_argv(tmp_path, output)) == 2
    assert capsys.readouterr().err.strip() == "build_tag_cleanup_uncertain"
    assert not output.exists()


def test_candidate_cleanup_interrupt_retries_reconciliation_and_never_commits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    build_receipt = _build_receipt(tmp_path)
    output = tmp_path / "candidate-output"
    fake, control, _, _ = _fake_docker_runner(tmp_path)
    original_cleanup = cli._cleanup_owned_build_image
    attempts = 0

    def interrupted_once(*, receipt):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise KeyboardInterrupt("injected cleanup interrupt")
        return original_cleanup(receipt=receipt)

    monkeypatch.setattr(cli, "run_docker", fake)
    monkeypatch.setattr(cli, "run_docker_control", control)
    monkeypatch.setattr(cli, "_cleanup_owned_build_image", interrupted_once)
    with pytest.raises(KeyboardInterrupt, match="cleanup interrupt"):
        cli.orchestrate(
            build_receipt,
            output,
            identity=cli.require_host_identity(),
        )
    assert attempts == 2
    assert not output.exists()


def test_missing_candidate_core_does_not_consume_build_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    touched: list[str] = []

    def unavailable():
        raise cli.CandidateCliError("candidate_core_unavailable")

    monkeypatch.setattr(cli, "_candidate_core", unavailable)
    monkeypatch.setattr(
        cli,
        "validate_build_receipt",
        lambda *_args, **_kwargs: touched.append("validated"),
    )
    monkeypatch.setattr(
        cli,
        "_activate_build_runtime",
        lambda *_args, **_kwargs: touched.append("activated"),
    )

    with pytest.raises(cli.CandidateCliError, match="candidate_core_unavailable"):
        cli.orchestrate(
            tmp_path / "not-read-build-receipt.json",
            tmp_path / "not-created-output",
            identity=cli.require_host_identity(),
        )

    assert touched == []
    assert not (tmp_path / "not-created-output").exists()
