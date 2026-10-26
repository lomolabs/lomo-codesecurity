from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/scanner-build-receipt.py"
IMAGE_ID = "sha256:" + "1" * 64


def _load_builder():
    spec = importlib.util.spec_from_file_location("scanner_build_receipt", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


builder = _load_builder()
PROVENANCE = builder.SourceProvenance(commit="a" * 40, tree="b" * 40)


def test_review_build_targets_are_native_and_closed() -> None:
    assert builder.scanner_review_build_target("Darwin", "arm64") == (
        builder.ScannerReviewBuildTarget("Darwin", "arm64", "linux/arm64", "arm64")
    )
    assert builder.scanner_review_build_target("Linux", "x86_64") == (
        builder.ScannerReviewBuildTarget("Linux", "amd64", "linux/amd64", "amd64")
    )
    with pytest.raises(builder.DockerRuntimeContractError, match="host_unsupported"):
        builder.scanner_review_build_target("Linux", "aarch64")
    with pytest.raises(builder.DockerRuntimeContractError, match="host_unsupported"):
        builder.scanner_review_build_target("Windows", "AMD64")


def test_owned_local_repo_digest_is_exact_and_closed() -> None:
    tag = "lomo-kodesec-scanner:trivy-review-" + "a" * 32
    exact = [f"lomo-kodesec-scanner@{IMAGE_ID}"]
    assert builder.owned_local_repo_digests(tag, IMAGE_ID, exact)
    assert not builder.owned_local_repo_digests(tag, IMAGE_ID, exact + exact)
    assert not builder.owned_local_repo_digests(
        tag, IMAGE_ID, exact + [f"foreign@{IMAGE_ID}"]
    )
    assert not builder.owned_local_repo_digests(tag, IMAGE_ID, [f"foreign@{IMAGE_ID}"])
    assert not builder.owned_local_repo_digests(tag, IMAGE_ID, exact[0])
    assert not builder.owned_local_repo_digests(
        "foreign:trivy-review-" + "a" * 32, IMAGE_ID, [f"foreign@{IMAGE_ID}"]
    )
    assert not builder.owned_local_repo_digests(
        tag, IMAGE_ID, ["lomo-kodesec-scanner@sha256:" + "f" * 64]
    )


def test_unsupported_host_imports_safely_and_fails_at_producer_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(builder.platform, "system", lambda: "Windows")
    monkeypatch.setattr(builder.platform, "machine", lambda: "AMD64")
    spec = importlib.util.spec_from_file_location("scanner_build_receipt_unsupported", SCRIPT)
    assert spec is not None and spec.loader is not None
    unsupported = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = unsupported
    spec.loader.exec_module(unsupported)

    assert unsupported.REVIEW_TARGET is None
    with pytest.raises(unsupported.BuildReceiptError, match="host_unsupported"):
        unsupported.require_review_build_host()
    with pytest.raises(unsupported.BuildReceiptError, match="host_unsupported"):
        unsupported.produce(
            Path("/not-read/output"),
            Path("/not-read/runtime-receipt.json"),
            identity=unsupported.require_host_identity(),
        )


def _private_parent(tmp_path: Path) -> Path:
    tmp_path.chmod(0o700)
    return tmp_path


def _image_inspect(
    tag: str, *, image_id: str = IMAGE_ID, repo_digests: object = None
) -> bytes:
    return json.dumps(
        {
            "Id": image_id,
            "Os": "linux",
            "Architecture": builder.ARCHITECTURE,
            "RepoTags": [tag],
            "RepoDigests": [] if repo_digests is None else repo_digests,
            "Config": {
                "Entrypoint": None,
                "Cmd": list(builder.EXPECTED_CMD),
                "User": "kodesec",
                "WorkingDir": "/app",
                "Volumes": None,
                "Labels": {
                    builder.OWNERSHIP_LABEL_KEY: tag.rsplit("-", 1)[1],
                    **PROVENANCE.labels("scanner"),
                },
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
            },
        },
        separators=(",", ":"),
    ).encode()


def _fake_docker(tmp_path: Path):
    calls: list[tuple[str, ...]] = []
    present: set[str] = set()

    def run(
        argv,
        *,
        timeout_seconds=builder.MAX_BUILD_SECONDS,
        pre_spawn_check=None,
    ):
        if pre_spawn_check is not None:
            pre_spawn_check()
        command = tuple(argv)
        calls.append(command)
        if command[1:3] == ("image", "ls"):
            reference_filters = [
                item for item in command if item.startswith("--filter=reference=")
            ]
            if reference_filters:
                tag = reference_filters[0].split("reference=", 1)[1]
                if tag in present:
                    return builder.CompletedDocker(f"{tag}|{IMAGE_ID}\n".encode(), b"")
                return builder.CompletedDocker(b"", b"")
            label_filters = [
                item for item in command if item.startswith("--filter=label=")
            ]
            if label_filters:
                assert len(label_filters) == 1
                if present:
                    return builder.CompletedDocker((IMAGE_ID + "\n").encode(), b"")
                return builder.CompletedDocker(b"", b"")
            assert command[-1] == "--format={{.ID}}"
            if present:
                return builder.CompletedDocker((IMAGE_ID + "\n").encode(), b"")
            return builder.CompletedDocker(b"", b"")
        if command[1] == "build":
            tag = next(
                item.split("=", 1)[1] for item in command if item.startswith("--tag=")
            )
            iidfile = Path(
                next(
                    item.split("=", 1)[1]
                    for item in command
                    if item.startswith("--iidfile=")
                )
            )
            iidfile.write_text(IMAGE_ID + "\n")
            iidfile.chmod(0o600)
            present.add(tag)
            return builder.CompletedDocker(b"build\n", b"")
        if command[1:3] == ("image", "inspect"):
            reference = command[-1]
            assert reference == IMAGE_ID or reference in present
            tag = next(iter(present))
            return builder.CompletedDocker(_image_inspect(tag), b"")
        if command[1:3] == ("image", "rm"):
            if command[-1] == IMAGE_ID:
                present.clear()
            else:
                present.discard(command[-1])
            return builder.CompletedDocker((command[-1] + "\n").encode(), b"")
        raise AssertionError(command)

    return run, calls, present


def _authorize_fake_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    class Runtime:
        root = tmp_path

        @staticmethod
        def environment():
            return {"PATH": "/usr/bin:/bin"}

        @staticmethod
        def record():
            return {"schema": "kodesec.docker-runtime-execution/v1"}

    runtime = Runtime()
    builder._ACTIVE_RUNTIME = runtime

    def prepare(_path, _output, *, identity):
        del identity
        builder._ACTIVE_RUNTIME = runtime
        return (
            runtime,
            {
                "observation": {
                    "schema": "kodesec.docker-runtime-observation/v1",
                    "sha256": "9" * 64,
                }
            },
            {
                "path": str(tmp_path / "observation.json"),
                "sha256": "8" * 64,
                "receipt_sha256": "7" * 64,
            },
        )

    monkeypatch.setattr(builder, "_prepare_authorized_runtime", prepare)
    monkeypatch.setattr(builder, "remove_runtime", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        builder,
        "resolve_source_provenance",
        lambda *_args, **_kwargs: PROVENANCE,
    )
    return tmp_path / "observation.json"


def test_exact_build_argv_is_fixed_and_uses_private_iidfile(tmp_path: Path) -> None:
    iidfile = _private_parent(tmp_path) / "image.iid"
    context = tmp_path / builder.STAGED_CONTEXT_NAME
    invocation = "a" * 32
    tag = f"lomo-kodesec-scanner:trivy-review-{invocation}"
    argv = builder.build_argv(
        tag=tag,
        iidfile=iidfile,
        context_dir=context,
        provenance=PROVENANCE,
    )
    assert argv[:12] == (
        "buildx",
        "build",
        "--builder=default",
        "--load",
        "--pull",
        "--no-cache",
        "--network=default",
        f"--platform={builder.PLATFORM}",
        f"--file={context / builder.DOCKERFILE_PATH}",
        f"--tag={tag}",
        f"--iidfile={iidfile}",
        f"--label={builder.OWNERSHIP_LABEL_KEY}={invocation}",
    )
    assert argv[12:-1] == tuple(
        f"--build-arg={name}={value}"
        for name, value in (*PROVENANCE.build_args(), *builder.BUILD_ARGS)
    )
    assert argv[-1] == str(context)
    assert f"--file={builder.REPO_ROOT / builder.DOCKERFILE_PATH}" not in argv
    with pytest.raises(builder.BuildReceiptError):
        builder.build_argv(
            tag="lomo-kodesec-scanner:latest",
            iidfile=iidfile,
            context_dir=context,
            provenance=PROVENANCE,
        )


def test_build_input_manifest_binds_exact_reviewed_inventory() -> None:
    evidence = builder.collect_build_inputs(identity=builder.require_host_identity())
    assert evidence["file_count"] == len(builder.BUILD_INPUT_FILES)
    assert evidence["size_bytes"] > 0
    assert [item["path"] for item in evidence["files"]] == list(
        builder.BUILD_INPUT_FILES
    )
    assert {item["path"] for item in evidence["files"]}.issuperset(
        {
            "scripts/scanner-build-receipt.py",
            ".dockerignore",
            "services/scanner/Dockerfile",
            "scanner-tools.lock.json",
            "scanner-rules.lock.json",
            "services/scanner/kodesec_scanner/data_catalog.py",
            "services/scanner/kodesec_scanner/grype_identity.py",
            "services/scanner/kodesec_scanner/release_signature.py",
            "services/scanner/kodesec_scanner/runtime_cache.py",
        }
    )
    assert all(item["mode"] in {"0644", "0755"} for item in evidence["files"])
    assert builder.SHA256.fullmatch(evidence["sha256"])
    assert builder.SHA256.fullmatch(evidence["identity_sha256"])


def test_reviewed_copy_inventory_matches_repository_tree() -> None:
    builder._validate_inventory()


def test_review_dockerfile_accepts_typed_source_args_but_not_extra_args() -> None:
    payload = (ROOT / builder.DOCKERFILE_PATH).read_bytes()
    builder._validate_dockerfile(payload)
    assert b"ARG KODESEC_SOURCE_KIND=git\n" in payload
    assert b"ARG KODESEC_SOURCE_DIGEST=\n" in payload
    for modified in (
        payload.replace(b"ARG KODESEC_SOURCE_KIND=git", b"ARG KODESEC_SOURCE_KIND=source-sha256"),
        payload.replace(b"ARG KODESEC_SOURCE_DIGEST=\n", b"ARG KODESEC_SOURCE_DIGEST=arbitrary\n"),
        payload + b"\nARG UNREVIEWED_SOURCE_IDENTITY\n",
    ):
        with pytest.raises(builder.BuildReceiptError, match="dockerfile_build_args_changed"):
            builder._validate_dockerfile(modified)


def test_review_producer_refuses_snapshot_before_runtime_or_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = builder.require_host_identity()
    monkeypatch.setattr(builder, "require_review_build_host", lambda: object())
    monkeypatch.setattr(builder, "_require_repo_root", lambda _identity: None)
    monkeypatch.setattr(builder, "resolve_source_provenance",
                        lambda *_args, **_kwargs: builder.SourceProvenance.snapshot("6" * 64))
    monkeypatch.setattr(builder, "_prepare_authorized_runtime",
                        lambda *_args, **_kwargs: pytest.fail("snapshot must not prepare a build runtime"))
    monkeypatch.setattr(builder, "run_docker",
                        lambda *_args, **_kwargs: pytest.fail("snapshot must not invoke Docker"))
    output = tmp_path / "review-build"
    with pytest.raises(builder.BuildReceiptError, match="review_build_requires_git_source"):
        builder.produce(output, tmp_path / "unused-observation.json", identity=identity)
    assert not output.exists()


def test_copy_inventory_rejects_unexpected_special_and_writable_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    expected = source / "expected.py"
    expected.write_text("pass\n")
    expected.chmod(0o600)
    monkeypatch.setattr(builder, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(builder, "COPY_ROOTS", ("source",))
    monkeypatch.setattr(builder, "COPY_FILES", ("source/expected.py",))
    monkeypatch.setattr(builder, "COPY_SINGLE_FILES", ())
    builder._validate_inventory()

    unexpected = source / "unexpected.py"
    unexpected.write_text("pass\n")
    with pytest.raises(builder.BuildReceiptError, match="unexpected"):
        builder._validate_inventory()
    unexpected.unlink()

    alias = source / "alias.py"
    alias.symlink_to(expected)
    with pytest.raises(builder.BuildReceiptError, match="special"):
        builder._validate_inventory()
    alias.unlink()

    directory = source / "nested"
    directory.mkdir(mode=0o777)
    directory.chmod(0o777)
    with pytest.raises(builder.BuildReceiptError, match="writable"):
        builder._validate_inventory()


def test_stable_file_rejects_hardlink_and_detects_same_fd_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = builder.require_host_identity()
    path = tmp_path / "input"
    path.write_bytes(b"input")
    path.chmod(0o600)
    alias = tmp_path / "alias"
    os.link(path, alias)
    with pytest.raises(builder.BuildReceiptError, match="unsafe"):
        builder._stable_file(path, relative="input", identity=identity)
    alias.unlink()

    original_read = builder.os.read
    changed = False

    def mutate_after_read(descriptor: int, count: int) -> bytes:
        nonlocal changed
        chunk = original_read(descriptor, count)
        if chunk and not changed:
            changed = True
            path.chmod(0o400)
        return chunk

    monkeypatch.setattr(builder.os, "read", mutate_after_read)
    with pytest.raises(builder.BuildReceiptError, match="changed"):
        builder._stable_file(path, relative="input", identity=identity)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"Os": "darwin"}, "identity"),
        (
            {"Architecture": "arm64" if builder.ARCHITECTURE == "amd64" else "amd64"},
            "identity",
        ),
        ({"RepoTags": ["lomo-kodesec-scanner:other"]}, "identity"),
        ({"Config": {"User": "root"}}, "security"),
    ],
)
def test_inspect_rejects_wrong_platform_alias_and_security_config(
    change: dict[str, object], message: str
) -> None:
    tag = "lomo-kodesec-scanner:trivy-review-" + "a" * 32
    value = json.loads(_image_inspect(tag))
    value.update(change)
    with pytest.raises(builder.BuildReceiptError, match=message):
        builder.parse_image_inspect(
            json.dumps(value).encode(),
            tag=tag,
            expected_id=IMAGE_ID,
            provenance=PROVENANCE,
        )


def test_inspect_rejects_duplicate_json_and_environment_keys() -> None:
    tag = "lomo-kodesec-scanner:trivy-review-" + "a" * 32
    duplicate = b'{"Id":"' + IMAGE_ID.encode() + b'","Id":"' + IMAGE_ID.encode() + b'"}'
    with pytest.raises(builder.BuildReceiptError, match="duplicate"):
        builder.parse_image_inspect(
            duplicate,
            tag=tag,
            expected_id=IMAGE_ID,
            provenance=PROVENANCE,
        )

    value = json.loads(_image_inspect(tag))
    value["Config"]["Env"].append("PATH=/hostile")
    with pytest.raises(builder.BuildReceiptError, match="environment"):
        builder.parse_image_inspect(
            json.dumps(value).encode(),
            tag=tag,
            expected_id=IMAGE_ID,
            provenance=PROVENANCE,
        )


@pytest.mark.parametrize("volumes", [None, {}])
def test_inspect_normalizes_docker_omitted_nullable_config_fields(
    volumes: object,
) -> None:
    tag = "lomo-kodesec-scanner:trivy-review-" + "a" * 32
    value = json.loads(_image_inspect(tag))
    del value["Config"]["Entrypoint"]
    if volumes is None:
        del value["Config"]["Volumes"]
    else:
        value["Config"]["Volumes"] = volumes

    image = builder.parse_image_inspect(
        json.dumps(value).encode(),
        tag=tag,
        expected_id=IMAGE_ID,
        provenance=PROVENANCE,
    )

    assert image["security_config"]["Entrypoint"] is None
    assert image["security_config"]["Volumes"] is None


@pytest.mark.parametrize("field", ["Cmd", "User", "WorkingDir", "Env", "Labels"])
def test_inspect_rejects_omitted_nonnullable_config_fields(field: str) -> None:
    tag = "lomo-kodesec-scanner:trivy-review-" + "a" * 32
    value = json.loads(_image_inspect(tag))
    del value["Config"][field]

    with pytest.raises(builder.BuildReceiptError, match="security_config_invalid"):
        builder.parse_image_inspect(
            json.dumps(value).encode(),
            tag=tag,
            expected_id=IMAGE_ID,
            provenance=PROVENANCE,
        )


def test_producer_emits_canonical_private_receipt_and_holds_only_owned_tag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _private_parent(tmp_path)
    output = tmp_path / "build"
    fake, calls, present = _fake_docker(tmp_path)
    observation = _authorize_fake_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(builder, "run_docker", fake)
    monkeypatch.setattr(builder, "require_review_build_host", lambda: builder.REVIEW_TARGET)
    monkeypatch.setattr(builder.secrets, "token_hex", lambda _: "a" * 32)
    receipt_path = builder.produce(
        output, observation, identity=builder.require_host_identity()
    )
    assert receipt_path == output / "scanner-build-receipt.json"
    metadata = receipt_path.lstat()
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1
    assert metadata.st_uid == os.getuid()
    raw = receipt_path.read_bytes()
    receipt = json.loads(raw)
    assert raw == builder.canonical_json_bytes(receipt)
    unsigned = dict(receipt)
    claimed = unsigned.pop("receipt_sha256")
    assert claimed == hashlib.sha256(builder.canonical_json_bytes(unsigned)).hexdigest()
    assert receipt["inputs_before"] == receipt["inputs_after"]
    assert receipt["build"]["source"] == {
        "commit": PROVENANCE.commit,
        "tree": PROVENANCE.tree,
        "build_identity": PROVENANCE.labels("scanner")[builder.BUILD_IDENTITY_LABEL],
    }
    assert receipt["build"]["args"] == [
        {"name": name, "value": value}
        for name, value in (*PROVENANCE.build_args(), *builder.BUILD_ARGS)
    ]
    assert receipt["build"]["argv"] == list(
        builder.build_argv(
            tag=receipt["build"]["tag"],
            iidfile=output / ".scanner-build.iid",
            context_dir=output / builder.STAGED_CONTEXT_NAME,
            provenance=PROVENANCE,
        )
    )
    assert receipt["producer"]["sha256"] == next(
        item["sha256"]
        for item in receipt["inputs_before"]["files"]
        if item["path"] == builder.PRODUCER_RELATIVE_PATH
    )
    tag = receipt["build"]["tag"]
    assert present == {tag}
    assert not (output / ".scanner-build.iid").exists()
    assert [call[1] for call in calls].count("build") == 1
    assert set(item.name for item in output.iterdir()) == {"scanner-build-receipt.json"}


def test_build_failure_cleans_partial_owned_tag_iidfile_and_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _private_parent(tmp_path)
    output = tmp_path / "build"
    fake, calls, present = _fake_docker(tmp_path)
    observation = _authorize_fake_runtime(monkeypatch, tmp_path)

    def fail_after_build(
        argv,
        *,
        timeout_seconds=builder.MAX_BUILD_SECONDS,
        pre_spawn_check=None,
    ):
        completed = fake(
            argv,
            timeout_seconds=timeout_seconds,
            pre_spawn_check=pre_spawn_check,
        )
        if tuple(argv)[1] == "build":
            raise builder.BuildReceiptError("injected_build_failure")
        return completed

    monkeypatch.setattr(builder, "run_docker", fail_after_build)
    monkeypatch.setattr(builder, "require_review_build_host", lambda: builder.REVIEW_TARGET)
    monkeypatch.setattr(builder.secrets, "token_hex", lambda _: "b" * 32)
    with pytest.raises(builder.BuildReceiptError, match="injected"):
        builder.produce(output, observation, identity=builder.require_host_identity())
    assert not output.exists()
    assert present == set()
    assert any(command[1:3] == ("image", "rm") for command in calls)


def test_post_build_source_drift_cleans_owned_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _private_parent(tmp_path)
    output = tmp_path / "build"
    fake, _, present = _fake_docker(tmp_path)
    observation = _authorize_fake_runtime(monkeypatch, tmp_path)
    original_collect = builder.collect_build_inputs
    calls = 0

    def drifting_collect(*, identity):
        nonlocal calls
        calls += 1
        evidence = original_collect(identity=identity)
        if calls == 1:
            evidence = dict(evidence)
            evidence["identity_sha256"] = "f" * 64
        return evidence

    monkeypatch.setattr(builder, "run_docker", fake)
    monkeypatch.setattr(builder, "collect_build_inputs", drifting_collect)
    monkeypatch.setattr(builder, "require_review_build_host", lambda: builder.REVIEW_TARGET)
    with pytest.raises(builder.BuildReceiptError, match="changed_during_build"):
        builder.produce(output, observation, identity=builder.require_host_identity())
    assert present == set()
    assert not output.exists()


def test_output_validation_rejects_public_parent_and_unsupported_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    with pytest.raises(builder.BuildReceiptError, match="not_private"):
        builder.require_new_private_output(
            public / "build", identity=builder.require_host_identity()
        )
    monkeypatch.setattr(builder.platform, "system", lambda: "FreeBSD")
    monkeypatch.setattr(builder.platform, "machine", lambda: "arm64")
    with pytest.raises(builder.BuildReceiptError, match="host_unsupported"):
        builder.require_review_build_host()


def test_iidfile_refuses_symlink_hardlink_and_partial_payload(tmp_path: Path) -> None:
    identity = builder.require_host_identity()
    target = tmp_path / "target"
    target.write_text(IMAGE_ID)
    target.chmod(0o600)
    alias = tmp_path / "iid"
    alias.symlink_to(target)
    with pytest.raises(builder.BuildReceiptError, match="identity"):
        builder._read_iidfile(alias, identity=identity)
    alias.unlink()
    os.link(target, alias)
    with pytest.raises(builder.BuildReceiptError, match="identity"):
        builder._read_iidfile(alias, identity=identity)
    alias.unlink()
    target.unlink()
    partial = tmp_path / "partial"
    partial.write_text("sha256:abc")
    partial.chmod(0o600)
    with pytest.raises(builder.BuildReceiptError, match="identity"):
        builder._read_iidfile(partial, identity=identity)


@pytest.mark.parametrize("mutation", ["replace", "add"])
def test_spawn_boundary_revalidates_frozen_context_before_popen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    identity = builder.require_host_identity()
    context = tmp_path / builder.STAGED_CONTEXT_NAME
    _, staged = builder.stage_build_context(context, identity=identity)
    context.chmod(0o700)
    if mutation == "replace":
        target = context / builder.DOCKERIGNORE_PATH
        target.chmod(0o600)
        target.unlink()
        target.write_bytes(b"hostile replacement\n")
        target.chmod(0o400)
    else:
        unexpected = context / "unexpected"
        unexpected.write_bytes(b"hostile\n")
        unexpected.chmod(0o400)
    context.chmod(0o500)
    popen_called = False

    def forbidden_popen(*_args, **_kwargs):
        nonlocal popen_called
        popen_called = True
        raise AssertionError("Popen must not observe a changed staged context")

    monkeypatch.setattr(builder.subprocess, "Popen", forbidden_popen)
    with pytest.raises(builder.BuildReceiptError, match="staged_context"):
        builder._run_bounded(
            ("docker", "build"),
            timeout_seconds=1,
            maximum_output_bytes=1024,
            pre_spawn_check=lambda: builder._revalidate_staged_context(
                context, expected=staged, identity=identity
            ),
        )
    assert popen_called is False
    builder._remove_staged_context(context, identity=identity)


@pytest.mark.parametrize("cleanup_failed", [False, True])
def test_natural_nonzero_retains_bounded_private_diagnostics_after_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, cleanup_failed: bool,
) -> None:
    _authorize_fake_runtime(monkeypatch, tmp_path)
    validations = 0

    def revalidate(*_args, **_kwargs):
        nonlocal validations
        validations += 1
        if cleanup_failed and validations == 2:
            raise RuntimeError("injected runtime identity change")

    monkeypatch.setattr(builder, "revalidate_runtime", revalidate)
    with pytest.raises(builder.BuildReceiptError) as caught:
        builder._run_bounded(
            (sys.executable, "-c", "import sys; print('private-out'); "
             "print('private-err', file=sys.stderr); sys.exit(23)"),
            timeout_seconds=5,
            maximum_output_bytes=1024,
        )
    assert validations == 2
    if cleanup_failed:
        assert isinstance(caught.value, builder.DockerProcessCleanupUncertain)
        assert not hasattr(caught.value, "completed")
    else:
        assert type(caught.value).__name__ == "DockerStatusFailed"
        assert caught.value.returncode == 23
        assert caught.value.completed == builder.CompletedDocker(
            b"private-out\n", b"private-err\n"
        )
        assert str(caught.value) == "docker_status_failed"
        assert "private-" not in repr(caught.value)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_bounded_runner_defers_cleanup_baseexception_and_proves_child_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    os.close(stdout_write)
    os.close(stderr_write)

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = os.fdopen(stdout_read, "rb", buffering=0)
            self.stderr = os.fdopen(stderr_read, "rb", buffering=0)
            self.alive = True
            self.terminate_calls = 0
            self.wait_calls = 0

        def poll(self):
            return None if self.alive else 0

        def terminate(self):
            self.terminate_calls += 1
            raise KeyboardInterrupt("injected terminate interrupt")

        def kill(self):
            self.alive = False

        def wait(self, *, timeout):
            del timeout
            self.wait_calls += 1
            self.alive = False
            return 0

    process = FakeProcess()
    process.pid = 12345
    _authorize_fake_runtime(monkeypatch, Path.cwd())
    monkeypatch.setattr(builder, "revalidate_runtime", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(builder.subprocess, "Popen", lambda *_args, **_kwargs: process)
    kill_calls: list[int] = []

    def killpg(_pid, signal_number):
        kill_calls.append(signal_number)
        if signal_number == builder.signal.SIGTERM:
            raise KeyboardInterrupt("injected process-group interrupt")
        process.alive = False

    monkeypatch.setattr(builder.os, "killpg", killpg)

    def interrupt_setup(*_args, **_kwargs):
        raise SystemExit("injected setup interrupt")

    monkeypatch.setattr(builder.os, "set_blocking", interrupt_setup)
    with pytest.raises(
        builder.DockerProcessCleanupUncertain, match="cleanup_uncertain"
    ):
        builder._run_bounded(
            ("docker", "build"),
            timeout_seconds=1,
            maximum_output_bytes=1024,
        )
    assert kill_calls
    assert process.wait_calls == 1
    assert process.poll() == 0
    assert process.stdout.closed
    assert process.stderr.closed


def test_forced_build_client_stop_is_classified_cleanup_uncertain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = os.fdopen(stdout_read, "rb", buffering=0)
            self.stderr = os.fdopen(stderr_read, "rb", buffering=0)
            self.alive = True

        def poll(self):
            return None if self.alive else -15

        def terminate(self):
            self.alive = False
            os.close(stdout_write)
            os.close(stderr_write)

        def kill(self):
            self.alive = False

        def wait(self, *, timeout):
            del timeout
            return -15

    process = FakeProcess()
    process.pid = 12346
    _authorize_fake_runtime(monkeypatch, Path.cwd())
    monkeypatch.setattr(builder, "revalidate_runtime", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(builder.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        builder.os,
        "killpg",
        lambda _pid, _signal: (
            setattr(process, "alive", False),
            os.close(stdout_write),
            os.close(stderr_write),
        ),
    )
    monkeypatch.setattr(
        builder.os,
        "set_blocking",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("injected setup failure")
        ),
    )
    with pytest.raises(
        builder.DockerProcessCleanupUncertain, match="completion_uncertain"
    ):
        builder._run_bounded(
            ("docker", "build"),
            timeout_seconds=1,
            maximum_output_bytes=1024,
        )
    assert process.poll() == -15


def test_cleanup_inspect_rejects_foreign_repo_digest() -> None:
    invocation_id = "a" * 32
    tag = f"lomo-kodesec-scanner:trivy-review-{invocation_id}"
    value = json.loads(_image_inspect(tag))
    value["RepoDigests"] = ["foreign@example.invalid:sha256:" + "f" * 64]
    completed = builder.CompletedDocker(json.dumps(value).encode(), b"")
    with pytest.raises(builder.BuildReceiptError, match="foreign_refs"):
        builder._validate_cleanup_image(
            completed,
            image_id=IMAGE_ID,
            tag=tag,
            invocation_id=invocation_id,
            allow_untagged=False,
            provenance=PROVENANCE,
        )


def test_build_and_cleanup_accept_exact_local_repo_digest() -> None:
    invocation_id = "a" * 32
    tag = f"lomo-kodesec-scanner:trivy-review-{invocation_id}"
    exact = [f"lomo-kodesec-scanner@{IMAGE_ID}"]
    raw = _image_inspect(tag, repo_digests=exact)

    assert builder.parse_image_inspect(
        raw, tag=tag, expected_id=IMAGE_ID, provenance=PROVENANCE
    )["id"] == IMAGE_ID
    builder._validate_cleanup_image(
        builder.CompletedDocker(raw, b""),
        image_id=IMAGE_ID,
        tag=tag,
        invocation_id=invocation_id,
        allow_untagged=False,
        provenance=PROVENANCE,
    )
    untagged = json.loads(raw)
    untagged["RepoTags"] = []
    builder._validate_cleanup_image(
        builder.CompletedDocker(json.dumps(untagged).encode(), b""),
        image_id=IMAGE_ID,
        tag=tag,
        invocation_id=invocation_id,
        allow_untagged=True,
        provenance=PROVENANCE,
    )


def test_receipt_parent_fsync_failure_rolls_back_canonical_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    identity = builder.require_host_identity()
    destination = tmp_path / "scanner-build-receipt.json"
    original_fsync = builder.os.fsync

    def fail_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected parent fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(builder.os, "fsync", fail_directory_fsync)
    with pytest.raises(builder.BuildReceiptError, match="rollback|removal"):
        builder._publish_private(
            destination,
            b'{"canonical":true}',
            identity=identity,
            invocation_id="b" * 32,
        )
    assert not destination.exists()
    assert not list(tmp_path.glob(".*.tmp"))


def test_failure_cleanup_attempts_every_action_under_baseexceptions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "build"
    observation = _authorize_fake_runtime(monkeypatch, tmp_path)
    calls: list[str] = []
    manifest = {
        "files": [
            {
                "path": builder.PRODUCER_RELATIVE_PATH,
                "sha256": "1" * 64,
            }
        ]
    }
    monkeypatch.setattr(builder, "require_review_build_host", lambda: builder.REVIEW_TARGET)
    monkeypatch.setattr(builder, "prove_build_identity_absent", lambda **_kwargs: None)
    monkeypatch.setattr(
        builder,
        "stage_build_context",
        lambda *_args, **_kwargs: (manifest, {}),
    )

    def fail_build(*_args, **_kwargs):
        raise builder.BuildReceiptError("injected primary")

    monkeypatch.setattr(builder, "run_docker", fail_build)

    def fail(name: str, exception: BaseException):
        def operation(*_args, **_kwargs):
            calls.append(name)
            raise exception

        return operation

    monkeypatch.setattr(
        builder,
        "_invalidate_receipt",
        fail("receipt", KeyboardInterrupt("receipt")),
    )
    monkeypatch.setattr(
        builder,
        "_cleanup_owned_image",
        fail("image", SystemExit("image")),
    )
    monkeypatch.setattr(
        builder,
        "_remove_staged_context",
        fail("context", RuntimeError("context")),
    )
    monkeypatch.setattr(
        builder,
        "_remove_private_output",
        fail("output", OSError("output")),
    )
    with pytest.raises(builder.BuildReceiptError, match="build_cleanup_uncertain"):
        builder.produce(output, observation, identity=builder.require_host_identity())
    assert calls == ["receipt", "image", "context", "output"]
    assert not (output / "scanner-build-receipt.json").exists()
