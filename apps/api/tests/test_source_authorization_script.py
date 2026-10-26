from __future__ import annotations

import base64
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
INIT = REPO_ROOT / "scripts" / "init-runtime.sh"
AUTHORIZE = REPO_ROOT / "scripts" / "authorize-source.py"
MAKEFILE = REPO_ROOT / "Makefile"
SECRET_KEYS = {
    "POSTGRES_PASSWORD",
    "KODESEC_INSTALLATION_SECRET",
    "KODESEC_BOOTSTRAP_TOKEN",
    "GRAFANA_ADMIN_PASSWORD",
    "GITEA_SECRET_KEY",
    "GITEA_INTERNAL_TOKEN",
    "GITEA_TEST_PASSWORD",
}


def _values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def _encoded(path: str) -> str:
    return base64.urlsafe_b64encode(path.encode("utf-8")).decode("ascii").rstrip("=")


def _initialize(state: Path) -> Path:
    result = subprocess.run(
        [str(INIT)],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "KODESEC_STATE_DIR": str(state),
            "KODESEC_RUNTIME_ENV": str(state / "runtime.env"),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return state / "runtime.env"


def _authorize(
    state: Path,
    selected: str,
    *,
    apply_source: bool = False,
    operation: str = "add",
    expected_installation: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, os.fspath(AUTHORIZE)],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "KODESEC_STATE_DIR": str(state),
            "KODESEC_RUNTIME_ENV": str(state / "runtime.env"),
            "KODESEC_SOURCE_ROOT_B64": _encoded(selected),
            "KODESEC_SOURCE_APPLY": "1" if apply_source else "",
            "KODESEC_SOURCE_OPERATION": operation,
            **({"KODESEC_EXPECT_INSTALLATION_ID": expected_installation} if expected_installation is not None else {}),
        },
        text=True,
        capture_output=True,
        check=False,
    )


def _authorize_batch(state: Path, roots: object, **environment: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(AUTHORIZE)], cwd=REPO_ROOT,
        env={**os.environ, "KODESEC_STATE_DIR": str(state),
            "KODESEC_RUNTIME_ENV": str(state / "runtime.env"),
            "KODESEC_SOURCE_ROOT_B64": "", "KODESEC_SOURCE_OPERATION": "add",
            "KODESEC_EXPECT_INSTALLATION_ID": _values(state / "runtime.env")["KODESEC_INSTALLATION_ID"],
            "KODESEC_SOURCE_ROOTS_B64": _encoded(json.dumps(roots, ensure_ascii=True)), **environment},
        capture_output=True, text=True, check=False,
    )


def test_reviewed_ten_root_batch_preserves_existing_authority_and_excludes_parent(tmp_path: Path) -> None:
    state = tmp_path / "batch-state"
    runtime = _initialize(state)
    before = _values(runtime)
    parent = tmp_path / "ten repositories"
    children = [parent / f"repo-{index}" for index in range(10)]
    for child in children:
        child.mkdir(parents=True)
    roots = [str(child.resolve()) for child in children]
    result = _authorize_batch(state, roots)
    assert result.returncode == 0, result.stderr
    after = _values(runtime)
    assert after["KODESEC_ALLOWED_ROOTS"].split(",") == before["KODESEC_ALLOWED_ROOTS"].split(",") + roots
    assert str(parent.resolve()) not in after["KODESEC_ALLOWED_ROOTS"].split(",")
    assert {key: value for key, value in after.items() if key != "KODESEC_ALLOWED_ROOTS"} == {
        key: value for key, value in before.items() if key != "KODESEC_ALLOWED_ROOTS"}
    assert all(before[key] not in result.stdout + result.stderr for key in SECRET_KEYS)
    inode = runtime.stat().st_ino
    repeated = _authorize_batch(state, roots)
    assert repeated.returncode == 0 and runtime.stat().st_ino == inode


@pytest.mark.parametrize("case", ["missing", "broad", "duplicate", "overlap", "relative", "too-many", "surrogate", "wrong-installation", "mixed", "remove"])
def test_batch_authorization_is_all_or_nothing(tmp_path: Path, case: str) -> None:
    state = tmp_path / "batch-state"
    runtime = _initialize(state)
    first = tmp_path / "safe-root"
    first.mkdir()
    child = first / "nested"
    child.mkdir()
    roots = [str(first.resolve()), str((tmp_path / "not-created").resolve())]
    environment = {}
    if case == "broad": roots[1] = "/"
    if case == "duplicate": roots[1] = roots[0]
    if case == "overlap": roots[1] = str(child.resolve())
    if case == "relative": roots[1] = "relative/path"
    if case == "too-many": roots = [str(tmp_path / f"root-{index}") for index in range(33)]
    if case == "surrogate": roots[1] = "/invalid/\ud800"
    if case == "wrong-installation":
        roots = [str(first.resolve())]
        environment["KODESEC_EXPECT_INSTALLATION_ID"] = "a" * 12
    if case == "mixed": environment["KODESEC_SOURCE_ROOT_B64"] = _encoded(str(first.resolve()))
    if case == "remove": environment["KODESEC_SOURCE_OPERATION"] = "remove"
    before = runtime.read_bytes()
    inode = runtime.stat().st_ino
    result = _authorize_batch(state, roots, **environment)
    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert runtime.read_bytes() == before and runtime.stat().st_ino == inode


def test_batch_authorization_checks_combined_root_limit_without_partial_write(tmp_path: Path) -> None:
    state = tmp_path / "batch-state"
    runtime = _initialize(state)
    roots = []
    for index in range(32):
        child = tmp_path / f"repo-{index}"
        child.mkdir()
        roots.append(str(child.resolve()))
    before = runtime.read_bytes()
    result = _authorize_batch(state, roots)
    assert result.returncode != 0  # The existing default root must remain too.
    assert runtime.read_bytes() == before


def test_batch_authorization_performs_one_atomic_runtime_replacement(tmp_path: Path, monkeypatch) -> None:
    state = tmp_path / "batch-state"
    runtime = _initialize(state)
    roots = []
    for index in range(10):
        child = tmp_path / f"repo-{index}"
        child.mkdir()
        roots.append(str(child.resolve()))
    monkeypatch.syspath_prepend(str(REPO_ROOT / "scripts"))
    module = runpy.run_path(str(AUTHORIZE), run_name="batch_test")
    main = module["main"]
    writes = []
    actual = main.__globals__["_write_private_runtime"]
    def write_once(*args):
        writes.append(args[0])
        return actual(*args)
    monkeypatch.setitem(main.__globals__, "_write_private_runtime", write_once)
    monkeypatch.setenv("KODESEC_STATE_DIR", str(state))
    monkeypatch.setenv("KODESEC_RUNTIME_ENV", str(runtime))
    monkeypatch.setenv("KODESEC_EXPECT_INSTALLATION_ID", _values(runtime)["KODESEC_INSTALLATION_ID"])
    monkeypatch.setenv("KODESEC_SOURCE_ROOT_B64", "")
    monkeypatch.setenv("KODESEC_SOURCE_ROOTS_B64", _encoded(json.dumps(roots)))
    monkeypatch.setattr(sys, "argv", [str(AUTHORIZE)])
    main()
    assert writes == [runtime]


@pytest.mark.parametrize("expected", ["012345abcdef", "", "not-an-installation"])
def test_guarded_source_command_never_initializes_missing_runtime(tmp_path: Path, expected: str) -> None:
    state = tmp_path / "missing-installation"
    result = subprocess.run(
        ["make", "authorize-source", f"STATE_DIR={state}"], cwd=REPO_ROOT,
        env={**os.environ, "KODESEC_EXPECT_INSTALLATION_ID": expected,
             "KODESEC_SOURCE_ROOT_B64": _encoded(str(tmp_path))},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert not state.exists()


def test_guarded_source_command_refuses_other_installation_before_any_mutation(tmp_path: Path) -> None:
    state = tmp_path / "original"
    runtime = _initialize(state)
    before = {path.name: path.read_bytes() for path in state.iterdir() if path.is_file()}
    modes = {path.name: path.stat().st_mode for path in state.iterdir()}
    expected = "012345abcdef" if _values(runtime)["KODESEC_INSTALLATION_ID"] != "012345abcdef" else "abcdef012345"
    result = subprocess.run(
        [str(INIT)], env={**os.environ, "KODESEC_STATE_DIR": str(state),
            "KODESEC_RUNTIME_ENV": str(runtime), "KODESEC_EXPECT_INSTALLATION_ID": expected},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert "exact STATE_DIR" in result.stderr
    denied = _authorize(state, str(tmp_path), expected_installation=expected)
    assert denied.returncode != 0
    assert not (state / ".source-roots.lock").exists()
    assert {path.name: path.read_bytes() for path in state.iterdir() if path.is_file()} == before
    assert {path.name: path.stat().st_mode for path in state.iterdir()} == modes


def test_guarded_source_command_adds_only_to_matching_installation(tmp_path: Path) -> None:
    state = tmp_path / "matching"
    runtime = _initialize(state)
    before = _values(runtime)
    source = tmp_path / "additional"
    source.mkdir()
    result = _authorize(state, str(source), expected_installation=before["KODESEC_INSTALLATION_ID"])
    assert result.returncode == 0, result.stderr
    after = _values(runtime)
    assert after["KODESEC_ALLOWED_ROOTS"] == before["KODESEC_ALLOWED_ROOTS"] + "," + str(source.resolve())
    assert {key: value for key, value in after.items() if key != "KODESEC_ALLOWED_ROOTS"} == {
        key: value for key, value in before.items() if key != "KODESEC_ALLOWED_ROOTS"}


def test_guarded_source_command_rechecks_identity_inside_transaction(tmp_path: Path, monkeypatch) -> None:
    state = tmp_path / "concurrent"
    runtime = _initialize(state)
    before = runtime.read_text()
    before_values = _values(runtime)
    expected = before_values["KODESEC_INSTALLATION_ID"]
    monkeypatch.syspath_prepend(str(REPO_ROOT / "scripts"))
    module = runpy.run_path(str(AUTHORIZE), run_name="source_test")
    @contextmanager
    def changed_identity(_runtime):
        runtime.write_text(before.replace(f"KODESEC_INSTALLATION_ID={expected}", "KODESEC_INSTALLATION_ID=abcdef012345"))
        yield
    main = module["main"]
    monkeypatch.setitem(main.__globals__, "_source_transaction", changed_identity)
    monkeypatch.setenv("KODESEC_STATE_DIR", str(state))
    monkeypatch.setenv("KODESEC_RUNTIME_ENV", str(runtime))
    monkeypatch.setenv("KODESEC_EXPECT_INSTALLATION_ID", expected)
    monkeypatch.setenv("KODESEC_SOURCE_ROOT_B64", _encoded(str(tmp_path)))
    monkeypatch.setattr(sys, "argv", [str(AUTHORIZE)])
    with pytest.raises(SystemExit):
        main()
    after = _values(runtime)
    assert after["KODESEC_ALLOWED_ROOTS"] == before_values["KODESEC_ALLOWED_ROOTS"]


def test_apply_source_recreates_only_source_bound_services_without_building() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")
    target = makefile.split("apply-source: authorize-source\n", 1)[1].split("\n\n", 1)[0]

    assert target == (
        "\t$(COMPOSE) up -d --no-deps --no-build --force-recreate --wait \\\n"
        "\t  --wait-timeout $(SOURCE_APPLY_WAIT_SECONDS) scanner\n"
        "\t$(COMPOSE) up -d --no-deps --no-build --force-recreate --wait \\\n"
        "\t  --wait-timeout $(SOURCE_APPLY_WAIT_SECONDS) api\n"
        "\t$(COMPOSE) up -d --no-deps --no-build --force-recreate --wait \\\n"
        "\t  --wait-timeout $(SOURCE_APPLY_WAIT_SECONDS) worker"
    )
    assert "apply-source: KODESEC_SOURCE_APPLY := 1" in makefile
    authorize_target = makefile.split("authorize-source: init\n", 1)[1].split("\n\n", 1)[0]
    assert 'KODESEC_SOURCE_APPLY="$(KODESEC_SOURCE_APPLY)"' in authorize_target
    assert "apply-source" in makefile.split(".PHONY:", 1)[1].split("\n", 1)[0].split()
    assert "--build" not in target
    assert "--no-deps" in target
    assert "--wait" in target
    assert "SOURCE_APPLY_WAIT_SECONDS ?= 120" in makefile
    assert target.count("$(COMPOSE) up") == 3
    assert "scanner api" not in target
    assert "api worker" not in target
    assert "--always-recreate-deps" not in target
    assert "--volumes" not in target
    assert "scanner-updater" not in target
    assert "postgres" not in target
    assert "api-ingress" not in target
    assert "schema-init" not in target
    assert "advisor-connector" not in target


def test_authorize_source_atomically_adds_without_replacing_existing_roots(tmp_path: Path) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    source = tmp_path / "development" / "team"
    source.mkdir(parents=True)
    before = _values(runtime)

    result = _authorize(state, str(source))

    assert result.returncode == 0, result.stderr
    after = _values(runtime)
    assert after["KODESEC_REPO_ROOT"] == before["KODESEC_REPO_ROOT"]
    assert after["KODESEC_ALLOWED_ROOTS"] == before["KODESEC_ALLOWED_ROOTS"] + "," + str(source.resolve())
    assert all(after[key] == before[key] for key in SECRET_KEYS)
    assert {
        key: value
        for key, value in after.items()
        if key not in {"KODESEC_REPO_ROOT", "KODESEC_ALLOWED_ROOTS"}
    } == {
        key: value
        for key, value in before.items()
        if key not in {"KODESEC_REPO_ROOT", "KODESEC_ALLOWED_ROOTS"}
    }
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o600
    assert runtime.stat().st_nlink == 1
    output = result.stdout + result.stderr
    assert all(before[key] not in output for key in SECRET_KEYS)
    assert "make apply-source" in result.stdout
    assert "make up" not in result.stdout

    digest = hashlib.sha256(runtime.read_bytes()).digest()
    repeated = _authorize(state, str(source))
    assert repeated.returncode == 0
    assert hashlib.sha256(runtime.read_bytes()).digest() == digest
    assert "already authorized" in repeated.stdout


def test_authorize_source_apply_mode_reports_the_targeted_recreation(tmp_path: Path) -> None:
    state = tmp_path / "state"
    _initialize(state)
    source = tmp_path / "development" / "team"
    source.mkdir(parents=True)

    result = _authorize(state, str(source), apply_source=True)

    assert result.returncode == 0, result.stderr
    assert (
        "Applying the source boundary by recreating only scanner, API, and worker "
        "from installed images."
    ) in result.stdout
    assert "Run 'make" not in result.stdout


@pytest.mark.parametrize(
    "selected",
    [
        "/",
        "/Users",
        "/home",
        "/Volumes",
        "/private/tmp",
        "/private/tmp/",
        "/private/tmp/.",
        "/private//tmp",
        "/private/var/../tmp",
        "/private/var/tmp",
        "/tmp",
        "/var",
        "/var/tmp",
        "/System/Volumes/Data",
        "/System/Volumes/Data/Users",
        "/System/Volumes/Data/Volumes",
        "/System/Volumes/Data/private",
        "/System/Volumes/Data/private/tmp",
        "/System/Volumes/Data/private/var/tmp",
        "/System/Volumes/Data/var",
        "/System/Volumes/Data/var/tmp",
        str(Path.home()),
    ],
)
def test_authorize_source_refuses_broad_roots_without_mutation(
    tmp_path: Path,
    selected: str,
) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    before = runtime.read_bytes()

    result = _authorize(state, selected)

    assert result.returncode == 2
    assert "broad source root" in result.stderr
    assert runtime.read_bytes() == before


def test_authorize_source_treats_shell_metacharacters_as_path_bytes(tmp_path: Path) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    marker = tmp_path / "must-not-be-created"
    source = tmp_path / "development" / "; touch must-not-be-created"
    source.mkdir(parents=True)

    result = _authorize(state, str(source))

    assert result.returncode == 0, result.stderr
    assert str(source.resolve()) in _values(runtime)["KODESEC_ALLOWED_ROOTS"].split(",")
    assert not marker.exists()


@pytest.mark.parametrize("ambiguous", ["$HOME", "${HOME}", "quote'", 'quote"', "hash#", "back\\slash", "edge ", "comma,root"])
def test_authorize_source_refuses_compose_interpolation_or_quoting_ambiguity(
    tmp_path: Path,
    ambiguous: str,
) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    before = runtime.read_bytes()
    source = tmp_path / "development" / ambiguous
    source.mkdir(parents=True)

    result = _authorize(state, str(source))

    assert result.returncode == 2
    assert "cannot be serialized literally" in result.stderr
    assert runtime.read_bytes() == before
    assert _values(runtime)["KODESEC_REPO_ROOT"] == str(REPO_ROOT.resolve())


@pytest.mark.parametrize("target_name", ["$HOME", "line\nbreak"])
def test_authorize_source_refuses_clean_symlink_to_unsafe_canonical_path(
    tmp_path: Path,
    target_name: str,
) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    before = runtime.read_bytes()
    target = tmp_path / "development" / target_name / "service"
    target.mkdir(parents=True)
    alias = tmp_path / "safe-source-alias"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks unavailable: {error}")

    result = _authorize(state, str(alias))

    assert result.returncode == 2
    assert "resolved source root" in result.stderr
    assert "cannot be serialized literally" in result.stderr
    assert runtime.read_bytes() == before


def test_authorize_source_rejects_untrusted_runtime_files_and_invalid_targets(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    source = tmp_path / "development" / "service"
    source.mkdir(parents=True)
    before = runtime.read_bytes()

    runtime.chmod(0o644)
    refused = _authorize(state, str(source))
    assert refused.returncode == 2
    assert "mode-0600 single-link" in refused.stderr
    assert runtime.read_bytes() == before

    runtime.chmod(0o600)
    missing = _authorize(state, str(tmp_path / "missing"))
    assert missing.returncode == 2
    assert "cannot be resolved" in missing.stderr
    assert runtime.read_bytes() == before

    hardlink = tmp_path / "runtime-hardlink"
    os.link(runtime, hardlink)
    linked = _authorize(state, str(source))
    assert linked.returncode == 2
    assert "single-link" in linked.stderr
    assert runtime.read_bytes() == before


def test_authorize_source_requires_encoded_or_interactive_input(tmp_path: Path) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    before = runtime.read_bytes()
    result = subprocess.run(
        [sys.executable, os.fspath(AUTHORIZE)],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "KODESEC_STATE_DIR": str(state),
            "KODESEC_RUNTIME_ENV": str(runtime),
        },
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "Copy host command" in result.stderr
    assert runtime.read_bytes() == before


def test_independent_nested_unicode_roots_remove_readd_and_restart_preserve_siblings(tmp_path: Path) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    first = tmp_path / "first" / "space 日本語"
    second = tmp_path / "independent" / "second"
    nested = first / "nested"
    nested.mkdir(parents=True)
    second.mkdir(parents=True)
    original = _values(runtime)
    for root in [first, second, nested]:
        result = _authorize(state, str(root))
        assert result.returncode == 0, result.stderr
    roots = _values(runtime)["KODESEC_ALLOWED_ROOTS"].split(",")
    assert roots == [original["KODESEC_REPO_ROOT"], *[str(p.resolve()) for p in [first, second, nested]]]
    assert str(tmp_path) not in roots
    # A disappearing directory must not prevent removal of its persisted identity.
    second_identity = str(second.resolve())
    second.rmdir()
    assert _authorize(state, second_identity, operation="remove").returncode == 0
    assert _values(runtime)["KODESEC_ALLOWED_ROOTS"].split(",") == [roots[0], roots[1], roots[3]]
    second.mkdir()
    assert _authorize(state, second_identity).returncode == 0
    before_restart = runtime.read_bytes()
    assert _initialize(state) == runtime
    assert runtime.read_bytes() == before_restart
    assert all(_values(runtime)[key] == original[key] for key in SECRET_KEYS)


def test_source_removal_does_not_remove_neighbours_or_the_last_root(tmp_path: Path) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    original = runtime.read_bytes()
    root = _values(runtime)["KODESEC_REPO_ROOT"]
    assert _authorize(state, root, operation="remove").returncode == 2
    assert runtime.read_bytes() == original
    assert _authorize(state, root + "-sibling", operation="remove").returncode == 2
    assert runtime.read_bytes() == original
    assert _authorize(state, root, operation="replace").returncode == 2
    assert runtime.read_bytes() == original


def test_runtime_compose_adds_only_read_only_exact_sources_and_cleans_override(tmp_path: Path) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    extra = tmp_path / "independent source"
    extra.mkdir()
    assert _authorize(state, str(extra)).returncode == 0
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    docker.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "overrides = [pathlib.Path(args[i + 1]) for i, item in enumerate(args) if item == '--file'][1:]\n"
        "print(json.dumps({'paths': [str(p) for p in overrides], 'overrides': [json.loads(p.read_text()) for p in overrides]}))\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts/runtime-compose.py"), str(runtime), "config"],
        env={**os.environ, "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"]},
        text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed["overrides"] == [{"services": {"scanner": {"volumes": [{
        "type": "bind", "source": str(extra.resolve()), "target": str(extra.resolve()),
        "read_only": True, "bind": {"create_host_path": False},
    }]}}}]
    assert all(not Path(path).exists() for path in observed["paths"])
    assert not list(state.glob(".source-mounts-*"))


def test_configured_sources_are_bounded_exact_and_cannot_shadow_the_runtime() -> None:
    module = runpy.run_path(str(REPO_ROOT / "scripts/source_roots.py"))
    parse = module["configured_source_roots"]
    error = module["SourceRootError"]
    roots = [f"/workspace/root-{index}" for index in range(32)]
    assert parse(roots[0], ",".join(roots)) == roots
    for invalid in [
        ",".join([*roots, "/workspace/33"]), "/workspace/a,/workspace/a",
        "/workspace/a,", "/workspace/a,/workspace/../escape", "/usr/local",
        "/data/artifacts/source", "/app/code", "/proc/self",
    ]:
        with pytest.raises(error):
            parse(invalid.split(",")[0], invalid)
    with pytest.raises(error):
        parse("/workspace/b", "/workspace/a,/workspace/b")


def test_startup_rejects_source_symlink_drift_without_blocking_teardown(tmp_path: Path) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    source = tmp_path / "approved"
    source.mkdir()
    assert _authorize(state, str(source)).returncode == 0
    source.rmdir()
    other = tmp_path / "not-approved"
    other.mkdir()
    source.symlink_to(other, target_is_directory=True)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    docker.write_text(f"#!{sys.executable}\nprint('docker-called')\n", encoding="utf-8")
    docker.chmod(0o755)
    environment = {**os.environ, "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"]}
    for action in ["up", "create", "run", "start", "restart", "watch"]:
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts/runtime-compose.py"), str(runtime), action],
            env=environment, text=True, capture_output=True, check=False,
        )
        assert result.returncode != 0
        assert "different host path" in result.stderr
        assert "docker-called" not in result.stdout
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts/runtime-compose.py"), str(runtime), "down"],
        env=environment, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "docker-called"


def test_source_addition_refuses_runtime_growth_before_changing_authority(tmp_path: Path) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    source = tmp_path / "new source"
    source.mkdir()
    original = runtime.read_bytes()
    prefix = original + b"QA_BOUNDED_PADDING="
    runtime.write_bytes(prefix + b"x" * (64 * 1024 - len(prefix) - 1) + b"\n")
    bounded = runtime.read_bytes()
    refused = _authorize(state, str(source))
    assert refused.returncode == 2
    assert "64-KiB runtime configuration limit" in refused.stderr
    assert runtime.read_bytes() == bounded


def test_concurrent_source_additions_preserve_every_explicit_root(tmp_path: Path) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    original = _values(runtime)
    roots = [tmp_path / f"root-{index}" for index in range(8)]
    for root in roots:
        root.mkdir()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda root: _authorize(state, str(root)), roots))
    assert all(result.returncode == 0 for result in results), [r.stderr for r in results]
    final = _values(runtime)
    assert set(final["KODESEC_ALLOWED_ROOTS"].split(",")) == {
        original["KODESEC_REPO_ROOT"], *[str(root.resolve()) for root in roots],
    }
    assert final["KODESEC_REPO_ROOT"] == original["KODESEC_REPO_ROOT"]
    assert all(final[key] == original[key] for key in SECRET_KEYS)


def test_source_transaction_refuses_a_symlink_lock_without_mutation(tmp_path: Path) -> None:
    state = tmp_path / "state"
    runtime = _initialize(state)
    original = runtime.read_bytes()
    unrelated = tmp_path / "unrelated"
    unrelated.write_text("preserve me")
    (state / ".source-roots.lock").symlink_to(unrelated)
    refused = _authorize(state, str(REPO_ROOT))
    assert refused.returncode == 2
    assert "lock is unavailable" in refused.stderr
    assert runtime.read_bytes() == original
    assert unrelated.read_text() == "preserve me"
