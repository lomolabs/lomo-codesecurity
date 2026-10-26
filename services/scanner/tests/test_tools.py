from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from kodesec_scanner import tools
from kodesec_scanner import verify_tools
from kodesec_scanner.cache_manifest import LockValidationError, load_tool_lock


def test_dockerfile_pins_verified_assets_and_an_exact_checkov_wheel() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")
    fetcher = (
        Path(__file__).parents[1] / "scripts" / "fetch-locked-asset.sh"
    ).read_text(encoding="utf-8")
    assert [line for line in dockerfile.splitlines() if line.startswith("FROM ")] == [
        "FROM golang:1.26.8-bookworm@sha256:"
        "a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS bearer-build",
        "FROM python:3.12-slim@sha256:"
        "229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36",
    ]
    for tool_id, version in EXPECTED_VERSIONS.items():
        assert f"ARG {tool_id.upper()}_VERSION={version}" in dockerfile
    assert "ARG SCANNER_VERSION_PROBE_TIMEOUT_SECONDS=30" in dockerfile
    assert "ARG SCANNER_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS=900" in dockerfile
    assert "ARG SCANNER_DOWNLOAD_RETRY_WINDOW_SECONDS=1800" in dockerfile
    assert '--probe-timeout-seconds "${SCANNER_VERSION_PROBE_TIMEOUT_SECONDS}"' in dockerfile
    expected_checksums = {
        "2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b",
        "13833d97e8a1a5367471c372a173180157f593bece570e20d5d925fef552f5dd",
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
        "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
        "9d47d7de3f22ec5a93b25af9126648191e3d3b5d759dd4f699006138724719b",
        "4efcd2f195da8719f16e4eac79fb918442e04d70f3bcc001fd6105c0afd53aae",
        "38525dab1e06f162ebaa02f94d82d1f807076b011a44180cf2777edf1a7b9c26",
        "935f628bdf9331ffdd946931ea5fdb50045d3970ba52670cbeb44a88f127291b",
        "7105f1cd6577f058a9e39d0578f1a99c8a1e481e4d3512cd8a09acfe22a0fdc0",
        "50acd4c7a3b8ebfe5083d8350956057030c44be3515dedd55b45263495c490b2",
        "2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f",
        "6c0466811541ea03add5213a60a1562f0851e4c0b0ecfdee1a694a9455285900",
        "5923565b2d29f6932011e1f479a78cb46fa6aede3110919a8f2028fb5318cbdc",
    }
    expected_checksums.add("218a181286ab11d6d189db879692e9ae556370d0304b9c09732e637f8c77c149")
    assert all(checksum in dockerfile for checksum in expected_checksums)
    assert "sha256sum --check --strict" in fetcher
    assert "--continue-at -" in fetcher
    assert "--retry" not in fetcher
    assert 'remaining=$((retry_window - (now - started_at)))' in fetcher
    assert 'transfer_timeout="$remaining"' in fetcher
    assert (
        "COPY services/scanner/scripts/fetch-locked-asset.sh "
        "/usr/local/bin/kodesec-fetch-locked-asset"
    ) in dockerfile
    assert dockerfile.count("kodesec-fetch-locked-asset") == 10
    assert "--retry" not in dockerfile
    assert "|| true" not in dockerfile
    assert re.search(r"\|\s+(?:ba)?sh(?:\s|\\)", dockerfile) is None
    assert 'checkov_download_dir="$(mktemp -d)"' in dockerfile
    assert (
        'checkov_wheel="$checkov_download_dir/checkov-3.3.10-py3-none-any.whl"'
        in dockerfile
    )
    assert "--require-hashes -r build-requirements.lock" in dockerfile
    assert "--only-binary=:all:" in dockerfile
    assert "--no-build-isolation --no-deps ." in dockerfile
    assert (
        'pip install --disable-pip-version-check --no-index --no-deps "$checkov_wheel"'
        in dockerfile
    )
    requirements = (Path(__file__).parents[1] / "build-requirements.lock").read_text(
        encoding="utf-8"
    )
    assert "make scanner-requirements-lock" in requirements.splitlines()[1]
    assert "# checkov" in requirements
    assert "/private/tmp" not in requirements
    assert "--hash=sha256:" in requirements
    assert not re.search(r"^checkov(?:==|\s*@)", requirements, flags=re.MULTILINE)
    assert 'opengrep_home="/usr/local/share/kodesec/opengrep-home"' in dockerfile
    assert (
        'opengrep_core="$opengrep_home/.cache/opengrep/v${OPENGREP_VERSION}/opengrep.bin"'
        in dockerfile
    )
    assert (
        'HOME="$opengrep_home" SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off'
        in dockerfile
    )
    assert "opengrep --experimental --version" in dockerfile
    assert 'test ! -L "$opengrep_core"' in dockerfile
    assert 'test -x "$opengrep_core"' in dockerfile
    assert 'ln -s opengrep.bin "$opengrep_executable"' in dockerfile
    assert 'test "$(readlink "$opengrep_executable")" = "opengrep.bin"' in dockerfile
    assert 'chown -R 0:0 "$opengrep_home"' in dockerfile
    assert 'chmod -R a-w,a+rX "$opengrep_home"' in dockerfile


def test_dockerfile_normalizes_external_binary_ownership_before_modes() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")
    downloaded_paths = {
        "/usr/local/bin/trivy",
        "/usr/local/bin/gitleaks",
        "/usr/local/bin/opengrep",
        "/usr/local/bin/bearer",
        "/usr/local/bin/grype",
        "/usr/local/bin/trufflehog",
        "/usr/local/bin/syft",
    }
    assert {Path(path).name for path in downloaded_paths} | {"checkov"} == set(
        EXPECTED_VERSIONS
    )

    chown_start = dockerfile.index("    chown 0:0 \\\n")
    chmod_start = dockerfile.index("    chmod 0755 \\\n", chown_start)
    chown_command = dockerfile[chown_start:chmod_start]
    chmod_end = dockerfile.index("; \\\n", chmod_start)
    chmod_command = dockerfile[chmod_start:chmod_end]
    path_pattern = r"/usr/local/bin/[a-z0-9-]+"

    assert set(re.findall(path_pattern, chown_command)) == downloaded_paths
    assert set(re.findall(path_pattern, chmod_command)) == downloaded_paths
    assert chown_start < chmod_start

    checkov_install = dockerfile.index(
        'pip install --disable-pip-version-check --no-index --no-deps "$checkov_wheel"'
    )
    checkov_chown = dockerfile.index(
        "chown 0:0 /usr/local/bin/checkov", checkov_install
    )
    checkov_chmod = dockerfile.index("chmod 0755 /usr/local/bin/checkov", checkov_chown)
    assert checkov_install < checkov_chown < checkov_chmod

    opengrep_home_chown = dockerfile.index('chown -R 0:0 "$opengrep_home"')
    opengrep_home_chmod = dockerfile.index(
        'chmod -R a-w,a+rX "$opengrep_home"', opengrep_home_chown
    )
    assert opengrep_home_chown < opengrep_home_chmod


def test_dockerfile_installs_the_updater_cache_as_private_owned_directories() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")
    private_layout = re.search(
        r"install -d -o 1000 -g 1000 -m 0700 \\\n"
        r"\s+/data/source-snapshots \\\n"
        r"\s+/data/source-snapshots/generations \\\n"
        r"\s+/data/tool-cache \\\n"
        r"\s+/data/tool-cache/generations \\\n"
        r"\s+/data/tool-cache/staging \\\n"
        r"\s+/data/tool-cache/tombstones \\\n",
        dockerfile,
    )

    assert private_layout is not None
    assert dockerfile.index("USER kodesec") > private_layout.end()


EXPECTED_VERSIONS = {
    "trivy": "0.73.0",
    "gitleaks": "8.30.1",
    "opengrep": "1.27.0",
    "bearer": "2.1.0+lomo.1",
    "grype": "0.117.0",
    "checkov": "3.3.10",
    "trufflehog": "3.96.0",
    "syft": "1.51.0",
}


@pytest.fixture(autouse=True)
def clear_manifest_cache() -> None:
    tools._verified_tool_manifest.cache_clear()
    tools._binary_sha256_for_stat.cache_clear()
    yield
    tools._verified_tool_manifest.cache_clear()
    tools._binary_sha256_for_stat.cache_clear()


def test_curated_versions_are_one_exact_eight_tool_set() -> None:
    assert tools.EXTERNAL_TOOL_VERSIONS == EXPECTED_VERSIONS
    assert set(tools.TOOL_VERSION_COMMANDS) == set(EXPECTED_VERSIONS)
    metadata = {
        item["id"]: item["version"]
        for item in tools.SCANNER_TOOLS
        if item["source"] == "external"
    }
    assert metadata == EXPECTED_VERSIONS


def test_runtime_constants_are_bound_to_the_reviewed_tool_lock() -> None:
    root = Path(__file__).resolve().parents[3]
    loaded = load_tool_lock(root / "scanner-tools.lock.json")
    tools.validate_runtime_lock_contract(loaded.value)

    changed = loaded.value.model_copy(
        update={
            "tools": [
                item.model_copy(update={"version": "9.9.9"})
                if item.id == "trivy"
                else item
                for item in loaded.value.tools
            ]
        }
    )
    with pytest.raises(LockValidationError, match="version differs"):
        tools.validate_runtime_lock_contract(changed)


def test_reviewed_source_recipes_match_the_tool_lock() -> None:
    root = Path(__file__).resolve().parents[3]
    lock = load_tool_lock(root / "scanner-tools.lock.json").value
    for tool in lock.tools:
        recipe = tool.binary.source_build
        if recipe is None:
            continue
        assert recipe.recipe_ref.startswith("repo:")
        path = root / recipe.recipe_ref.removeprefix("repo:")
        assert path.resolve().is_relative_to(root)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == recipe.recipe_sha256


def test_bearer_runtime_contract_requires_same_scan_jsonv2() -> None:
    root = Path(__file__).resolve().parents[3]
    lock = load_tool_lock(root / "scanner-tools.lock.json").value
    bearer = lock.tool("bearer")
    assert bearer.adapter.output_format == "jsonv2"
    assert bearer.adapter.arguments[bearer.adapter.arguments.index("--format") + 1] == "jsonv2"
    assert tools.TOOL_ADAPTER_OUTPUT_FORMATS["bearer"] == "jsonv2"
    assert next(tool for tool in tools.SCANNER_TOOLS if tool["id"] == "bearer")["output_format"] == "jsonv2"
    obsolete = bearer.model_copy(update={"adapter": bearer.adapter.model_copy(update={"output_format": "sarif"})})
    changed = lock.model_copy(update={"tools": [obsolete if item.id == "bearer" else item for item in lock.tools]})
    with pytest.raises(LockValidationError, match="output format"):
        tools.validate_runtime_lock_contract(changed)


def test_runtime_context_reuses_one_generation_for_readiness_and_components(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded_tools = SimpleNamespace(value=object(), sha256="a" * 64)
    loaded_rules = SimpleNamespace(value=object(), sha256="b" * 64)
    generation = SimpleNamespace(
        manifest=SimpleNamespace(
            generation_id="generation-one",
            tool_lock_sha256=loaded_tools.sha256,
            rules_lock_sha256=loaded_rules.sha256,
        )
    )
    resolved = SimpleNamespace(state="ready", generation=generation)
    readiness = SimpleNamespace(tool_id="fixture", ready=True)
    component_snapshot = SimpleNamespace(generation_id="generation-one")
    observed: list[tuple[str, object]] = []

    monkeypatch.setattr(tools, "load_tool_lock", lambda _path: loaded_tools)
    monkeypatch.setattr(tools, "load_rules_lock", lambda _path: loaded_rules)
    monkeypatch.setattr(
        tools,
        "validate_runtime_lock_contract",
        lambda value: observed.append(("lock", value)),
    )
    monkeypatch.setattr(tools, "external_tool_ids", lambda: {"fixture"})
    monkeypatch.setattr(
        tools,
        "tool_runtime_state",
        lambda tool_id: {"id": tool_id, "status": "ready"},
    )

    def resolve_once(_root: Path, **digests: str) -> object:
        observed.append(("resolve", digests))
        return resolved

    def evaluate(
        tool_document: object,
        rules_document: object,
        resolved_generation: object,
        binary_states: object,
    ) -> list[object]:
        assert tool_document is loaded_tools
        assert rules_document is loaded_rules
        assert resolved_generation is resolved
        assert binary_states == {"fixture": "ready"}
        observed.append(("readiness", resolved_generation))
        return [readiness]

    def resolve_components(
        resolved_generation: object,
        tool_document: object,
        rules_document: object,
        component_ids: list[str],
    ) -> object:
        assert resolved_generation is resolved
        assert tool_document is loaded_tools
        assert rules_document is loaded_rules
        assert component_ids == ["fixture-rules"]
        observed.append(("components", resolved_generation))
        return component_snapshot

    monkeypatch.setattr(tools, "resolve_active_generation_cached", resolve_once)
    monkeypatch.setattr(tools, "evaluate_tool_readiness", evaluate)
    monkeypatch.setattr(tools, "runtime_components_from_resolved", resolve_components)

    context = tools.scanner_runtime_context(
        tool_lock_path=Path("tools.lock"),
        rules_lock_path=Path("rules.lock"),
        cache_root=Path("cache"),
    )

    assert context.generation_id == "generation-one"
    assert context.runtime_by_id == {"fixture": {"id": "fixture", "status": "ready"}}
    assert context.readiness_by_id == {"fixture": readiness}
    assert context.resolve_components(["fixture-rules"]) is component_snapshot
    assert [name for name, _value in observed].count("resolve") == 1
    assert ("readiness", resolved) in observed
    assert ("components", resolved) in observed


def test_runtime_context_never_degrades_a_checkpoint_interruption_to_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded_tools = SimpleNamespace(value=object(), sha256="a" * 64)
    loaded_rules = SimpleNamespace(value=object(), sha256="b" * 64)
    monkeypatch.setattr(tools, "load_tool_lock", lambda _path: loaded_tools)
    monkeypatch.setattr(tools, "load_rules_lock", lambda _path: loaded_rules)
    monkeypatch.setattr(tools, "validate_runtime_lock_contract", lambda _value: None)
    monkeypatch.setattr(tools, "external_tool_ids", lambda: {"fixture"})
    monkeypatch.setattr(
        tools,
        "tool_runtime_state",
        lambda tool_id: {"id": tool_id, "status": "ready"},
    )

    def resolve(_root: Path, **kwargs: object) -> object:
        checkpoint = kwargs["checkpoint"]
        assert callable(checkpoint)
        checkpoint()
        raise AssertionError("checkpoint must interrupt resolution")

    monkeypatch.setattr(tools, "resolve_active_generation_cached", resolve)

    def interrupt() -> None:
        # TimeoutError is also an OSError, which ordinary cache failures catch.
        # A caller cancellation/deadline must nevertheless propagate.
        raise TimeoutError("scanner deadline")

    with pytest.raises(TimeoutError, match="scanner deadline"):
        tools.scanner_runtime_context(
            tool_lock_path=Path("tools.lock"),
            rules_lock_path=Path("rules.lock"),
            cache_root=Path("cache"),
            checkpoint=interrupt,
        )


def test_tools_endpoint_reuses_the_binary_snapshot_used_for_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    external_ids = tools.external_tool_ids()
    snapshot = {
        tool_id: {
            "id": tool_id,
            "available": True,
            "status": "ready",
            "installed_version": tools.EXTERNAL_TOOL_VERSIONS[tool_id],
        }
        for tool_id in external_ids
    }
    context = SimpleNamespace(
        runtime_by_id=snapshot,
        readiness_by_id={
            tool_id: tools._invalid_external_readiness(tool_id)
            for tool_id in external_ids
        },
        generation_id="a" * 64,
        resolved=None,
    )
    monkeypatch.setattr(tools, "scanner_runtime_context", lambda **_kwargs: context)
    sampled: list[str] = []

    def sample(tool_id: str) -> dict[str, object]:
        sampled.append(tool_id)
        return {
            "id": tool_id,
            "available": True,
            "status": "ready",
            "installed_version": "internal",
        }

    monkeypatch.setattr(tools, "tool_runtime_state", sample)

    result = tools.scanner_tools_snapshot_with_runtime(
        tool_lock_path=Path("tools.lock"),
        rules_lock_path=Path("rules.lock"),
        cache_root=Path("cache"),
    )

    assert set(sampled) == tools.internal_tool_ids()
    assert result.active_generation == "a" * 64
    observed = {item["id"]: item for item in result.tools}
    for tool_id in external_ids:
        assert (
            observed[tool_id]["installed_version"]
            == tools.EXTERNAL_TOOL_VERSIONS[tool_id]
        )


@pytest.mark.parametrize(
    ("output", "expected", "matches"),
    [
        ("Version: 0.73.0", "0.73.0", True),
        ("trufflehog 3.96.0", "3.96.0", True),
        ("opengrep v1.27.0 (python 3.12.4)", "1.27.0", True),
        ("version 0.73.1", "0.73.0", False),
        ("python 3.12.4", "3.3.10", False),
    ],
)
def test_version_match_uses_complete_tokens(
    output: str, expected: str, matches: bool
) -> None:
    assert tools.version_output_matches(output, expected) is matches


@pytest.mark.parametrize("platform", ["mac", "linux", "windows"])
def test_build_verifier_requires_every_binary_and_exact_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, platform: str,
) -> None:
    binaries: dict[str, Path] = {}
    for tool_id, command in tools.TOOL_VERSION_COMMANDS.items():
        binary = tmp_path / command[0]
        binary.write_text(tool_id, encoding="utf-8")
        binaries[command[0]] = binary
    opengrep_core = (
        tmp_path / "opengrep-home" / ".cache" / "opengrep" / "v1.27.0" / "opengrep.bin"
    )
    opengrep_core.parent.mkdir(parents=True)
    opengrep_core.write_bytes(b"native opengrep core")
    opengrep_core.chmod(0o555)
    opengrep_executable = opengrep_core.with_name("opengrep")
    opengrep_executable.symlink_to(opengrep_core.name)

    monkeypatch.setattr(verify_tools.shutil, "which", lambda name: str(binaries[name]))
    monkeypatch.setattr(verify_tools, "OPENGREP_CORE_PATH", opengrep_core)
    monkeypatch.setattr(verify_tools, "OPENGREP_EXECUTABLE_PATH", opengrep_executable)
    monkeypatch.setattr(verify_tools, "OPENGREP_HOME_PATH", opengrep_core.parents[3])
    monkeypatch.setattr(
        verify_tools,
        "_bounded_version_output",
        lambda command, **_kwargs: (
            f"{command[0]} {EXPECTED_VERSIONS[next(key for key, value in tools.TOOL_VERSION_COMMANDS.items() if value == command)]}"
        ),
    )
    manifest = verify_tools.verified_manifest(platform=platform)
    assert manifest["schema_version"] == 1
    assert set(manifest["tools"]) == set(EXPECTED_VERSIONS)
    assert manifest["tools"]["syft"]["sha256"] == hashlib.sha256(b"syft").hexdigest()
    assert manifest["tools"]["opengrep"]["runtime_components"] == {
        "opengrep_core": {
            "path": str(opengrep_core),
            "sha256": hashlib.sha256(b"native opengrep core").hexdigest(),
        }
    }

    monkeypatch.setattr(
        verify_tools.shutil,
        "which",
        lambda name: None if name == "bearer" else str(binaries[name]),
    )
    with pytest.raises(
        RuntimeError, match="required scanner binary is missing: bearer"
    ):
        verify_tools.verified_manifest(platform=platform)


@pytest.mark.parametrize("platform,factor", [("mac", 1), ("linux", 2.6), ("windows", 3.9)])
def test_version_probe_uses_one_bounded_configured_deadline(
    monkeypatch: pytest.MonkeyPatch, platform: str, factor: float,
) -> None:
    assert verify_tools.DEFAULT_VERSION_PROBE_TIMEOUT_SECONDS == 30
    assert verify_tools.MAX_VERSION_PROBE_TIMEOUT_SECONDS == 60
    waits: list[int] = []

    class CompletedProcess:
        pid = 123

        def wait(self, timeout: int) -> int:
            waits.append(timeout)
            return 0

    monkeypatch.setattr(
        verify_tools.subprocess,
        "Popen",
        lambda *_args, **_kwargs: CompletedProcess(),
    )

    assert verify_tools._bounded_version_output(
        ["checkov", "--version"],
        timeout_seconds=30, platform=platform,
    ) == ""
    assert waits == [30 * factor]
    for invalid in (True, 0, 61):
        with pytest.raises(ValueError, match="version probe timeout"):
            verify_tools._version_probe_timeout(invalid)


@pytest.mark.parametrize("platform,factor", [("mac", 1), ("linux", 2.6), ("windows", 3.9)])
def test_version_probe_timeout_kills_and_reaps_its_process_group(
    monkeypatch: pytest.MonkeyPatch, platform: str, factor: float,
) -> None:
    waits: list[int] = []
    killed: list[tuple[int, signal.Signals]] = []

    class TimedOutProcess:
        pid = 456

        def wait(self, timeout: int) -> int:
            waits.append(timeout)
            if len(waits) == 1:
                raise subprocess.TimeoutExpired("checkov", timeout)
            return -signal.SIGKILL

    monkeypatch.setattr(
        verify_tools.subprocess,
        "Popen",
        lambda *_args, **_kwargs: TimedOutProcess(),
    )
    monkeypatch.setattr(
        verify_tools.os,
        "killpg",
        lambda pid, signal_number: killed.append((pid, signal_number)),
    )

    with pytest.raises(RuntimeError, match="version probe timed out: checkov"):
        verify_tools._bounded_version_output(
            ["checkov", "--version"],
            timeout_seconds=30, platform=platform,
        )
    assert waits == [30 * factor, 5]
    assert killed == [(456, signal.SIGKILL)]


def test_version_probe_uses_only_the_baked_home_for_opengrep(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baked_home = tmp_path / "baked-opengrep-home"
    baked_executable = baked_home / ".cache" / "opengrep" / "v1.27.0" / "opengrep"
    monkeypatch.setattr(verify_tools, "OPENGREP_HOME_PATH", baked_home)
    monkeypatch.setattr(verify_tools, "OPENGREP_EXECUTABLE_PATH", baked_executable)
    monkeypatch.setenv("HOME", "/untrusted/runtime-home")

    opengrep_environment = verify_tools._version_environment(["opengrep", "--version"])
    assert opengrep_environment["HOME"] == str(baked_home)
    assert opengrep_environment["PATH"].split(os.pathsep)[0] == str(
        baked_executable.parent
    )
    assert verify_tools._version_environment(["trivy", "--version"])["HOME"] == (
        "/untrusted/runtime-home"
    )


def test_runtime_readiness_requires_manifest_version_path_and_unchanged_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "trivy"
    binary.write_bytes(b"candidate executable")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "tools": {
                    "trivy": {
                        "installed_version": EXPECTED_VERSIONS["trivy"],
                        "path": str(binary),
                        "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(tools, "TOOL_MANIFEST_PATH", manifest)
    monkeypatch.setattr(
        tools.shutil, "which", lambda name: str(binary) if name == "trivy" else None
    )
    tools._verified_tool_manifest.cache_clear()
    assert tools.tool_runtime_state("trivy") == {
        "id": "trivy",
        "available": True,
        "status": "ready",
        "installed_version": EXPECTED_VERSIONS["trivy"],
        "runtime_identity": tools._runtime_identity("trivy", tools.observed_binary_sha256(binary)),
    }

    binary.write_bytes(b"unexpected mutation")
    assert tools.tool_runtime_state("trivy")["status"] == "binary_changed"

    manifest.write_text('{"schema_version":1,"tools":{}}', encoding="utf-8")
    tools._verified_tool_manifest.cache_clear()
    assert tools.tool_runtime_state("trivy")["status"] == "unverified"


def test_opengrep_readiness_requires_unchanged_baked_native_core(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper = tmp_path / "opengrep"
    wrapper.write_bytes(b"verified self-extracting wrapper")
    wrapper.chmod(0o555)
    core = (
        tmp_path / "opengrep-home" / ".cache" / "opengrep" / "v1.27.0" / "opengrep.bin"
    )
    core.parent.mkdir(parents=True)
    core.write_bytes(b"verified native core")
    core.chmod(0o555)
    executable = core.with_name("opengrep")
    executable.symlink_to(core.name)
    manifest = tmp_path / "manifest.json"

    def write_manifest(*, include_core: bool = True) -> None:
        entry: dict[str, object] = {
            "installed_version": EXPECTED_VERSIONS["opengrep"],
            "path": str(wrapper),
            "sha256": hashlib.sha256(wrapper.read_bytes()).hexdigest(),
        }
        if include_core:
            entry["runtime_components"] = {
                "opengrep_core": {
                    "path": str(core),
                    "sha256": hashlib.sha256(core.read_bytes()).hexdigest(),
                }
            }
        manifest.write_text(
            json.dumps({"schema_version": 1, "tools": {"opengrep": entry}}),
            encoding="utf-8",
        )

    write_manifest()
    monkeypatch.setattr(tools, "TOOL_MANIFEST_PATH", manifest)
    monkeypatch.setattr(tools, "OPENGREP_CORE_PATH", core)
    monkeypatch.setattr(tools, "OPENGREP_EXECUTABLE_PATH", executable)
    monkeypatch.setattr(
        tools.shutil,
        "which",
        lambda name: str(wrapper) if name == "opengrep" else None,
    )
    tools._verified_tool_manifest.cache_clear()
    assert tools.tool_runtime_state("opengrep") == {
        "id": "opengrep",
        "available": True,
        "status": "ready",
        "installed_version": EXPECTED_VERSIONS["opengrep"],
        "runtime_identity": tools._runtime_identity("opengrep", tools.observed_binary_sha256(wrapper), tools.observed_binary_sha256(core)),
    }

    core.chmod(0o755)
    core.write_bytes(b"unexpected replacement native core")
    assert tools.tool_runtime_state("opengrep")["status"] == "binary_changed"

    write_manifest(include_core=False)
    tools._verified_tool_manifest.cache_clear()
    assert tools.tool_runtime_state("opengrep")["status"] == "unverified"


def test_observed_binary_digest_cache_rehashes_after_metadata_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "scanner"
    binary.write_bytes(b"first")
    calls = 0
    original = tools.binary_sha256

    def counted(path: Path) -> str:
        nonlocal calls
        calls += 1
        return original(path)

    monkeypatch.setattr(tools, "binary_sha256", counted)
    first = tools.observed_binary_sha256(binary)
    assert tools.observed_binary_sha256(binary) == first
    assert calls == 1

    binary.write_bytes(b"second payload")
    second = tools.observed_binary_sha256(binary)
    assert second != first
    assert calls == 2


@pytest.mark.parametrize("platform", ["wsl", "ubuntu", "windows ", "MAC", 3, None, []])
def test_version_probe_unknown_platform_refuses_before_launch(monkeypatch, platform):
    monkeypatch.setattr(verify_tools.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("invalid lane cannot launch a probe"))
    with pytest.raises(ValueError, match="version probe platform"):
        verify_tools._bounded_version_output(["checkov", "--version"], platform=platform)
