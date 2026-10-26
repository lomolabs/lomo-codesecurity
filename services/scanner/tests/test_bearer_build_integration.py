"""Pure source preflight; no native build or platform qualification is implied."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shlex
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from kodesec_scanner import tools
from kodesec_scanner.cache_manifest import (
    CacheValidationError, load_rules_lock, load_tool_lock,
    runtime_components_from_resolved, validate_lock_alignment,
)

ROOT = Path(__file__).resolve().parents[3]


def _builder():
    spec = importlib.util.spec_from_file_location(
        "scanner_build_receipt_bearer_integration", ROOT / "scripts/scanner-build-receipt.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


builder = _builder()


def test_source_recipe_is_complete_in_the_frozen_build_context():
    evidence = builder.collect_build_inputs(identity=builder.require_host_identity())
    files = {item["path"]: item for item in evidence["files"]}
    recipe_path = "services/scanner/bearer/source.lock.json"
    recipe = json.loads((ROOT / recipe_path).read_bytes())
    assert builder.FROM_DIRECTIVES[0] == f"FROM {recipe['toolchain']['image']} AS bearer-build"
    for name, expected in recipe["inputs"].items():
        assert files[f"services/scanner/bearer/{name}"]["sha256"] == expected
    source_lock = load_tool_lock(ROOT / "scanner-tools.lock.json").value.tool("bearer").binary.source_build
    assert files[recipe_path]["sha256"] == source_lock.recipe_sha256
    # Generated outputs are never mistaken for repository build inputs.
    assert not any(path.startswith("/out/") for path in files)


def test_archive_download_is_exact_and_bounded_then_build_is_offline():
    dockerfile = (ROOT / builder.DOCKERFILE_PATH).read_text()
    stage, runtime = dockerfile.split(builder.FROM_DIRECTIVES[1], 1)
    recipe = json.loads((ROOT / "services/scanner/bearer/source.lock.json").read_bytes())
    commands = stage.replace("\\\n", " ").splitlines()
    fetch = next(line for line in commands if line.startswith("RUN kodesec-fetch-locked-asset "))
    arguments = shlex.split(fetch)[2:]
    assert arguments[:4] == [recipe["source"]["archive_url"], "/tmp/bearer.tar.gz",
                             recipe["source"]["archive_sha256"], str(recipe["source"]["archive_bytes"])]
    assert ("RUN python3 /recipe/source-build.py dependencies --source /src "
            "--output /dependency-output") in commands
    assert ("RUN --network=none python3 /recipe/source-build.py build --source /src "
            "--output /out") in commands
    assert "GOARCH=" not in dockerfile and "GOOS=" not in dockerfile
    assert "Bearer/bearer/releases/download" not in runtime
    assert "bearer_sha256=" not in runtime


@pytest.mark.parametrize("extra", [
    "COPY --from=bearer-build /usr/local/go /usr/local/go",
    "COPY --from=bearer-build /src /src",
    "COPY --from=bearer-build /recipe/lomo.patch /usr/local/share/kodesec/lomo.patch",
    "COPY --from=bearer-build /out/logs /usr/local/share/kodesec/logs",
])
def test_runtime_copy_contract_rejects_compiler_source_patch_and_logs(extra):
    payload = (ROOT / builder.DOCKERFILE_PATH).read_bytes()
    builder._validate_dockerfile(payload)
    with pytest.raises(builder.BuildReceiptError, match="dockerfile_copy_contract_changed"):
        builder._validate_dockerfile(payload + b"\n" + extra.encode() + b"\n")


@pytest.mark.parametrize("old,new", [
    ("golang:1.26.8-bookworm@sha256:", "golang:latest@sha256:"),
    ("RUN --network=none python3 /recipe/source-build.py build",
     "RUN --network=default python3 /recipe/source-build.py build"),
    ("ARG BEARER_VERSION=2.1.0+lomo.1", "ARG BEARER_VERSION=2.1.0"),
    ("ARG SCANNER_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS=900", "ARG SCANNER_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS=0"),
])
def test_source_build_preflight_refuses_changed_stage_or_version(old, new):
    payload = (ROOT / builder.DOCKERFILE_PATH).read_bytes()
    with pytest.raises(builder.BuildReceiptError):
        builder._validate_dockerfile(payload.replace(old.encode(), new.encode(), 1))


def test_modified_tool_rule_and_runtime_expectations_are_one_exact_identity():
    locked = load_tool_lock(ROOT / "scanner-tools.lock.json")
    rules = load_rules_lock(ROOT / "scanner-rules.lock.json")
    validate_lock_alignment(locked.value, rules.value)
    bearer = locked.value.tool("bearer")
    assert bearer.version == tools.EXTERNAL_TOOL_VERSIONS["bearer"] == "2.1.0+lomo.1"
    assert bearer.binary.artifacts == []
    assert 'RUN test "${BEARER_VERSION}" = "2.1.0+lomo.1"' in (ROOT / builder.DOCKERFILE_PATH).read_text()
    assert rules.value.rule_set("bearer-rules").engine_version == bearer.version


def test_stock_cache_identity_is_rejected_before_component_readiness():
    locked = load_tool_lock(ROOT / "scanner-tools.lock.json")
    rules = load_rules_lock(ROOT / "scanner-rules.lock.json")
    # Distinct historical stock locks cannot authorize the modified runtime.
    old_tool = "885cde4bc7a884455cce3448ff55a13025ae06597070217b6e4740107d98fb54"
    old_rules = "39358b2930c1ec86d0d68153135ad856d2cd295f3d35928a5a16e32d6086b9f0"
    assert locked.sha256 != old_tool and rules.sha256 != old_rules
    resolved = SimpleNamespace(state="ready", generation=SimpleNamespace(manifest=SimpleNamespace(
        tool_lock_sha256=old_tool, rules_lock_sha256=old_rules,
    )))
    with pytest.raises(CacheValidationError, match="built from different locks"):
        runtime_components_from_resolved(resolved, locked, rules, [])
