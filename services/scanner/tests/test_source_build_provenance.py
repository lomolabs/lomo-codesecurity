"""Source-build packaging boundaries; fixtures do not qualify native builds."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from kodesec_scanner import source_build
from kodesec_scanner.cache_manifest import BinarySourceBuildLock, ToolLockFile


ROOT = Path(__file__).resolve().parents[3]


def _stock_document():
    # Explicit upstream fixture keeps legacy tests independent of production adoption.
    document = json.loads((ROOT / "scanner-tools.lock.json").read_bytes())
    stock = json.loads((Path(__file__).parent / "fixtures/bearer-stock-2.1.0.json").read_bytes())
    bearer = next(item for item in document["tools"] if item["id"] == "bearer")
    bearer["version"] = stock["version"]
    bearer["binary"] = stock["binary"]
    return document


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _lock(recipe_raw: bytes) -> BinarySourceBuildLock:
    return BinarySourceBuildLock(
        kind="bearer-source-build", recipe_ref="repo:services/scanner/bearer/source.lock.json",
        recipe_sha256=_digest(recipe_raw), output_version="2.1.0+lomo.1",
        platforms=["linux/amd64", "linux/arm64"],
    )


def _producer_test_packages():
    """Derive fixtures from the actual producer, independently of the verifier."""
    module = ast.parse((ROOT / "services/scanner/bearer/source-build.py").read_text())
    selections = next(ast.literal_eval(node.value) for node in module.body
                      if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "TESTS"
                              for target in node.targets))
    return tuple(package.removeprefix("./") for package, _pattern in selections)


@pytest.fixture
def packaged(tmp_path, monkeypatch):
    directory = tmp_path / "builds" / "bearer"
    directory.mkdir(parents=True)
    recipe_dir = ROOT / "services/scanner/bearer"
    recipe_raw = (recipe_dir / "source.lock.json").read_bytes()
    recipe = json.loads(recipe_raw)
    (directory / "source.lock.json").write_bytes(recipe_raw)
    for name in ("LICENSE.txt", "NOTICE"):
        (directory / name).write_bytes((recipe_dir / name).read_bytes())
    binary = tmp_path / "bearer"
    binary.write_bytes(b"synthetic packaging fixture, not an executable")
    tests = [{
        "package": "github.com/bearer/bearer/" + package,
        "top_tests": ["TestFixture"], "started_tests": ["TestFixture", "TestFixture/child"],
        "passed_tests": ["TestFixture", "TestFixture/child"], "skipped_tests": 0,
    } for package in _producer_test_packages()]
    steps = ["go-env", "go-mod-verify", "go-deps", "go-build", "go-symbols", "build-info", "elf"]
    steps += [f"test-{index}" for index in range(len(tests))]
    receipt = {
        "schema_version": 1, "kind": "bearer-source-build-output",
        "source_commit": recipe["source"]["commit"],
        "source_archive_sha256": recipe["source"]["archive_sha256"],
        "source_lock_sha256": _digest(recipe_raw), "inputs": recipe["inputs"],
        "toolchain": recipe["toolchain"],
        "go_env": {"GOVERSION": "go1.26.8", "GOOS": "linux", "GOARCH": "arm64", "CGO_ENABLED": "1"},
        "semantic_tests": tests, "platform": "linux/arm64", "version": "2.1.0+lomo.1",
        "binary_sha256": _digest(binary.read_bytes()), "binary_bytes": binary.stat().st_size,
        "private_probes_absent": True,
        "logs": {f"logs/{step}.{stream}": "a" * 64 for step in steps for stream in ("stdout", "stderr")},
    }
    def write():
        (directory / "build.json").write_text(json.dumps(receipt))
    write()
    monkeypatch.setattr(source_build.platform, "system", lambda: "Linux")
    monkeypatch.setattr(source_build.platform, "machine", lambda: "aarch64")
    return _lock(recipe_raw), binary, directory, receipt, write


def test_stock_lock_projection_is_unchanged_and_source_build_cannot_reuse_stock_artifacts():
    document = _stock_document()
    old = ToolLockFile.model_validate(document)
    assert all("source_build" not in tool["binary"] for tool in old.model_dump(mode="json")["tools"])
    changed = copy.deepcopy(document)
    bearer = next(item for item in changed["tools"] if item["id"] == "bearer")
    recipe = (ROOT / "services/scanner/bearer/source.lock.json").read_bytes()
    bearer["binary"]["source_build"] = _lock(recipe).model_dump(mode="json")
    bearer["version"] = "2.1.0+lomo.1"
    with pytest.raises(ValidationError, match="mutually exclusive"):
        ToolLockFile.model_validate(changed)
    bearer["binary"]["artifacts"] = []
    accepted = ToolLockFile.model_validate(changed)
    assert accepted.tool("bearer").binary.source_build.recipe_sha256 == _digest(recipe)
    bearer["version"] = "2.1.0"
    with pytest.raises(ValidationError, match="exact Bearer tool identity"):
        ToolLockFile.model_validate(changed)


def test_build_output_binds_binary_native_identity_recipe_and_notices(packaged):
    locked, binary, directory, receipt, _ = packaged
    proof = source_build.verify_source_build(locked, binary, root=directory.parent)
    assert proof == {
        "kind": "bearer-source-build", "recipe_sha256": locked.recipe_sha256,
        "receipt_sha256": _digest((directory / "build.json").read_bytes()),
        "platform": "linux/arm64", "binary_sha256": receipt["binary_sha256"],
    }


@pytest.mark.parametrize("damage", ["binary", "license", "notice", "recipe", "symlink", "duplicate_json"])
def test_packaging_damage_is_rejected(packaged, damage):
    locked, binary, directory, _, _ = packaged
    paths = {"binary": binary, "license": directory / "LICENSE.txt", "notice": directory / "NOTICE",
             "recipe": directory / "source.lock.json"}
    if damage in paths:
        path = paths[damage]
        path.write_bytes(path.read_bytes() + b"changed")
    elif damage == "symlink":
        payload = binary.read_bytes()
        binary.unlink()
        (binary.parent / "other").write_bytes(payload)
        binary.symlink_to("other")
    else:
        path = directory / "build.json"
        path.write_bytes(path.read_bytes().replace(b'{', b'{"version":"2.1.0",', 1))
    with pytest.raises(ValueError):
        source_build.verify_source_build(locked, binary, root=directory.parent)


@pytest.mark.parametrize("damage", ["schema", "architecture", "compiler", "version", "probe", "unfinished", "skipped", "package", "missing_package", "extra_package", "log", "missing_platform_tests", "package_order"])
def test_unproven_or_different_build_cannot_seal_manifest(packaged, damage):
    locked, binary, directory, receipt, write = packaged
    if damage == "schema":
        receipt["schema_version"] = True
    elif damage == "architecture":
        receipt["platform"] = "linux/amd64"
    elif damage == "compiler":
        receipt["go_env"]["GOVERSION"] = "go1.20.0"
    elif damage == "version":
        receipt["version"] = "2.1.0"
    elif damage == "probe":
        receipt["private_probes_absent"] = False
    elif damage == "unfinished":
        receipt["semantic_tests"][0]["passed_tests"].pop()
    elif damage == "skipped":
        receipt["semantic_tests"][0]["skipped_tests"] = 1
    elif damage == "package":
        receipt["semantic_tests"][1] = receipt["semantic_tests"][0]
    elif damage == "missing_package":
        receipt["semantic_tests"].pop(4)
    elif damage == "extra_package":
        receipt["semantic_tests"].append(copy.deepcopy(receipt["semantic_tests"][0]))
    elif damage == "missing_platform_tests":
        receipt["semantic_tests"] = receipt["semantic_tests"][2:]
    elif damage == "package_order":
        receipt["semantic_tests"][:2] = reversed(receipt["semantic_tests"][:2])
    else:
        receipt["logs"].pop("logs/go-build.stderr")
    write()
    with pytest.raises(ValueError):
        source_build.verify_source_build(locked, binary, root=directory.parent)


@pytest.fixture
def runtime_packaged(packaged, monkeypatch):
    from kodesec_scanner import tools
    locked, binary, directory, receipt, write = packaged
    document = json.loads((ROOT / "scanner-tools.lock.json").read_bytes())
    bearer = next(item for item in document["tools"] if item["id"] == "bearer")
    bearer["version"] = locked.output_version
    bearer["binary"]["artifacts"] = []
    bearer["binary"]["source_build"] = locked.model_dump(mode="json")
    tool_document = ToolLockFile.model_validate(document)
    proof = source_build.verify_source_build(locked, binary, root=directory.parent)
    manifest = {
        "installed_version": locked.output_version, "path": str(binary),
        "sha256": receipt["binary_sha256"], "source_build": proof,
    }
    monkeypatch.setattr(source_build, "BUILD_ROOT", directory.parent)
    monkeypatch.setattr(tools, "shutil", type("Lookup", (), {"which": staticmethod(lambda _name: str(binary))}))
    monkeypatch.setattr(tools, "_verified_tool_manifest", lambda: {"bearer": manifest})
    monkeypatch.setattr(tools, "SCANNER_TOOLS", [dict(item, version=locked.output_version)
                       if item["id"] == "bearer" else item for item in tools.SCANNER_TOOLS])
    monkeypatch.setattr(tools, "_runtime_identity", lambda name, *parts: _digest("\0".join((name, *parts)).encode()))
    tools._binary_sha256_for_stat.cache_clear()
    return tool_document, binary, directory, receipt, write, manifest


def test_runtime_revalidates_small_metadata_and_reuses_observed_binary_digest(runtime_packaged, monkeypatch):
    from kodesec_scanner import tools
    document, binary, directory, receipt, write, manifest = runtime_packaged
    observed = []
    original_digest = tools.binary_sha256
    monkeypatch.setattr(tools, "binary_sha256", lambda path: (observed.append(path), original_digest(path))[1])
    bounded = source_build._read_bounded_regular_file
    def metadata_only(path, maximum, description):
        assert path != binary, "readiness must not re-read the binary through provenance verification"
        assert maximum <= 1024 * 1024
        return bounded(path, maximum, description)
    monkeypatch.setattr(source_build, "_read_bounded_regular_file", metadata_only)
    first = tools.tool_runtime_state("bearer", locked_tool=document.tool("bearer"))
    second = tools.tool_runtime_state("bearer", locked_tool=document.tool("bearer"))
    assert first == second and first["status"] == "ready"
    assert observed == [binary]
    receipt["logs"]["logs/go-build.stdout"] = "b" * 64
    write()
    # A different otherwise valid build receipt changes authorization identity.
    manifest["source_build"]["receipt_sha256"] = _digest((directory / "build.json").read_bytes())
    changed = tools.tool_runtime_state("bearer", locked_tool=document.tool("bearer"))
    assert changed["status"] == "ready" and changed["runtime_identity"] != first["runtime_identity"]
    assert observed == [binary]


@pytest.mark.parametrize("damage", ["missing_proof", "extra_proof", "missing_receipt", "receipt", "recipe", "notice", "native", "digest"])
def test_runtime_source_provenance_drift_refuses(runtime_packaged, monkeypatch, damage):
    from kodesec_scanner import tools
    document, _, directory, receipt, write, manifest = runtime_packaged
    if damage == "missing_proof":
        manifest.pop("source_build")
    elif damage == "extra_proof":
        manifest["source_build"]["unexpected"] = "accepted"
    elif damage == "missing_receipt":
        (directory / "build.json").unlink()
    elif damage == "receipt":
        receipt["logs"]["logs/go-build.stdout"] = "b" * 64
        write()
    elif damage in {"recipe", "notice"}:
        path = directory / ("source.lock.json" if damage == "recipe" else "NOTICE")
        path.write_bytes(path.read_bytes() + b"changed")
    elif damage == "native":
        monkeypatch.setattr(source_build.platform, "machine", lambda: "x86_64")
    else:
        manifest["source_build"]["binary_sha256"] = "b" * 64
    state = tools.tool_runtime_state("bearer", locked_tool=document.tool("bearer"))
    assert state == {"id": "bearer", "available": False, "status": "unverified",
                     "installed_version": "2.1.0+lomo.1"}


def test_standalone_runtime_uses_configured_lock_and_stock_cannot_accept_source_metadata(runtime_packaged, monkeypatch):
    from types import SimpleNamespace
    from kodesec_scanner import settings, tools
    document, _, directory, _, _, manifest = runtime_packaged
    configured = directory.parent / "configured-tools.json"
    configured.write_text(document.model_dump_json())
    monkeypatch.setattr(settings, "get_settings", lambda: SimpleNamespace(tool_lock_path=str(configured)))
    assert tools.tool_runtime_state("bearer")["status"] == "ready"
    stock = ToolLockFile.model_validate(_stock_document())
    configured.write_text(stock.model_dump_json())
    assert tools.tool_runtime_state("bearer")["status"] == "unverified"
    manifest.pop("source_build")
    assert tools.tool_runtime_state("bearer", locked_tool=stock.tool("bearer"))["status"] == "unverified"


def test_context_verifies_generation_selected_lock_not_default_configured_lock(runtime_packaged, monkeypatch):
    from types import SimpleNamespace
    from kodesec_scanner import settings, tools
    from kodesec_scanner.cache_manifest import LoadedDocument
    document, _, directory, _, _, _ = runtime_packaged
    stock = ToolLockFile.model_validate(_stock_document())
    configured = directory.parent / "configured-tools.json"
    configured.write_text(stock.model_dump_json())
    monkeypatch.setattr(settings, "get_settings", lambda: SimpleNamespace(tool_lock_path=str(configured)))
    selected = LoadedDocument(value=document, sha256="b" * 64, path=configured)
    original = LoadedDocument(value=stock, sha256="a" * 64, path=configured)
    rules = SimpleNamespace(sha256="c" * 64)
    monkeypatch.setattr(tools, "load_tool_lock", lambda path: original if path == configured else selected)
    monkeypatch.setattr(tools, "load_rules_lock", lambda _path: rules)
    monkeypatch.setattr(tools, "external_tool_ids", lambda: {"bearer"})
    monkeypatch.setattr(tools, "validate_runtime_lock_contract", lambda _document: None)
    monkeypatch.setattr(tools, "generation_locks", lambda *_args, **_kw: (selected, rules))
    monkeypatch.setattr(tools, "evaluate_tool_readiness", lambda *_args: [])
    resolved = SimpleNamespace(generation=object(), state="ready")
    observations = []
    original_runtime = tools.tool_runtime_state
    def observe(name, **kw):
        observations.append(kw.get("locked_tool"))
        return original_runtime(name, **kw)
    monkeypatch.setattr(tools, "tool_runtime_state", observe)
    context = tools.scanner_runtime_context(tool_lock_path=configured, rules_lock_path=directory / "rules.json",
                                           cache_root=directory, resolver=lambda *_args, **_kw: resolved)
    assert observations == [selected.value.tool("bearer")]
    assert context.tools is selected
    assert context.runtime_by_id["bearer"]["status"] == "ready"
    # The same receipt cannot authorize a generation selecting the stock recipe.
    monkeypatch.setattr(tools, "generation_locks", lambda *_args, **_kw: (original, rules))
    context = tools.scanner_runtime_context(tool_lock_path=configured, rules_lock_path=directory / "rules.json",
                                           cache_root=directory, resolver=lambda *_args, **_kw: resolved)
    assert context.runtime_by_id["bearer"]["status"] == "unverified"


def test_absent_default_lock_preserves_exact_stock_development_lane(runtime_packaged, monkeypatch):
    from types import SimpleNamespace
    from kodesec_scanner import settings, tools
    _, _, directory, _, _, manifest = runtime_packaged
    missing = directory.parent / "absent-tools.json"
    monkeypatch.setattr(settings, "get_settings", lambda: SimpleNamespace(tool_lock_path=str(missing)))
    # Source-built expectation and metadata always fail closed without a lock.
    assert tools.tool_runtime_state("bearer")["status"] == "unverified"
    manifest.pop("source_build")
    assert tools.tool_runtime_state("bearer")["status"] == "unverified"
    manifest["installed_version"] = "2.1.0"
    monkeypatch.setattr(tools, "SCANNER_TOOLS", [dict(item, version="2.1.0")
                       if item["id"] == "bearer" else item for item in tools.SCANNER_TOOLS])
    assert tools.tool_runtime_state("bearer")["status"] == "ready"
    # An existing invalid document is different from an absent stock dev lock.
    missing.write_text('{"invalid":true}')
    assert tools.tool_runtime_state("bearer")["status"] == "unverified"


@pytest.mark.parametrize("entry", [None, 7, "invalid", []])
def test_malformed_bearer_manifest_context_is_unverified_not_exception(runtime_packaged, monkeypatch, entry):
    from types import SimpleNamespace
    from kodesec_scanner import tools
    from kodesec_scanner.cache_manifest import LoadedDocument
    _, _, directory, _, _, _ = runtime_packaged
    stock = ToolLockFile.model_validate(_stock_document())
    selected = LoadedDocument(value=stock, sha256="a" * 64, path=directory / "tools.json")
    monkeypatch.setattr(tools, "_verified_tool_manifest", lambda: {"bearer": entry})
    monkeypatch.setattr(tools, "external_tool_ids", lambda: {"bearer"})
    monkeypatch.setattr(tools, "load_tool_lock", lambda _path: selected)
    monkeypatch.setattr(tools, "load_rules_lock", lambda _path: SimpleNamespace(sha256="b" * 64))
    monkeypatch.setattr(tools, "validate_runtime_lock_contract", lambda _document: None)
    observed = []
    def evaluate(_tools, _rules, _resolved, binary_states):
        observed.append(binary_states)
        return []
    monkeypatch.setattr(tools, "evaluate_tool_readiness", evaluate)
    context = tools.scanner_runtime_context(
        tool_lock_path=selected.path, rules_lock_path=directory / "rules.json", cache_root=directory,
        resolver=lambda *_args, **_kw: SimpleNamespace(generation=None, state="ready"),
    )
    assert context.runtime_by_id["bearer"]["status"] == "unverified"
    assert observed == [{"bearer": "unverified"}]
