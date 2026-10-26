from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from kodesec_scanner import data_catalog as module
from kodesec_scanner.cache_manifest import (
    CacheComponentReceipt, CacheFileRecord, CanaryReceipt, GenerationManifest,
    ResolvedGeneration, ValidatedGeneration, canonical_json_bytes, load_tool_lock, load_rules_lock,
)
from kodesec_scanner.data_catalog import DataCatalog, DataCatalogError, DataCatalogStore, binary_compatibility_sha256, generation_locks
from kodesec_scanner.release_signature import SignatureVerificationError, VerifiedBlob
from kodesec_scanner.updater import LockedLifecycleHandlers, OperationRequest, operation_request_digest

ROOT = Path(__file__).resolve().parents[3]
TOOLS = load_tool_lock(ROOT / "scanner-tools.lock.json")
RULES = load_rules_lock(ROOT / "scanner-rules.lock.json")
NOW = datetime(2026, 9, 8, tzinfo=UTC)


def catalog_payload() -> dict[str, object]:
    tools = TOOLS.value.model_dump(mode="json")
    requirement = next(item for tool in tools["tools"] for item in tool["requirements"] if item["id"] == "trivy-checks")
    requirement["source"]["sha256"] = "a" * 64
    requirement["source"]["immutable_ref"] = "ghcr.io/aquasecurity/trivy-checks@sha256:" + "a" * 64
    return {"schema_version": 1, "sequence": 1, "issued_at": "2026-09-08T00:00:00Z",
        "expires_at": "2026-09-09T00:00:00Z",
        "binary_compatibility_sha256": binary_compatibility_sha256(TOOLS.value, RULES.value),
        "tools": tools, "rules": RULES.value.model_dump(mode="json")}


class Response(io.BytesIO):
    status = 200
    def __init__(self, value: bytes, url: str):
        super().__init__(value)
        self.url = url
    def geturl(self) -> str:
        return self.url


def configured_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: dict[str, object] | None = None) -> tuple[DataCatalogStore, dict[str, bytes]]:
    tmp_path = tmp_path.resolve()
    root = tmp_path / "cache"
    root.mkdir()
    executable, trust_root, config = (tmp_path / name for name in ("cosign", "root", "scanner-data-trust.json"))
    executable.write_bytes(b"fixture executable")
    trust_root.write_bytes(b"fixture trust")
    url = "https://raw.githubusercontent.com/example/fixture/scanner-data/catalog.json"
    config.write_bytes(canonical_json_bytes({"schema_version": 1, "catalog_url": url,
        "bundle_url": url + ".sigstore.json", "cosign_path": str(executable),
        "cosign_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "trusted_root_path": str(trust_root), "trusted_root_sha256": hashlib.sha256(trust_root.read_bytes()).hexdigest(),
        "certificate_identity": "https://github.com/example/fixture/.github/workflows/data.yml@refs/heads/main",
        "oidc_issuer": "https://token.actions.githubusercontent.com"}))
    content = {url: canonical_json_bytes(payload or catalog_payload()), url + ".sigstore.json": b"fixture signed bundle"}
    class Opener:
        def open(self, request: object, timeout: int) -> Response:
            return Response(content[request.full_url], request.full_url)
    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *args: Opener())
    def verification(artifact: Path, bundle: Path, trust: object, **kwargs: object) -> VerifiedBlob:
        raw, signature = artifact.read_bytes(), bundle.read_bytes()
        return VerifiedBlob(raw, hashlib.sha256(raw).hexdigest(), hashlib.sha256(signature).hexdigest(), "f" * 64)
    monkeypatch.setattr(module, "verify_blob", verification)
    module._PROOFS.clear()
    return DataCatalogStore(root, TOOLS, RULES, trust_path=config), content


def test_data_catalog_selection_is_exact_and_generation_uses_own_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, _content = configured_store(tmp_path, monkeypatch)
    verified = store.check(checkpoint=lambda: None, now=NOW)
    assert verified.tools.sha256 != TOOLS.sha256
    assert verified.tools.value.tool("trivy").binary == TOOLS.value.tool("trivy").binary
    assert store.selected(verified.digest, now=NOW).digest == verified.digest
    with pytest.raises(DataCatalogError, match="selection"):
        store.selected("b" * 64, now=NOW)
    with pytest.raises(DataCatalogError, match="expired"):
        store.selected(verified.digest, now=datetime(2026, 9, 10, tzinfo=UTC))
    # Active resolution intentionally ignores catalog expiry/selected pointer;
    # ordinary component intrinsic freshness still controls execution.
    assert store.for_locks(verified.tools.sha256, verified.rules.sha256).digest == verified.digest
    candidate = SimpleNamespace(path=store.cache_root / "generations" / ("a" * 64),
        manifest=SimpleNamespace(tool_lock_sha256=verified.tools.sha256, rules_lock_sha256=verified.rules.sha256))
    tools_with_trust = replace(TOOLS, path=store.trust_path.with_name("scanner-tools.lock.json"))
    dynamic_tools, dynamic_rules = generation_locks(candidate, tools_with_trust, RULES)
    assert dynamic_tools.sha256 == verified.tools.sha256
    assert dynamic_rules.sha256 == verified.rules.sha256


@pytest.mark.parametrize("change", ["binary", "fixture", "freshness", "schema", "embedded_rules"])
def test_data_catalog_cannot_change_binary_or_runtime_contract(change: str) -> None:
    payload = catalog_payload()
    tool = next(tool for tool in payload["tools"]["tools"] if tool["id"] == "trivy")
    requirement = next(item for item in tool["requirements"] if item["id"] == "trivy-checks")
    if change == "binary":
        tool["version"] = "0.74.0"
    elif change == "fixture":
        requirement["canaries"][0]["fixture_sha256"] = "b" * 64
    elif change == "freshness":
        requirement["max_age_seconds"] += 1
    elif change == "schema":
        requirement["data_contract"]["major_version"] = 3
    else:
        payload["rules"]["rule_sets"][0]["requested_version"] = "changed"
    with pytest.raises(ValueError):
        DataCatalog.model_validate(payload)


def test_data_catalog_outage_preserves_selection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, content = configured_store(tmp_path, monkeypatch)
    verified = store.check(checkpoint=lambda: None, now=NOW)
    selected_path = store.cache_root / "catalogs" / "selected.json"
    before = selected_path.read_bytes()
    def unavailable(*args: object, **kwargs: object) -> object:
        raise OSError("private transport message")
    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *args: SimpleNamespace(open=unavailable))
    with pytest.raises(DataCatalogError, match="transport"):
        store.check(checkpoint=lambda: None, now=NOW)
    assert selected_path.read_bytes() == before
    assert store.selected(verified.digest, now=NOW).digest == verified.digest


def test_data_catalog_missing_trust_refuses_before_transport(tmp_path: Path) -> None:
    store = DataCatalogStore(tmp_path, TOOLS, RULES, trust_path=tmp_path / "missing")
    with pytest.raises(DataCatalogError, match="trust"):
        store.check(checkpoint=lambda: None)


def test_signed_update_digest_is_fenced_and_not_silently_baked(tmp_path: Path) -> None:
    selected = "a" * 64
    fields = {"schema_version": 1, "kind": "cache_update", "requested_components": ["trivy-checks"]}
    base_digest = operation_request_digest(**fields)
    digest = operation_request_digest(**fields, catalog_digest=selected)
    assert digest != base_digest
    request = OperationRequest(**fields, operation_id=uuid4(), request_digest=digest,
        attempt=1, max_attempts=1, catalog_digest=selected)
    with pytest.raises(ValueError):
        OperationRequest(**fields, operation_id=uuid4(), request_digest=base_digest,
            attempt=1, max_attempts=1, catalog_digest=selected)
    handler = LockedLifecycleHandlers(TOOLS, RULES, tmp_path / "cache", tmp_path / "scratch")
    with pytest.raises(DataCatalogError, match="trust"):
        handler.cache_update(SimpleNamespace(request=request))


@pytest.mark.parametrize("case", ["signature", "rollback", "cancellation"])
def test_data_catalog_failed_check_preserves_accepted_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    payload = catalog_payload()
    payload["sequence"] = 2
    store, content = configured_store(tmp_path, monkeypatch, payload)
    verified = store.check(checkpoint=lambda: None, now=NOW)
    selection = store.cache_root / "catalogs" / "selected.json"
    before = selection.read_bytes()
    url = next(url for url in content if not url.endswith("sigstore.json"))
    payload["sequence"] = 1 if case == "rollback" else 3
    content[url] = canonical_json_bytes(payload)
    if case == "signature":
        def reject(*args: object, **kwargs: object) -> object:
            raise SignatureVerificationError("signature")
        monkeypatch.setattr(module, "verify_blob", reject)
    cancellation = RuntimeError("cancel catalog check")
    calls = 0
    def checkpoint() -> None:
        nonlocal calls
        calls += 1
        if case == "cancellation" and calls == 2:
            raise cancellation
    with pytest.raises(RuntimeError if case == "cancellation" else DataCatalogError) as raised:
        store.check(checkpoint=checkpoint, now=NOW)
    if case == "cancellation":
        assert raised.value is cancellation
    assert selection.read_bytes() == before
    assert store.selected(verified.digest, now=NOW).digest == verified.digest


def test_signed_generation_readiness_and_activation_use_effective_data_locks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from kodesec_scanner import tools as runtime, updater
    store, _content = configured_store(tmp_path, monkeypatch)
    verified = store.check(checkpoint=lambda: None, now=NOW)
    rule = RULES.value.rule_set("bearer-rules")
    expected = rule.canaries[0]
    receipt = CacheComponentReceipt(component_id=rule.id, tool_id="bearer", kind="rules", root="bearer/rules",
        immutable_ref=rule.source_commit, source_sha256=rule.tree_sha256,
        updated_at="2026-09-08T00:00:00Z", expires_at=None,
        files=[CacheFileRecord(path="bearer/rules/fixture.yml", size_bytes=1, sha256="c" * 64)],
        canaries=[CanaryReceipt(canary_id=expected.id, fixture_sha256=expected.fixture_sha256,
            output_sha256=expected.output_sha256, exit_code=expected.expected_exit_code,
            result_count=expected.expected_result_count, expected_ids=sorted(expected.expected_rule_ids),
            observed_ids=sorted(expected.expected_rule_ids), passed=True)])
    manifest = GenerationManifest.create(tool_lock_sha256=verified.tools.sha256,
        rules_lock_sha256=verified.rules.sha256, created_at="2026-09-08T00:00:00Z", components=[receipt])
    generation = ValidatedGeneration(store.cache_root / "generations" / manifest.generation_id, manifest, "e" * 64)
    resolved = ResolvedGeneration("ready", generation, None)
    baked_tools = replace(TOOLS, path=store.trust_path.with_name("scanner-tools.lock.json"))
    monkeypatch.setattr(runtime, "load_tool_lock", lambda path: baked_tools)
    monkeypatch.setattr(runtime, "load_rules_lock", lambda path: RULES)
    observed_locks = {}
    def ready_runtime(tool_id, *, locked_tool=None):
        observed_locks[tool_id] = locked_tool
        return {"status": "ready"}
    monkeypatch.setattr(runtime, "tool_runtime_state", ready_runtime)
    context = runtime.scanner_runtime_context(tool_lock_path=baked_tools.path, rules_lock_path=RULES.path,
        cache_root=store.cache_root, resolver=lambda *args, **kwargs: resolved)
    assert context.tools.sha256 == verified.tools.sha256
    assert observed_locks["bearer"] == verified.tools.value.tool("bearer")
    assert context.readiness_by_id["bearer"].ready is True
    updater._validate_candidate_components(generation, ["bearer-rules"], baked_tools, RULES, evaluated_at=NOW)
    # A different component's data refresh does not make the identical existing
    # Bearer rules appear as another required download.
    monkeypatch.setattr(updater, "resolve_active_generation", lambda *args, **kwargs: resolved)
    monkeypatch.setattr(updater, "tool_runtime_state", lambda tool_id: {"installed_version": TOOLS.value.tool(tool_id).version})
    result = LockedLifecycleHandlers(verified.tools, verified.rules, store.cache_root, tmp_path / "scratch",
        evaluation_now=lambda: NOW).catalog_check(SimpleNamespace(checkpoint=lambda: None))
    assert next(item for item in result.components if item.component_id == "bearer-rules").state == "current"
    assert next(item for item in result.components if item.component_id == "trivy-checks").state == "candidate_available"
    # Missing signed authority cannot be covered by the baked lock hashes.
    (store.trust_path).unlink()
    context = runtime.scanner_runtime_context(tool_lock_path=baked_tools.path, rules_lock_path=RULES.path,
        cache_root=store.cache_root, resolver=lambda *args, **kwargs: resolved)
    assert context.readiness_by_id["bearer"].ready is False


def test_source_reviewed_default_is_explicit_and_signed_mode_is_digest_bound() -> None:
    from kodesec_scanner.settings import UpdaterSettings
    from kodesec_scanner.updater import CatalogOperationResult, CATALOG_TOOL_IDS, CACHE_COMPONENT_IDS
    assert UpdaterSettings(_env_file=None).data_catalog_mode == "source-reviewed/bundled"
    fields = {"kind": "catalog", "checked_at": "2026-09-08T00:00:00Z",
        "tools": [{"tool_id": tool, "state": "unavailable"} for tool in CATALOG_TOOL_IDS],
        "components": [{"component_id": component, "state": "unavailable"} for component in CACHE_COMPONENT_IDS]}
    result = CatalogOperationResult.model_validate(fields)
    assert result.catalog_mode == "source-reviewed/bundled" and result.catalog_digest is None
    for extra in ({"catalog_mode": "signed"}, {"catalog_digest": "a" * 64}):
        with pytest.raises(ValueError):
            CatalogOperationResult.model_validate({**fields, **extra})
    result = CatalogOperationResult.model_validate({**fields, "catalog_mode": "signed", "catalog_digest": "a" * 64})
    assert result.catalog_digest == "a" * 64


def test_catalog_retention_is_bounded_and_recovers_only_owned_check_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, content = configured_store(tmp_path, monkeypatch)
    url = next(url for url in content if not url.endswith("sigstore.json"))
    first = store.check(checkpoint=lambda: None, now=NOW)
    orphan = store.cache_root / "catalogs" / "check-abcdefgh"
    orphan.mkdir(mode=0o700)
    (orphan / "catalog.json").write_bytes(b"interrupted metadata only")
    for sequence in range(2, 7):
        payload = catalog_payload()
        payload["sequence"] = sequence
        source = next(item["source"] for tool in payload["tools"]["tools"]
            for item in tool["requirements"] if item["id"] == "trivy-checks")
        source["sha256"] = f"{sequence:064x}"
        source["immutable_ref"] = "ghcr.io/aquasecurity/trivy-checks@sha256:" + source["sha256"]
        content[url] = canonical_json_bytes(payload)
        selected = store.check(checkpoint=lambda: None, now=NOW)
        assert store.selected(selected.digest, now=NOW).catalog.sequence == sequence
        directories = [path for path in (store.cache_root / "catalogs").iterdir() if path.is_dir()]
        assert len(directories) <= 2  # current and immediately preceding selection
    assert not orphan.exists()
    assert first.digest != selected.digest


def test_catalog_metadata_only_renewal_is_refused_without_reselecting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, content = configured_store(tmp_path, monkeypatch)
    accepted = store.check(checkpoint=lambda: None, now=NOW)
    selected = (store.cache_root / "catalogs" / "selected.json").read_bytes()
    payload = catalog_payload()
    payload["sequence"] = 2
    url = next(url for url in content if not url.endswith("sigstore.json"))
    content[url] = canonical_json_bytes(payload)
    with pytest.raises(DataCatalogError, match="rollback"):
        store.check(checkpoint=lambda: None, now=NOW)
    assert (store.cache_root / "catalogs" / "selected.json").read_bytes() == selected
    assert store.selected(accepted.digest, now=NOW).catalog.sequence == 1
