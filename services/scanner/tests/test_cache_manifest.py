from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from kodesec_scanner import cache_manifest
from kodesec_scanner.cache_manifest import (
    CacheActivationError,
    CacheComponentReceipt,
    CacheFileRecord,
    CacheValidationError,
    CanaryReceipt,
    CANONICAL_TREE_HASH_ALGORITHM,
    GenerationManifest,
    GENERATION_HASH_CHECKPOINT_BYTES,
    LockValidationError,
    RuleSetLock,
    ResolvedGeneration,
    activate_generation,
    canonical_tree_sha256,
    canonical_json_bytes,
    collect_canonical_tree,
    evaluate_tool_readiness,
    load_rules_lock,
    load_tool_lock,
    resolve_active_generation,
    rollback_to_previous_good,
    validate_lock_alignment,
    validate_generation,
    write_generation_manifest,
)


ROOT = Path(__file__).resolve().parents[3]
TOOLS_LOCK = ROOT / "scanner-tools.lock.json"
RULES_LOCK = ROOT / "scanner-rules.lock.json"
OPERATION_ID = str(UUID("123e4567-e89b-42d3-a456-426614174000"))


def _prepare_generation(
    cache_root: Path,
    *,
    content: bytes,
    created_at: str = "2026-08-12T20:00:00Z",
) -> GenerationManifest:
    cache_root.mkdir(mode=0o700)
    generations = cache_root / "generations"
    generations.mkdir(mode=0o700)
    stage = generations / "stage"
    payload_dir = stage / "bearer" / "rules"
    payload_dir.mkdir(parents=True, mode=0o700)
    payload = payload_dir / "python.yml"
    payload.write_bytes(content)
    payload.chmod(0o600)
    receipt = CacheComponentReceipt(
        component_id="bearer-rules",
        tool_id="bearer",
        kind="rules",
        root="bearer/rules",
        immutable_ref="30a6919acec715bf915ff4704d1b4ffeac998eab",
        source_sha256="1e58ac09b18435ed53e57fc67f1d31af6c13e17776469a8f1fe8995f40f1a0e1",
        updated_at=created_at,
        expires_at=None,
        files=[
            CacheFileRecord(
                path="bearer/rules/python.yml",
                size_bytes=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            )
        ],
        canaries=[
            CanaryReceipt(
                canary_id="python-eval-user-input",
                fixture_sha256="9289314772d645fff0ce80ac985af3f3dd8557622ee4888f25e4702fc62a669f",
                output_sha256="29b9f3c2464585d242130aae7c13eac0f704beb40ccc42c50ed13b8650480bd7",
                exit_code=1,
                result_count=1,
                expected_ids=["python_lang_eval_using_user_input"],
                observed_ids=["python_lang_eval_using_user_input"],
                passed=True,
            )
        ],
    )
    manifest = GenerationManifest.create(
        tool_lock_sha256=hashlib.sha256(TOOLS_LOCK.read_bytes()).hexdigest(),
        rules_lock_sha256=hashlib.sha256(RULES_LOCK.read_bytes()).hexdigest(),
        created_at=created_at,
        components=[receipt],
    )
    destination = generations / manifest.generation_id
    stage.rename(destination)
    write_generation_manifest(destination, manifest)
    return manifest


def test_cache_receipt_accepts_rfc3339_nanoseconds_but_rejects_extra_precision() -> None:
    receipt = CacheComponentReceipt(
        component_id="trivy-db",
        tool_id="trivy",
        kind="database",
        root="trivy/db",
        immutable_ref="ghcr.io/aquasecurity/trivy-db@sha256:" + "a" * 64,
        source_sha256="a" * 64,
        updated_at="2026-08-12T19:12:05.145200672Z",
        expires_at="2026-08-13T19:12:05.145200271Z",
        files=[
            CacheFileRecord(
                path="trivy/db/metadata.json",
                size_bytes=1,
                sha256="b" * 64,
            )
        ],
        canaries=[
            CanaryReceipt(
                canary_id="source-vulnerabilities-zero",
                fixture_sha256="c" * 64,
                output_sha256="d" * 64,
                exit_code=0,
                result_count=0,
                expected_ids=[],
                observed_ids=[],
                passed=True,
            )
        ],
    )

    assert receipt.updated_at.endswith(".145200672Z")
    with pytest.raises(ValidationError):
        CacheComponentReceipt.model_validate(
            {
                **receipt.model_dump(mode="json"),
                "updated_at": "2026-08-12T19:12:05.1452006721Z",
            }
        )


def test_rules_cache_receipt_rejects_an_arbitrary_expiry(tmp_path: Path) -> None:
    manifest = _prepare_generation(tmp_path / "cache", content=b"reviewed")
    receipt = manifest.components[0]

    with pytest.raises(ValidationError, match="may not declare an expiry"):
        CacheComponentReceipt.model_validate(
            {
                **receipt.model_dump(mode="json"),
                "expires_at": "2026-08-13T20:00:00Z",
            }
        )


def test_curated_locks_strict_load_and_preserve_readiness_boundaries() -> None:
    tools = load_tool_lock(TOOLS_LOCK).value
    rules = load_rules_lock(RULES_LOCK).value

    assert {tool.id for tool in tools.tools} == {
        "trivy",
        "gitleaks",
        "opengrep",
        "bearer",
        "grype",
        "checkov",
        "trufflehog",
        "syft",
    }
    assert tools.tool("opengrep").binary.artifacts[0].sha256 == (
        "9d47d7de3f22ec5a93b25af9126648191e3d3b5d759dd4f699006138724719b3"
    )
    assert all(
        requirement.provenance == "verified"
        for requirement in tools.tool("trivy").requirements
    )
    assert all(tool.adapter.offline_contract == "verified" for tool in tools.tools)
    assert tools.tool("grype").requirements[0].provenance == "verified"
    assert tools.schema_version == 2
    trivy_contract = tools.tool("trivy").requirements[0].data_contract
    assert trivy_contract.kind == "trivy-db-metadata/v2"
    assert trivy_contract.publisher_updated_at == "2026-10-23T01:18:09.482141619Z"
    assert (
        trivy_contract.publisher_refresh_due_at
        == "2026-10-24T01:18:09.482141078Z"
    )
    grype_contract = tools.tool("grype").requirements[0].data_contract
    assert grype_contract.kind == "grype-db-status/v1"
    assert grype_contract.schema_version == "v6.1.10"
    assert grype_contract.built_at == "2026-10-22T18:51:21Z"
    assert tools.tool("bearer").requirements[0].provenance == "verified"
    assert tools.tool("bearer").binary.license.state == "verified"
    opengrep = rules.rule_set("opengrep-reviewed-rules")
    assert opengrep.state == "verified"
    assert opengrep.distribution_mode == "embedded"
    assert opengrep.source_repository is None
    assert opengrep.source_path == "services/scanner/rules/opengrep"
    assert opengrep.tree_hash_algorithm == CANONICAL_TREE_HASH_ALGORITHM
    assert (
        opengrep.tree_sha256
        == "001cd317216c296d29ccc4c86d68d912a5c9ff7b2ea52d6c81b3951bc6588183"
    )
    assert opengrep.tree_file_count == 3
    assert opengrep.tree_size_bytes == 16457
    assert {item.kind for item in opengrep.files} == {"rule", "license", "notice"}
    assert {
        item.id: item.output_sha256 for item in opengrep.canaries
    } == {
        "supported-sinks-positive": "79272bf4929fbf35861b7ada00d130dd850490d1afa8d6b0fd789c1984e785d8",
        "supported-sinks-zero": "76f45a74ad4efe9401f4fb64a11c689c27669feaa4c48ca609a0e1b0586d0212",
    }
    assert all(item.state == "verified" for item in opengrep.canaries)
    bearer = rules.rule_set("bearer-rules")
    assert bearer.state == "verified"
    assert bearer.source_commit == "30a6919acec715bf915ff4704d1b4ffeac998eab"
    assert bearer.tree_hash_algorithm == CANONICAL_TREE_HASH_ALGORITHM
    assert (
        bearer.tree_sha256
        == "1e58ac09b18435ed53e57fc67f1d31af6c13e17776469a8f1fe8995f40f1a0e1"
    )
    assert bearer.tree_file_count == 554
    assert bearer.tree_size_bytes == 1_278_246
    assert len(bearer.assets) == 6
    assert bearer.license.state == "verified"


def test_unattested_offline_contract_maps_to_execution_unattested() -> None:
    tools = load_tool_lock(TOOLS_LOCK)
    rules = load_rules_lock(RULES_LOCK)
    payload = tools.value.model_dump(mode="json")
    bearer = next(item for item in payload["tools"] if item["id"] == "bearer")
    bearer["adapter"]["offline_contract"] = "unattested"
    bearer["adapter"]["reason"] = "qualification receipt is pending"
    tools = type(tools)(
        value=type(tools.value).model_validate(payload),
        sha256=tools.sha256,
        path=tools.path,
    )
    bearer_only_ready = [
        item
        for item in evaluate_tool_readiness(
            tools,
            rules,
            ResolvedGeneration(state="unavailable", generation=None, pointer=None),
            {tool.id: "ready" for tool in tools.value.tools},
        )
        if item.tool_id == "bearer"
    ][0]

    assert bearer_only_ready.execution.state == "unattested"
    assert bearer_only_ready.binary.state == "ready"
    assert bearer_only_ready.binary.reason is None
    assert bearer_only_ready.rules.state == "unavailable"
    assert bearer_only_ready.ready is False


def test_promoted_bearer_rule_receipt_is_runtime_ready_after_adapter_qualification(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    manifest = _prepare_generation(cache_root, content=b"id: reviewed-rule\n")
    generation = validate_generation(cache_root, manifest.generation_id)
    tools = load_tool_lock(TOOLS_LOCK)
    rules = load_rules_lock(RULES_LOCK)
    readiness = next(
        item
        for item in evaluate_tool_readiness(
            tools,
            rules,
            ResolvedGeneration(state="ready", generation=generation, pointer=None),
            {tool.id: "ready" for tool in tools.value.tools},
        )
        if item.tool_id == "bearer"
    )

    assert readiness.rules.state == "ready"
    assert readiness.rules.component_ids == ["bearer-rules"]
    assert readiness.execution.state == "ready"
    assert readiness.ready is True


def test_bearer_jsonv2_lock_format_remains_explicit_and_bounded() -> None:
    adapter = load_tool_lock(TOOLS_LOCK).value.tool("bearer").adapter
    assert adapter.output_format == "jsonv2"
    assert cache_manifest.AdapterLock.model_validate(adapter.model_dump()).output_format == "jsonv2"
    with pytest.raises(ValidationError):
        cache_manifest.AdapterLock.model_validate({**adapter.model_dump(), "output_format": "arbitrary-json"})


def test_tool_and_rule_locks_have_one_exact_immutable_alignment() -> None:
    tools = load_tool_lock(TOOLS_LOCK).value
    rules = load_rules_lock(RULES_LOCK).value
    validate_lock_alignment(tools, rules)

    payload = tools.model_dump(mode="json")
    opengrep = next(item for item in payload["tools"] if item["id"] == "opengrep")
    opengrep["requirements"][0]["source"]["sha256"] = "0" * 64
    tampered = type(tools).model_validate(payload)
    with pytest.raises(LockValidationError, match="immutable identity"):
        validate_lock_alignment(tampered, rules)


def test_verified_data_lock_requires_more_than_the_activation_margin() -> None:
    tools = load_tool_lock(TOOLS_LOCK).value
    payload = tools.model_dump(mode="json")
    trivy = next(item for item in payload["tools"] if item["id"] == "trivy")
    trivy_db = next(
        item for item in trivy["requirements"] if item["id"] == "trivy-db"
    )
    trivy_db["max_age_seconds"] = cache_manifest.MIN_CACHE_ACTIVATION_FRESHNESS_SECONDS

    with pytest.raises(ValidationError, match="usable freshness window"):
        type(tools).model_validate(payload)


@pytest.mark.parametrize(
    ("component_id", "mutation", "message"),
    [
        ("trivy-db", {"schema_version": 1}, "literal_error"),
        ("trivy-java-db", {"schema_version": 2}, "literal_error"),
        ("trivy-checks", {"major_version": 1}, "literal_error"),
        ("grype-db", {"built_at": "not-a-time"}, "timestamp"),
    ],
)
def test_typed_data_contracts_reject_cross_profile_or_malformed_identity(
    component_id: str,
    mutation: dict[str, object],
    message: str,
) -> None:
    tools = load_tool_lock(TOOLS_LOCK).value
    payload = tools.model_dump(mode="json")
    requirement = next(
        requirement
        for tool in payload["tools"]
        for requirement in tool["requirements"]
        if requirement["id"] == component_id
    )
    requirement["data_contract"].update(mutation)

    with pytest.raises(ValidationError, match=message):
        type(tools).model_validate(payload)


def test_verified_data_contract_is_required_and_rules_cannot_carry_one() -> None:
    tools = load_tool_lock(TOOLS_LOCK).value
    payload = tools.model_dump(mode="json")
    trivy = next(item for item in payload["tools"] if item["id"] == "trivy")
    trivy_db = next(item for item in trivy["requirements"] if item["id"] == "trivy-db")
    trivy_db.pop("data_contract")
    with pytest.raises(ValidationError, match="typed data contract"):
        type(tools).model_validate(payload)

    payload = tools.model_dump(mode="json")
    bearer = next(item for item in payload["tools"] if item["id"] == "bearer")
    bearer["requirements"][0]["data_contract"] = {
        "kind": "trivy-db-metadata/v2",
        "schema_version": 2,
        "timestamp_kind": "intrinsic",
        "publisher_updated_at": "2026-08-24T00:58:29Z",
        "publisher_refresh_due_at": "2026-08-25T00:58:29Z",
    }
    with pytest.raises(ValidationError, match="rules freshness"):
        type(tools).model_validate(payload)


DATA_COMPONENT_IDS = (
    "grype-db",
    "trivy-checks",
    "trivy-db",
    "trivy-java-db",
)


def _data_requirement_payload(
    payload: dict[str, object],
    component_id: str,
) -> tuple[dict[str, object], dict[str, object]]:
    tools = payload["tools"]
    assert isinstance(tools, list)
    for tool in tools:
        assert isinstance(tool, dict)
        requirements = tool["requirements"]
        assert isinstance(requirements, list)
        for requirement in requirements:
            assert isinstance(requirement, dict)
            if requirement["id"] == component_id:
                return tool, requirement
    raise AssertionError(f"missing data requirement {component_id}")


def _incompatible_requirement(
    requirement: dict[str, object],
    provenance: str,
    *,
    retain_source_identity: bool = True,
) -> None:
    requirement.update(
        {
            "provenance": provenance,
            "reason": "publisher review is pending",
            "installed_size_bytes": None,
            "installed_content": None,
            "data_contract": None,
            "max_age_seconds": None,
            "canaries": [],
        }
    )
    if not retain_source_identity:
        source = requirement["source"]
        assert isinstance(source, dict)
        source.update(
            {
                "immutable_ref": None,
                "sha256": None,
                "size_bytes": None,
            }
        )


@pytest.mark.parametrize("component_id", DATA_COMPONENT_IDS)
@pytest.mark.parametrize("provenance", ["unavailable", "unattested"])
@pytest.mark.parametrize("retain_source_identity", [True, False])
def test_unverified_exact_data_profiles_retain_structure_without_evidence(
    component_id: str,
    provenance: str,
    retain_source_identity: bool,
) -> None:
    tools = load_tool_lock(TOOLS_LOCK).value
    payload = tools.model_dump(mode="json")
    _tool, requirement = _data_requirement_payload(payload, component_id)
    _incompatible_requirement(
        requirement,
        provenance,
        retain_source_identity=retain_source_identity,
    )

    validated = type(tools).model_validate(payload)
    observed = next(
        requirement
        for tool in validated.tools
        for requirement in tool.requirements
        if requirement.id == component_id
    )
    assert observed.provenance == provenance
    assert observed.reason == "publisher review is pending"
    assert observed.data_contract is None
    assert observed.max_age_seconds is None
    assert observed.installed_content is None
    assert observed.canaries == []
    assert (observed.source.immutable_ref is not None) is retain_source_identity


@pytest.mark.parametrize("component_id", DATA_COMPONENT_IDS)
@pytest.mark.parametrize("provenance", ["verified", "unavailable", "unattested"])
@pytest.mark.parametrize(
    "fixed_field",
    [
        "id",
        "owner_tool_id",
        "kind",
        "required",
        "cache_subpath",
        "source_kind",
        "discovery_ref",
    ],
)
def test_exact_data_profiles_reject_every_structural_field_mutation(
    component_id: str,
    provenance: str,
    fixed_field: str,
) -> None:
    tools = load_tool_lock(TOOLS_LOCK).value
    payload = tools.model_dump(mode="json")
    owner, requirement = _data_requirement_payload(payload, component_id)
    if provenance != "verified":
        _incompatible_requirement(requirement, provenance)

    if fixed_field == "id":
        requirement["id"] = f"{component_id}-hostile"
    elif fixed_field == "owner_tool_id":
        owner_requirements = owner["requirements"]
        assert isinstance(owner_requirements, list)
        owner_requirements.remove(requirement)
        hostile_owner = next(
            item for item in payload["tools"] if item["id"] == "bearer"
        )
        hostile_owner["requirements"].append(requirement)
    elif fixed_field == "kind":
        requirement["kind"] = (
            "database" if requirement["kind"] == "checks" else "checks"
        )
    elif fixed_field == "required":
        requirement["required"] = False
    elif fixed_field == "cache_subpath":
        requirement["cache_subpath"] = "hostile/cache"
    else:
        source = requirement["source"]
        assert isinstance(source, dict)
        if fixed_field == "source_kind":
            source["kind"] = "https" if source["kind"] == "oci" else "oci"
        else:
            assert fixed_field == "discovery_ref"
            source["discovery_ref"] = "https://example.invalid/data"

    with pytest.raises(ValidationError):
        type(tools).model_validate(payload)


@pytest.mark.parametrize("component_id", DATA_COMPONENT_IDS)
@pytest.mark.parametrize("contract_field", ["class", "timestamp_kind"])
def test_verified_exact_data_profiles_reject_contract_profile_mutation(
    component_id: str,
    contract_field: str,
) -> None:
    tools = load_tool_lock(TOOLS_LOCK).value
    payload = tools.model_dump(mode="json")
    _owner, requirement = _data_requirement_payload(payload, component_id)
    if contract_field == "class":
        replacement_id = "trivy-db" if component_id != "trivy-db" else "trivy-java-db"
        _other_owner, replacement = _data_requirement_payload(payload, replacement_id)
        requirement["data_contract"] = replacement["data_contract"]
    else:
        contract = requirement["data_contract"]
        assert isinstance(contract, dict)
        contract["timestamp_kind"] = (
            "acquisition-relative"
            if contract["timestamp_kind"] == "intrinsic"
            else "intrinsic"
        )

    with pytest.raises(ValidationError):
        type(tools).model_validate(payload)


def test_reviewed_grype_proposal_fields_remain_mutable() -> None:
    tools = load_tool_lock(TOOLS_LOCK).value
    payload = tools.model_dump(mode="json")
    _owner, requirement = _data_requirement_payload(payload, "grype-db")
    source = requirement["source"]
    contract = requirement["data_contract"]
    installed = requirement["installed_content"]
    canaries = requirement["canaries"]
    assert isinstance(source, dict)
    assert isinstance(contract, dict)
    assert isinstance(installed, dict)
    assert isinstance(canaries, list)
    source.update(
        {
            "immutable_ref": "https://grype.anchore.io/databases/v6/reviewed.tar.zst",
            "sha256": "1" * 64,
            "size_bytes": 141_482_521,
        }
    )
    contract.update(
        {
            "schema_version": "v6.2.1",
            "built_at": "2026-08-13T06:38:08Z",
        }
    )
    requirement["max_age_seconds"] = 1_209_600
    requirement["installed_size_bytes"] = 2_005_753_954
    installed.update({"sha256": "2" * 64, "size_bytes": 2_005_753_954})
    canaries[0]["output_sha256"] = "3" * 64

    reviewed = type(tools).model_validate(payload)
    observed = reviewed.tool("grype").requirements[0]
    assert observed.source.sha256 == "1" * 64
    assert observed.data_contract.schema_version == "v6.2.1"
    assert observed.data_contract.built_at == "2026-08-13T06:38:08Z"
    assert observed.max_age_seconds == 1_209_600


def test_exact_data_component_rejects_a_cross_profile_contract() -> None:
    tools = load_tool_lock(TOOLS_LOCK).value
    payload = tools.model_dump(mode="json")
    trivy = next(item for item in payload["tools"] if item["id"] == "trivy")
    trivy_db = next(item for item in trivy["requirements"] if item["id"] == "trivy-db")
    java_db = next(
        item for item in trivy["requirements"] if item["id"] == "trivy-java-db"
    )
    trivy_db["data_contract"] = java_db["data_contract"]

    with pytest.raises(ValidationError, match="exact profile"):
        type(tools).model_validate(payload)


def test_lock_reader_rejects_duplicate_keys_and_symlinks(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1}\n')
    with pytest.raises(LockValidationError, match="unambiguous"):
        load_tool_lock(duplicate)

    symlink = tmp_path / "tools.json"
    try:
        symlink.symlink_to(TOOLS_LOCK)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    with pytest.raises(LockValidationError):
        load_tool_lock(symlink)


def test_unverified_rule_set_rejects_partial_evidence() -> None:
    payload = (
        load_rules_lock(RULES_LOCK)
        .value.rule_set("opengrep-reviewed-rules")
        .model_dump(mode="json")
    )
    payload["state"] = "unavailable"
    payload["reason"] = "not admitted"
    with pytest.raises(ValidationError, match="partial rule evidence"):
        RuleSetLock.model_validate(payload)


def test_embedded_opengrep_tree_matches_exact_lock_and_license() -> None:
    rule_set = load_rules_lock(RULES_LOCK).value.rule_set("opengrep-reviewed-rules")
    source = ROOT / str(rule_set.source_path)
    observed = collect_canonical_tree(source)

    assert observed.algorithm == rule_set.tree_hash_algorithm
    assert observed.sha256 == rule_set.tree_sha256
    assert observed.file_count == rule_set.tree_file_count
    assert observed.size_bytes == rule_set.tree_size_bytes
    locked = {item.path: (item.size_bytes, item.sha256) for item in rule_set.files}
    assert {
        item.path: (item.size_bytes, item.sha256) for item in observed.files
    } == locked
    license_file = next(item for item in rule_set.files if item.kind == "license")
    assert (
        rule_set.license.source_ref
        == f"repo:{rule_set.source_path}/{license_file.path}"
    )
    assert rule_set.license.source_sha256 == license_file.sha256


def test_canonical_tree_v1_sorts_records_and_binds_path_size_and_digest() -> None:
    first = CacheFileRecord(path="z.txt", size_bytes=1, sha256="1" * 64)
    second = CacheFileRecord(path="a.txt", size_bytes=2, sha256="2" * 64)
    forward = canonical_tree_sha256([first, second])
    reverse = canonical_tree_sha256([second, first])

    assert forward == reverse
    assert forward != canonical_tree_sha256(
        [second, CacheFileRecord(path="z.txt", size_bytes=2, sha256="1" * 64)]
    )
    with pytest.raises(CacheValidationError, match="unique"):
        canonical_tree_sha256([first, first])


def test_canonical_tree_collector_rejects_aliases_empty_dirs_and_writable_content(
    tmp_path: Path,
) -> None:
    root = tmp_path / "rules"
    root.mkdir()
    rule = root / "rules.yml"
    rule.write_text("rules: []\n", encoding="utf-8")

    observed = collect_canonical_tree(root)
    assert observed.file_count == 1
    assert observed.size_bytes == len(b"rules: []\n")
    with pytest.raises(CacheValidationError, match="writable"):
        collect_canonical_tree(root, require_immutable=True)

    hardlink = root / "copy.yml"
    hardlink.hardlink_to(rule)
    with pytest.raises(CacheValidationError, match="hard-linked"):
        collect_canonical_tree(root)
    hardlink.unlink()

    linked = root / "linked.yml"
    try:
        linked.symlink_to(rule.name)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    with pytest.raises(CacheValidationError, match="symlink"):
        collect_canonical_tree(root)
    linked.unlink()

    empty = root / "empty"
    empty.mkdir()
    with pytest.raises(CacheValidationError, match="empty"):
        collect_canonical_tree(root)


def test_canonical_tree_collector_detects_file_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "rules"
    root.mkdir()
    rule = root / "rules.yml"
    rule.write_bytes(b"rules: []\n")
    original_read = os.read
    mutated = False

    def mutating_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, size)
        if chunk and not mutated:
            mutated = True
            rule.write_bytes(b"rules: []\n# changed\n")
        return chunk

    monkeypatch.setattr(os, "read", mutating_read)
    with pytest.raises(CacheValidationError, match="changed"):
        collect_canonical_tree(root)


def test_generation_validation_rejects_extra_symlink_and_digest_tampering(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    manifest = _prepare_generation(cache_root, content=b"id: safe-rule\n")
    validated = validate_generation(cache_root, manifest.generation_id)
    assert validated.manifest == manifest

    validated.path.chmod(0o700)
    undeclared = validated.path / "undeclared.txt"
    undeclared.write_text("not in manifest")
    undeclared.chmod(0o600)
    with pytest.raises(CacheValidationError, match="immutable|missing or undeclared"):
        validate_generation(cache_root, manifest.generation_id)
    undeclared.unlink()
    validated.path.chmod(0o500)

    symlink = validated.path / "escape"
    outside = tmp_path / "outside-generation"
    outside.write_bytes(b"outside")
    validated.path.chmod(0o700)
    try:
        symlink.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    validated.path.chmod(0o500)
    with pytest.raises(CacheValidationError, match="symlinks"):
        validate_generation(cache_root, manifest.generation_id)
    validated.path.chmod(0o700)
    symlink.unlink()
    validated.path.chmod(0o500)

    payload = validated.path / "bearer" / "rules" / "python.yml"
    validated.path.chmod(0o700)
    (validated.path / "bearer").chmod(0o700)
    (validated.path / "bearer" / "rules").chmod(0o700)
    payload.chmod(0o600)
    payload.write_bytes(b"tampered")
    with pytest.raises(CacheValidationError, match="immutable|identity or size|digest"):
        validate_generation(cache_root, manifest.generation_id)


def test_generation_hashing_observes_bounded_cancellation_checkpoints(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    manifest = _prepare_generation(
        cache_root,
        content=b"x" * (GENERATION_HASH_CHECKPOINT_BYTES * 2),
    )
    calls = 0

    class CancelValidation(RuntimeError):
        pass

    def checkpoint() -> None:
        nonlocal calls
        calls += 1
        # validate + walk start/end are the first three observations. The
        # fourth occurs after at most one 16 MiB hashing quantum.
        if calls == 4:
            raise CancelValidation("cancelled during generation hashing")

    started = time.monotonic()
    with pytest.raises(CancelValidation, match="cancelled during generation hashing"):
        validate_generation(
            cache_root,
            manifest.generation_id,
            checkpoint=checkpoint,
        )

    assert calls == 4
    assert time.monotonic() - started < 2.0


def test_generation_validation_reports_exact_component_bytes(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    content = b"exact progress evidence"
    manifest = _prepare_generation(cache_root, content=content)
    observations: list[tuple[str, int, int, int, int]] = []

    validate_generation(
        cache_root,
        manifest.generation_id,
        progress=lambda *values: observations.append(values),
    )

    assert observations[0] == ("bearer-rules", 1, 1, 0, len(content))
    assert observations[-1] == (
        "bearer-rules",
        1,
        1,
        len(content),
        len(content),
    )
    assert [item[3] for item in observations] == sorted(
        item[3] for item in observations
    )


def test_generation_hash_budget_is_aggregate_across_file_boundaries(
    tmp_path: Path,
) -> None:
    content = b"x" * (9 * 1024 * 1024)
    first = tmp_path / "first.db"
    second = tmp_path / "second.db"
    for path in (first, second):
        path.write_bytes(content)
        path.chmod(0o400)
    calls = 0

    class CancelValidation(RuntimeError):
        pass

    def checkpoint() -> None:
        nonlocal calls
        calls += 1
        raise CancelValidation("aggregate hash budget reached")

    budget = cache_manifest._GenerationHashCheckpoint(checkpoint)
    assert cache_manifest._hash_generation_file(
        first,
        len(content),
        budget,
    ) == hashlib.sha256(content).hexdigest()
    with pytest.raises(CancelValidation, match="aggregate hash budget reached"):
        cache_manifest._hash_generation_file(second, len(content), budget)

    assert calls == 1


def test_active_pointer_uses_last_good_and_rollback(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    first = _prepare_generation(
        cache_root, content=b"first", created_at="2026-08-12T20:00:00Z"
    )
    first_pointer = activate_generation(
        cache_root,
        first.generation_id,
        OPERATION_ID,
        activated_at="2026-08-12T20:00:01Z",
    )
    assert first_pointer.revision == 1

    # _prepare_generation creates the roots, so stage a second generation by
    # temporarily moving the first root through the same deterministic helper.
    other_root = tmp_path / "other-cache"
    second = _prepare_generation(
        other_root, content=b"second", created_at="2026-08-12T20:00:02Z"
    )
    (other_root / "generations").chmod(0o700)
    (cache_root / "generations").chmod(0o700)
    (other_root / "generations" / second.generation_id).chmod(0o700)
    (other_root / "generations" / second.generation_id).rename(
        cache_root / "generations" / second.generation_id
    )
    (cache_root / "generations" / second.generation_id).chmod(0o500)
    second_pointer = activate_generation(
        cache_root,
        second.generation_id,
        OPERATION_ID,
        activated_at="2026-08-12T20:00:03Z",
    )
    assert second_pointer.previous_good == first_pointer.active

    active_payload = (
        cache_root
        / "generations"
        / second.generation_id
        / "bearer"
        / "rules"
        / "python.yml"
    )
    (cache_root / "generations" / second.generation_id).chmod(0o700)
    (cache_root / "generations" / second.generation_id / "bearer").chmod(0o700)
    (cache_root / "generations" / second.generation_id / "bearer" / "rules").chmod(0o700)
    active_payload.chmod(0o600)
    active_payload.write_bytes(b"broken")
    resolved = resolve_active_generation(cache_root)
    assert resolved.state == "fallback"
    assert resolved.generation is not None
    assert resolved.generation.manifest.generation_id == first.generation_id

    rollback_targets: list[str] = []

    def prepare_rollback(candidate: object) -> str:
        rollback_targets.append(candidate.manifest.generation_id)  # type: ignore[attr-defined]
        return "2026-08-12T20:00:04.123456Z"

    rolled_back = rollback_to_previous_good(
        cache_root,
        OPERATION_ID,
        prepare_publication=prepare_rollback,
    )
    assert rollback_targets == [first.generation_id]
    assert rolled_back.activated_at == "2026-08-12T20:00:04.123456Z"
    assert rolled_back.active.generation_id == first.generation_id
    assert rolled_back.previous_good is None


def test_activation_publication_hook_guards_every_pointer_write(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    manifest = _prepare_generation(cache_root, content=b"guarded")
    guarded_ids: list[str] = []

    def initial_guard(candidate: object) -> str:
        guarded_ids.append(candidate.manifest.generation_id)  # type: ignore[attr-defined]
        return "2026-08-12T20:00:00.123456Z"

    first = activate_generation(
        cache_root,
        manifest.generation_id,
        OPERATION_ID,
        prepare_publication=initial_guard,
    )
    assert guarded_ids == [manifest.generation_id]
    assert first.activated_at == "2026-08-12T20:00:00.123456Z"

    def unexpected_replay_guard(_candidate: object) -> str:
        raise AssertionError("idempotent no-write replay invoked publication guard")

    assert (
        activate_generation(
            cache_root,
            manifest.generation_id,
            OPERATION_ID,
            prepare_publication=unexpected_replay_guard,
        )
        == first
    )

    active_before = (cache_root / "active.json").read_bytes()

    def reject_distinct_operation(_candidate: object) -> str:
        raise CacheActivationError("publication guard rejected candidate")

    with pytest.raises(CacheActivationError, match="guard rejected"):
        activate_generation(
            cache_root,
            manifest.generation_id,
            str(UUID("223e4567-e89b-42d3-a456-426614174000")),
            prepare_publication=reject_distinct_operation,
        )
    assert (cache_root / "active.json").read_bytes() == active_before

    guarded_ids.clear()
    second = activate_generation(
        cache_root,
        manifest.generation_id,
        str(UUID("323e4567-e89b-42d3-a456-426614174000")),
        prepare_publication=initial_guard,
    )
    assert guarded_ids == [manifest.generation_id]
    assert second.revision == first.revision + 1


def test_activation_replay_semantic_guard_is_only_for_same_operation_no_write(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"
    manifest = _prepare_generation(cache_root, content=b"replay-guard")
    replay_calls: list[str] = []

    def refuse_replay(candidate: object) -> None:
        replay_calls.append(candidate.manifest.generation_id)  # type: ignore[attr-defined]
        raise CacheActivationError("replay semantic guard rejected candidate")

    first = activate_generation(
        cache_root, manifest.generation_id, OPERATION_ID,
        validate_replay=refuse_replay,
    )
    assert replay_calls == []
    pointer_before = (cache_root / "active.json").read_bytes()

    with pytest.raises(CacheActivationError, match="replay semantic guard"):
        activate_generation(
            cache_root, manifest.generation_id, OPERATION_ID,
            validate_replay=refuse_replay,
        )
    assert replay_calls == [manifest.generation_id]
    assert (cache_root / "active.json").read_bytes() == pointer_before
    assert cache_manifest.load_active_pointer(cache_root) == first


def test_activation_revalidates_target_after_the_current_generation_walk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "cache"
    first = _prepare_generation(cache_root, content=b"first")
    activate_generation(cache_root, first.generation_id, OPERATION_ID)

    other_root = tmp_path / "other-cache"
    candidate = _prepare_generation(other_root, content=b"candidate")
    (other_root / "generations").chmod(0o700)
    (cache_root / "generations").chmod(0o700)
    candidate_root = other_root / "generations" / candidate.generation_id
    candidate_root.chmod(0o700)
    candidate_root.rename(cache_root / "generations" / candidate.generation_id)
    candidate_root = cache_root / "generations" / candidate.generation_id
    candidate_root.chmod(0o500)
    candidate_payload = candidate_root / "bearer" / "rules" / "python.yml"
    active_before = (cache_root / "active.json").read_bytes()
    original_validate = cache_manifest.validate_generation
    target_mutated = False
    guard_called = False

    def mutate_target_after_current(*args: object, **kwargs: object):
        nonlocal target_mutated
        validated = original_validate(*args, **kwargs)  # type: ignore[arg-type]
        if validated.manifest.generation_id == first.generation_id and not target_mutated:
            target_mutated = True
            candidate_root.chmod(0o700)
            (candidate_root / "bearer").chmod(0o700)
            (candidate_root / "bearer" / "rules").chmod(0o700)
            candidate_payload.chmod(0o600)
            candidate_payload.write_bytes(b"tampered")
        return validated

    def guard(_candidate: object) -> str:
        nonlocal guard_called
        guard_called = True
        return "2026-08-12T20:00:05.000000Z"

    monkeypatch.setattr(cache_manifest, "validate_generation", mutate_target_after_current)

    with pytest.raises(CacheValidationError):
        activate_generation(
            cache_root,
            candidate.generation_id,
            str(UUID("423e4567-e89b-42d3-a456-426614174000")),
            prepare_publication=guard,
        )
    assert target_mutated is True
    assert guard_called is False
    assert (cache_root / "active.json").read_bytes() == active_before


def test_rollback_revalidates_target_after_the_current_generation_walk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "cache"
    first = _prepare_generation(cache_root, content=b"first")
    activate_generation(cache_root, first.generation_id, OPERATION_ID)
    other_root = tmp_path / "other-cache"
    second = _prepare_generation(other_root, content=b"second")
    (other_root / "generations").chmod(0o700)
    (cache_root / "generations").chmod(0o700)
    second_root = other_root / "generations" / second.generation_id
    second_root.chmod(0o700)
    second_root.rename(cache_root / "generations" / second.generation_id)
    (cache_root / "generations" / second.generation_id).chmod(0o500)
    activate_generation(
        cache_root,
        second.generation_id,
        str(UUID("523e4567-e89b-42d3-a456-426614174000")),
    )

    previous_root = cache_root / "generations" / first.generation_id
    previous_payload = previous_root / "bearer" / "rules" / "python.yml"
    active_before = (cache_root / "active.json").read_bytes()
    original_validate = cache_manifest.validate_generation
    target_mutated = False
    guard_called = False

    def mutate_previous_after_current(*args: object, **kwargs: object):
        nonlocal target_mutated
        validated = original_validate(*args, **kwargs)  # type: ignore[arg-type]
        if validated.manifest.generation_id == second.generation_id and not target_mutated:
            target_mutated = True
            previous_root.chmod(0o700)
            (previous_root / "bearer").chmod(0o700)
            (previous_root / "bearer" / "rules").chmod(0o700)
            previous_payload.chmod(0o600)
            previous_payload.write_bytes(b"tampered")
        return validated

    def guard(_candidate: object) -> str:
        nonlocal guard_called
        guard_called = True
        return "2026-08-12T20:00:06.000000Z"

    monkeypatch.setattr(cache_manifest, "validate_generation", mutate_previous_after_current)

    with pytest.raises(CacheValidationError):
        rollback_to_previous_good(
            cache_root,
            str(UUID("623e4567-e89b-42d3-a456-426614174000")),
            prepare_publication=guard,
        )
    assert target_mutated is True
    assert guard_called is False
    assert (cache_root / "active.json").read_bytes() == active_before


def test_activation_refuses_an_active_pointer_symlink(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    manifest = _prepare_generation(cache_root, content=b"safe")
    target = tmp_path / "outside.json"
    target.write_bytes(canonical_json_bytes({"outside": True}))
    try:
        (cache_root / "active.json").symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    with pytest.raises((CacheActivationError, CacheValidationError)):
        activate_generation(cache_root, manifest.generation_id, OPERATION_ID)
    assert json.loads(target.read_text()) == {"outside": True}
