"""Recovery from an exact local database, using real sealed files and copies."""
from dataclasses import replace
from datetime import datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from kodesec_scanner import cache_manifest as cache, updater
from test_updater import TOOLS, RULES, _prepare_generation, _request


@pytest.fixture
def retained(tmp_path):
    root = tmp_path / "cache"
    root.mkdir(mode=0o700)
    generations = root / "generations"
    generations.mkdir(mode=0o700)
    stage = generations / "stage"
    component = stage / "trivy/java-db"
    component.mkdir(parents=True, mode=0o700)
    (component / "trivy-java.db").write_bytes(b"synthetic database bytes")
    (component / "metadata.json").write_bytes(b"{\"Version\": 1}\n")
    tree = cache.collect_canonical_tree(component)
    original = next(x for x in TOOLS.value.tool("trivy").requirements if x.id == "trivy-java-db")
    stable = [x for x in tree.files if x.path != "metadata.json"]
    requirement = cache.ComponentRequirementLock.model_validate({
        **original.model_dump(mode="json"),
        "installed_size_bytes": tree.size_bytes,
        "installed_content": {
            "hash_algorithm": tree.algorithm, "sha256": cache.canonical_tree_sha256(stable),
            "file_count": len(stable), "size_bytes": sum(x.size_bytes for x in stable),
            "volatile_paths": ["metadata.json"],
        },
    })
    tools_value = TOOLS.value.model_dump(mode="json")
    for tool in tools_value["tools"]:
        tool["requirements"] = [requirement.model_dump(mode="json") if x["id"] == requirement.id else x
                                for x in tool["requirements"]]
    tools = replace(TOOLS, value=cache.ToolLockFile.model_validate(tools_value))
    updated = requirement.data_contract.publisher_updated_at
    receipt = cache.CacheComponentReceipt(
        component_id=requirement.id, tool_id="trivy", kind=requirement.kind,
        root=requirement.cache_subpath, immutable_ref=requirement.source.immutable_ref,
        source_sha256=requirement.source.sha256, updated_at=updated,
        expires_at=updater._timestamp_plus(updated, requirement.max_age_seconds),
        files=updater._prefixed_records(requirement.cache_subpath, tree.files),
        canaries=[cache.CanaryReceipt(
            canary_id=x.id, fixture_sha256=x.fixture_sha256, output_sha256=x.output_sha256,
            exit_code=x.expected_exit_code, result_count=x.expected_result_count,
            expected_ids=x.expected_ids, observed_ids=x.expected_ids, passed=True,
        ) for x in sorted(requirement.canaries, key=lambda x: x.id)],
    )
    manifest = cache.GenerationManifest.create(tool_lock_sha256=tools.sha256,
        rules_lock_sha256=RULES.sha256, created_at=updated, components=[receipt])
    destination = generations / manifest.generation_id
    stage.rename(destination)
    cache.write_generation_manifest(destination, manifest)
    cache.activate_generation(root, manifest.generation_id, str(uuid4()))
    active = _prepare_generation(root, uuid4())
    cache.activate_generation(root, active.generation_id, str(uuid4()))
    events = []
    now = datetime.fromisoformat(updated) + timedelta(hours=1)
    context = SimpleNamespace(
        request=_request(components=[requirement.id], issued_at=now), _repair_source=None,
        checkpoint=lambda: None, refresh_activity=lambda: None,
        progress=lambda stage, **details: events.append((stage, details)),
        byte_progress=lambda *args, **kwargs: None,
    )
    return SimpleNamespace(root=root, tools=tools, receipt=receipt, requirement=requirement,
        previous=destination, now=now, context=context, events=events, scratch=tmp_path / "scratch")


def select(fixture, *, resolved=None, requested=None, now=None):
    return updater._previous_data_for_missing_components(
        fixture.root, resolved or cache.resolve_active_generation(fixture.root),
        requested or ["trivy-java-db"], fixture.tools, RULES, fixture.context,
        evaluated_at=now or fixture.now,
    )


def test_missing_data_can_use_only_the_exact_referenced_verified_previous_tree(retained):
    with updater.generation_lock(retained.root):
        previous, receipts = select(retained)
    assert previous.path == retained.previous
    assert receipts == {"trivy-java-db": retained.receipt}


@pytest.mark.parametrize("case", ["cold", "fallback", "invalid", "no_previous", "already_installed", "rules"])
def test_cold_repair_rules_and_explicit_current_refresh_do_not_use_previous(retained, monkeypatch, case):
    resolved = cache.resolve_active_generation(retained.root)
    requested = ["trivy-java-db"]
    if case in {"cold", "fallback", "invalid"}:
        resolved = replace(resolved, state={"cold": "unavailable"}.get(case, case))
    elif case == "no_previous":
        resolved = replace(resolved, pointer=resolved.pointer.model_copy(update={"previous_good": None}))
    elif case == "already_installed":
        resolved = replace(resolved, generation=replace(resolved.generation,
            manifest=resolved.generation.manifest.model_copy(update={"components": [retained.receipt]})))
    else:
        requested = ["bearer-rules"]
    monkeypatch.setattr(updater, "validate_generation", lambda *a, **kw: pytest.fail("unneeded previous-tree read"))
    assert select(retained, resolved=resolved, requested=requested) == (None, {})


@pytest.mark.parametrize("case", ["expired", "near_expiry", "identity", "canary", "content", "future"])
def test_ineligible_previous_data_is_not_reused(retained, monkeypatch, case):
    real_validate = updater.validate_generation
    changes = {}
    now = retained.now
    if case in {"expired", "near_expiry"}:
        now = datetime.fromisoformat(retained.receipt.expires_at) - timedelta(seconds=0 if case == "expired" else 30)
    elif case == "identity":
        changes["source_sha256"] = "f" * 64
    elif case == "canary":
        changes["canaries"] = [retained.receipt.canaries[0].model_copy(update={"output_sha256": "f" * 64})]
    elif case == "content":
        changes["files"] = [x.model_copy(update={"sha256": "f" * 64}) for x in retained.receipt.files]
    else:
        now = datetime.fromisoformat(retained.receipt.updated_at) - timedelta(hours=1)
    def changed(*args, **kwargs):
        result = real_validate(*args, **kwargs)
        return replace(result, manifest=result.manifest.model_copy(update={
            "components": [retained.receipt.model_copy(update=changes)]}))
    monkeypatch.setattr(updater, "validate_generation", changed)
    previous, receipts = select(retained, now=now)
    assert previous.path == retained.previous and receipts == {}


@pytest.mark.parametrize("case", ["bytes", "alias", "manifest", "cancel"])
def test_invalid_or_cancelled_previous_validation_cannot_fall_through(retained, case):
    path = retained.previous / "trivy/java-db/trivy-java.db"
    if case == "bytes":
        path.chmod(0o600)
        path.write_bytes(b"changed database bytes!!")
        path.chmod(0o400)
    elif case == "alias":
        path.parent.chmod(0o700)
        path.unlink()
        path.symlink_to("metadata.json")
        path.parent.chmod(0o500)
    elif case == "manifest":
        path = retained.previous / "manifest.json"
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b" ")
        path.chmod(0o400)
    else:
        def cancel():
            raise updater.OperationStateError("cancelled owned preparation")
        retained.context.checkpoint = cancel
    resolved = cache.resolve_active_generation(retained.root)
    with pytest.raises((cache.CacheValidationError, updater.OperationStateError)):
        select(retained, resolved=resolved)


@pytest.mark.parametrize("failure", [None, "canary", "copy_changed", "cancel_copy"])
def test_actual_update_rehashes_missing_data_reruns_canaries_and_preserves_age(retained, monkeypatch, failure):
    handlers = updater.LockedLifecycleHandlers(tools=retained.tools, rules=RULES,
        cache_root=retained.root, scratch_root=retained.scratch, evaluation_now=lambda: retained.now)
    monkeypatch.setattr(updater, "validate_lock_alignment", lambda *_: None)  # synthetic tiny data lock
    monkeypatch.setattr(updater, "_stage_trivy_component", lambda *a, **kw: pytest.fail("downloaded retained data"))
    before = (retained.root / "active.json").read_bytes()
    observed = []
    def canary(context, staged, *, payload, scratch_root):
        assert (payload / "trivy/java-db/trivy-java.db").read_bytes() == b"synthetic database bytes"
        assert (payload / "bearer/rules/python.yml").is_file()  # carried sibling exists first
        assert (staged.updated_at, staged.expires_at) == (retained.receipt.updated_at, retained.receipt.expires_at)
        observed.append(staged)
        if failure == "canary":
            raise updater.OperationError("fresh canary failed")
        return retained.receipt.canaries
    monkeypatch.setattr(updater, "_run_data_canaries", canary)
    original_copy = updater._copy_validated_component
    def copy(source, receipt, *args, **kwargs):
        if receipt.component_id == "trivy-java-db":
            if failure == "copy_changed":
                path = source.path / receipt.files[0].path
                path.chmod(0o600)
                path.write_bytes(b"modified after validation")
                path.chmod(0o400)
            elif failure == "cancel_copy":
                raise updater.OperationStateError("cancelled owned copy")
        return original_copy(source, receipt, *args, **kwargs)
    monkeypatch.setattr(updater, "_copy_validated_component", copy)
    with updater.generation_lock(retained.root):
        if failure:
            with pytest.raises((updater.OperationError, cache.CacheValidationError)):
                handlers.cache_update(retained.context)
        else:
            generation_id = handlers.cache_update(retained.context)
            result = cache.validate_generation(retained.root, generation_id)
            actual = next(x for x in result.manifest.components if x.component_id == "trivy-java-db")
            assert actual == retained.receipt
            assert len(observed) == 1
    assert (retained.root / "active.json").read_bytes() == before  # staging cannot activate
    assert not list((retained.root / "staging").iterdir())
    assert not any(stage == "downloading" for stage, _ in retained.events)


@pytest.mark.parametrize("expire_during_canary", [False, True])
def test_real_operation_activation_rechecks_retained_freshness(retained, monkeypatch, expire_during_canary):
    moment = [retained.now]
    monkeypatch.setattr(updater, "validate_lock_alignment", lambda *_: None)
    monkeypatch.setattr(updater, "_utc_now", lambda: retained.now)
    monkeypatch.setattr(updater, "_stage_trivy_component", lambda *a, **kw: pytest.fail("network used"))
    def canary(*args, **kwargs):
        if expire_during_canary:
            moment[0] = datetime.fromisoformat(retained.receipt.expires_at)
        return retained.receipt.canaries
    monkeypatch.setattr(updater, "_run_data_canaries", canary)
    handlers = updater.LockedLifecycleHandlers(tools=retained.tools, rules=RULES,
        cache_root=retained.root, scratch_root=retained.scratch, evaluation_now=lambda: moment[0])
    before = (retained.root / "active.json").read_bytes()
    result = updater.execute_operation(retained.context.request, retained.tools, RULES,
        updater.OperationStore(retained.root), cache_update=handlers.cache_update,
        now=lambda: retained.now.isoformat().replace("+00:00", "Z"), evaluation_now=lambda: moment[0])
    if expire_during_canary:
        assert result.status == "failed"
        assert (retained.root / "active.json").read_bytes() == before
    else:
        assert result.status == "completed"
        active = cache.resolve_active_generation(retained.root).generation
        assert next(x for x in active.manifest.components if x.component_id == "trivy-java-db") == retained.receipt


def test_different_previous_identity_uses_normal_locked_acquisition(retained, monkeypatch):
    tools_value = retained.tools.value.model_dump(mode="json")
    for tool in tools_value["tools"]:
        for requirement in tool["requirements"]:
            if requirement["id"] == "trivy-java-db":
                requirement["source"]["sha256"] = "f" * 64
    tools = replace(retained.tools, value=cache.ToolLockFile.model_validate(tools_value))
    monkeypatch.setattr(updater, "validate_lock_alignment", lambda *_: None)
    seen = []
    def download(context, requirement, **kwargs):
        seen.append(requirement.source.sha256)
        raise updater.OperationError("stop at actual acquisition boundary")
    monkeypatch.setattr(updater, "_stage_trivy_component", download)
    handlers = updater.LockedLifecycleHandlers(tools=tools, rules=RULES,
        cache_root=retained.root, scratch_root=retained.scratch, evaluation_now=lambda: retained.now)
    with updater.generation_lock(retained.root), pytest.raises(updater.OperationError, match="actual acquisition"):
        handlers.cache_update(retained.context)
    assert seen == ["f" * 64]
