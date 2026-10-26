"""Focused policy/tree/verdict regressions, not foreground release acceptance."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from kodesec_api import git_push_evidence as evidence, git_push_policy as policy, main
from kodesec_api.auth import AuthContext
from kodesec_api.db import Base
from kodesec_api.models import Finding, GatePolicy, Job, Project, RuntimeConfig, Scan, ScannerLifecycleState


SLOT = "ks1_" + "s" * 43
STAMP = "2026-09-12T21:00:00+00:00"
ROOT = "/fixture/git-project"
REPOSITORY = hashlib.sha256(f"lomo-git-repository/v1\0{ROOT}\0{ROOT}/.git".encode()).hexdigest()
PREFLIGHT = "c" * 64
RUNTIME_IDENTITY = "d" * 64
REAL_PREFLIGHT = main._scanner_preflight


def tree(content: bytes = b"print('synthetic fixture')\n", filename: str = "app.py") -> evidence.GitTreeUpload:
    oid = evidence._git_oid("blob", content, "sha1")
    tree_oid = evidence._git_oid("tree", b"100644 " + filename.encode() + b"\0" + bytes.fromhex(oid), "sha1")
    return evidence.GitTreeUpload(object_format="sha1", tree_oid=tree_oid, files=[{
        "path": filename, "mode": "100644", "oid": oid, "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content), "content_base64": base64.b64encode(content).decode(),
    }])


def test_git_tree_asset_transfer_retains_complete_object_and_snapshot_binding(tmp_path):
    content = b"\x89PNG\r\n\x1a\n" + b"x" * (5_800_000 - 8)
    upload = tree(content, "image.png")
    files = evidence.verified_tree_files(upload)
    assert len(files) == 1
    assert base64.b64decode(files[0].content_base64) == content
    from kodesec_api.schemas import SourceSnapshotCreate
    from kodesec_api.source_snapshots import store_source_snapshot, validate_source_snapshot
    settings = SimpleNamespace(source_snapshot_dir=str(tmp_path / "source-snapshots"))
    snapshot = SourceSnapshotCreate(source_id=REPOSITORY, name="Git asset", files=files)
    digest, source, count, size = store_source_snapshot(settings, snapshot)
    assert (count, size) == (1, len(content))
    assert (source / "image.png").read_bytes() == content
    assert validate_source_snapshot(settings, digest, source_id=REPOSITORY) == source
    with pytest.raises(HTTPException, match="complete immutable Git tree"):
        evidence.verified_tree_files(upload.model_copy(update={"files": []}))
    with pytest.raises(ValueError):
        tree(b"x" * (8 * 1024 * 1024 + 1), "image.png")


def plan(tree_oid: str) -> evidence.PushPlan:
    body = {"schema": "lomo-git-push-plan/v1", "repository_id": REPOSITORY, "object_format": "sha1",
        "destination_digest": "e" * 64, "advertised_bases": [],
        "refs": [{"local_ref": "HEAD", "local_oid": "a" * 40, "remote_ref": "refs/heads/main", "remote_oid": "0" * 40}],
        "commits": [{"commit_oid": "a" * 40, "tree_oid": tree_oid}], "trees": [tree_oid]}
    body["digest"] = hashlib.sha256(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return evidence.PushPlan.model_validate(body)


def _lane(monkeypatch, tmp_path, engine):
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        project = Project(name="fixture", repo_path=ROOT)
        db.add(project)
        db.flush()
        assert project.id == 1, "the isolated schema starts with its own normal sequence"
        db.add(GatePolicy(project_id=1, active=True, max_critical=0, max_high=0, block_secrets=True))
        grant = policy.PushMember(client_slot=SLOT, generation=1, name="QA profile", state="approved", requested_at=STAMP, approved_at=STAMP)
        current = policy.PushPolicy(repository_id=REPOSITORY, name="fixture", project_id=1, root_path=ROOT,
            git_directory=ROOT + "/.git", revision=4, enabled=True, members=[grant])
        db.add(RuntimeConfig(key=policy.POLICY_PREFIX + REPOSITORY, value=current.model_dump_json()))
        db.commit()
        request = SimpleNamespace(state=SimpleNamespace(auth=AuthContext(kind="ide", subject=SLOT,
            scopes=frozenset(), capability_generation=1)))
        runtime = SimpleNamespace(settings=SimpleNamespace(source_snapshot_dir=str(tmp_path / "source-snapshots")))
        monkeypatch.setattr(policy, "_active_member", lambda *args, **kwargs: {"generation": 1, "client_name": "QA profile"})
        preflight = {"ready": True, "revision": PREFLIGHT, "enabled_tool_ids": ["sast-lite"],
            "runtime_identities": {"sast-lite": RUNTIME_IDENTITY}}
        monkeypatch.setattr(main, "_scanner_preflight", lambda *args, **kwargs: dict(preflight))
        yield SimpleNamespace(db=db, request=request, runtime=runtime, current=current, preflight=preflight)


@pytest.fixture
def lane(monkeypatch, tmp_path):
    # SQLite domain checks do not claim production concurrency qualification.
    engine = create_engine("sqlite://")
    try:
        yield from _lane(monkeypatch, tmp_path, engine)
    finally:
        engine.dispose()


@pytest.fixture
def postgres_lane(monkeypatch, tmp_path, postgres_engine):
    yield from _lane(monkeypatch, tmp_path, postgres_engine)


def seed_scan(lane, upload=None):
    upload = upload or tree()
    binding = evidence.upload_git_tree(REPOSITORY, upload, lane.request, lane.runtime, lane.db)
    scan = Scan(project_id=binding["project_id"], status="completed", revision=1, findings_revision=1,
        scanner_summary={"tools": [{"id": "sast-lite", "enabled": True, "runtime_identity": RUNTIME_IDENTITY}]})
    lane.db.add(scan)
    lane.db.flush()
    job = Job(kind="scan", title="Git fixture", scan_id=scan.id, status="completed", payload={
        "source_snapshot_digest": binding["snapshot_digest"], "preflight_revision": PREFLIGHT,
        "coverage": "complete", "use_ai": False, "enabled_tools": ["sast-lite"], "omitted_tools": [],
        "target_path": None, "target_kind": None, "source_snapshot": {"kind": "git-commit"}})
    lane.db.add(job)
    lane.db.commit()
    return binding, scan, job, plan(upload.tree_oid)


def test_tree_recomputation_rejects_tampering_modes_and_excessive_depth():
    valid = tree()
    assert evidence.verified_tree_files(valid)[0].path == "app.py"
    changed = valid.model_copy(update={"tree_oid": "0" * 40})
    with pytest.raises(HTTPException) as mismatch:
        evidence.verified_tree_files(changed)
    assert mismatch.value.detail["code"] == "push_tree_invalid"
    file = valid.files[0].model_copy(update={"mode": "100755"})
    with pytest.raises(HTTPException):
        evidence.verified_tree_files(valid.model_copy(update={"files": [file]}))
    file = valid.files[0].model_copy(update={"path": "/".join(["d"] * 64 + ["app.py"])} )
    with pytest.raises(HTTPException) as depth:
        evidence.verified_tree_files(valid.model_copy(update={"files": [file]}))
    assert depth.value.detail["code"] == "push_tree_unsupported"


def test_one_repository_reuses_source_project_and_tree_identity(lane):
    first = evidence.upload_git_tree(REPOSITORY, tree(), lane.request, lane.runtime, lane.db)
    repeated = evidence.upload_git_tree(REPOSITORY, tree(), lane.request, lane.runtime, lane.db)
    second = evidence.upload_git_tree(REPOSITORY, tree(b"second immutable version\n"), lane.request, lane.runtime, lane.db)
    assert first == repeated
    assert first["project_id"] == second["project_id"]
    assert first["source_id"] == second["source_id"] == REPOSITORY
    assert first["snapshot_digest"] != second["snapshot_digest"]
    assert len(list(lane.db.scalars(select(Project)))) == 2


def test_removed_source_project_blocks_without_recreating_user_state(lane):
    _, _, _, outgoing = seed_scan(lane)
    lane.db.delete(lane.db.get(Project, 1))
    lane.db.commit()
    assert evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)["reason_code"] == "push_project_unavailable"
    with pytest.raises(HTTPException) as blocked:
        evidence.upload_git_tree(REPOSITORY, tree(b"different\n"), lane.request, lane.runtime, lane.db)
    assert blocked.value.detail["code"] == "push_project_unavailable"
    assert len(list(lane.db.scalars(select(Project)))) == 1


@pytest.mark.parametrize("root", [
    "/Users/Developer/dev/lomo-kodesec/.kodesec-test/git-push-acceptance/git-push-PZEG9d/source",
    "C:\\Users\\Developer\\Documents\\Lomo CodeSecurity\\git-push-acceptance\\unicode-ž\\source",
])
def test_repository_path_identity_accepts_long_canonical_directories(root):
    separator = "\\" if root.startswith("C:") else "/"
    directory = root + separator + ".git"
    repository_id = hashlib.sha256(f"lomo-git-repository/v1\0{root}\0{directory}".encode()).hexdigest()
    value = policy.PushPolicyCreate(repository_id=repository_id, name="Local fixture", root_path=root, git_directory=directory)
    assert value.root_path == root and value.git_directory == directory


def test_repository_name_accepts_long_descriptive_name_but_not_explicit_credentials():
    name = "owasp-benchmark-java-20cbf3d-upstream"
    value = policy.PushPolicyCreate(repository_id=REPOSITORY, name=name, root_path=ROOT, git_directory=ROOT + "/.git")
    assert value.name == name
    with pytest.raises(ValueError):
        policy.PushPolicyCreate(repository_id=REPOSITORY, name="ghp_syntheticcredential123456789", root_path=ROOT, git_directory=ROOT + "/.git")


@pytest.mark.parametrize("suffix", ["ghp_syntheticcredential123456789", "password=synthetic", "Bearer synthetic", "unsafe\u202esource", "unsafe\0source"])
def test_repository_path_identity_still_rejects_credentials_and_controls(suffix):
    root = "/fixture/" + suffix
    directory = root + "/.git"
    repository_id = hashlib.sha256(f"lomo-git-repository/v1\0{root}\0{directory}".encode()).hexdigest()
    with pytest.raises(ValueError):
        policy.PushPolicyCreate(repository_id=repository_id, name="Fixture", root_path=root, git_directory=directory)


@pytest.mark.parametrize("enabled", [True, False])
def test_project_delete_refuses_gate_and_snapshot_companion_before_any_file_cleanup(lane, monkeypatch, enabled):
    binding, scan, _, _ = seed_scan(lane)
    row, current = policy.load_policy(lane.db, REPOSITORY)
    row.value = current.model_copy(update={"enabled": enabled}).model_dump_json()
    lane.db.commit()
    monkeypatch.setattr(main, "_delete_artifact_files", lambda *args: pytest.fail("the deletion guard must run before file cleanup"))
    for project_id in (current.project_id, binding["project_id"]):
        with pytest.raises(HTTPException) as failure:
            main.delete_project(project_id, lane.runtime, lane.db)
        assert failure.value.status_code == 409
        assert failure.value.detail["code"] == "push_protection_attached"
    assert lane.db.get(Scan, scan.id) is not None
    assert len(list(lane.db.scalars(select(Project)))) == 2


def removal(lane):
    return policy.PushPolicyRemoval(expected_revision=lane.current.revision, confirm_removal=True, hook_digest=None)


def test_remove_registration_is_explicit_and_preserves_projects_scans_snapshots_and_other_bindings(lane):
    binding, scan, _, _ = seed_scan(lane)
    other_repository = "9" * 64
    other = evidence.GitTreeBinding.model_validate(binding).model_copy(update={"repository_id": other_repository, "source_id": other_repository})
    other_key = evidence.tree_key(other_repository, other.tree_oid)
    lane.db.add(RuntimeConfig(key=other_key, value=other.model_dump_json(by_alias=True)))
    lane.db.commit()
    snapshot_files = sorted(path.relative_to(lane.runtime.settings.source_snapshot_dir) for path in Path(lane.runtime.settings.source_snapshot_dir).rglob("*") if path.is_file())
    result = policy.remove_push_repository(REPOSITORY, removal(lane), lane.request, lane.db)
    assert result == {"repository_id": REPOSITORY, "removed": True, "revision": lane.current.revision,
        "tree_bindings_deleted": 1, "already_removed": False}
    assert lane.db.get(RuntimeConfig, policy.POLICY_PREFIX + REPOSITORY) is None
    lane.db.expire_all()
    assert lane.db.get(RuntimeConfig, evidence.tree_key(REPOSITORY, binding["tree_oid"])) is None
    assert lane.db.get(RuntimeConfig, other_key) is not None
    assert lane.db.get(Scan, scan.id) is not None and len(list(lane.db.scalars(select(Project)))) == 2
    assert snapshot_files == sorted(path.relative_to(lane.runtime.settings.source_snapshot_dir) for path in Path(lane.runtime.settings.source_snapshot_dir).rglob("*") if path.is_file())
    repeated = policy.remove_push_repository(REPOSITORY, removal(lane), lane.request, lane.db)
    assert repeated == {**result, "already_removed": True}


def test_remove_orphan_then_reregister_requires_new_approval_and_never_recycles_revision(lane):
    policy.remove_push_repository(REPOSITORY, removal(lane), lane.request, lane.db)
    created = policy.register_push_repository(policy.PushPolicyCreate(repository_id=REPOSITORY, name="Fixture", project_id=1,
        root_path=ROOT, git_directory=ROOT + "/.git"), lane.request, lane.db)
    assert created.revision == lane.current.revision + 1
    assert created.enabled is False and created.members[0].state == "requested"
    # A late response/retry from the previous host removal cannot erase a new registration.
    with pytest.raises(HTTPException) as stale:
        policy.remove_push_repository(REPOSITORY, removal(lane), lane.request, lane.db)
    assert stale.value.detail["code"] == "push_approval_required"
    assert policy.load_policy(lane.db, REPOSITORY)[1].revision == created.revision


def test_remove_existing_orphan_does_not_recreate_deleted_gate_project(lane):
    _, scan, _, _ = seed_scan(lane)
    lane.db.delete(lane.db.get(Project, 1))
    lane.db.commit()
    result = policy.remove_push_repository(REPOSITORY, removal(lane), lane.request, lane.db)
    assert result["removed"] is True
    assert lane.db.get(Project, 1) is None and lane.db.get(Scan, scan.id) is not None


def test_remove_refuses_cancel_stale_revision_changed_hook_and_other_profile(lane):
    seed_scan(lane)
    payload = removal(lane)
    for changed, expected in [
        ({"confirm_removal": False}, "push_removal_confirmation_required"),
        ({"expected_revision": payload.expected_revision - 1}, "push_policy_changed"),
    ]:
        with pytest.raises(HTTPException) as failure:
            policy.remove_push_repository(REPOSITORY, payload.model_copy(update=changed), lane.request, lane.db)
        assert failure.value.detail["code"] == expected
    row, current = policy.load_policy(lane.db, REPOSITORY)
    row.value = current.model_copy(update={"hook_digest": "a" * 64}).model_dump_json()
    lane.db.commit()
    with pytest.raises(HTTPException) as hook:
        policy.remove_push_repository(REPOSITORY, payload, lane.request, lane.db)
    assert hook.value.detail["code"] == "push_hook_changed"
    other = SimpleNamespace(state=SimpleNamespace(auth=AuthContext(kind="ide", subject="ks1_" + "b" * 43,
        scopes=frozenset(), capability_generation=1)))
    with pytest.raises(HTTPException) as denied:
        policy.remove_push_repository(REPOSITORY, payload, other, lane.db)
    assert denied.value.status_code == 403 and denied.value.detail["code"] == "push_approval_required"
    assert policy.load_policy(lane.db, REPOSITORY)[1].revision == lane.current.revision


def test_current_gate_and_lifecycle_control_verdict_not_latest_scan(lane):
    _, scan, _, outgoing = seed_scan(lane)
    clean = evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)
    assert clean["decision"] == "pass" and clean["reason_code"] is None
    assert clean["preflight_revision"] == PREFLIGHT and len(clean["evidence_digest"]) == 64
    finding = Finding(scan_id=scan.id, scan_finding_number=1, scanner="gitleaks", rule_id="fixture-secret",
        severity="high", file_path="app.py", message="bounded synthetic token", fingerprint="f" * 64,
        lifecycle_status="open", suppressed=False, gate_exempt=False)
    lane.db.add(finding)
    lane.db.commit()
    assert evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)["decision"] == "blocked"
    finding.gate_exempt = True
    finding.lifecycle_status = "gate_exempt"
    lane.db.commit()
    assert evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)["decision"] == "pass"
    gate = lane.db.scalar(select(GatePolicy).where(GatePolicy.project_id == 1))
    gate.active = False
    lane.db.commit()
    assert evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)["reason_code"] == "push_gate_not_configured"


def test_persisted_scanner_runtime_identity_allows_only_matching_git_evidence(lane):
    _, scan, _, outgoing = seed_scan(lane)
    # Match the worker's actual summary persistence boundary, not a direct
    # unredacted fixture assignment that bypasses production storage behavior.
    scan.scanner_summary = main._redacted_json_object(scan.scanner_summary)
    lane.db.commit()
    lane.db.expire_all()
    assert lane.db.get(Scan, scan.id).scanner_summary["tools"][0]["runtime_identity"] == RUNTIME_IDENTITY
    current = evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)
    assert current["decision"] == "pass" and current["scans"][0]["scan_id"] == scan.id

    lane.preflight["runtime_identities"] = {"sast-lite": "b" * 64}
    changed = evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)
    assert changed["decision"] == "blocked"
    assert changed["reason_code"] == "push_evidence_missing_or_stale"
    assert changed["missing_trees"] == outgoing.trees
    assert changed["scans"] == []


@pytest.mark.parametrize("mutation", ["binary", "data", "limited", "advisor", "cancelled"])
def test_missing_or_stale_execution_never_authorizes(lane, mutation):
    _, scan, job, outgoing = seed_scan(lane)
    if mutation == "binary":
        lane.preflight["runtime_identities"] = {"sast-lite": "b" * 64}
    elif mutation == "data":
        lane.preflight["revision"] = "b" * 64
    elif mutation == "limited":
        job.payload = {**job.payload, "coverage": "limited"}
    elif mutation == "advisor":
        job.payload = {**job.payload, "use_ai": True}
    else:
        scan.status = job.status = "cancelled"
    lane.db.commit()
    assert evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)["decision"] == "blocked"


@pytest.mark.parametrize("mutation", ["policy", "member", "finding", "gate", "gate_limits", "readiness"])
def test_final_fence_rejects_authority_changed_during_evaluation(lane, monkeypatch, mutation):
    _, scan, _, outgoing = seed_scan(lane)
    calls = 0
    def readiness(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            row = lane.db.get(RuntimeConfig, policy.POLICY_PREFIX + REPOSITORY)
            saved = policy.PushPolicy.model_validate_json(row.value)
            if mutation == "policy":
                row.value = saved.model_copy(update={"enabled": False, "revision": saved.revision + 1}).model_dump_json()
            elif mutation == "member":
                row.value = saved.model_copy(update={"members": [saved.members[0].model_copy(update={"state": "revoked", "approved_at": None})], "revision": saved.revision + 1}).model_dump_json()
            elif mutation == "finding":
                lane.db.get(Scan, scan.id).findings_revision += 1
            elif mutation == "gate":
                lane.db.scalar(select(GatePolicy).where(GatePolicy.project_id == 1)).active = False
            elif mutation == "gate_limits":
                lane.db.scalar(select(GatePolicy).where(GatePolicy.project_id == 1)).max_high = 1
            else:
                lane.preflight["revision"] = "b" * 64
            lane.db.commit()
        return dict(lane.preflight)
    monkeypatch.setattr(main, "_scanner_preflight", readiness)
    if mutation == "member":
        with pytest.raises(HTTPException) as rejected:
            evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)
        assert rejected.value.detail["code"] == "push_approval_required"
    else:
        assert evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)["decision"] == "blocked"


def test_owner_consent_revision_and_independent_member_scope(lane):
    browser = SimpleNamespace(state=SimpleNamespace(auth=AuthContext(kind="browser", subject="owner", scopes=frozenset())))
    with pytest.raises(HTTPException) as no_warning:
        policy.update_push_policy(REPOSITORY, policy.PushPolicyUpdate(expected_revision=4, enabled=False), browser, lane.db)
    assert no_warning.value.detail["code"] == "push_bypass_confirmation_required"
    off = policy.update_push_policy(REPOSITORY, policy.PushPolicyUpdate(expected_revision=4, enabled=False, confirm_bypass=True), browser, lane.db)
    assert off.enabled is False and off.revision == 5
    assert evidence.check_git_push(REPOSITORY, plan(tree().tree_oid), lane.request, lane.runtime, lane.db)["decision"] == "off"
    with pytest.raises(HTTPException) as stale:
        policy.update_push_policy(REPOSITORY, policy.PushPolicyUpdate(expected_revision=4, enabled=True), browser, lane.db)
    assert stale.value.detail["code"] == "push_policy_changed"
    lane.request.state.auth = AuthContext(kind="ide", subject="ks1_" + "x" * 43, scopes=frozenset(), capability_generation=1)
    with pytest.raises(HTTPException) as other:
        evidence.upload_git_tree(REPOSITORY, tree(), lane.request, lane.runtime, lane.db)
    assert other.value.detail["code"] == "push_approval_required"


def test_api_cli_positive_contract(lane):
    _, _, _, outgoing = seed_scan(lane)
    result = jsonable_encoder(evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db))
    value = {"plan": outgoing.model_dump(mode="json", by_alias=True), "policy_revision": 4, "response": result}
    contract = Path(__file__).parent / "fixtures" / "git-push-check-pass.json"
    if not contract.exists():
        pytest.fail("Add this production-serialized cross-client fixture: " + json.dumps(value, sort_keys=True))
    assert value == json.loads(contract.read_text())


def test_deletion_only_and_empty_plan_do_not_require_scanners(lane, monkeypatch):
    for refs in ([], [{"local_ref": "(delete)", "local_oid": "0" * 40,
            "remote_ref": "refs/heads/main", "remote_oid": "a" * 40}]):
        body = plan(tree().tree_oid).model_dump(mode="json", by_alias=True, exclude={"digest"})
        body.update(refs=refs, trees=[], commits=[])
        body["digest"] = hashlib.sha256(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        no_source = evidence.PushPlan.model_validate(body)
        def unavailable(*args, **kwargs):
            raise AssertionError("Deletion-only check must not require scanner work")
        monkeypatch.setattr(main, "_scanner_preflight", unavailable)
        assert evidence.check_git_push(REPOSITORY, no_source, lane.request, lane.runtime, lane.db)["decision"] == "pass"


def test_real_preflight_revision_binds_executing_runtime_identity(lane, monkeypatch):
    # Retrieve the actual implementation rather than the lane's readiness stub.
    snapshot = SimpleNamespace(tools={"sast-lite": {"runtime_identity": "a" * 64}}, active_generation=None, cache_verification=None)
    monkeypatch.setattr(main, "_scanner_runtime_snapshot", lambda settings: snapshot)
    monkeypatch.setattr(main, "_scanner_tool_rows", lambda *args, **kwargs: [{"id": "sast-lite", "enabled": True, "runtime_ready": True}])
    first = REAL_PREFLIGHT(lane.db, lane.runtime.settings)
    snapshot.tools["sast-lite"]["runtime_identity"] = "b" * 64
    second = REAL_PREFLIGHT(lane.db, lane.runtime.settings, include_runtime_identity=True)
    assert first["ready"] is True and second["ready"] is True
    assert first["revision"] != second["revision"]
    assert "runtime_identities" not in first
    assert second["runtime_identities"] == {"sast-lite": "b" * 64}


@pytest.mark.parametrize("change", ["catalog", "runtime", "generation", "cache", "readiness", "critical"])
def test_catalog_check_reuses_evidence_without_weakening_execution_or_gate_checks(lane, monkeypatch, change):
    snapshot = SimpleNamespace(tools={"sast-lite": {"runtime_identity": RUNTIME_IDENTITY}},
        active_generation="a" * 64, cache_verification=None)
    rows = [{"id": "sast-lite", "name": "SAST Lite", "enabled": True, "runtime_ready": True}]
    monkeypatch.setattr(main, "_scanner_runtime_snapshot", lambda settings: snapshot)
    monkeypatch.setattr(main, "_scanner_tool_rows", lambda *args, **kwargs: rows)
    monkeypatch.setattr(main, "_scanner_cache_rollback_eligibility", lambda *args: {
        "eligible": False, "reason_code": "no_previous_generation",
        "reason": "No previous-good scanner cache generation is available.", "target_generation": None})
    monkeypatch.setattr(main, "_scanner_preflight", REAL_PREFLIGHT)
    catalog = lane.db.get(ScannerLifecycleState, "catalog")
    cache = lane.db.get(ScannerLifecycleState, "cache")
    catalog.revision = cache.revision = 16
    lane.db.commit()
    initial = REAL_PREFLIGHT(lane.db, lane.runtime.settings)
    _, scan, job, outgoing = seed_scan(lane)
    job.payload = {**job.payload, "preflight_revision": initial["revision"]}
    lane.db.commit()
    assert evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)["decision"] == "pass"

    catalog.revision = 19  # A catalog check does not install binaries, rules or data.
    lane.db.commit()
    refreshed = REAL_PREFLIGHT(lane.db, lane.runtime.settings)
    assert refreshed["catalog_revision"] == 19
    assert refreshed["revision"] == initial["revision"]
    if change == "runtime":
        snapshot.tools["sast-lite"]["runtime_identity"] = "b" * 64
    elif change == "generation":
        snapshot.active_generation = "b" * 64
    elif change == "cache":
        cache.revision += 1
    elif change == "readiness":
        rows[0]["runtime_ready"] = False
    elif change == "critical":
        lane.db.add(Finding(scan_id=scan.id, scan_finding_number=1, scanner="sast-lite",
            rule_id="fixture-critical", severity="critical", file_path="app.py",
            message="Synthetic critical finding", fingerprint="f" * 64,
            lifecycle_status="open", suppressed=False, gate_exempt=False))
    lane.db.commit()
    result = evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)
    assert result["decision"] == ("pass" if change == "catalog" else "blocked")
    if change == "catalog":
        assert result["scans"][0]["scan_id"] == scan.id
    assert list(lane.db.scalars(select(Job.id))) == [job.id]


def test_postgres_concurrent_tree_upload_is_one_source_and_one_binding(postgres_lane):
    lane = postgres_lane
    ready = Barrier(2)
    engine = lane.db.get_bind()
    def upload():
        with Session(engine) as db:
            ready.wait(timeout=10)
            return evidence.upload_git_tree(REPOSITORY, tree(), lane.request, lane.runtime, db)
    with ThreadPoolExecutor(max_workers=2) as pool:
        left, right = pool.submit(upload), pool.submit(upload)
        assert left.result(timeout=20) == right.result(timeout=20)
    assert len(list(lane.db.scalars(select(Project)))) == 2
    assert len(list(lane.db.scalars(select(RuntimeConfig).where(RuntimeConfig.key.startswith(evidence.TREE_PREFIX))))) == 1


def test_postgres_removal_serializes_tree_upload_without_orphan_binding(postgres_lane):
    lane = postgres_lane
    seed_scan(lane)
    ready = Barrier(2)
    engine = lane.db.get_bind()
    def upload():
        with Session(engine) as db:
            ready.wait(timeout=10)
            try:
                return evidence.upload_git_tree(REPOSITORY, tree(b"concurrent synthetic tree\n"), lane.request, lane.runtime, db)
            except HTTPException as error:
                assert error.status_code == 404 and error.detail["code"] == "push_setup_required"
                return None
    def remove():
        with Session(engine) as db:
            ready.wait(timeout=10)
            return policy.remove_push_repository(REPOSITORY, removal(lane), lane.request, db)
    with ThreadPoolExecutor(max_workers=2) as pool:
        uploaded, removed = pool.submit(upload), pool.submit(remove)
        uploaded.result(timeout=20)
        assert removed.result(timeout=20)["removed"] is True
    lane.db.expire_all()
    assert lane.db.get(RuntimeConfig, policy.POLICY_PREFIX + REPOSITORY) is None
    assert list(lane.db.scalars(select(RuntimeConfig).where(RuntimeConfig.key.startswith(evidence.TREE_PREFIX)))) == []
    assert len(list(lane.db.scalars(select(Project)))) == 2
    assert len(list(lane.db.scalars(select(Scan)))) == 1


def test_postgres_registration_and_project_deletion_never_leave_orphan_policy(postgres_lane):
    lane = postgres_lane
    policy.remove_push_repository(REPOSITORY, removal(lane), lane.request, lane.db)
    ready = Barrier(2)
    engine = lane.db.get_bind()
    payload = policy.PushPolicyCreate(repository_id=REPOSITORY, name="Fixture", project_id=1,
        root_path=ROOT, git_directory=ROOT + "/.git")
    def register():
        with Session(engine) as db:
            ready.wait(timeout=10)
            try:
                return policy.register_push_repository(payload, lane.request, db)
            except HTTPException as error:
                assert error.status_code == 409 and error.detail["code"] == "push_project_conflict"
                return None
    def delete_project():
        with Session(engine) as db:
            ready.wait(timeout=10)
            try:
                return main.delete_project(1, lane.runtime, db)
            except HTTPException as error:
                assert error.status_code == 409 and error.detail["code"] == "push_protection_attached"
                return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        registered, deleted = pool.submit(register), pool.submit(delete_project)
        outcomes = (registered.result(timeout=20), deleted.result(timeout=20))
    assert sum(result is not None for result in outcomes) == 1
    lane.db.expire_all()
    assert (lane.db.get(Project, 1) is not None) == (lane.db.get(RuntimeConfig, policy.POLICY_PREFIX + REPOSITORY) is not None)


@pytest.mark.parametrize("revoke", [False, True])
def test_postgres_concurrent_policy_change_cannot_pass(postgres_lane, monkeypatch, revoke):
    lane = postgres_lane
    _, _, _, outgoing = seed_scan(lane)
    calls = 0
    def change_policy():
        with Session(lane.db.get_bind()) as db:
            row, saved = policy.load_policy(db, REPOSITORY)
            if revoke:
                changed = saved.model_copy(update={"revision": saved.revision + 1,
                    "members": [saved.members[0].model_copy(update={"state": "revoked", "approved_at": None})]})
            else:
                changed = saved.model_copy(update={"revision": saved.revision + 1, "enabled": False})
            policy._save(db, row, changed)
    def readiness(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(change_policy).result(timeout=10)
        return dict(lane.preflight)
    monkeypatch.setattr(main, "_scanner_preflight", readiness)
    if revoke:
        with pytest.raises(HTTPException) as denied:
            evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)
        assert denied.value.detail["code"] == "push_approval_required"
    else:
        assert evidence.check_git_push(REPOSITORY, outgoing, lane.request, lane.runtime, lane.db)["decision"] == "blocked"
