"""Immutable Git tree verification over the existing sealed snapshot/scan boundary.

The trusted local hook walks Git's DAG. The API independently binds uploaded
regular-file bytes/modes to each claimed tree and re-evaluates current scanner,
gate and finding evidence. It never runs Git or trusts a latest-worktree scan.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import Runtime, get_db, get_runtime
from .git_push_policy import load_policy, lock_push_repository, problem, require_push_member
from .models import GatePolicy, Job, Project, RuntimeConfig, Scan
from .schemas import SourceSnapshotCreate, SourceSnapshotFile
from .source_snapshots import SourceSnapshotError, source_snapshot_project_path, store_source_snapshot


router = APIRouter(prefix="/v1/git/push-protection", tags=["Git push evidence"])
TREE_PREFIX = "git.push.tree.v1."


class GitTreeFile(SourceSnapshotFile):
    mode: Literal["100644", "100755"]
    oid: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class GitTreeUpload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    object_format: Literal["sha1", "sha256"]
    tree_oid: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    files: list[GitTreeFile] = Field(max_length=5000)


class GitTreeBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_id: Literal["lomo-git-tree-evidence/v1"] = Field(alias="schema")
    repository_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    object_format: Literal["sha1", "sha256"]
    tree_oid: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    project_id: int = Field(ge=1)
    source_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    file_count: int = Field(ge=0, le=5000)
    total_bytes: int = Field(ge=0, le=64 * 1024 * 1024)


class PushRef(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    local_ref: str = Field(min_length=1, max_length=1024)
    local_oid: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    remote_ref: str = Field(min_length=6, max_length=1024)
    remote_oid: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class CommitTree(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    commit_oid: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    tree_oid: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class PushPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_id: Literal["lomo-git-push-plan/v1"] = Field(alias="schema")
    repository_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    object_format: Literal["sha1", "sha256"]
    destination_digest: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    advertised_bases: list[str] = Field(max_length=1024)
    refs: list[PushRef] = Field(max_length=64)
    commits: list[CommitTree] = Field(max_length=256)
    trees: list[str] = Field(max_length=256)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exact_plan(self) -> "PushPlan":
        length = 40 if self.object_format == "sha1" else 64
        ids = [*self.trees, *self.advertised_bases, *(item.commit_oid for item in self.commits), *(item.tree_oid for item in self.commits), *(item.local_oid for item in self.refs), *(item.remote_oid for item in self.refs)]
        if any(len(value) != length or any(char not in "0123456789abcdef" for char in value) for value in ids):
            raise ValueError("Git plan object formats must match exactly")
        if len({item.remote_ref for item in self.refs}) != len(self.refs) or len({item.commit_oid for item in self.commits}) != len(self.commits) or self.trees != sorted({item.tree_oid for item in self.commits}):
            raise ValueError("Git plan references and immutable tree coverage must be unique and complete")
        if bool(self.commits) != any(set(item.local_oid) != {"0"} for item in self.refs):
            raise ValueError("Non-deletion references require immutable commit coverage")
        rendered = json.dumps(self.model_dump(mode="json", by_alias=True, exclude={"digest"}), ensure_ascii=False, separators=(",", ":"))
        if hashlib.sha256(rendered.encode()).hexdigest() != self.digest:
            raise ValueError("Git plan digest does not match its exact immutable identities")
        return self


def _git_oid(kind: str, content: bytes, algorithm: str) -> str:
    return hashlib.new(algorithm, f"{kind} {len(content)}\0".encode() + content).hexdigest()


def verified_tree_files(payload: GitTreeUpload) -> list[SourceSnapshotFile]:
    """Recompute Git's complete tree recursively; filenames never become commands."""
    root: dict[str, Any] = {}
    total = 0
    metadata_bytes = 0
    files: list[SourceSnapshotFile] = []
    for item in payload.files:
        try:
            content = base64.b64decode(item.content_base64, validate=True)
        except (ValueError, TypeError) as exc:
            raise problem("push_tree_invalid", "An immutable Git file is not valid bounded content.", 422) from exc
        total += len(content)
        if total > 64 * 1024 * 1024 or len(content) != item.size_bytes or hashlib.sha256(content).hexdigest() != item.sha256 or _git_oid("blob", content, payload.object_format) != item.oid:
            raise problem("push_tree_invalid", "Immutable Git file bytes do not match their declared identity.", 422)
        node = root
        parts = item.path.split("/")
        metadata_bytes += len(item.path.encode()) + 128
        if len(parts) > 64 or metadata_bytes > 4 * 1024 * 1024:
            raise problem("push_tree_unsupported", "The immutable tree exceeds the supported path depth or metadata bound.", 422)
        if any(part.lower() == ".git" for part in parts):
            raise problem("push_tree_unsupported", "Git administration paths cannot be included in an immutable scan.", 422)
        for part in parts[:-1]:
            child = node.setdefault(part, {})
            if not isinstance(child, dict):
                raise problem("push_tree_invalid", "Immutable Git paths overlap a regular file.", 422)
            node = child
        if parts[-1] in node:
            raise problem("push_tree_invalid", "Immutable Git paths must be unique.", 422)
        node[parts[-1]] = (item.mode, item.oid)
        files.append(SourceSnapshotFile.model_validate(item.model_dump(exclude={"mode", "oid"})))

    def tree_oid(node: dict[str, Any]) -> str:
        entries: list[tuple[bytes, bytes]] = []
        for name, entry in node.items():
            directory = isinstance(entry, dict)
            mode, oid = ("40000", tree_oid(entry)) if directory else entry
            encoded = name.encode("utf-8")
            entries.append((encoded + (b"/" if directory else b""), mode.encode() + b" " + encoded + b"\0" + bytes.fromhex(oid)))
        return _git_oid("tree", b"".join(value for _, value in sorted(entries)), payload.object_format)

    if tree_oid(root) != payload.tree_oid:
        raise problem("push_tree_invalid", "Uploaded files do not cover the complete immutable Git tree.", 422)
    return sorted(files, key=lambda item: item.path)


def tree_key(repository_id: str, tree_oid: str) -> str:
    return TREE_PREFIX + hashlib.sha256(f"{repository_id}\0{tree_oid}".encode()).hexdigest()


def remove_tree_bindings(db: Session, repository_id: str) -> int:
    """Remove typed metadata only, under the caller's exact repository lock.

    RuntimeConfig stores JSON as text; validate that metadata with its existing
    type instead of matching JSON substrings or casting arbitrary config values.
    Batches bound memory without changing or deleting source snapshots/findings.
    """
    statement = select(RuntimeConfig.key, RuntimeConfig.value).where(
        RuntimeConfig.key.startswith(TREE_PREFIX),
    ).order_by(RuntimeConfig.key).execution_options(yield_per=64)
    count = 0
    for rows in db.execute(statement).partitions(64):
        keys = []
        for key, value in rows:
            try:
                binding = GitTreeBinding.model_validate_json(value)
            except ValueError as exc:
                raise problem("push_evidence_corrupt", "Git evidence needs owner review before registration cleanup.", 503) from exc
            if binding.source_id != binding.repository_id or key != tree_key(binding.repository_id, binding.tree_oid):
                raise problem("push_evidence_corrupt", "Git evidence names another source; no registration cleanup was committed.", 503)
            if binding.repository_id == repository_id:
                keys.append(key)
        if keys:
            db.execute(delete(RuntimeConfig).where(RuntimeConfig.key.in_(keys)), execution_options={"synchronize_session": False})
        count += len(keys)
    return count


@router.post("/{repository_id}/trees", status_code=201)
def upload_git_tree(repository_id: str, payload: GitTreeUpload, request: Request, runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)) -> dict[str, object]:
    lock_push_repository(db, repository_id)
    _, policy = load_policy(db, repository_id, for_update=True)
    require_push_member(request, db, policy, for_update=True)
    if db.get(Project, policy.project_id) is None:
        raise problem("push_project_unavailable", "The registered source project was removed. Review this repository's protection before creating more scan data.")
    files = verified_tree_files(payload)
    source_id = repository_id
    snapshot = SourceSnapshotCreate(source_id=source_id, name=f"Git check · {policy.name[:100]}", files=files)
    try:
        snapshot_digest, _, count, size = store_source_snapshot(runtime.settings, snapshot)
    except SourceSnapshotError as exc:
        status = {"snapshot_storage_full": 507, "snapshot_storage_busy": 409, "snapshot_storage_unavailable": 503}.get(exc.code, 422)
        raise problem(exc.code, str(exc), status) from exc
    project_path = source_snapshot_project_path(source_id, kind="git-commit")
    project = db.scalar(select(Project).where(Project.repo_path == project_path))
    if project is None:
        project = Project(name=snapshot.name, repo_path=project_path, remote_url=None, default_branch="main")
        db.add(project)
        db.flush()
        # The exact root's current gate policy owns the final push verdict;
        # this explicit inactive policy prevents an incidental synthetic scan
        # from claiming to be the original working-tree project's passing gate.
        db.add(GatePolicy(project_id=project.id, active=False))
    value = {"schema": "lomo-git-tree-evidence/v1", "repository_id": repository_id,
        "object_format": payload.object_format, "tree_oid": payload.tree_oid,
        "project_id": project.id, "source_id": source_id, "snapshot_digest": snapshot_digest,
        "file_count": count, "total_bytes": size}
    row = db.get(RuntimeConfig, tree_key(repository_id, payload.tree_oid))
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if row is not None and row.value != encoded:
        raise problem("push_tree_binding_changed", "The immutable Git tree's stored source binding changed. Review it before scanning.")
    if row is None:
        db.add(RuntimeConfig(key=tree_key(repository_id, payload.tree_oid), value=encoded))
    db.commit()
    return value


@router.post("/{repository_id}/check")
def check_git_push(repository_id: str, plan: PushPlan, request: Request, runtime: Runtime = Depends(get_runtime), db: Session = Depends(get_db)) -> dict[str, object]:
    # Import after application assembly; these are the existing authoritative
    # readiness and scoring boundaries, not a second implementation of them.
    from .main import _evaluate_scan_gate, _scanner_preflight

    _, policy = load_policy(db, repository_id)
    require_push_member(request, db, policy)
    if plan.repository_id != repository_id:
        raise problem("push_repository_changed", "The outgoing plan belongs to a different repository.", 422)
    result: dict[str, object] = {"repository_id": repository_id, "policy_revision": policy.revision,
        "plan_digest": plan.digest, "decision": "blocked", "reason_code": None,
        "missing_trees": [], "scans": []}
    if not policy.enabled:
        return {**result, "decision": "off"}
    if db.get(Project, policy.project_id) is None:
        return {**result, "reason_code": "push_project_unavailable"}
    if not plan.trees:
        # A verified deletion-only/no-op plan transmits no new source trees.
        # Still check current approval and policy; scanner outages need not
        # prevent removing a remote branch.
        _, current = load_policy(db, repository_id, for_update=True)
        require_push_member(request, db, current, for_update=True)
        if current.model_dump() != policy.model_dump():
            return {**result, "reason_code": "push_policy_changed"}
        empty_revision = hashlib.sha256(b"lomo-git-no-outgoing-trees/v1").hexdigest()
        proof = {"plan": plan.digest, "policy": current.model_dump(mode="json"), "scope": "no_outgoing_trees"}
        return {**result, "decision": "pass", "preflight_revision": empty_revision,
            "evidence_digest": hashlib.sha256(json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    preflight = _scanner_preflight(db, runtime.settings, include_runtime_identity=True)
    gate = db.scalar(select(GatePolicy).where(GatePolicy.project_id == policy.project_id))
    if gate is None or not gate.active:
        return {**result, "reason_code": "push_gate_not_configured"}
    gate_fields = ("active", "max_critical", "max_high", "block_secrets")
    gate_values = {field: getattr(gate, field) for field in gate_fields}
    if not preflight.get("ready"):
        return {**result, "reason_code": "push_scanners_not_ready"}
    runtime_identities = preflight.get("runtime_identities", {})
    if not runtime_identities or any(not isinstance(value, str) or len(value) != 64 for value in runtime_identities.values()):
        return {**result, "reason_code": "push_scanner_identity_unavailable"}
    missing: list[str] = []
    scans: list[dict[str, object]] = []
    for tree in plan.trees:
        row = db.get(RuntimeConfig, tree_key(repository_id, tree))
        if row is None:
            missing.append(tree)
            continue
        try:
            binding = GitTreeBinding.model_validate_json(row.value).model_dump(by_alias=True)
        except (ValueError, TypeError) as exc:
            raise problem("push_evidence_corrupt", "Immutable Git evidence needs owner review.", 503) from exc
        if binding["repository_id"] != repository_id or binding["tree_oid"] != tree or binding["source_id"] != repository_id or binding["object_format"] != plan.object_format:
            raise problem("push_evidence_corrupt", "Immutable Git evidence names another source.", 503)
        project = db.get(Project, binding["project_id"])
        if project is None or project.repo_path != source_snapshot_project_path(repository_id, kind="git-commit"):
            raise problem("push_evidence_corrupt", "Immutable Git evidence lost its exact source project.", 503)
        candidates = list(db.execute(select(Scan, Job).join(Job, Job.scan_id == Scan.id).where(
            Scan.project_id == binding["project_id"], Job.kind == "scan",
            Job.payload["source_snapshot_digest"].as_string() == binding["snapshot_digest"],
            Job.payload["preflight_revision"].as_string() == preflight["revision"],
        ).order_by(Scan.id.desc()).limit(8)))
        selected = next(((scan, job) for scan, job in candidates if isinstance(job.payload, dict)
            and job.payload.get("source_snapshot_digest") == binding["snapshot_digest"]
            and job.payload.get("preflight_revision") == preflight["revision"]
            and job.payload.get("coverage") == "complete" and job.payload.get("use_ai") is False
            and job.payload.get("enabled_tools") == preflight["enabled_tool_ids"]
            and job.payload.get("omitted_tools") == []
            and job.payload.get("target_path") is None and job.payload.get("target_kind") is None
            and isinstance(job.payload.get("source_snapshot"), dict)
            and job.payload["source_snapshot"].get("kind") == "git-commit"), None)
        if selected is None:
            missing.append(tree)
            continue
        scan, job = selected
        tools = scan.scanner_summary.get("tools") if isinstance(scan.scanner_summary, dict) else None
        executed = {tool["id"]: tool.get("runtime_identity") for tool in tools
            if isinstance(tool, dict) and isinstance(tool.get("id"), str) and tool.get("enabled") is True} if isinstance(tools, list) else {}
        if scan.status == "completed" and (job.status != "completed" or executed != runtime_identities):
            missing.append(tree)
            continue
        decision, _ = _evaluate_scan_gate(db, scan, policy_project_id=policy.project_id)
        scans.append({"tree_oid": tree, "scan_id": scan.id, "job_id": job.id,
            "status": scan.status, "gate_decision": decision, "revision": scan.revision,
            "findings_revision": scan.findings_revision})
    result.update({"missing_trees": missing, "scans": scans, "preflight_revision": preflight["revision"]})
    if missing:
        return {**result, "reason_code": "push_evidence_missing_or_stale"}
    if any(item["status"] != "completed" or item["gate_decision"] != "pass" for item in scans):
        return {**result, "reason_code": "push_gate_failed_or_incomplete"}
    # Read readiness once more before acquiring the final database locks: its
    # existing version reconciliation may commit. After that, no helper in this
    # final authority observation commits or releases our locks.
    db.expire_all()
    final_preflight = _scanner_preflight(db, runtime.settings, include_runtime_identity=True)
    if final_preflight["revision"] != preflight["revision"]:
        return {**result, "reason_code": "push_evidence_changed"}
    db.expire_all()
    _, final_policy = load_policy(db, repository_id, for_update=True)
    require_push_member(request, db, final_policy, for_update=True)
    if final_policy.model_dump() != policy.model_dump():
        return {**result, "reason_code": "push_policy_changed"}
    final_gate = db.scalar(select(GatePolicy).where(GatePolicy.project_id == policy.project_id)
        .execution_options(populate_existing=True).with_for_update())
    if final_gate is None or not final_gate.active:
        return {**result, "reason_code": "push_gate_not_configured"}
    if {field: getattr(final_gate, field) for field in gate_fields} != gate_values:
        return {**result, "reason_code": "push_policy_changed"}
    locked_scans = {scan.id: scan for scan in db.scalars(select(Scan)
        .where(Scan.id.in_([item["scan_id"] for item in scans])).order_by(Scan.id)
        .execution_options(populate_existing=True).with_for_update())}
    for item in scans:
        scan = locked_scans.get(item["scan_id"])
        if scan is None or scan.revision != item["revision"] or scan.findings_revision != item["findings_revision"]:
            return {**result, "reason_code": "push_evidence_changed"}
        decision, _ = _evaluate_scan_gate(db, scan, policy_project_id=policy.project_id)
        if scan.status != "completed" or decision != "pass":
            return {**result, "reason_code": "push_gate_failed_or_incomplete"}
    evidence = {"plan": plan.digest, "policy": policy.model_dump(mode="json"),
        "gate": {field: getattr(final_gate, field) for field in gate_fields},
        "preflight": preflight["revision"], "scans": scans}
    return {**result, "decision": "pass", "evidence_digest": hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
