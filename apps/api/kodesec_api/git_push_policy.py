"""Repository push policy. Desired configuration is not installed-hook evidence.

This first-release feature uses the existing private configuration store and
compare-and-swap pattern; it does not create a schema adoption path or execute Git.
"""
from __future__ import annotations

import re
import hashlib
import ntpath
import posixpath
import unicodedata
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import AuthContext, _browser_context, _ide_context, active_ide_capability_record
from .db import get_db
from .models import GatePolicy, Project, RuntimeConfig
from .redaction import contains_explicit_credential, redact_text
from .source_snapshots import source_snapshot_project_path


router = APIRouter(prefix="/v1/git/push-protection", tags=["Git push protection"])
POLICY_PREFIX = "git.push.policy.v1."
REMOVAL_PREFIX = "git.push.removed.v1."
MAX_REPOSITORIES = 32
IDENTITY = re.compile(r"[0-9a-f]{64}\Z")


class PushMember(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    client_slot: str = Field(pattern=r"^ks1_[A-Za-z0-9_-]{43}$")
    generation: int = Field(ge=1, le=2_147_483_647)
    name: str = Field(min_length=1, max_length=120)
    state: Literal["requested", "approved", "revoked"]
    requested_at: str
    approved_at: str | None = None

    @model_validator(mode="after")
    def coherent_member(self) -> "PushMember":
        PushPolicy.safe_name(self.name)
        for value in (self.requested_at, self.approved_at):
            if value is not None and (len(value) > 40 or datetime.fromisoformat(value).utcoffset() is None):
                raise ValueError("Member activity must have an explicit timestamp")
        if (self.state == "approved") != (self.approved_at is not None):
            raise ValueError("Member approval and its timestamp must agree")
        return self


class PushPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    repository_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    name: str = Field(min_length=1, max_length=120)
    project_id: int = Field(ge=1)
    root_path: str = Field(min_length=1, max_length=4096)
    git_directory: str = Field(min_length=1, max_length=4096)
    revision: int = Field(ge=1, le=2_147_483_647)
    enabled: bool = False
    observed_state: Literal["not_installed", "installed", "needs_repair"] = "not_installed"
    observed_revision: int | None = Field(default=None, ge=1)
    observed_at: str | None = None
    hook_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reason_code: Literal["host_setup_required", "hook_missing_or_changed", "policy_changed"] | None = "host_setup_required"
    members: list[PushMember] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def coherent_policy(self) -> "PushPolicy":
        PushPolicyCreate(repository_id=self.repository_id, name=self.name, project_id=self.project_id,
            root_path=self.root_path, git_directory=self.git_directory)
        if len({(member.client_slot, member.generation) for member in self.members}) != len(self.members):
            raise ValueError("Repository member identities must be unique")
        if self.observed_revision is not None and self.observed_revision > self.revision:
            raise ValueError("A hook cannot observe a future policy revision")
        if self.observed_at is not None and (len(self.observed_at) > 40 or datetime.fromisoformat(self.observed_at).utcoffset() is None):
            raise ValueError("Hook observation needs an explicit timestamp")
        if self.observed_state == "installed" and (self.observed_at is None or self.observed_revision is None or self.hook_digest is None):
            raise ValueError("Installed observation requires exact digest, revision and timestamp")
        return self

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        if value != value.strip() or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value) or contains_explicit_credential(value):
            raise ValueError("Use a recognizable repository name without secrets or control characters.")
        return value


class PushPolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    repository_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    name: str = Field(min_length=1, max_length=120)
    project_id: int | None = Field(default=None, ge=1)
    root_path: str = Field(min_length=1, max_length=4096)
    git_directory: str = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def source_binding(self) -> "PushPolicyCreate":
        for value in (self.root_path, self.git_directory):
            if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value) or contains_explicit_credential(value):
                raise ValueError("Use an exact local Git path without credential-shaped or control text")
        paths = ntpath if re.match(r"^[A-Za-z]:\\", self.root_path) else posixpath
        if not paths.isabs(self.root_path) or paths.dirname(self.root_path) == self.root_path or paths.normpath(self.root_path) != self.root_path or paths.join(self.root_path, ".git") != self.git_directory:
            raise ValueError("Push protection requires one canonical standalone repository and its own .git directory")
        expected = hashlib.sha256(f"lomo-git-repository/v1\0{self.root_path}\0{self.git_directory}".encode()).hexdigest()
        if expected != self.repository_id:
            raise ValueError("Repository identity does not match the exact host source")
        PushPolicy.safe_name(self.name)
        return self


class PushPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: int = Field(ge=1, le=2_147_483_646)
    enabled: bool
    confirm_bypass: bool = False


class PushHookObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: int = Field(ge=1, le=2_147_483_647)
    state: Literal["installed", "needs_repair"]
    hook_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class PushMemberApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: int = Field(ge=1, le=2_147_483_646)
    approve: bool


class PushPolicyRemoval(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: int = Field(ge=1, le=2_147_483_647)
    confirm_removal: bool
    hook_digest: str | None = Field(pattern=r"^[0-9a-f]{64}$")


class PushRemovalReceipt(BaseModel):
    """One bounded receipt per clone prevents a retried removal from targeting a new policy."""
    model_config = ConfigDict(extra="forbid", strict=True)
    repository_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    revision: int = Field(ge=1, le=2_147_483_647)
    client_slot: str = Field(pattern=r"^ks1_[A-Za-z0-9_-]{43}$")
    generation: int = Field(ge=1, le=2_147_483_647)
    hook_digest: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    tree_bindings_deleted: int = Field(ge=0)


def problem(code: str, message: str, status: int = 409) -> HTTPException:
    return HTTPException(status, {"code": code, "message": message})


def _key(repository_id: str) -> str:
    if IDENTITY.fullmatch(repository_id) is None:
        raise problem("push_repository_invalid", "Select one registered Git repository.", 422)
    return POLICY_PREFIX + repository_id


def lock_push_repository(db: Session, repository_id: str) -> None:
    """Serialize initial source/binding admission using the existing PG lock boundary."""
    if db.get_bind().dialect.name == "postgresql":
        identity = int.from_bytes(hashlib.sha256((POLICY_PREFIX + repository_id).encode()).digest()[:8], "big", signed=True)
        db.execute(select(func.pg_advisory_xact_lock(identity)))


def load_policy(db: Session, repository_id: str, *, for_update: bool = False) -> tuple[RuntimeConfig, PushPolicy]:
    statement = select(RuntimeConfig).where(RuntimeConfig.key == _key(repository_id)).execution_options(populate_existing=True)
    row = db.scalar(statement.with_for_update() if for_update else statement)
    if row is None:
        raise problem("push_setup_required", "Set up push protection for this exact repository in VS Code.", 404)
    try:
        policy = PushPolicy.model_validate_json(row.value)
    except ValueError as exc:
        raise problem("push_policy_corrupt", "Push protection configuration needs owner review; no push is approved.", 503) from exc
    if policy.repository_id != repository_id:
        raise problem("push_policy_corrupt", "Push protection configuration has a different repository identity.", 503)
    return row, policy


def _removal_receipt(db: Session, repository_id: str) -> tuple[RuntimeConfig | None, PushRemovalReceipt | None]:
    row = db.get(RuntimeConfig, REMOVAL_PREFIX + repository_id, populate_existing=True)
    if row is None:
        return None, None
    try:
        receipt = PushRemovalReceipt.model_validate_json(row.value)
    except ValueError as exc:
        raise problem("push_removal_corrupt", "This repository's removal receipt needs owner review.", 503) from exc
    if receipt.repository_id != repository_id:
        raise problem("push_removal_corrupt", "The removal receipt names another repository.", 503)
    return row, receipt


def guard_push_project_deletion(db: Session, project: Project) -> None:
    """Hold registration admission through deletion; never orphan a gate or Git source."""
    lock_push_repository(db, "registration")
    rows = list(db.scalars(select(RuntimeConfig).where(RuntimeConfig.key.startswith(POLICY_PREFIX))
        .order_by(RuntimeConfig.key).limit(MAX_REPOSITORIES + 1)))
    if len(rows) > MAX_REPOSITORIES:
        raise problem("push_policy_corrupt", "Review registered push protection before deleting projects.", 503)
    for row in rows:
        policy = load_policy(db, row.key[len(POLICY_PREFIX):])[1]
        if policy.project_id == project.id or project.repo_path == source_snapshot_project_path(policy.repository_id, kind="git-commit"):
            raise problem("push_protection_attached",
                "This project is used by repository push protection. In its owning VS Code profile, choose Protect Pushes → Remove push protection from this clone before deleting the project. Turning it off alone keeps its scan and gate bindings for re-enabling.")


def require_push_member(request: Request, db: Session, policy: PushPolicy, *, for_update: bool = False) -> AuthContext:
    context = _ide_context(request)
    if not any(member.client_slot == context.subject and member.generation == context.capability_generation and member.state == "approved" for member in policy.members):
        raise problem("push_approval_required", "Approve this editor’s repository push-protection request once in the paired browser’s Settings.", 403)
    if _active_member(db, context.subject, context.capability_generation, for_update=for_update) is None:
        raise problem("push_member_revoked", "This editor’s repository authority is no longer active.", 403)
    return context


def _active_member(db: Session, slot: str, generation: int | None, *, for_update: bool = False) -> dict[str, object] | None:
    active = active_ide_capability_record(db, slot, for_update=for_update)
    return active if active is not None and active.get("generation") == generation else None


def _save(db: Session, row: RuntimeConfig, policy: PushPolicy) -> PushPolicy:
    original = row.value
    encoded = policy.model_dump_json()
    result = db.execute(update(RuntimeConfig).where(RuntimeConfig.key == row.key, RuntimeConfig.value == original).values(value=encoded), execution_options={"synchronize_session": False})
    if result.rowcount != 1:
        db.rollback()
        raise problem("push_policy_changed", "Push protection changed in another window. Refresh before changing it.")
    db.commit()
    db.expire(row)
    return policy


@router.get("")
def list_push_policies(db: Session = Depends(get_db)) -> dict[str, list[dict[str, object]]]:
    rows = list(db.scalars(select(RuntimeConfig).where(RuntimeConfig.key.startswith(POLICY_PREFIX)).order_by(RuntimeConfig.key).limit(MAX_REPOSITORIES + 1)))
    if len(rows) > MAX_REPOSITORIES:
        raise problem("push_policy_corrupt", "Push protection exceeds its registered repository bound.", 503)
    return {"repositories": [load_policy(db, row.key[len(POLICY_PREFIX):])[1].model_dump(mode="json") for row in rows]}


@router.get("/{repository_id}", response_model=PushPolicy)
def get_push_policy(repository_id: str, db: Session = Depends(get_db)) -> PushPolicy:
    return load_policy(db, repository_id)[1]


@router.post("", response_model=PushPolicy, status_code=201)
def register_push_repository(payload: PushPolicyCreate, request: Request, db: Session = Depends(get_db)) -> PushPolicy:
    lock_push_repository(db, "registration")
    context = _ide_context(request)
    active = _active_member(db, context.subject, context.capability_generation)
    if active is None:
        raise problem("push_member_revoked", "Only a currently approved editor can request repository push protection.", 403)
    member = PushMember(client_slot=context.subject, generation=context.capability_generation,
        name=redact_text(str(active.get("client_name", "VS Code")))[:120], state="requested",
        requested_at=datetime.now(timezone.utc).isoformat())
    key = _key(payload.repository_id)
    existing = db.get(RuntimeConfig, key)
    if existing is not None:
        retained = load_policy(db, payload.repository_id)[1]
        if retained.root_path != payload.root_path or retained.git_directory != payload.git_directory or (payload.project_id is not None and retained.project_id != payload.project_id):
            raise problem("push_project_conflict", "This repository is bound to a different source project. Review its existing policy.")
        if any(item.client_slot == member.client_slot and item.generation == member.generation for item in retained.members):
            return retained
        if len(retained.members) >= 32:
            raise problem("push_member_limit", "Review existing repository members before requesting another editor.")
        return _save(db, existing, retained.model_copy(update={"revision": retained.revision + 1, "members": [*retained.members, member]}))
    git_only_path = source_snapshot_project_path(payload.repository_id, kind="git-commit")
    if payload.project_id is not None:
        project = db.get(Project, payload.project_id)
        if re.match(r"^[A-Za-z]:\\", payload.root_path):
            native_id = hashlib.sha256(("native-windows\0" + unicodedata.normalize("NFC", payload.root_path.rstrip("\\")).lower()).encode()).hexdigest()
            source_path = source_snapshot_project_path(native_id)
        else:
            source_path = payload.root_path
        if project is None or project.repo_path not in {source_path, git_only_path}:
            raise problem("push_project_conflict", "The selected project does not identify this exact repository source.")
    else:
        project = db.scalar(select(Project).where(Project.repo_path == git_only_path))
        if project is None:
            from .main import _gate_policy_values, _runtime_config_values
            from .db import get_runtime
            runtime = get_runtime(request)
            project = Project(name=payload.name, repo_path=git_only_path, remote_url=None, default_branch="main")
            db.add(project)
            db.flush()
            db.add(GatePolicy(project_id=project.id, **_gate_policy_values(_runtime_config_values(runtime.settings, db))))
    if len(list(db.scalars(select(RuntimeConfig.key).where(RuntimeConfig.key.startswith(POLICY_PREFIX)).limit(MAX_REPOSITORIES)))) >= MAX_REPOSITORIES:
        raise problem("push_repository_limit", "The installation already has the maximum registered push-protection repositories.")
    _, removed = _removal_receipt(db, payload.repository_id)
    if removed is not None and removed.revision >= 2_147_483_647:
        raise problem("push_revision_exhausted", "This repository exhausted its safe policy revision range. Owner review is required.")
    policy = PushPolicy(repository_id=payload.repository_id, name=payload.name, project_id=project.id,
        root_path=payload.root_path, git_directory=payload.git_directory,
        revision=removed.revision + 1 if removed is not None else 1, members=[member])
    db.add(RuntimeConfig(key=key, value=policy.model_dump_json()))
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise problem("push_policy_changed", "Another profile registered this repository. Refresh its existing policy.") from exc
    return policy


@router.post("/{repository_id}/remove")
def remove_push_repository(repository_id: str, payload: PushPolicyRemoval, request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    """Forget only an explicitly removed host hook's registration, never its scan data."""
    from .git_push_evidence import remove_tree_bindings

    _key(repository_id)
    context = _ide_context(request)
    if not payload.confirm_removal:
        raise problem("push_removal_confirmation_required", "Confirm removal of this clone's protection. Normal pushes will no longer be checked by Lomo.")
    lock_push_repository(db, "registration")
    lock_push_repository(db, repository_id)
    row = db.scalar(select(RuntimeConfig).where(RuntimeConfig.key == _key(repository_id))
        .execution_options(populate_existing=True).with_for_update())
    receipt_row, receipt = _removal_receipt(db, repository_id)
    if row is None:
        if _active_member(db, context.subject, context.capability_generation, for_update=True) is None:
            raise problem("push_member_revoked", "This editor is no longer active. No registration cleanup was authorized.", 403)
        if receipt is None or (receipt.revision, receipt.client_slot, receipt.generation, receipt.hook_digest) != (
            payload.expected_revision, context.subject, context.capability_generation, payload.hook_digest,
        ):
            raise problem("push_removal_changed", "This removal does not match the retained cleanup receipt. Review this exact repository.")
        return {"repository_id": repository_id, "removed": True, "revision": receipt.revision,
            "tree_bindings_deleted": receipt.tree_bindings_deleted, "already_removed": True}
    _, policy = load_policy(db, repository_id, for_update=True)
    require_push_member(request, db, policy, for_update=True)
    if policy.revision != payload.expected_revision:
        raise problem("push_policy_changed", "Protection changed before registration cleanup. The removed hook is not automatically restored; review the current setting.")
    if policy.hook_digest is not None and policy.hook_digest != payload.hook_digest:
        raise problem("push_hook_changed", "The removed hook does not match the last observed installation. No registration was deleted.")
    removed_count = remove_tree_bindings(db, repository_id)
    receipt = PushRemovalReceipt(repository_id=repository_id, revision=policy.revision,
        client_slot=context.subject, generation=context.capability_generation,
        hook_digest=payload.hook_digest, tree_bindings_deleted=removed_count)
    if receipt_row is None:
        db.add(RuntimeConfig(key=REMOVAL_PREFIX + repository_id, value=receipt.model_dump_json()))
    else:
        receipt_row.value = receipt.model_dump_json()
    db.delete(row)
    db.commit()
    return {"repository_id": repository_id, "removed": True, "revision": receipt.revision,
        "tree_bindings_deleted": removed_count, "already_removed": False}


@router.patch("/{repository_id}", response_model=PushPolicy)
def update_push_policy(repository_id: str, payload: PushPolicyUpdate, request: Request, db: Session = Depends(get_db)) -> PushPolicy:
    row, current = load_policy(db, repository_id)
    context = getattr(request.state, "auth", None)
    if not isinstance(context, AuthContext) or context.kind != "browser":
        require_push_member(request, db, current)
    if current.revision != payload.expected_revision:
        raise problem("push_policy_changed", "Push protection changed in another window. Refresh before changing it.")
    if current.enabled and not payload.enabled and not payload.confirm_bypass:
        raise problem("push_bypass_confirmation_required", "Turning protection off allows failed or unscanned commits to be pushed. Confirm that choice explicitly.")
    if current.enabled == payload.enabled:
        return current
    return _save(db, row, current.model_copy(update={
        "revision": current.revision + 1, "enabled": payload.enabled,
        # Any policy change needs current host observation. Retain the last
        # observation so clients can explain why requested != observed.
        "reason_code": "policy_changed",
    }))


@router.post("/{repository_id}/observation", response_model=PushPolicy)
def observe_push_hook(repository_id: str, payload: PushHookObservation, request: Request, db: Session = Depends(get_db)) -> PushPolicy:
    row, current = load_policy(db, repository_id)
    require_push_member(request, db, current)
    if current.revision != payload.expected_revision:
        raise problem("push_policy_changed", "The protection setting changed before hook verification. Inspect it again.")
    if payload.state == "installed" and payload.hook_digest is None:
        raise problem("push_hook_observation_invalid", "An installed hook needs its exact observed digest.", 422)
    return _save(db, row, current.model_copy(update={
        "observed_state": payload.state, "observed_revision": current.revision,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "hook_digest": payload.hook_digest,
        "reason_code": None if payload.state == "installed" else "hook_missing_or_changed",
    }))


@router.post("/{repository_id}/members/{client_slot}/{generation}", response_model=PushPolicy)
def approve_push_member(repository_id: str, client_slot: str, generation: int, payload: PushMemberApproval, request: Request, db: Session = Depends(get_db)) -> PushPolicy:
    _browser_context(request)
    row, current = load_policy(db, repository_id)
    if current.revision != payload.expected_revision:
        raise problem("push_policy_changed", "Repository permissions changed. Refresh before approving this exact member.")
    selected = next((member for member in current.members if member.client_slot == client_slot and member.generation == generation), None)
    if selected is None:
        raise problem("push_member_missing", "This exact repository access request is no longer present.", 404)
    if payload.approve and _active_member(db, client_slot, generation) is None:
        raise problem("push_member_revoked", "The requested editor generation is no longer active. Do not approve a replacement implicitly.")
    selected = selected.model_copy(update={"state": "approved" if payload.approve else "revoked",
        "approved_at": datetime.now(timezone.utc).isoformat() if payload.approve else None})
    members = [selected if member.client_slot == client_slot and member.generation == generation else member for member in current.members]
    return _save(db, row, current.model_copy(update={"revision": current.revision + 1, "members": members, "reason_code": "policy_changed"}))
