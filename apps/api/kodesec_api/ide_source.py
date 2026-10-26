from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .auth import AuthContext, _browser_context, _ide_context, active_ide_capability_record
from .db import Runtime, get_db, get_runtime
from .events import EventWakeBroker, ide_stream_subject
from .jobs.repository import durable_idempotency_key
from .models import Finding, IdeSourceOpenCommand, Project, Scan
from .schemas import normalize_project_repo_path
from .source_snapshots import is_source_snapshot_project, source_snapshot_project_kind


router = APIRouter(prefix="/v1/ide/source-open-commands", tags=["IDE source navigation"])

COMMAND_TTL = timedelta(minutes=5)
COMMAND_RETENTION = timedelta(hours=24)
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,159}\Z")
_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")


class SourceOpenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: int = Field(ge=1)
    expected_finding_revision: int = Field(ge=1)
    expected_findings_revision: int = Field(ge=1)
    target_capability_id: str = Field(min_length=1, max_length=64)
    expected_target_generation: int = Field(strict=True, ge=1, le=2_147_483_647)


class SourceOpenAck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["opened", "failed"]
    error_code: str | None = Field(default=None, max_length=80)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _aware_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _requester(context: AuthContext) -> str:
    return f"{context.kind}:{context.subject}"[:160]


def _command_out(command: IdeSourceOpenCommand) -> dict[str, object]:
    return {
        "id": command.id,
        "finding_id": command.finding_id,
        "project_id": command.project_id,
        "scan_id": command.scan_id,
        "scan_finding_number": command.scan_finding_number,
        "expected_finding_revision": command.expected_finding_revision,
        "expected_findings_revision": command.expected_findings_revision,
        "target_capability_id": command.target_capability_id,
        "expected_target_generation": command.expected_target_generation,
        "status": command.status,
        "revision": command.revision,
        "error_code": command.error_code,
        "created_at": _timestamp(command.created_at),
        "expires_at": _timestamp(command.expires_at),
        "acknowledged_at": (
            _timestamp(command.acknowledged_at) if command.acknowledged_at is not None else None
        ),
    }


def source_open_command_document(command: IdeSourceOpenCommand) -> dict[str, object]:
    """Return the body-free envelope sent only to the selected capability."""

    return {
        "v": 1,
        "command_id": command.id,
        "project_id": command.project_id,
        "scan_id": command.scan_id,
        "finding_id": command.finding_id,
        "scan_finding_number": command.scan_finding_number,
        "expected_finding_revision": command.expected_finding_revision,
        "expected_findings_revision": command.expected_findings_revision,
        "expires_at": _timestamp(command.expires_at),
    }


def pending_source_open_commands(
    session_factory: sessionmaker[Session],
    capability_id: str,
    capability_generation: int,
) -> tuple[dict[str, object], ...]:
    now = _utcnow()
    with session_factory() as db:
        rows = list(
            db.scalars(
                select(IdeSourceOpenCommand)
                .where(
                    IdeSourceOpenCommand.target_capability_id == capability_id,
                    IdeSourceOpenCommand.expected_target_generation == capability_generation,
                    IdeSourceOpenCommand.status == "queued",
                    IdeSourceOpenCommand.expires_at > now,
                )
                .order_by(IdeSourceOpenCommand.created_at, IdeSourceOpenCommand.id)
                .limit(16)
            )
        )
        return tuple(source_open_command_document(row) for row in rows)


def _expire_if_needed(command: IdeSourceOpenCommand, db: Session) -> None:
    if command.status != "queued" or _aware_utc(command.expires_at) > _utcnow():
        return
    command.status = "expired"
    command.revision += 1
    command.acknowledged_at = _utcnow()
    db.add(command)
    db.commit()


def _owned_browser_command(
    db: Session,
    command_id: str,
    context: AuthContext,
) -> IdeSourceOpenCommand:
    command = db.get(IdeSourceOpenCommand, command_id)
    if command is None or command.requester_subject != _requester(context):
        raise HTTPException(404, "source-open command not found")
    _expire_if_needed(command, db)
    return command


def _owned_active_ide_command(
    db: Session,
    command_id: str,
    context: AuthContext,
) -> IdeSourceOpenCommand:
    active_target = active_ide_capability_record(
        db,
        context.subject,
        for_update=True,
    )
    if (
        active_target is None
        or active_target["generation"] != context.capability_generation
    ):
        raise HTTPException(404, "source-open command not found")
    command = db.scalar(
        select(IdeSourceOpenCommand)
        .where(
            IdeSourceOpenCommand.id == command_id,
            IdeSourceOpenCommand.target_capability_id == context.subject,
            IdeSourceOpenCommand.expected_target_generation == active_target["generation"],
        )
        .with_for_update()
    )
    if command is None:
        raise HTTPException(404, "source-open command not found")
    _expire_if_needed(command, db)
    return command


def _request_digest(payload: SourceOpenCreate) -> str:
    encoded = json.dumps(
        payload.model_dump(mode="json"),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@router.post("", status_code=202)
def create_source_open_command(
    payload: SourceOpenCreate,
    request: Request,
    context: AuthContext = Depends(_browser_context),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    raw_key = (request.headers.get("Idempotency-Key") or "").strip()
    if _IDEMPOTENCY_KEY.fullmatch(raw_key) is None:
        raise HTTPException(
            422,
            "Idempotency-Key must contain 8-160 ASCII letters, digits, '.', '_', ':', or '-'",
        )
    requester = _requester(context)
    stored_key = durable_idempotency_key(raw_key)
    digest = _request_digest(payload)
    existing = db.scalar(
        select(IdeSourceOpenCommand).where(
            IdeSourceOpenCommand.requester_subject == requester,
            IdeSourceOpenCommand.idempotency_key == stored_key,
        )
    )
    if existing is not None:
        if existing.request_digest != digest:
            raise HTTPException(409, "Idempotency-Key is already bound to a different source-open command")
        _expire_if_needed(existing, db)
        return _command_out(existing)

    broker = getattr(request.app.state, "event_wake_broker", None)
    active_target = active_ide_capability_record(
        db,
        payload.target_capability_id,
        for_update=True,
    )
    if active_target is None:
        raise HTTPException(
            409,
            {
                "code": "ide_source_target_inactive",
                "message": "The selected IDE client is invalid or not active.",
                "action": "refresh_ide_clients",
                "context": {
                    "target_capability_id": payload.target_capability_id,
                    "expected_target_generation": payload.expected_target_generation,
                },
            },
        )
    if active_target["generation"] != payload.expected_target_generation:
        raise HTTPException(
            409,
            {
                "code": "ide_source_target_generation_conflict",
                "message": "The selected IDE authority changed before source navigation was queued.",
                "action": "refresh_ide_clients",
                "context": {
                    "target_capability_id": payload.target_capability_id,
                    "expected_target_generation": payload.expected_target_generation,
                    "current_target_generation": active_target["generation"],
                },
            },
        )
    subject = ide_stream_subject(
        payload.target_capability_id,
        payload.expected_target_generation,
    )
    connection_count = (
        broker.subject_connection_count(subject)
        if isinstance(broker, EventWakeBroker)
        else 0
    )
    if connection_count != 1:
        raise HTTPException(
            409,
            {
                "code": "ide_source_target_ambiguous",
                "message": "Source navigation requires exactly one event-stream connection for the selected IDE capability.",
                "action": "reconnect_ide",
                "context": {
                    "target_capability_id": payload.target_capability_id,
                    "expected_target_generation": payload.expected_target_generation,
                    "connection_count": connection_count,
                },
            },
        )

    finding = db.scalar(select(Finding).where(Finding.id == payload.finding_id).with_for_update(read=True))
    if finding is None:
        raise HTTPException(404, "finding not found")
    scan = db.scalar(select(Scan).where(Scan.id == finding.scan_id).with_for_update(read=True))
    if scan is None:
        raise HTTPException(404, "finding scan not found")
    project = db.get(Project, scan.project_id)
    if project is None:
        raise HTTPException(404, "finding project not found")
    if is_source_snapshot_project(project.repo_path) and source_snapshot_project_kind(project.repo_path) == "git-commit":
        raise HTTPException(409, {
            "code": "ide_source_immutable_git",
            "message": "This finding belongs to a committed Git snapshot, not the current workspace file. Read its captured details; historical editor navigation is not available.",
            "action": "open_finding_details",
        })
    try:
        canonical_project_path = normalize_project_repo_path(project.repo_path)
    except ValueError as exc:
        raise HTTPException(
            409,
            {
                "code": "ide_source_project_noncanonical",
                "message": "The registered project for this source-open command has an unsafe source identity.",
                "action": "re_register_source",
            },
        ) from exc
    if (
        canonical_project_path != project.repo_path
        or len(canonical_project_path.encode("utf-8")) > 4096
    ):
        raise HTTPException(
            409,
            {
                "code": "ide_source_project_noncanonical",
                "message": "The registered project for this source-open command has a non-canonical source identity.",
                "action": "re_register_source",
            },
        )
    if (
        finding.revision != payload.expected_finding_revision
        or scan.findings_revision != payload.expected_findings_revision
    ):
        raise HTTPException(
            409,
            {
                "code": "revision_conflict",
                "message": "The selected finding changed before the source-open command was queued.",
                "action": "refresh_findings",
                "context": {
                    "finding_id": finding.id,
                    "current_finding_revision": finding.revision,
                    "current_findings_revision": scan.findings_revision,
                },
            },
        )

    now = _utcnow()
    db.execute(
        delete(IdeSourceOpenCommand).where(
            IdeSourceOpenCommand.created_at < now - COMMAND_RETENTION,
        )
    )
    command = IdeSourceOpenCommand(
        id=uuid4().hex,
        requester_subject=requester,
        idempotency_key=stored_key,
        request_digest=digest,
        target_capability_id=payload.target_capability_id,
        expected_target_generation=payload.expected_target_generation,
        project_id=scan.project_id,
        project_repo_path=canonical_project_path,
        scan_id=scan.id,
        finding_id=finding.id,
        scan_finding_number=finding.scan_finding_number,
        expected_finding_revision=finding.revision,
        expected_findings_revision=scan.findings_revision,
        status="queued",
        revision=1,
        created_at=now,
        expires_at=now + COMMAND_TTL,
    )
    db.add(command)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "source-open command identity already exists") from exc
    db.refresh(command)
    broker.wake_subject(subject)
    return _command_out(command)


@router.get("/{command_id}")
def get_source_open_command(
    command_id: str,
    context: AuthContext = Depends(_browser_context),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    return _command_out(_owned_browser_command(db, command_id, context))


@router.get("/{command_id}/context")
def get_source_open_project_context(
    command_id: str,
    context: AuthContext = Depends(_ide_context),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return only the registered source identity for one recipient-bound command."""

    command = _owned_active_ide_command(db, command_id, context)
    if command.status != "queued":
        raise HTTPException(
            409,
            {
                "code": "ide_source_command_not_pending",
                "message": "The source-open command is no longer pending for this IDE.",
                "action": "request_source_open_again",
            },
        )
    return {
        "v": 1,
        "command_id": command.id,
        "project_id": command.project_id,
        "project_repo_path": command.project_repo_path,
    }


@router.get("/{command_id}/wait")
async def wait_for_source_open_command(
    command_id: str,
    request: Request,
    context: AuthContext = Depends(_browser_context),
    runtime: Runtime = Depends(get_runtime),
) -> dict[str, object]:
    def read() -> dict[str, object]:
        with runtime.session_factory() as db:
            return _command_out(_owned_browser_command(db, command_id, context))

    initial = read()
    if initial["status"] != "queued":
        return initial
    broker = getattr(request.app.state, "event_wake_broker", None)
    if not isinstance(broker, EventWakeBroker):
        return initial
    subscription = await broker.subscribe(_requester(context))
    try:
        after_subscribe = read()
        if after_subscribe["status"] != "queued":
            return after_subscribe
        await subscription.wait(timeout=12.0)
        return read()
    finally:
        subscription.close()


@router.post("/{command_id}/ack")
def acknowledge_source_open_command(
    command_id: str,
    payload: SourceOpenAck,
    request: Request,
    context: AuthContext = Depends(_ide_context),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    command = _owned_active_ide_command(db, command_id, context)
    if command.status == "expired":
        raise HTTPException(
            409,
            {
                "code": "ide_source_command_expired",
                "message": "The source-open command expired before the IDE acknowledged it.",
                "action": "request_source_open_again",
            },
        )
    error_code = payload.error_code.strip() if isinstance(payload.error_code, str) else None
    if payload.status == "failed":
        if error_code is None or _ERROR_CODE.fullmatch(error_code) is None:
            raise HTTPException(422, "A failed source-open acknowledgement requires a safe error_code")
    elif error_code is not None:
        raise HTTPException(422, "An opened source-open acknowledgement cannot include error_code")
    if command.status != "queued":
        if command.status != payload.status or command.error_code != error_code:
            raise HTTPException(409, "source-open command already has a different terminal acknowledgement")
        return _command_out(command)

    command.status = payload.status
    command.error_code = error_code
    command.revision += 1
    command.acknowledged_at = _utcnow()
    db.add(command)
    db.commit()
    db.refresh(command)
    broker = getattr(request.app.state, "event_wake_broker", None)
    if isinstance(broker, EventWakeBroker):
        broker.wake_subject(command.requester_subject)
    return _command_out(command)
