from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Collection

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.orm import Session, aliased

from ..models import Job, ScannerLifecycleState
from ..preparation_budget import PreparationBudget, PreparationDeadlineExceeded, budget_remaining
from ..recovery_contract import RecoveryBudget
from ..redaction import REDACTED, redact_json, redact_text


DEFAULT_LEASE_SECONDS = 30
MAX_LEASE_SECONDS = 300
MAX_JOB_DOCUMENT_BYTES = 16 * 1024
MAX_DETAIL_LENGTH = 4000
TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled"})
LEASED_STATUSES = frozenset({"leased", "running", "cancelling"})
_SCAN_ADMISSION_LOCK_ID = 21297445770945861
_ADVISOR_ADMISSION_LOCK_ID = 21297445770945862
_SCANNER_MUTATION_ADMISSION_KINDS = frozenset(
    {"scan", "scanner_cache_update", "scanner_cache_rollback", "scanner_cache_reconcile"}
)
_MAX_SKIPPED_ADMISSION_CANDIDATES = 32
_SAFE_DIGEST = re.compile(r"[0-9a-fA-F]{64}\Z")
_SAFE_OPERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_DURABLE_IDEMPOTENCY_KEY = re.compile(r"h1\$([0-9a-fA-F]{64})\Z")
_SAFE_ADVISOR_DOCUMENT_SCHEMAS = frozenset(
    {
        "lomo-advisor-activation-approval/v1",
        "lomo-advisor-provider-job-collection/v1",
        "lomo-advisor-provider-job-pin/v1",
        "lomo-advisor-provider-job-profile/v1",
        "lomo-advisor-provider-receipt/v1",
        "lomo-advisor-run-confirmation/v1",
        "lomo-advisor-source-consent/v1",
    }
)


def durable_idempotency_key(value: str, *, stored: bool = False) -> str:
    """Return a versioned one-way representation safe for persistence."""

    normalized = value.strip()
    match = _DURABLE_IDEMPOTENCY_KEY.fullmatch(normalized) if stored else None
    if match is not None:
        return f"h1${match.group(1).lower()}"
    digest = hashlib.sha256(
        b"kodesec-idempotency-v1\0" + normalized.encode("utf-8")
    ).hexdigest()
    return f"h1${digest}"


def lock_advisor_admission(session: Session) -> None:
    """Serialize provider mutation, exact resolution, and Advisor enqueue.

    The provider collection row supplies the ordinary configuration fence.
    This transaction-scoped lock also covers the valid empty/default state,
    where no row exists yet to lock. SQLite unit tests remain single-process;
    production PostgreSQL gets the cross-process admission boundary.
    """

    if session.bind is not None and session.bind.dialect.name == "postgresql":
        session.execute(select(func.pg_advisory_xact_lock(_ADVISOR_ADMISSION_LOCK_ID)))


def _redact_job_document(value: Any, key: str = "", *, depth: int = 0) -> Any:
    """Redact command data while retaining explicitly typed safe digests."""

    if depth >= 64 and isinstance(value, (dict, list)):
        return REDACTED
    if key and redact_json(None, key) == REDACTED:
        return REDACTED
    if isinstance(value, dict):
        if key == "preparation_budget":
            # Preserve only the closed server-budget document. Generic UUID or
            # timestamp strings elsewhere retain ordinary credential redaction.
            try:
                return PreparationBudget.model_validate(value).model_dump(mode="json")
            except (ValueError, TypeError):
                return REDACTED
        if key in {"reconciliation_budget", "reconciliation_target"}:
            from ..recovery_contract import RecoveryBudget, RecoveryTarget
            try:
                model = RecoveryBudget if key == "reconciliation_budget" else RecoveryTarget
                return model.model_validate(value).model_dump(mode="json")
            except (ValueError, TypeError):
                return REDACTED
        schema = value.get("schema")
        if key == "source_snapshot" and value.get("kind") in {"native-windows", "git-commit"}:
            from ..schemas import ScanSourceSnapshotOut

            try:
                source = ScanSourceSnapshotOut.model_validate(value)
            except ValueError:
                return REDACTED
            if any(
                path is not None and redact_text(path) != path
                for path in (source.directory_scope, source.target_path)
            ):
                return REDACTED
            return source.model_dump(mode="json")
        if schema in _SAFE_ADVISOR_DOCUMENT_SCHEMAS:
            # These documents contain only exact identifiers, digests,
            # timestamps, and a strictly canonical credential-free
            # destination. Preserve the normalized document atomically so URL
            # user-info redaction cannot corrupt an SSH confirmation digest.
            from ..advisor import disclosure as advisor_disclosure
            from ..advisor import providers as advisor_providers

            normalizers = {
                "lomo-advisor-activation-approval/v1": advisor_providers.normalize_activation_approval,
                "lomo-advisor-provider-receipt/v1": advisor_providers.normalize_receipt,
                "lomo-advisor-run-confirmation/v1": advisor_disclosure.normalize_confirmation,
                "lomo-advisor-source-consent/v1": advisor_providers.normalize_consent,
            }
            try:
                if schema == "lomo-advisor-provider-job-collection/v1":
                    return advisor_providers.job_collection_snapshot(
                        advisor_providers.normalize_job_collection_snapshot(value)
                    )
                if schema == "lomo-advisor-provider-job-pin/v1":
                    return advisor_providers.job_pin_snapshot(
                        advisor_providers.normalize_job_pin_snapshot(value)
                    )
                if schema == "lomo-advisor-provider-job-profile/v1":
                    return advisor_providers.job_profile_snapshot(
                        advisor_providers.normalize_job_profile_snapshot(value)
                    )
                return normalizers[str(schema)](value)
            except (TypeError, ValueError):
                return REDACTED
        return {
            str(item_key): _redact_job_document(item, str(item_key), depth=depth + 1)
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_job_document(item, depth=depth + 1) for item in value]
    if isinstance(value, str):
        if key == "schema" and value in _SAFE_ADVISOR_DOCUMENT_SCHEMAS:
            return value
        if key in {
            "catalog_digest",
            "config_digest",
            "confirmation_digest",
            "model_digest",
            "prompt_sha256",
            "provider_config_digest",
            "request_digest",
            "source_snapshot_digest",
            "preflight_revision",
            "sha256",
            "fingerprint",
        } and _SAFE_DIGEST.fullmatch(value):
            return value.lower()
        if key == "advisor_operation_id" and _SAFE_OPERATION_ID.fullmatch(value):
            return value
        return redact_text(value)
    return value


class JobRepositoryError(RuntimeError):
    """Base class for a rejected durable-job operation."""


class JobNotFoundError(JobRepositoryError):
    pass


class IdempotencyConflictError(JobRepositoryError):
    pass


class LeaseLostError(JobRepositoryError):
    pass


class InvalidJobTransition(JobRepositoryError):
    pass


class CacheCommitInProgressError(InvalidJobTransition):
    """Cache publication has crossed its non-cancellable boundary."""


@dataclass(frozen=True, slots=True)
class EnqueueResult:
    job: Job
    created: bool


@dataclass(frozen=True, slots=True)
class CancellationResult:
    job: Job
    changed: bool


def _required_text(value: str, name: str, maximum: int) -> str:
    rendered = value.strip()
    if not rendered:
        raise ValueError(f"{name} must not be empty")
    if len(rendered) > maximum:
        raise ValueError(f"{name} must be at most {maximum} characters")
    return rendered


def _optional_text(value: str | None, name: str, maximum: int) -> str | None:
    if value is None:
        return None
    return _required_text(value, name, maximum)


def _document(value: dict[str, Any], name: str, *, require_version: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    safe_value = _redact_job_document(value)
    if not isinstance(safe_value, dict):  # pragma: no cover - input guard above
        raise ValueError(f"{name} must be a JSON object")
    try:
        encoded = json.dumps(
            safe_value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain valid JSON values") from exc
    if len(encoded) > MAX_JOB_DOCUMENT_BYTES:
        raise ValueError(f"{name} must be at most {MAX_JOB_DOCUMENT_BYTES} UTF-8 bytes")
    normalized = json.loads(encoded)
    if require_version and normalized.get("v") != 1:
        raise ValueError(f"{name} must declare schema version 1")
    return normalized


def _preparation_rejection(job: Job, current: datetime) -> str | None:
    if job.kind not in {"scanner_catalog_check", "scanner_cache_update", "scanner_cache_reconcile"}:
        return None
    recovery = job.kind == "scanner_cache_reconcile"
    raw = job.payload.get("reconciliation_budget" if recovery else "preparation_budget") if isinstance(job.payload, dict) else None
    if raw is None:
        return "scanner_reconciliation_invalid" if recovery else "scanner_preparation_budget_required"
    try:
        budget = (RecoveryBudget if recovery else PreparationBudget).model_validate(raw)
        budget_remaining(budget, now=current, high_water=job.updated_at or job.created_at)
    except PreparationDeadlineExceeded:
        return "scanner_reconciliation_deadline" if recovery else "scanner_preparation_deadline"
    except (ValueError, TypeError):
        return "scanner_reconciliation_invalid" if recovery else "scanner_preparation_budget_invalid"
    return None


def preparation_retry_blocked_reason(job: Job, *, now: datetime) -> str | None:
    """Explain the same immutable-budget refusal enforced by the retry command."""
    if job.status != "failed" or job.kind not in {"scanner_catalog_check", "scanner_cache_update"}:
        return None
    rejection = _preparation_rejection(job, now)
    if rejection is None:
        return None
    if rejection == "scanner_preparation_deadline":
        return "This preparation's time limit has expired. Open Tools to check scanner readiness. Start a new preparation only if it is offered."
    return "This preparation has no valid time budget. Open Tools to check scanner readiness. Start a new preparation only if it is offered."


def retry_failed_job(
    session: Session,
    job_id: int,
    *,
    expected_revision: int,
    detail: str | None = None,
    now: datetime | None = None,
) -> Job:
    """Queue one explicit retry without changing command or run identity.

    An exhausted job receives exactly one additional bounded attempt. A job
    that failed early for a non-retryable condition uses its already-unused
    attempt budget. Checkpoints stay intact, allowing scanner evidence and
    completed advisor items to resume idempotently.
    """

    if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 1:
        raise ValueError("expected_revision must be a positive integer")
    current = _time(now, session)
    job = session.scalar(select(Job).where(Job.id == job_id).with_for_update(of=Job))
    if job is None:
        raise JobNotFoundError(f"job {job_id} does not exist")
    if job.revision != expected_revision:
        raise InvalidJobTransition("job revision changed; reload before retrying")
    if job.status != "failed":
        raise InvalidJobTransition("only a failed job can be retried")
    if job.kind == "scanner_cache_reconcile":
        raise InvalidJobTransition("read-only recovery is single-attempt; review a new explicit command")
    rejection = _preparation_rejection(job, current)
    if rejection is not None:
        raise InvalidJobTransition(rejection)
    if (
        job.kind == "advisor"
        and isinstance(job.payload, dict)
        and job.payload.get("remote_advisor_confirmation") is not None
        and isinstance(job.checkpoint, dict)
        and job.checkpoint.get("remote_advisor_transmission") is not None
    ):
        raise InvalidJobTransition(
            "remote Advisor authorization was consumed; review a fresh disclosure preview and explicitly confirm a new request"
        )
    retry_limit = (
        3
        if job.kind
        in {"scanner_catalog_check", "scanner_cache_update", "scanner_cache_rollback"}
        else 10
    )
    if job.attempt >= job.max_attempts:
        if job.max_attempts >= retry_limit:
            raise InvalidJobTransition("job has reached the maximum retry limit")
        job.max_attempts += 1
    job.status = "queued"
    job.stage = "queued"
    job.detail = _optional_text(detail, "detail", MAX_DETAIL_LENGTH) or "Operator retry queued."
    job.completed_at = None
    job.cancel_requested_at = None
    job.lease_owner = None
    job.lease_expires_at = None
    job.heartbeat_at = None
    job.error = None
    job.error_code = None
    job.error_detail = None
    job.updated_at = current
    job.revision += 1
    session.flush()
    return job


def _priority(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not -10 <= value <= 10:
        raise ValueError("priority must be an integer between -10 and 10")
    return value


def _attempt_limit(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10:
        raise ValueError("max_attempts must be an integer between 1 and 10")
    return value


def _progress(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise ValueError("progress must be an integer between 0 and 100")
    return value


def _lease_duration(value: int) -> timedelta:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_LEASE_SECONDS:
        raise ValueError(f"lease_seconds must be an integer between 1 and {MAX_LEASE_SECONDS}")
    return timedelta(seconds=value)


def _time(value: datetime | None, session: Session) -> datetime:
    if value is None:
        value = session.scalar(select(func.now()))
        if not isinstance(value, datetime):
            raise RuntimeError("database did not return its current timestamp")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("job timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _assert_same_command(
    job: Job,
    *,
    title: str,
    payload: dict[str, Any],
    scan_id: int | None,
    finding_id: int | None,
    external_run_id: str | None,
    priority: int,
    max_attempts: int,
) -> None:
    if (
        job.title != title
        or job.payload != payload
        or job.scan_id != scan_id
        or job.finding_id != finding_id
        or job.external_run_id != external_run_id
        or job.priority != priority
        or job.max_attempts != max_attempts
    ):
        raise IdempotencyConflictError(
            "idempotency key is already bound to a different command"
        )


def enqueue_job(
    session: Session,
    *,
    kind: str,
    title: str,
    client_id: str,
    idempotency_key: str,
    payload: dict[str, Any],
    priority: int = 0,
    max_attempts: int = 3,
    scan_id: int | None = None,
    finding_id: int | None = None,
    external_run_id: str | None = None,
) -> EnqueueResult:
    """Insert one logical command, returning its prior job on safe replay.

    PostgreSQL's unique constraint and ``ON CONFLICT`` close the concurrent
    check/insert race. The caller owns the surrounding transaction and commit.
    """

    values = {
        "kind": _required_text(kind, "kind", 40),
        "title": _required_text(title, "title", 240),
        "client_id": _required_text(client_id, "client_id", 160),
        "idempotency_key": durable_idempotency_key(
            _required_text(idempotency_key, "idempotency_key", 160)
        ),
        "payload": _document(payload, "payload", require_version=True),
        "checkpoint": {},
        "priority": _priority(priority),
        "attempt": 0,
        "max_attempts": _attempt_limit(max_attempts),
        "status": "queued",
        "stage": "queued",
        "progress": 0,
        "revision": 1,
        "scan_id": scan_id,
        "finding_id": finding_id,
        "external_run_id": _optional_text(external_run_id, "external_run_id", 160),
    }

    if session.bind is not None and session.bind.dialect.name == "postgresql":
        statement = (
            postgresql_insert(Job)
            .values(**values)
            .on_conflict_do_nothing(constraint="uq_jobs_client_kind_idempotency")
            .returning(Job.id)
        )
        inserted_id = session.scalar(statement)
        if inserted_id is not None:
            job = session.get(Job, int(inserted_id))
            if job is None:  # pragma: no cover - guarded by RETURNING in one transaction
                raise RuntimeError("inserted job could not be reloaded")
            return EnqueueResult(job=job, created=True)
    else:
        existing = session.scalar(
            select(Job).where(
                Job.client_id == values["client_id"],
                Job.kind == values["kind"],
                Job.idempotency_key == values["idempotency_key"],
            )
        )
        if existing is None:
            job = Job(**values)
            session.add(job)
            session.flush()
            return EnqueueResult(job=job, created=True)

    job = session.scalar(
        select(Job).where(
            Job.client_id == values["client_id"],
            Job.kind == values["kind"],
            Job.idempotency_key == values["idempotency_key"],
        )
    )
    if job is None:  # pragma: no cover - would imply a broken uniqueness contract
        raise RuntimeError("idempotent job disappeared during enqueue")
    _assert_same_command(
        job,
        title=str(values["title"]),
        payload=values["payload"],
        scan_id=scan_id,
        finding_id=finding_id,
        external_run_id=values["external_run_id"],
        priority=int(values["priority"]),
        max_attempts=int(values["max_attempts"]),
    )
    return EnqueueResult(job=job, created=False)


def claim_next_job(
    session: Session,
    *,
    worker_id: str,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    now: datetime | None = None,
    kinds: Collection[str] | None = None,
) -> Job | None:
    """Lock and claim one eligible row without waiting on another worker."""

    if session.bind is None or session.bind.dialect.name != "postgresql":
        raise RuntimeError("durable job claims require PostgreSQL")
    owner = _required_text(worker_id, "worker_id", 160)
    current = _time(now, session)
    duration = _lease_duration(lease_seconds)
    lease_available = or_(Job.lease_expires_at.is_(None), Job.lease_expires_at <= current)
    cancellation = and_(
        or_(Job.status == "cancelling", Job.cancel_requested_at.is_not(None)),
        Job.status.not_in(TERMINAL_STATUSES),
        lease_available,
    )
    exhausted_recovery = and_(
        Job.cancel_requested_at.is_(None),
        Job.status.in_(("leased", "running")),
        Job.lease_expires_at <= current,
        Job.attempt >= Job.max_attempts,
    )
    ordinary = and_(
        Job.cancel_requested_at.is_(None),
        Job.attempt < Job.max_attempts,
        or_(
            and_(Job.status == "queued", lease_available),
            and_(Job.status.in_(("leased", "running")), lease_available),
        ),
    )
    base_statement = select(Job).where(or_(cancellation, exhausted_recovery, ordinary))
    if kinds is not None:
        normalized_kinds = tuple(sorted({_required_text(kind, "kind", 40) for kind in kinds}))
        if not normalized_kinds:
            return None
        base_statement = base_statement.where(Job.kind.in_(normalized_kinds))

    excluded_ids: list[int] = []
    job: Job | None = None
    is_cancelling = False
    is_exhausted_recovery = False
    for _ in range(_MAX_SKIPPED_ADMISSION_CANDIDATES):
        statement = base_statement
        if excluded_ids:
            statement = statement.where(Job.id.not_in(excluded_ids))
        statement = (
            statement.order_by(
                case(
                    (or_(Job.status == "cancelling", Job.cancel_requested_at.is_not(None)), 0),
                    (
                        and_(
                            Job.status.in_(("leased", "running")),
                            Job.lease_expires_at <= current,
                        ),
                        1,
                    ),
                    else_=2,
                ),
                Job.priority.desc(),
                Job.created_at,
                Job.id,
            )
            .with_for_update(skip_locked=True, of=Job)
            .limit(1)
        )
        job = session.scalar(statement)
        if job is None:
            return None

        is_cancelling = job.status == "cancelling" or job.cancel_requested_at is not None
        rejection = _preparation_rejection(job, current)
        if rejection is not None and not is_cancelling and job.status == "queued" and job.attempt == 0:
            job.status = "failed"
            job.stage = "failed"
            job.error_code = rejection
            job.error_detail = "Preparation cannot start under an expired or missing server budget."
            job.error = job.error_detail
            job.completed_at = current
            job.updated_at = current
            job.revision += 1
            scope = "catalog" if job.kind == "scanner_catalog_check" else "cache"
            lifecycle = session.get(ScannerLifecycleState, scope)
            if lifecycle is not None and lifecycle.job_id == job.id:
                lifecycle.status = "failed"
                lifecycle.error_code = rejection
                lifecycle.error_detail = job.error_detail
                lifecycle.completed_at = current
                lifecycle.updated_at = current
                lifecycle.revision += 1
            session.flush()
            excluded_ids.append(job.id)
            job = None
            continue
        is_exhausted_recovery = (
            not is_cancelling
            and job.status in {"leased", "running"}
            and job.lease_expires_at is not None
            and job.lease_expires_at <= current
            and job.attempt >= job.max_attempts
        )
        is_exhausted_recovery = is_exhausted_recovery or (rejection is not None and not is_cancelling and job.attempt > 0)
        prerequisite_job_id = (
            job.payload.get("prerequisite_job_id")
            if job.kind == "scanner_cache_update" and isinstance(job.payload, dict)
            else None
        )
        if (
            isinstance(prerequisite_job_id, int)
            and not isinstance(prerequisite_job_id, bool)
            and prerequisite_job_id > 0
            and prerequisite_job_id != job.id
        ):
            prerequisite = session.get(Job, prerequisite_job_id)
            if prerequisite is not None and prerequisite.status in {
                "queued",
                "leased",
                "running",
                "cancelling",
            }:
                excluded_ids.append(job.id)
                job = None
                continue
            if prerequisite is not None and prerequisite.status == "cancelled":
                job.status = "cancelling"
                job.stage = "cancelling"
                job.cancel_requested_at = current
                job.detail = "Scanner preparation stopped because its catalog check was cancelled."
                is_cancelling = True
                is_exhausted_recovery = False
        if job.kind in _SCANNER_MUTATION_ADMISSION_KINDS:
            admission_lock = _SCAN_ADMISSION_LOCK_ID
            conflicting_kinds: Collection[str] = _SCANNER_MUTATION_ADMISSION_KINDS
        elif job.kind in {"advisor", "advisor_provider"}:
            admission_lock = _ADVISOR_ADMISSION_LOCK_ID
            conflicting_kinds = ("advisor", "advisor_provider")
        else:
            admission_lock = None
            conflicting_kinds = ()
        if admission_lock is None:
            break

        # Lock the tiny class-specific admission boundary after SKIP LOCKED has
        # chosen a row. Generic jobs therefore retain non-blocking queue
        # throughput, while separate worker processes cannot both lease scans
        # (or advisors) after observing an empty admission predicate.
        session.execute(select(func.pg_advisory_xact_lock(admission_lock)))
        if is_cancelling or is_exhausted_recovery:
            break
        admitted = aliased(Job)
        live_job_id = session.scalar(
            select(admitted.id)
            .where(
                admitted.id != job.id,
                admitted.kind.in_(tuple(conflicting_kinds)),
                admitted.status.in_(("leased", "running", "cancelling")),
                admitted.lease_expires_at > current,
            )
            .limit(1)
        )
        if live_job_id is None:
            break
        excluded_ids.append(job.id)
        job = None

    if job is None:
        return None

    if is_cancelling:
        job.status = "cancelling"
    elif is_exhausted_recovery:
        # This fenced lease exists only so the worker can commit a stable
        # ``attempts_exhausted`` terminal failure. It must not execute the
        # external operation again or increment beyond max_attempts.
        job.status = "leased"
        job.stage = "recovery_exhausted"
        job.detail = "Prior worker lease expired after the final allowed attempt."
    else:
        job.status = "leased"
        job.attempt += 1
        job.error = None
        job.error_code = None
        job.error_detail = None
    job.lease_owner = owner
    job.lease_expires_at = current + duration
    job.heartbeat_at = current
    job.updated_at = current
    job.revision += 1
    session.flush()
    return job


def _owned_job(
    session: Session,
    job_id: int,
    *,
    worker_id: str,
    attempt: int,
    now: datetime | None,
    statuses: Collection[str],
) -> tuple[Job, datetime]:
    owner = _required_text(worker_id, "worker_id", 160)
    current = _time(now, session)
    job = session.scalar(
        select(Job)
        .where(
            Job.id == job_id,
            Job.lease_owner == owner,
            Job.attempt == attempt,
            Job.status.in_(tuple(statuses)),
            Job.lease_expires_at.is_not(None),
            Job.lease_expires_at > current,
        )
        .with_for_update(of=Job)
    )
    if job is None:
        raise LeaseLostError("job lease is absent, expired, or owned by another worker attempt")
    return job, current


def heartbeat_job(
    session: Session,
    job_id: int,
    *,
    worker_id: str,
    attempt: int,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    now: datetime | None = None,
) -> Job:
    """Renew an unexpired lease without changing client-visible revision."""

    duration = _lease_duration(lease_seconds)
    job, current = _owned_job(
        session,
        job_id,
        worker_id=worker_id,
        attempt=attempt,
        now=now,
        statuses=LEASED_STATUSES,
    )
    job.heartbeat_at = current
    job.lease_expires_at = current + duration
    session.flush()
    return job


def mark_job_running(
    session: Session,
    job_id: int,
    *,
    worker_id: str,
    attempt: int,
    stage: str,
    detail: str | None = None,
    progress: int = 0,
    now: datetime | None = None,
) -> Job:
    # Cancellation changes state, not lease ownership. Let the still-fenced
    # owner enter cleanup immediately; foreign/expired owners still fail below.
    job, current = _owned_job(
        session,
        job_id,
        worker_id=worker_id,
        attempt=attempt,
        now=now,
        statuses=("leased", "cancelling"),
    )
    if job.status == "cancelling" or job.cancel_requested_at is not None:
        raise InvalidJobTransition("a cancellation request prevents starting the job")
    job.status = "running"
    job.stage = _required_text(stage, "stage", 120)
    job.detail = _optional_text(detail, "detail", MAX_DETAIL_LENGTH)
    job.progress = _progress(progress)
    job.started_at = job.started_at or current
    job.updated_at = current
    job.revision += 1
    session.flush()
    return job


def update_job_progress(
    session: Session,
    job_id: int,
    *,
    worker_id: str,
    attempt: int,
    progress: int,
    stage: str | None = None,
    detail: str | None = None,
    checkpoint: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> Job:
    job, current = _owned_job(
        session,
        job_id,
        worker_id=worker_id,
        attempt=attempt,
        now=now,
        statuses=("running", "cancelling"),
    )
    if job.status == "cancelling" or job.cancel_requested_at is not None:
        raise InvalidJobTransition("a cancellation request prevents progress updates")
    job.progress = _progress(progress)
    if stage is not None:
        job.stage = _required_text(stage, "stage", 120)
    if detail is not None:
        job.detail = _required_text(detail, "detail", MAX_DETAIL_LENGTH)
    if checkpoint is not None:
        job.checkpoint = _document(checkpoint, "checkpoint")
    job.updated_at = current
    job.revision += 1
    session.flush()
    return job


def can_cancel_job(job: Job) -> bool:
    """Advertise cancellation only before a known cache publication boundary."""

    return job.status in {"queued", "leased", "running"} and not (
        job.kind in {"scanner_cache_update", "scanner_cache_rollback", "scanner_cache_reconcile"}
        and job.stage in {"committing", "activating"}
    )


def request_cancellation(
    session: Session,
    job_id: int,
    *,
    detail: str | None = None,
    now: datetime | None = None,
) -> CancellationResult:
    current = _time(now, session)
    # Authorization may already have loaded this row. Refresh the identity-map
    # entry under the lock so a newer persisted commit stage cannot be missed.
    job = session.scalar(
        select(Job).where(Job.id == job_id).with_for_update(of=Job)
        .execution_options(populate_existing=True)
    )
    if job is None:
        raise JobNotFoundError(f"job {job_id} does not exist")
    if job.status in TERMINAL_STATUSES:
        return CancellationResult(job=job, changed=False)
    if job.status == "cancelling":
        return CancellationResult(job=job, changed=False)
    if job.status not in {"queued", "leased", "running"}:
        raise InvalidJobTransition(f"job status {job.status!r} cannot be cancelled")
    if not can_cancel_job(job):
        raise CacheCommitInProgressError("scanner cache publication is already committing")
    job.status = "cancelling"
    job.cancel_requested_at = current
    job.stage = "cancelling"
    if detail is not None:
        job.detail = _required_text(detail, "detail", MAX_DETAIL_LENGTH)
    job.updated_at = current
    job.revision += 1
    session.flush()
    return CancellationResult(job=job, changed=True)


def complete_job(
    session: Session,
    job_id: int,
    *,
    worker_id: str,
    attempt: int,
    detail: str | None = None,
    result_ref: str | None = None,
    now: datetime | None = None,
) -> Job:
    job, current = _owned_job(
        session,
        job_id,
        worker_id=worker_id,
        attempt=attempt,
        now=now,
        statuses=("running", "cancelling"),
    )
    if job.status == "cancelling" or job.cancel_requested_at is not None:
        raise InvalidJobTransition("a cancellation request wins the terminal-state race")
    job.status = "completed"
    job.stage = "completed"
    if detail is not None:
        job.detail = _required_text(detail, "detail", MAX_DETAIL_LENGTH)
    job.result_ref = _optional_text(result_ref, "result_ref", 240)
    job.progress = 100
    job.completed_at = current
    job.updated_at = current
    job.lease_owner = None
    job.lease_expires_at = None
    job.error = None
    job.error_code = None
    job.error_detail = None
    job.revision += 1
    session.flush()
    return job


def fail_job(
    session: Session,
    job_id: int,
    *,
    worker_id: str,
    attempt: int,
    error_code: str,
    error_detail: str,
    retryable: bool,
    now: datetime | None = None,
) -> Job:
    job, current = _owned_job(
        session,
        job_id,
        worker_id=worker_id,
        attempt=attempt,
        now=now,
        statuses=("leased", "running"),
    )
    if job.cancel_requested_at is not None:
        raise InvalidJobTransition("a cancellation request must be finalized as cancelled")
    safe_code = _required_text(error_code, "error_code", 80)
    safe_detail = _required_text(error_detail, "error_detail", MAX_DETAIL_LENGTH)
    rejection = _preparation_rejection(job, current)
    uncertain_publication = (
        job.kind == "scanner_cache_update"
        and safe_code == "scanner_preparation_commit_uncertain"
        and rejection == "scanner_preparation_deadline"
        and not retryable
    )
    if rejection is not None and not uncertain_publication:
        safe_code = rejection
        safe_detail = "Preparation cannot retry under an expired or missing server budget."
    will_retry = retryable and rejection is None and job.attempt < job.max_attempts
    job.status = "queued" if will_retry else "failed"
    job.stage = "queued" if will_retry else "failed"
    job.error = safe_detail
    job.error_code = safe_code
    job.error_detail = safe_detail
    job.completed_at = None if will_retry else current
    job.updated_at = current
    job.lease_owner = None
    job.lease_expires_at = None
    if not will_retry:
        job.progress = min(job.progress or 0, 99)
    job.revision += 1
    session.flush()
    return job


def finalize_cancelled(
    session: Session,
    job_id: int,
    *,
    worker_id: str,
    attempt: int,
    detail: str | None = None,
    now: datetime | None = None,
) -> Job:
    job, current = _owned_job(
        session,
        job_id,
        worker_id=worker_id,
        attempt=attempt,
        now=now,
        statuses=("cancelling",),
    )
    job.status = "cancelled"
    job.stage = "cancelled"
    if detail is not None:
        job.detail = _required_text(detail, "detail", MAX_DETAIL_LENGTH)
    job.progress = min(job.progress or 0, 99)
    job.completed_at = current
    job.updated_at = current
    job.lease_owner = None
    job.lease_expires_at = None
    job.error = None
    job.error_code = None
    job.error_detail = None
    job.revision += 1
    session.flush()
    return job
