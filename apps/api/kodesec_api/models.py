from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    event,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


INITIAL_SCHEMA_IDENTITY = "lomo-kodesec-0.1.0-initial"


class SchemaIdentity(Base):
    """Immutable identity of the sole greenfield 0.1.0 database shape."""

    __tablename__ = "schema_identity"
    __table_args__ = (
        CheckConstraint(
            "id = 1",
            name="ck_schema_identity_singleton",
        ),
        CheckConstraint(
            f"schema_id = '{INITIAL_SCHEMA_IDENTITY}'",
            name="ck_schema_identity_schema_id",
        ),
        CheckConstraint(
            "schema_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_schema_identity_fingerprint_hex",
        ).ddl_if(dialect="postgresql"),
        CheckConstraint(
            "length(schema_fingerprint) = 64 "
            "AND schema_fingerprint NOT GLOB '*[^0-9a-f]*'",
            name="ck_schema_identity_fingerprint_hex_sqlite",
        ).ddl_if(dialect="sqlite"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    schema_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    schema_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    initialized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint("revision >= 1", name="ck_projects_revision"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    repo_path: Mapped[str] = mapped_column(Text)
    remote_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    default_branch: Mapped[str] = mapped_column(String(120), default="main")
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    gate_policy: Mapped["GatePolicy | None"] = relationship(back_populates="project", cascade="all, delete-orphan")


Index("ix_projects_repo_path", Project.repo_path, unique=True)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("revision >= 1", name="ck_scans_revision"),
        CheckConstraint("findings_revision >= 1", name="ck_scans_findings_revision"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    mode: Mapped[str] = mapped_column(String(40), default="full")
    base_ref: Mapped[str | None] = mapped_column(String(160), nullable=True)
    head_ref: Mapped[str | None] = mapped_column(String(160), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="pending", index=True)
    gate_decision: Mapped[str | None] = mapped_column(String(40), nullable=True)
    gate_reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    scanner_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    findings_revision: Mapped[int] = mapped_column(Integer, default=1)

    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    artifacts: Mapped[list["ScanArtifact"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    jobs: Mapped[list["Job"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


Index("ix_scans_project_id_id", Scan.project_id, Scan.id)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "scan_finding_number", name="uq_findings_scan_finding_number"),
        CheckConstraint("revision >= 1", name="ck_findings_revision"),
        CheckConstraint(
            "lifecycle_status IN ('open', 'needs_review', 'gate_exempt', "
            "'accepted_risk', 'ignore', 'false_positive', 'fixed')",
            name="ck_findings_lifecycle_status",
        ),
        CheckConstraint(
            "(start_line IS NULL AND end_line IS NULL AND start_column IS NULL AND end_column IS NULL) OR "
            "(start_line >= 1 AND end_line >= start_line AND "
            "((start_column IS NULL AND end_column IS NULL) OR "
            "(start_column >= 1 AND (end_column IS NULL OR "
            "(end_column >= 1 AND (end_line <> start_line OR end_column >= start_column))))))",
            name="ck_findings_location_range",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    scan_finding_number: Mapped[int] = mapped_column(Integer)
    scanner: Mapped[str] = mapped_column(String(80), index=True)
    rule_id: Mapped[str] = mapped_column(String(160), index=True)
    severity: Mapped[str] = mapped_column(String(30), index=True)
    file_path: Mapped[str] = mapped_column(Text)
    start_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    start_column: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_column: Mapped[int | None] = mapped_column(Integer, nullable=True)
    message: Mapped[str] = mapped_column(Text)
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    ai_verdict: Mapped[str | None] = mapped_column(String(40), nullable=True)
    ai_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    ai_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_fix: Mapped[str | None] = mapped_column(Text, nullable=True)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    suppression_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    lifecycle_status: Mapped[str] = mapped_column(String(40), default="open")
    gate_exempt: Mapped[bool] = mapped_column(Boolean, default=False)
    lifecycle_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    lifecycle_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped[Scan] = relationship(back_populates="findings")


Index("ix_findings_scan_file_number", Finding.scan_id, Finding.file_path, Finding.scan_finding_number)
Index("ix_findings_scan_severity_number", Finding.scan_id, Finding.severity, Finding.scan_finding_number)
Index("ix_findings_scan_scanner_number", Finding.scan_id, Finding.scanner, Finding.scan_finding_number)
Index(
    "ix_findings_scan_lifecycle_number",
    Finding.scan_id,
    Finding.lifecycle_status,
    Finding.scan_finding_number,
)
Index("ix_findings_fingerprint_scan_id", Finding.fingerprint, Finding.scan_id)


class ScanArtifact(Base):
    __tablename__ = "scan_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    scanner: Mapped[str] = mapped_column(String(80), index=True)
    artifact_type: Mapped[str] = mapped_column(String(80), index=True)
    format: Mapped[str] = mapped_column(String(80))
    path: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped[Scan] = relationship(back_populates="artifacts")


class GatePolicy(Base):
    __tablename__ = "gate_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), unique=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    max_critical: Mapped[int] = mapped_column(Integer, default=0)
    max_high: Mapped[int] = mapped_column(Integer, default=-1)
    block_secrets: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    project: Mapped[Project] = relationship(back_populates="gate_policy")


class RuntimeConfig(Base):
    __tablename__ = "runtime_config"

    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class IdeEnrollment(Base):
    """Browser-reviewed sidecar for one pending IDE authority generation."""

    __tablename__ = "ide_enrollments"
    __table_args__ = (
        UniqueConstraint(
            "client_slot",
            "generation",
            name="uq_ide_enrollments_slot_generation",
        ),
        CheckConstraint(
            "generation BETWEEN 1 AND 2147483647",
            name="ck_ide_enrollments_generation",
        ),
        CheckConstraint(
            "revision BETWEEN 1 AND 2147483647",
            name="ck_ide_enrollments_revision",
        ),
        CheckConstraint(
            "state IN ('awaiting_approval', 'approved', 'rejected')",
            name="ck_ide_enrollments_state",
        ),
        CheckConstraint(
            "(state = 'awaiting_approval' AND decision_at IS NULL) OR "
            "(state IN ('approved', 'rejected') AND decision_at IS NOT NULL)",
            name="ck_ide_enrollments_decision_state",
        ),
        CheckConstraint(
            "activated_at IS NULL OR state = 'approved'",
            name="ck_ide_enrollments_activation_state",
        ),
        CheckConstraint(
            "activation_expires_at > requested_at",
            name="ck_ide_enrollments_expiry_order",
        ),
    )

    request_id: Mapped[str] = mapped_column(String(29), primary_key=True)
    client_slot: Mapped[str] = mapped_column(String(47), index=True)
    generation: Mapped[int] = mapped_column(Integer)
    client_name: Mapped[str] = mapped_column(String(120))
    verification_code: Mapped[str] = mapped_column(String(9), index=True)
    scopes: Mapped[list[str]] = mapped_column(JSON)
    state: Mapped[str] = mapped_column(String(24), index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    activation_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    decision_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'leased', 'running', 'cancelling', 'completed', 'failed', 'cancelled')",
            name="ck_jobs_status",
        ),
        CheckConstraint("progress IS NULL OR progress BETWEEN 0 AND 100", name="ck_jobs_progress"),
        CheckConstraint("priority BETWEEN -10 AND 10", name="ck_jobs_priority"),
        CheckConstraint("attempt >= 0 AND attempt <= max_attempts", name="ck_jobs_attempt"),
        CheckConstraint("max_attempts BETWEEN 1 AND 10", name="ck_jobs_max_attempts"),
        CheckConstraint("revision >= 1", name="ck_jobs_revision"),
        CheckConstraint(
            "(client_id IS NULL AND idempotency_key IS NULL) OR "
            "(client_id IS NOT NULL AND idempotency_key IS NOT NULL)",
            name="ck_jobs_idempotency_pair",
        ),
        CheckConstraint(
            "octet_length(convert_to(CAST(payload AS TEXT), 'UTF8')) <= 16384",
            name="ck_jobs_payload_size",
        ).ddl_if(dialect="postgresql"),
        CheckConstraint(
            "octet_length(convert_to(CAST(checkpoint AS TEXT), 'UTF8')) <= 16384",
            name="ck_jobs_checkpoint_size",
        ).ddl_if(dialect="postgresql"),
        CheckConstraint(
            "length(CAST(payload AS BLOB)) <= 16384",
            name="ck_jobs_payload_size_sqlite",
        ).ddl_if(dialect="sqlite"),
        CheckConstraint(
            "length(CAST(checkpoint AS BLOB)) <= 16384",
            name="ck_jobs_checkpoint_size_sqlite",
        ).ddl_if(dialect="sqlite"),
        CheckConstraint("detail IS NULL OR length(detail) <= 4000", name="ck_jobs_detail_size"),
        CheckConstraint("error IS NULL OR length(error) <= 4000", name="ck_jobs_error_size"),
        CheckConstraint("error_detail IS NULL OR length(error_detail) <= 4000", name="ck_jobs_error_detail_size"),
        UniqueConstraint("client_id", "kind", "idempotency_key", name="uq_jobs_client_kind_idempotency"),
        UniqueConstraint("external_run_id", name="uq_jobs_external_run_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    title: Mapped[str] = mapped_column(String(240))
    status: Mapped[str] = mapped_column(String(40), default="queued", index=True)
    stage: Mapped[str | None] = mapped_column(String(120), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=lambda: {"v": 1})
    checkpoint: Mapped[dict] = mapped_column(JSON, default=dict)
    client_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    lease_owner: Mapped[str | None] = mapped_column(String(160), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    external_run_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    result_ref: Mapped[str | None] = mapped_column(String(240), nullable=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped[Scan | None] = relationship(back_populates="jobs")


_JOB_CLAIMABLE_PREDICATE = text("status IN ('queued', 'leased', 'running', 'cancelling')")
Index(
    "ix_jobs_claimable",
    Job.priority.desc(),
    Job.created_at,
    Job.id,
    postgresql_where=_JOB_CLAIMABLE_PREDICATE,
    sqlite_where=_JOB_CLAIMABLE_PREDICATE,
)
Index(
    "ix_jobs_lease_expires_at",
    Job.lease_expires_at,
    postgresql_where=_JOB_CLAIMABLE_PREDICATE,
    sqlite_where=_JOB_CLAIMABLE_PREDICATE,
)


class ScannerToolState(Base):
    __tablename__ = "scanner_tool_state"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    current_version: Mapped[str] = mapped_column(String(80), default="0.1.0")
    latest_version: Mapped[str] = mapped_column(String(80), default="0.1.0")
    pinned_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="ready")
    update_available: Mapped[bool] = mapped_column(Boolean, default=False)
    candidate_release_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    candidate_manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    published_at: Mapped[str | None] = mapped_column(String(80), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ScannerLifecycleState(Base):
    """Latest durable catalog/cache operation state exposed to local clients.

    Jobs remain the authoritative command log.  These two singleton rows keep
    the scanner lifecycle's last admitted, bounded receipt and link it back to
    the job that produced (or is producing) it.
    """

    __tablename__ = "scanner_lifecycle_state"
    __table_args__ = (
        CheckConstraint("id IN ('catalog', 'cache')", name="ck_scanner_lifecycle_state_id"),
        CheckConstraint(
            "status IN ('idle', 'queued', 'leased', 'running', 'cancelling', "
            "'completed', 'failed', 'cancelled')",
            name="ck_scanner_lifecycle_state_status",
        ),
        CheckConstraint("revision >= 1", name="ck_scanner_lifecycle_state_revision"),
        CheckConstraint(
            "octet_length(convert_to(CAST(receipt AS TEXT), 'UTF8')) <= 16384",
            name="ck_scanner_lifecycle_state_receipt_size",
        ).ddl_if(dialect="postgresql"),
        CheckConstraint(
            "length(CAST(receipt AS BLOB)) <= 16384",
            name="ck_scanner_lifecycle_state_receipt_size_sqlite",
        ).ddl_if(dialect="sqlite"),
        CheckConstraint(
            "error_detail IS NULL OR length(error_detail) <= 4000",
            name="ck_scanner_lifecycle_state_error_detail_size",
        ),
        UniqueConstraint("job_id", name="uq_scanner_lifecycle_state_job_id"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    status: Mapped[str] = mapped_column(String(40), default="idle", index=True)
    job_id: Mapped[int | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    revision: Mapped[int] = mapped_column(Integer, default=1)
    active_generation: Mapped[str | None] = mapped_column(String(160), nullable=True)
    previous_generation: Mapped[str | None] = mapped_column(String(160), nullable=True)
    receipt: Mapped[dict] = mapped_column(JSON, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EventOutbox(Base):
    """Committed notification intent; ``row_id`` is never a replay cursor."""

    __tablename__ = "event_outbox"
    __table_args__ = (
        CheckConstraint("schema_version = 1", name="ck_event_outbox_schema_version"),
        CheckConstraint(
            "kind IN ('project.changed', 'scan.changed', 'job.changed', 'findings.changed')",
            name="ck_event_outbox_kind",
        ),
        CheckConstraint(
            "aggregate_type IN ('project', 'scan', 'job', 'findings')",
            name="ck_event_outbox_aggregate_type",
        ),
        CheckConstraint(
            "(kind = 'project.changed' AND aggregate_type = 'project') OR "
            "(kind = 'scan.changed' AND aggregate_type = 'scan') OR "
            "(kind = 'job.changed' AND aggregate_type = 'job') OR "
            "(kind = 'findings.changed' AND aggregate_type = 'findings')",
            name="ck_event_outbox_kind_aggregate",
        ),
        CheckConstraint("aggregate_revision >= 1", name="ck_event_outbox_revision"),
        CheckConstraint(
            "change IN ('created', 'updated', 'deleted')",
            name="ck_event_outbox_change",
        ),
        CheckConstraint("event_id IS NULL OR event_id >= 1", name="ck_event_outbox_event_id"),
        CheckConstraint(
            "dispatch_attempts BETWEEN 0 AND 3",
            name="ck_event_outbox_dispatch_attempts",
        ),
        CheckConstraint(
            "dispatch_error_code IS NULL OR length(dispatch_error_code) <= 80",
            name="ck_event_outbox_dispatch_error_code",
        ),
        CheckConstraint(
            "(event_id IS NULL AND dispatched_at IS NULL) OR "
            "(event_id IS NOT NULL AND dispatched_at IS NOT NULL)",
            name="ck_event_outbox_dispatch_pair",
        ),
        CheckConstraint(
            "quarantined_at IS NULL OR (event_id IS NULL AND dispatch_attempts = 3)",
            name="ck_event_outbox_quarantine_state",
        ),
        # The complete encoder independently enforces a 4 KiB envelope. Keeping
        # the two variable JSON maps below 3 KiB leaves a deterministic margin
        # for the bounded aggregate and protocol fields.
        CheckConstraint(
            "octet_length(convert_to(CAST(scope AS TEXT) || CAST(hint AS TEXT), 'UTF8')) <= 3072",
            name="ck_event_outbox_json_size",
        ).ddl_if(dialect="postgresql"),
        CheckConstraint(
            "length(CAST(scope AS BLOB)) + length(CAST(hint AS BLOB)) <= 3072",
            name="ck_event_outbox_json_size_sqlite",
        ).ddl_if(dialect="sqlite"),
    )

    row_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, unique=True, index=True)
    schema_version: Mapped[int] = mapped_column(Integer, default=1, server_default=text("1"))
    kind: Mapped[str] = mapped_column(String(40), index=True)
    aggregate_type: Mapped[str] = mapped_column(String(40))
    aggregate_id: Mapped[str] = mapped_column(String(160))
    aggregate_revision: Mapped[int] = mapped_column(Integer)
    scope: Mapped[dict] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        default=dict,
        server_default=text("'{}'"),
    )
    change: Mapped[str] = mapped_column(String(40))
    hint: Mapped[dict] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        default=dict,
        server_default=text("'{}'"),
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dispatch_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    dispatch_error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    quarantined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


Index(
    "ix_event_outbox_pending",
    EventOutbox.row_id,
    postgresql_where=text("event_id IS NULL AND quarantined_at IS NULL"),
    sqlite_where=text("event_id IS NULL AND quarantined_at IS NULL"),
)


class IdeSourceOpenCommand(Base):
    """Durable, recipient-bound request to reveal one finding in one IDE."""

    __tablename__ = "ide_source_open_commands"
    __table_args__ = (
        CheckConstraint("finding_id >= 1", name="ck_ide_source_open_finding_id"),
        CheckConstraint("project_id >= 1", name="ck_ide_source_open_project_id"),
        CheckConstraint("scan_id >= 1", name="ck_ide_source_open_scan_id"),
        CheckConstraint(
            "scan_finding_number >= 1",
            name="ck_ide_source_open_scan_finding_number",
        ),
        CheckConstraint(
            "expected_finding_revision >= 1",
            name="ck_ide_source_open_finding_revision",
        ),
        CheckConstraint(
            "expected_findings_revision >= 1",
            name="ck_ide_source_open_findings_revision",
        ),
        CheckConstraint(
            "expected_target_generation BETWEEN 1 AND 2147483647",
            name="ck_ide_source_open_target_generation",
        ),
        CheckConstraint("revision >= 1", name="ck_ide_source_open_revision"),
        CheckConstraint(
            "status IN ('queued', 'opened', 'failed', 'expired')",
            name="ck_ide_source_open_status",
        ),
        CheckConstraint(
            "error_code IS NULL OR length(error_code) <= 80",
            name="ck_ide_source_open_error_code",
        ),
        CheckConstraint(
            "(status = 'failed' AND error_code IS NOT NULL) OR "
            "(status != 'failed' AND error_code IS NULL)",
            name="ck_ide_source_open_error_state",
        ),
        CheckConstraint(
            "(status = 'queued' AND acknowledged_at IS NULL) OR "
            "(status != 'queued' AND acknowledged_at IS NOT NULL)",
            name="ck_ide_source_open_ack_state",
        ),
        UniqueConstraint(
            "requester_subject",
            "idempotency_key",
            name="uq_ide_source_open_request",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    requester_subject: Mapped[str] = mapped_column(String(160), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(67))
    request_digest: Mapped[str] = mapped_column(String(64))
    target_capability_id: Mapped[str] = mapped_column(String(64), index=True)
    expected_target_generation: Mapped[int] = mapped_column(Integer)
    project_id: Mapped[int] = mapped_column(Integer)
    project_repo_path: Mapped[str] = mapped_column(Text)
    scan_id: Mapped[int] = mapped_column(Integer)
    finding_id: Mapped[int] = mapped_column(Integer)
    scan_finding_number: Mapped[int] = mapped_column(Integer)
    expected_finding_revision: Mapped[int] = mapped_column(Integer)
    expected_findings_revision: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EventDispatchState(Base):
    """Singleton allocator locked by dispatchers after source transactions commit."""

    __tablename__ = "event_dispatch_state"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_event_dispatch_state_singleton"),
        CheckConstraint("next_event_id >= 1", name="ck_event_dispatch_state_next_event_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    next_event_id: Mapped[int] = mapped_column(BigInteger, default=1, server_default=text("1"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


@event.listens_for(Base.metadata, "after_create")
def _seed_initial_schema_singletons(_metadata, connection, **_kwargs) -> None:
    """Seed required singleton rows in the same transaction as initial DDL."""

    from .db import schema_fingerprint

    connection.execute(
        SchemaIdentity.__table__.insert(),
        {
            "id": 1,
            "schema_id": INITIAL_SCHEMA_IDENTITY,
            "schema_fingerprint": schema_fingerprint(),
        },
    )
    connection.execute(
        EventDispatchState.__table__.insert(),
        {"id": 1, "next_event_id": 1},
    )
    connection.execute(
        ScannerLifecycleState.__table__.insert(),
        [
            {"id": "catalog", "status": "idle", "revision": 1, "receipt": {}},
            {"id": "cache", "status": "idle", "revision": 1, "receipt": {}},
        ],
    )
