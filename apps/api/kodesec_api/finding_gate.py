"""Project policy evaluation for complete scanner evidence and finding review."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from fastapi import HTTPException
from sqlalchemy import and_, case, cast, exists, func, literal, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from .git_push_policy import load_policy
from .models import Finding, GatePolicy, Project, Scan
from .source_snapshots import is_source_snapshot_project, source_snapshot_project_kind, source_snapshot_project_source_id


# The pinned Bearer JSONv2 adapter preserves upstream rule IDs as names. These
# rules identify hardcoded values. A policy/configuration message mentioning
# secrets, service-account tokens, or a key file is not such a detection.
_BEARER_CREDENTIAL_RULES = (
    "java_lang_hardcoded_secret",
    "javascript_express_hardcoded_secret",
    "javascript_lang_hardcoded_secret",
    "javascript_lang_jwt_hardcoded_secret",
    "javascript_third_parties_passport_hardcoded_secret",
    "php_lang_hardcoded_secret",
    "ruby_lang_hardcoded_secret",
)


def secret_evidence(db: Session):
    """Use typed detector ownership and native rule evidence, including older Trivy rows."""
    # Only approved mixed-purpose detectors can identify a credential via a
    # native rule category. Tags on an IaC configuration finding never do so.
    if db.get_bind().dialect.name == "postgresql":
        tags = cast(Finding.metadata_json, JSONB)["tags"]
        array = case((func.jsonb_typeof(tags) == "array", tags), else_=cast(literal("[]"), JSONB))
        values = func.jsonb_array_elements_text(array).table_valued("value")
        tagged = exists(select(1).select_from(values).where(func.lower(values.c.value).in_(("secret", "secrets"))))
    else:
        values = func.json_each(Finding.metadata_json, "$.tags").table_valued("value", "type")
        tagged = and_(func.json_type(Finding.metadata_json, "$.tags") == "array",
                      exists(select(1).select_from(values).where(values.c.type == "text",
                             func.lower(values.c.value).in_(("secret", "secrets")))))
    return or_(
        Finding.scanner.in_(("gitleaks", "trufflehog", "secrets-lite")),
        and_(Finding.scanner.in_(("trivy", "opengrep")), tagged),
        and_(Finding.scanner == "bearer", Finding.rule_id.in_(_BEARER_CREDENTIAL_RULES)),
        and_(
            Finding.scanner == "trivy",
            or_(Finding.metadata_json["rule_name"].as_string() == "Secret",
                Finding.rule_id.in_(("aws-access-key-id", "github-pat"))),
        ),
    )


GateReason = Literal["critical", "high", "secret"]


@dataclass
class GateEvaluation:
    project_id: int | None
    decision: str
    messages: list[str] = field(default_factory=list)
    categories: set[GateReason] = field(default_factory=set)
    contributors: int = 0

    def reasons_for(self, finding: Finding, secret: bool) -> list[GateReason] | None:
        if self.decision not in ("pass", "fail", "row_criteria"):
            return None
        if finding.suppressed or finding.gate_exempt:
            return []
        return [category for category in ("critical", "high", "secret")
                if category in self.categories and (finding.severity == category if category != "secret" else secret)]

    def review(self) -> dict:
        if self.decision == "row_criteria":
            raise ValueError("Finding criteria cannot be used as a scan verdict")
        return {"policy_project_id": self.project_id, "decision": self.decision,
                "reasons": self.messages, "contributors": self.contributors if self.decision in ("pass", "fail") else None}


def evaluate(db: Session, scan: Scan, project_id: int, *, rows_only: bool = False) -> GateEvaluation:
    policy = db.scalar(select(GatePolicy).where(GatePolicy.project_id == project_id, GatePolicy.active.is_(True)))
    if policy is None:
        return GateEvaluation(project_id, "not_configured")
    eligible = (Finding.scan_id == scan.id, Finding.suppressed.is_(False), Finding.gate_exempt.is_(False))
    limits = (("critical", policy.max_critical), ("high", policy.max_high))
    if rows_only:
        # A matching row proves its own zero-tolerance category. With a
        # positive tolerance only its severity population needs counting.
        # Never inspect every other row's metadata to display one page.
        criteria = GateEvaluation(project_id, "row_criteria")
        positive = [severity for severity, limit in limits if limit > 0]
        positive_counts = dict(db.execute(select(Finding.severity, func.count()).where(
            *eligible, Finding.severity.in_(positive)
        ).group_by(Finding.severity)).all()) if positive else {}
        for severity, limit in limits:
            if limit == 0 or (limit > 0 and positive_counts.get(severity, 0) > limit):
                criteria.categories.add(severity)
        if policy.block_secrets:
            criteria.categories.add("secret")
        return criteria
    secret = func.coalesce(secret_evidence(db), False) if policy.block_secrets else None
    columns = (Finding.severity, secret) if secret is not None else (Finding.severity,)
    groups = db.execute(select(*columns, func.count()).where(*eligible).group_by(*columns))
    counts = {(row[0], bool(row[1]) if secret is not None else False): row[-1] for row in groups}
    result = GateEvaluation(project_id, "pass")
    for severity, limit in limits:
        count = counts.get((severity, False), 0) + counts.get((severity, True), 0)
        if limit >= 0 and count > limit:
            result.categories.add(severity)
            result.messages.append(f"{severity} findings: {count} > max {limit}")
    secret_count = sum(count for (_, is_secret), count in counts.items() if is_secret)
    if secret_count:
        result.categories.add("secret")
        result.messages.append(f"secret findings: {secret_count}")
    if result.categories:
        result.decision = "fail"
        result.contributors = sum(count for (severity, is_secret), count in counts.items()
                                  if severity in result.categories or is_secret)
    return result


def review_scan(db: Session, scan: Scan, *, rows_only: bool = False) -> GateEvaluation:
    """Resolve the exact current policy for display without issuing a Git push verdict."""
    project_id = scan.project_id
    path = scan.project.repo_path
    if is_source_snapshot_project(path) and source_snapshot_project_kind(path) == "git-commit":
        try:
            _, policy = load_policy(db, source_snapshot_project_source_id(path))
        except HTTPException as exc:
            if exc.status_code not in (404, 503):
                raise
            return GateEvaluation(None, "unavailable")
        if db.get(Project, policy.project_id) is None:
            return GateEvaluation(None, "unavailable")
        if not policy.enabled:
            return GateEvaluation(policy.project_id, "not_configured")
        project_id = policy.project_id
    if scan.status != "completed":
        return GateEvaluation(project_id, "incomplete")
    return evaluate(db, scan, project_id, rows_only=rows_only)
