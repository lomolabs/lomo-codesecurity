from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping, Set


class AdvisorSelectionError(ValueError):
    """Public-safe rejection shared by retry admission and worker execution."""

    def __init__(self, detail: str, *, invalid: bool = False) -> None:
        self.code = "invalid_payload" if invalid else "advisor_selection_changed"
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class AdvisorSelectionSnapshot:
    finding_ids: list[int] | None
    expected_revisions: dict[int, int] | None

    def require_current(
        self,
        candidate_revisions: Mapping[int, int],
        *,
        completed: Set[int],
        include_existing: bool,
    ) -> None:
        if (
            self.finding_ids is not None
            and include_existing
            and set(candidate_revisions) != set(self.finding_ids)
        ):
            raise AdvisorSelectionError(
                "One or more selected findings are no longer active in this scan; "
                "open the findings and submit a new Advisor review."
            )
        if self.expected_revisions is not None and any(
            finding_id not in completed
            and revision != self.expected_revisions[finding_id]
            for finding_id, revision in candidate_revisions.items()
        ):
            raise AdvisorSelectionError(
                "One or more selected findings changed after admission; "
                "open the findings and submit a new Advisor review."
            )


def advisor_selection_snapshot(payload: Mapping[str, object]) -> AdvisorSelectionSnapshot:
    """Adapt the worker's exact bounded finding/revision command once."""

    selected = payload.get("finding_ids")
    selected_ids: list[int] | None = None
    if selected is not None:
        if not isinstance(selected, list) or len(selected) > 200:
            raise AdvisorSelectionError("Advisor finding selection is invalid.", invalid=True)
        selected_ids = []
        for value in selected:
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, str))
                or (isinstance(value, str) and (not value.isascii() or not value.isdigit() or len(value) > 20))
                or int(value) < 1
            ):
                raise AdvisorSelectionError("Advisor finding selection is invalid.", invalid=True)
            selected_ids.append(int(value))
        if len(selected_ids) != len(set(selected_ids)):
            raise AdvisorSelectionError("Advisor finding selection must contain unique IDs.", invalid=True)
    raw_revisions = payload.get("expected_revisions")
    revisions: dict[int, int] | None = None
    if raw_revisions is not None:
        if not isinstance(raw_revisions, dict) or len(raw_revisions) > 200:
            raise AdvisorSelectionError("Advisor revision snapshot is invalid.", invalid=True)
        revisions = {}
        for raw_id, revision in raw_revisions.items():
            if (
                isinstance(raw_id, bool)
                or not isinstance(raw_id, (int, str))
                or (isinstance(raw_id, str) and (not raw_id.isascii() or not raw_id.isdigit() or len(raw_id) > 20))
                or int(raw_id) < 1
                or isinstance(revision, bool)
                or not isinstance(revision, int)
                or revision < 1
                or int(raw_id) in revisions
            ):
                raise AdvisorSelectionError("Advisor revision snapshot is invalid.", invalid=True)
            revisions[int(raw_id)] = revision
        if selected_ids is None or set(revisions) != set(selected_ids):
            raise AdvisorSelectionError(
                "Advisor revision snapshot must match the exact finding selection.", invalid=True
            )
    return AdvisorSelectionSnapshot(selected_ids, revisions)


class InvalidScanCommandSnapshot(ValueError):
    """Typed, public-safe rejection of an immutable scan command."""

    code = "invalid_scan_command_snapshot"
    reason_code = "invalid_use_ai_snapshot"
    detail = (
        "The scan job's immutable AI selection is invalid; use_ai must be an "
        "exact JSON boolean."
    )

    def __init__(self) -> None:
        super().__init__(self.detail)


class UnsupportedScanCommandVersion(InvalidScanCommandSnapshot):
    code = "unsupported_scan_command_version"
    reason_code = "unsupported_scan_command_version"
    detail = "The scan job's immutable command must declare exact schema version 1."


class ScanCommandKindMismatch(InvalidScanCommandSnapshot):
    code = "scan_command_kind_mismatch"
    reason_code = "scan_command_kind_mismatch"
    detail = "The scan job kind and immutable operation do not identify the same command."


@dataclass(frozen=True, slots=True)
class ScanCommandSnapshot:
    use_ai: bool


def scan_command_snapshot(
    job_kind: str,
    payload: object,
) -> ScanCommandSnapshot | None:
    """Validate and adapt a scan command without coercion or truthiness.

    Exact JSON ``false`` is non-AI and exact JSON ``true`` is AI-enabled.
    Non-scan commands return ``None`` unchanged. Any command whose kind or
    operation implicates scan execution must declare exact schema v1, agree on
    both identities, and carry the required AI selection.
    """

    operation = payload.get("operation") if isinstance(payload, dict) else None
    implicated = job_kind == "scan" or operation == "scan"
    if not implicated:
        return None
    if not isinstance(payload, dict):
        raise InvalidScanCommandSnapshot()
    version = payload.get("v")
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise UnsupportedScanCommandVersion()
    if job_kind != "scan" or operation != "scan":
        raise ScanCommandKindMismatch()
    use_ai = payload.get("use_ai")
    if use_ai is False:
        return ScanCommandSnapshot(use_ai=False)
    if use_ai is True:
        return ScanCommandSnapshot(use_ai=True)
    raise InvalidScanCommandSnapshot()
