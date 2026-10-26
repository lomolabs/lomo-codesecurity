from __future__ import annotations

import base64
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import unicodedata

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, insert, select
from sqlalchemy.pool import StaticPool

from kodesec_api.auth import AuthContext
from kodesec_api.db import Base, Runtime, initialize_database
from kodesec_api.main import (
    INCOMPLETE_GATE_REASON,
    _normalized_finding_location,
    _normalized_finding_path,
    router,
    triage_finding,
)
from kodesec_api.models import Finding, GatePolicy, Job, Project, Scan
from kodesec_api.schemas import TriageRequest
from kodesec_api.settings import Settings


@pytest.fixture()
def finding_api() -> Iterator[tuple[TestClient, Runtime]]:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    settings = Settings(
        _env_file=None,
        DATABASE_URL="sqlite+pysqlite://",
        KODESEC_ALLOWED_ROOTS="/workspaces",
    )
    runtime = Runtime.create(settings, engine=engine)
    app = FastAPI()
    app.state.runtime = runtime
    app.include_router(router)
    try:
        with TestClient(app) as client:
            yield client, runtime
    finally:
        engine.dispose()


@pytest.fixture()
def postgres_finding_api(postgres_engine) -> Iterator[tuple[TestClient, Runtime]]:
    initialize_database(postgres_engine)
    settings = Settings(
        _env_file=None,
        DATABASE_URL=str(postgres_engine.url),
        KODESEC_ALLOWED_ROOTS="/workspaces",
    )
    runtime = Runtime.create(settings, engine=postgres_engine)
    app = FastAPI()
    app.state.runtime = runtime
    app.include_router(router)
    with TestClient(app) as client:
        yield client, runtime


def _seed_scan(
    runtime: Runtime,
    *,
    name: str,
    count: int,
    repo_path: str | None = None,
    distinct_files: bool = False,
) -> tuple[int, int, list[int]]:
    with runtime.session_factory() as db:
        project = Project(
            name=name,
            repo_path=repo_path or f"/workspaces/{name}",
            default_branch="main",
        )
        db.add(project)
        db.flush()
        scan = Scan(
            project_id=project.id,
            mode="full",
            status="completed",
            gate_decision="pass",
            gate_reasons=[],
            scanner_summary={},
        )
        db.add(scan)
        db.flush()
        db.execute(
            insert(Finding),
            [
                {
                    "scan_id": scan.id,
                    "scan_finding_number": number,
                    "scanner": "semgrep" if number % 2 else "trivy",
                    "rule_id": f"fixture.rule.{number}",
                    "severity": "high" if number % 3 else "medium",
                    "file_path": (
                        f"src/manifest/file-{number:05d}.py"
                        if distinct_files
                        else "src/one.py" if number % 2 else "src/two.py"
                    ),
                    "start_line": number,
                    "end_line": number,
                    "message": f"finding {number}",
                    "code_snippet": "password=fixture-secret",
                    "fingerprint": f"fingerprint-{number:06d}",
                    "metadata_json": {"api_key": "fixture-secret", "safe": number},
                    "ai_verdict": "needs_review",
                    "ai_confidence": 0.75,
                    "ai_reasoning": "password=fixture-secret",
                    "ai_fix": "replace the unsafe call",
                    "suppressed": False,
                    "lifecycle_status": "open",
                    "gate_exempt": False,
                    "revision": 1,
                }
                for number in range(1, count + 1)
            ],
        )
        db.commit()
        finding_ids = list(
            db.scalars(
                select(Finding.id)
                .where(Finding.scan_id == scan.id)
                .order_by(Finding.scan_finding_number)
            )
        )
        return project.id, scan.id, [int(item) for item in finding_ids]


@pytest.mark.parametrize("status", ["completed", "partial", "failed", "cancelled"])
def test_scan_history_preserves_current_gate_coverage_and_failures(finding_api, status: str) -> None:
    client, runtime = finding_api
    project_id, scan_id, _ = _seed_scan(runtime, name="history", count=1)
    raw_summary = {
        "findings_total": 1,
        "advisor": {"status": "failed", "error": "password=fixture-only"},
        "requested_mode": "incremental_diff", "effective_mode": "full",
        "warnings": ["incremental-diff-fallback-full"],
        "scope": {"kind": "file", "target_path": "src/one.py"},
        "source_coverage": {"complete": False, "reason_counts": {"eligible_file_too_large": 1}},
        "coverage": {"mode": "limited", "complete": False, "omitted_tool_ids": ["bearer"]},
        "tools": [{"id": "bearer", "name": "Bearer", "enabled": True,
                   "status": "failed", "error": "password=fixture-only",
                   "readiness": {"large_unused_receipt": "details" * 400}}],
        "external_runs": [{"engine_receipt": "preserved exact evidence"}],
    }
    with runtime.session_factory() as db:
        scan = db.get(Scan, scan_id)
        scan.status = status
        scan.gate_decision = "fail"
        scan.gate_reasons = ["incomplete coverage"]
        scan.scanner_summary = raw_summary
        scan.revision = 4
        scan.findings_revision = 3
        db.commit()
    full = client.get("/v1/scans").json()
    history = client.get("/v1/scans", params={"view": "history", "project_id": project_id}).json()
    assert len(history) == len(full) == 1
    expected = {**full[0], "scanner_summary": {
        key: value for key, value in full[0]["scanner_summary"].items() if key != "external_runs"
    }}
    expected["scanner_summary"]["tools"] = [{
        key: value for key, value in full[0]["scanner_summary"]["tools"][0].items() if key != "readiness"
    }]
    assert history == [expected]
    assert "fixture-only" not in json.dumps(history)
    assert client.get(f"/v1/scans/{scan_id}").json() == full[0]
    assert client.get("/v1/scans", params={"view": "full"}).json() == full
    assert client.get("/v1/scans", params={"view": "unknown"}).status_code == 422
    with runtime.session_factory() as db:
        assert db.get(Scan, scan_id).scanner_summary == raw_summary
        scan = db.get(Scan, scan_id)
        scan.gate_decision = "pass"
        scan.gate_reasons = []
        scan.revision += 1
        db.commit()
    refreshed = client.get("/v1/scans", params={"view": "history"}).json()[0]
    assert refreshed["gate_decision"] == "pass" and refreshed["gate_reasons"] == []
    assert refreshed["revision"] == 5 and refreshed["findings_revision"] == 3


def _detail_params(
    *, finding_revision: int = 1, findings_revision: int = 1
) -> dict[str, int]:
    return {
        "expected_revision": finding_revision,
        "expected_findings_revision": findings_revision,
    }


def test_source_target_denial_is_structured_and_creates_nothing(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    denied = client.post(
        "/v1/projects",
        json={"name": "outside", "repo_path": "/tmp/outside"},
    )
    assert denied.status_code == 422
    assert denied.json()["detail"] == {
        "code": "source_outside_allowed_root",
        "message": "The selected directory is outside the authorized source root.",
        "action": "authorize_source",
        "context": {
            "source_target": {
                "kind": "mounted_directory",
                "display_path": "/tmp/outside",
            },
            "authorization_boundary": {
                "kind": "allowed_roots",
                "display_paths": ["/workspaces"],
            },
            "selected_path": "/tmp/outside",
            "allowed_roots": ["/workspaces"],
        },
        "safe_details": {
            "selected_source": "/tmp/outside",
            "configured_source_boundary": "/workspaces",
        },
    }
    with runtime.session_factory() as db:
        assert db.query(Project).count() == 0


@pytest.mark.parametrize(
    ("selected", "canonical", "authorized"),
    [
        ("/workspaces/demo", "/workspaces/demo", True),
        ("/independent/日本語 space/./nested", "/independent/日本語 space/nested", True),
        ("/workspaces-other/demo", "/workspaces-other/demo", False),
        ("/independent", "/independent", False),
    ],
)
def test_source_preview_matches_admission_without_creating_resources(
    finding_api: tuple[TestClient, Runtime], selected: str, canonical: str, authorized: bool,
) -> None:
    client, runtime = finding_api
    runtime.settings.allowed_roots = "/workspaces,/independent/日本語 space"
    preview = client.post("/v1/sources/preview", json={"repo_path": selected})
    assert preview.status_code == 200
    assert preview.json() == {
        "installation_id": runtime.settings.installation_id,
        "repo_path": canonical,
        "authorization_mode": "mounted",
        "authorized": authorized,
        "configured_roots": ["/workspaces", "/independent/日本語 space"],
        "reason_code": None if authorized else "source_outside_allowed_root",
    }
    with runtime.session_factory() as db:
        assert db.query(Project).count() == 0
        assert db.query(Scan).count() == 0
        assert db.query(Job).count() == 0
    admission = client.post("/v1/projects", json={"name": "previewed", "repo_path": selected})
    assert admission.status_code == (201 if authorized else 422)


def test_source_preview_rejects_traversal_and_does_not_grant_authorization(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    assert client.post("/v1/sources/preview", json={"repo_path": "/workspaces/../outside"}).status_code == 422
    assert client.post("/v1/sources/preview", json={"repo_path": "/workspaces/demo", "authorize": True}).status_code == 422
    assert client.post("/v1/sources/preview", json={"repo_path": "/workspaces/demo"}).json()["authorized"] is True
    runtime.settings.allowed_roots = "/different-root"
    refused = client.post("/v1/projects", json={"name": "changed-boundary", "repo_path": "/workspaces/demo"})
    assert refused.status_code == 422
    with runtime.session_factory() as db:
        assert db.query(Project).count() == 0


def test_source_preview_uses_only_the_read_only_project_resolve_scope() -> None:
    from kodesec_api.security import ide_scope_for_request

    assert ide_scope_for_request("POST", "/v1/sources/preview") == "project:resolve"
    assert ide_scope_for_request("GET", "/v1/sources/preview") is None
    assert ide_scope_for_request("POST", "/v1/sources/preview/other") is None


def test_long_source_target_denial_remains_a_bounded_structured_422(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    selected = "/tmp/" + "a" * 600

    denied = client.post(
        "/v1/projects",
        json={"name": "outside-long", "repo_path": selected},
    )

    assert denied.status_code == 422
    detail = denied.json()["detail"]
    assert detail["code"] == "source_outside_allowed_root"
    assert detail["action"] == "authorize_source"
    assert detail["context"]["selected_path"] == selected
    assert detail["safe_details"]["selected_source"] == selected[:500]
    assert detail["safe_details"]["configured_source_boundary"] == "/workspaces"
    with runtime.session_factory() as db:
        assert db.query(Project).count() == 0


def test_findings_keyset_page_handles_10000_and_anchor_without_heavy_fields(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    _, scan_id, _ = _seed_scan(runtime, name="large-page", count=10_005)

    first = client.get(f"/v1/scans/{scan_id}/findings", params={"limit": 200})
    assert first.status_code == 200, first.text
    page = first.json()
    assert page["total"] == 10_005
    assert page["revision"] == 1
    assert page["truncated"] is True
    assert page["next_cursor"]
    assert len(page["items"]) == 200
    assert [item["scan_finding_number"] for item in page["items"][:3]] == [1, 2, 3]
    assert {
        "code_snippet",
        "metadata_json",
        "ai_reasoning",
        "ai_fix",
        "suppression_reason",
        "lifecycle_reason",
    }.isdisjoint(page["items"][0])

    anchored = client.get(
        f"/v1/scans/{scan_id}/findings",
        params={"limit": 200, "anchor_scan_finding_number": 10_000},
    )
    assert anchored.status_code == 200, anchored.text
    anchor_page = anchored.json()
    assert anchor_page["items"][0]["scan_finding_number"] == 9_801
    assert anchor_page["items"][-1]["scan_finding_number"] == 10_000
    assert anchor_page["truncated"] is True

    terminal = client.get(
        f"/v1/scans/{scan_id}/findings",
        params={"limit": 200, "cursor": anchor_page["next_cursor"]},
    )
    assert terminal.status_code == 200, terminal.text
    terminal_page = terminal.json()
    assert [item["scan_finding_number"] for item in terminal_page["items"]] == list(
        range(10_001, 10_006)
    )
    assert terminal_page["total"] == 10_005
    assert terminal_page["truncated"] is False
    assert terminal_page["next_cursor"] is None


def test_cursor_is_filter_bound_path_opaque_and_stale_after_delete(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    _, scan_id, _ = _seed_scan(runtime, name="cursor-boundary", count=8)
    params = {"limit": 2, "file_path": "src/one.py"}
    first = client.get(f"/v1/scans/{scan_id}/findings", params=params)
    assert first.status_code == 200, first.text
    body = first.json()
    cursor = body["next_cursor"]
    assert body["total"] == 4
    assert cursor and len(cursor) <= 512
    decoded = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
    assert "src/one.py" not in decoded

    mismatch = client.get(
        f"/v1/scans/{scan_id}/findings", params={"limit": 2, "cursor": cursor}
    )
    assert mismatch.status_code == 400
    assert mismatch.json()["detail"]["code"] == "cursor_invalid"

    file_page = client.get(
        f"/v1/scans/{scan_id}/finding-files", params={"limit": 1}
    )
    assert file_page.status_code == 200, file_page.text
    file_cursor = file_page.json()["next_cursor"]
    assert file_cursor
    diagnostic_page = client.get(
        f"/v1/scans/{scan_id}/finding-diagnostics", params={"limit": 1}
    )
    assert diagnostic_page.status_code == 200, diagnostic_page.text
    diagnostic_cursor = diagnostic_page.json()["next_cursor"]
    assert diagnostic_cursor
    expected = client.get(
        f"/v1/scans/{scan_id}/findings",
        params={**params, "expected_revision": 1},
    )
    assert expected.status_code == 200, expected.text

    item = body["items"][0]
    deleted = client.delete(
        f"/v1/findings/{item['id']}", params={"expected_revision": item["revision"]}
    )
    assert deleted.status_code == 200, deleted.text
    stale = client.get(
        f"/v1/scans/{scan_id}/findings", params={**params, "cursor": cursor}
    )
    assert stale.status_code == 409
    assert stale.json()["detail"] == {
        "code": "cursor_stale",
        "message": "findings changed after this cursor was issued; restart pagination",
        "revision": 2,
    }
    stale_file_page = client.get(
        f"/v1/scans/{scan_id}/finding-files", params={"limit": 1, "cursor": file_cursor}
    )
    assert stale_file_page.status_code == 409
    assert stale_file_page.json()["detail"] == {
        "code": "cursor_stale",
        "message": "findings changed after this cursor was issued; restart pagination",
        "revision": 2,
    }
    stale_diagnostics = client.get(
        f"/v1/scans/{scan_id}/finding-diagnostics",
        params={"limit": 1, "cursor": diagnostic_cursor},
    )
    assert stale_diagnostics.status_code == 409
    assert stale_diagnostics.json()["detail"] == {
        "code": "cursor_stale",
        "message": "findings changed after this cursor was issued; restart pagination",
        "revision": 2,
    }
    stale_expected = client.get(
        f"/v1/scans/{scan_id}/findings",
        params={**params, "expected_revision": 1},
    )
    assert stale_expected.status_code == 409
    assert stale_expected.json()["detail"] == {
        "code": "revision_conflict",
        "message": "findings changed after the selected manifest snapshot",
        "revision": 2,
    }
    current_expected = client.get(
        f"/v1/scans/{scan_id}/findings",
        params={**params, "expected_revision": 2},
    )
    assert current_expected.status_code == 200, current_expected.text


def test_scan_local_detail_is_precise_redacted_and_loaded_on_demand(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    project_id, scan_id, finding_ids = _seed_scan(
        runtime, name="precise-detail", count=1
    )
    with runtime.session_factory() as db:
        finding = db.get(Finding, finding_ids[0])
        assert finding is not None
        finding.start_line = 7
        finding.start_column = 13
        finding.end_line = 7
        finding.end_column = None
        db.add(finding)
        newer = Scan(
            project_id=project_id,
            mode="incremental_diff",
            status="completed",
            gate_decision="fail",
            gate_reasons=["one high finding"],
            scanner_summary={},
        )
        db.add(newer)
        db.commit()
        newer_id = newer.id

    resolved = client.post(
        "/v1/projects/resolve", json={"repo_path": "/workspaces/precise-detail"}
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["id"] == project_id
    assert client.post(
        "/v1/projects/resolve", json={"repo_path": "/workspaces/missing"}
    ).status_code == 404
    latest = client.get(f"/v1/projects/{project_id}/scans/latest")
    assert latest.status_code == 200
    assert latest.json()["id"] == newer_id

    listing = client.get(f"/v1/scans/{scan_id}/findings")
    assert listing.status_code == 200, listing.text
    item = listing.json()["items"][0]
    assert (item["start_line"], item["start_column"]) == (7, 13)
    assert (item["end_line"], item["end_column"]) == (7, None)
    assert "code_snippet" not in item
    assert "ai_reasoning" not in item

    detail = client.get(
        f"/v1/scans/{scan_id}/findings/1", params=_detail_params()
    )
    assert detail.status_code == 200, detail.text
    evidence = detail.json()
    assert evidence["id"] == finding_ids[0]
    assert evidence["display_id"] == f"S{scan_id}-F001"
    assert evidence["start_column"] == 13
    assert evidence["end_column"] is None
    assert evidence["findings_revision"] == 1
    assert "fixture-secret" not in evidence["code_snippet"]
    assert evidence["metadata_json"]["api_key"] == "[REDACTED]"
    assert "fixture-secret" not in evidence["ai_reasoning"]

    with runtime.session_factory() as db:
        finding = db.get(Finding, finding_ids[0])
        assert finding is not None
        finding.code_snippet = "safe text " * 3_000
        finding.metadata_json = {"safe": "safe text " * 3_000}
        db.commit()
    bounded = client.get(
        f"/v1/scans/{scan_id}/findings/1", params=_detail_params()
    )
    assert bounded.status_code == 200, bounded.text
    assert len(bounded.json()["code_snippet"]) == 20_000
    assert bounded.json()["metadata_json"] == {"_kodesec_truncated": True}

    removed = client.get(
        f"/v1/scans/{scan_id}/findings/99", params=_detail_params()
    )
    assert removed.status_code == 409
    assert removed.json()["detail"]["code"] == "finding_removed"
    assert client.get("/v1/scans/999999/findings").status_code == 404
    assert client.get("/v1/scans/999999/finding-files").status_code == 404
    assert client.get("/v1/scans/999999/finding-diagnostics").status_code == 404
    assert client.get("/v1/scans/999999/summary").status_code == 404


def test_scan_local_detail_fences_item_and_collection_then_reports_removal(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    _, scan_id, finding_ids = _seed_scan(
        runtime, name="detail-revision-fence", count=1
    )
    finding_id = finding_ids[0]

    current = client.get(
        f"/v1/scans/{scan_id}/findings/1", params=_detail_params()
    )
    assert current.status_code == 200, current.text
    assert current.json()["id"] == finding_id
    assert current.json()["findings_revision"] == 1

    changed = client.patch(
        f"/v1/findings/{finding_id}/lifecycle",
        json={"action": "needs_review", "expected_revision": 1},
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["revision"] == 2

    stale_collection = client.get(
        f"/v1/scans/{scan_id}/findings/1", params=_detail_params()
    )
    assert stale_collection.status_code == 409
    assert stale_collection.json()["detail"] == {
        "code": "revision_conflict",
        "message": "Findings changed after the selected collection snapshot.",
        "action": "refresh_findings",
        "context": {
            "scan_id": scan_id,
            "scan_finding_number": 1,
            "expected_findings_revision": 1,
            "current_findings_revision": 2,
        },
    }

    stale_item = client.get(
        f"/v1/scans/{scan_id}/findings/1",
        params=_detail_params(finding_revision=1, findings_revision=2),
    )
    assert stale_item.status_code == 409
    assert stale_item.json()["detail"]["context"]["current_revision"] == 2

    refreshed = client.get(
        f"/v1/scans/{scan_id}/findings/1",
        params=_detail_params(finding_revision=2, findings_revision=2),
    )
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["lifecycle_status"] == "needs_review"

    deleted = client.delete(
        f"/v1/findings/{finding_id}", params={"expected_revision": 2}
    )
    assert deleted.status_code == 200, deleted.text
    removed = client.get(
        f"/v1/scans/{scan_id}/findings/1",
        params=_detail_params(finding_revision=2, findings_revision=3),
    )
    assert removed.status_code == 409
    assert removed.json()["detail"]["code"] == "finding_removed"


def test_single_advisor_admission_requires_and_persists_exact_revision(
    finding_api: tuple[TestClient, Runtime],
    seed_ready_local_advisor,
) -> None:
    _client, runtime = finding_api
    _, _scan_id, finding_ids = _seed_scan(
        runtime, name="advisor-revision-admission", count=1
    )
    finding_id = finding_ids[0]
    provider_pin = seed_ready_local_advisor(runtime)

    def command_request(key: bytes) -> Request:
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": f"/v1/findings/{finding_id}/triage",
                "headers": [(b"idempotency-key", key)],
            }
        )
        request.state.auth = AuthContext(
            kind="browser", subject="test-session", scopes=frozenset()
        )
        return request

    with runtime.session_factory() as db:
        with pytest.raises(HTTPException) as stale:
            triage_finding(
                finding_id,
                TriageRequest(
                    expected_revision=2,
                    advisor_provider_pin=provider_pin,
                ),
                command_request(b"advisor-stale-revision"),
                runtime=runtime,
                db=db,
            )
        assert stale.value.status_code == 409
        assert stale.value.detail["code"] == "revision_conflict"
        assert db.query(Job).count() == 0

        accepted = triage_finding(
            finding_id,
            TriageRequest(
                expected_revision=1,
                advisor_provider_pin=provider_pin,
            ),
            command_request(b"advisor-current-revision"),
            runtime=runtime,
            db=db,
        )
        assert accepted["status"] == "queued"
        job = db.query(Job).one()
        assert job.payload["expected_revisions"] == {str(finding_id): 1}


def test_summary_counts_and_exact_file_filter(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    _, scan_id, finding_ids = _seed_scan(runtime, name="summary", count=4)
    with runtime.session_factory() as db:
        suppressed = db.get(Finding, finding_ids[0])
        exempt = db.get(Finding, finding_ids[1])
        assert suppressed is not None and exempt is not None
        suppressed.suppressed = True
        suppressed.lifecycle_status = "ignore"
        suppressed.lifecycle_reason = "fixture reason"
        exempt.gate_exempt = True
        exempt.lifecycle_status = "accepted_risk"
        exempt.lifecycle_reason = "fixture reason"
        db.commit()

    summary = client.get(f"/v1/scans/{scan_id}/summary")
    assert summary.status_code == 200, summary.text
    findings = summary.json()["findings"]
    assert findings["total"] == 4
    assert findings["active"] == 3
    assert findings["suppressed"] == 1
    assert findings["gate_exempt"] == 1
    assert sum(findings["severity_counts"].values()) == 3
    assert sum(findings["scanner_counts"].values()) == 3

    filtered = client.get(
        f"/v1/scans/{scan_id}/findings", params={"file_path": "src/two.py"}
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 2
    assert {item["file_path"] for item in filtered.json()["items"]} == {"src/two.py"}
    assert client.get(
        f"/v1/scans/{scan_id}/findings", params={"file_path": "../src/two.py"}
    ).status_code == 422


def test_finding_diagnostics_are_compact_revisioned_and_query_bounded(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    _, scan_id, finding_ids = _seed_scan(
        runtime,
        name="finding-diagnostics",
        count=405,
        distinct_files=True,
    )
    exact_path = "src/password=canonical-filename-secret.py"
    with runtime.session_factory() as db:
        first = db.get(Finding, finding_ids[0])
        assert first is not None
        first.file_path = exact_path
        first.message = "password=diagnostic-message-secret"
        db.commit()

    statements: list[str] = []

    def capture_query(_connection, _cursor, statement, _parameters, _context, _executemany):
        statements.append(" ".join(str(statement).lower().split()))

    event.listen(runtime.engine, "before_cursor_execute", capture_query)
    try:
        first_response = client.get(
            f"/v1/scans/{scan_id}/finding-diagnostics", params={"limit": 200}
        )
    finally:
        event.remove(runtime.engine, "before_cursor_execute", capture_query)
    assert first_response.status_code == 200, first_response.text
    first_page = first_response.json()
    assert set(first_page) == {
        "scan_id",
        "items",
        "total",
        "truncated",
        "next_cursor",
        "revision",
    }
    assert first_page["scan_id"] == scan_id
    assert first_page["total"] == 405
    assert first_page["revision"] == 1
    assert first_page["truncated"] is True
    assert len(first_page["items"]) == 200
    assert first_page["next_cursor"]
    assert len(statements) == 3
    selected = statements[-1]
    for excluded in (
        "code_snippet",
        "metadata_json",
        "fingerprint",
        "rule_id",
        "ai_verdict",
        "lifecycle_reason",
        "row_number",
    ):
        assert excluded not in selected

    first_item = first_page["items"][0]
    assert set(first_item) == {
        "id",
        "scan_finding_number",
        "display_id",
        "scanner",
        "severity",
        "file_path",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
        "message",
        "revision",
    }
    assert first_item["id"] == finding_ids[0]
    assert first_item["scan_finding_number"] == 1
    assert first_item["display_id"] == f"S{scan_id}-F001"
    assert first_item["file_path"] == exact_path
    assert "diagnostic-message-secret" not in first_item["message"]

    decoded = base64.urlsafe_b64decode(
        first_page["next_cursor"]
        + "=" * (-len(first_page["next_cursor"]) % 4)
    ).decode("ascii")
    assert '"k":"finding_diagnostics"' in decoded
    assert "src/" not in decoded

    pages = [first_page]
    cursor = first_page["next_cursor"]
    while cursor is not None:
        response = client.get(
            f"/v1/scans/{scan_id}/finding-diagnostics",
            params={"limit": 200, "cursor": cursor},
        )
        assert response.status_code == 200, response.text
        page = response.json()
        assert page["scan_id"] == scan_id
        assert page["total"] == 405
        assert page["revision"] == 1
        pages.append(page)
        cursor = page["next_cursor"]
    assert [len(page["items"]) for page in pages] == [200, 200, 5]
    assert pages[-1]["truncated"] is False
    items = [item for page in pages for item in page["items"]]
    assert [item["scan_finding_number"] for item in items] == list(range(1, 406))
    assert len({item["id"] for item in items}) == 405
    assert all(item["display_id"].startswith(f"S{scan_id}-F") for item in items)

    exact_file = client.get(
        f"/v1/scans/{scan_id}/finding-diagnostics",
        params={"file_path": exact_path, "expected_revision": 1},
    )
    assert exact_file.status_code == 200, exact_file.text
    assert exact_file.json()["total"] == 1
    assert exact_file.json()["items"][0]["file_path"] == exact_path
    stale_expected = client.get(
        f"/v1/scans/{scan_id}/finding-diagnostics",
        params={"expected_revision": 2},
    )
    assert stale_expected.status_code == 409
    assert stale_expected.json()["detail"]["code"] == "revision_conflict"

    filtered = client.get(
        f"/v1/scans/{scan_id}/finding-diagnostics",
        params={"limit": 1, "severity": "high"},
    )
    assert filtered.status_code == 200, filtered.text
    assert filtered.json()["next_cursor"]
    mismatched_filter = client.get(
        f"/v1/scans/{scan_id}/finding-diagnostics",
        params={"limit": 1, "cursor": filtered.json()["next_cursor"]},
    )
    assert mismatched_filter.status_code == 400
    assert mismatched_filter.json()["detail"]["code"] == "cursor_invalid"


def test_canonical_credential_shaped_filenames_round_trip_and_invalid_paths_fail_closed(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    _, scan_id, finding_ids = _seed_scan(
        runtime,
        name="finding-path-contract",
        count=1,
    )
    finding_id = finding_ids[0]
    canonical = "src/password=canonical-filename-secret.py"
    with runtime.session_factory() as db:
        finding = db.get(Finding, finding_id)
        assert finding is not None
        finding.file_path = canonical
        finding.message = "password=finding-message-secret"
        db.commit()

    manifest = client.get(f"/v1/scans/{scan_id}/finding-files")
    assert manifest.status_code == 200, manifest.text
    assert manifest.json()["items"][0]["file_path"] == canonical
    listing = client.get(f"/v1/scans/{scan_id}/findings")
    assert listing.status_code == 200, listing.text
    assert listing.json()["items"][0]["file_path"] == canonical
    detail = client.get(
        f"/v1/scans/{scan_id}/findings/1", params=_detail_params()
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["file_path"] == canonical
    packet = client.get(f"/v1/findings/{finding_id}/packet")
    assert packet.status_code == 200, packet.text
    assert packet.json()["location"]["file_path"] == canonical
    diagnostics = client.get(f"/v1/scans/{scan_id}/finding-diagnostics")
    assert diagnostics.status_code == 200, diagnostics.text
    assert diagnostics.json()["items"][0]["file_path"] == canonical
    assert "finding-message-secret" not in diagnostics.json()["items"][0]["message"]
    exact_filter = client.get(
        f"/v1/scans/{scan_id}/findings", params={"file_path": canonical}
    )
    assert exact_filter.status_code == 200, exact_filter.text
    assert exact_filter.json()["total"] == 1

    invalid_paths = (
        "/tmp/password=absolute-secret.py",
        "src/../password=traversal-secret.py",
        "src//password=duplicate-secret.py",
        ".",
        "src\\password=windows-secret.py",
        "C:/password=drive-secret.py",
        "https:password=scheme-secret.py",
        "src/\u202epassword=format-secret.py",
    )
    for invalid_path in invalid_paths:
        with runtime.session_factory() as db:
            finding = db.get(Finding, finding_id)
            assert finding is not None
            finding.file_path = invalid_path
            db.commit()
        listing = client.get(f"/v1/scans/{scan_id}/findings")
        assert listing.status_code == 200, listing.text
        assert listing.json()["items"][0]["file_path"] == "[REDACTED]"
        detail = client.get(
            f"/v1/scans/{scan_id}/findings/1", params=_detail_params()
        )
        assert detail.status_code == 200, detail.text
        assert detail.json()["file_path"] == "[REDACTED]"
        packet = client.get(f"/v1/findings/{finding_id}/packet")
        assert packet.status_code == 200, packet.text
        assert packet.json()["location"]["file_path"] == "[REDACTED]"
        manifest = client.get(f"/v1/scans/{scan_id}/finding-files")
        assert manifest.status_code == 500
        assert manifest.json()["detail"]["code"] == "finding_file_manifest_invalid"
        diagnostics = client.get(f"/v1/scans/{scan_id}/finding-diagnostics")
        assert diagnostics.status_code == 500
        assert diagnostics.json()["detail"]["code"] == "finding_diagnostics_invalid"

    rejected_filter = client.get(
        f"/v1/scans/{scan_id}/findings", params={"file_path": invalid_paths[0]}
    )
    assert rejected_filter.status_code == 422


def test_finding_messages_are_redacted_and_display_safe_across_editor_surfaces(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    _, scan_id, finding_ids = _seed_scan(
        runtime,
        name="finding-message-contract",
        count=1,
    )
    with runtime.session_factory() as db:
        finding = db.get(Finding, finding_ids[0])
        assert finding is not None
        finding.message = "first line\nsecond\tline \u202epassword=diagnostic-secret"
        db.commit()

    responses = (
        client.get(f"/v1/scans/{scan_id}/findings"),
        client.get(
            f"/v1/scans/{scan_id}/findings/1", params=_detail_params()
        ),
        client.get(f"/v1/scans/{scan_id}/finding-diagnostics"),
    )
    messages = (
        responses[0].json()["items"][0]["message"],
        responses[1].json()["message"],
        responses[2].json()["items"][0]["message"],
    )
    assert all(response.status_code == 200 for response in responses)
    assert all("diagnostic-secret" not in message for message in messages)
    assert all(
        all(unicodedata.category(character) not in {"Cc", "Cf"} for character in message)
        for message in messages
    )


def test_finding_file_manifest_is_revisioned_path_opaque_and_query_bounded(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    project_id, scan_id, finding_ids = _seed_scan(
        runtime,
        name="file-manifest",
        count=405,
        distinct_files=True,
    )
    exact_path = "src/manifest/a file/ümlaut.py"
    with runtime.session_factory() as db:
        ignored = db.get(Finding, finding_ids[0])
        accepted = db.get(Finding, finding_ids[1])
        review = db.get(Finding, finding_ids[2])
        assert ignored is not None and accepted is not None and review is not None
        ignored.file_path = exact_path
        ignored.suppressed = True
        ignored.lifecycle_status = "ignore"
        ignored.lifecycle_reason = "fixture reason"
        accepted.lifecycle_status = "accepted_risk"
        accepted.gate_exempt = True
        accepted.lifecycle_reason = "fixture reason"
        review.lifecycle_status = "needs_review"
        db.commit()

    statements: list[str] = []

    def capture_query(_connection, _cursor, statement, _parameters, _context, _executemany):
        statements.append(" ".join(str(statement).lower().split()))

    event.listen(runtime.engine, "before_cursor_execute", capture_query)
    try:
        first_response = client.get(
            f"/v1/scans/{scan_id}/finding-files", params={"limit": 200}
        )
    finally:
        event.remove(runtime.engine, "before_cursor_execute", capture_query)
    assert first_response.status_code == 200, first_response.text
    first = first_response.json()
    assert first["scan"] == {
        "id": scan_id,
        "project_id": project_id,
        "status": "completed",
        "gate_decision": "pass",
        "gate_reasons": [],
        "error": None,
        "revision": 1,
        "findings_revision": 1,
    }
    assert first["total_findings"] == 405
    assert first["total_files"] == 405
    assert first["truncated"] is True
    assert len(first["items"]) == 200
    assert first["next_cursor"]
    assert len(statements) == 4
    assert all("findings.message" not in statement for statement in statements)
    assert all("findings.code_snippet" not in statement for statement in statements)

    decoded = base64.urlsafe_b64decode(
        first["next_cursor"] + "=" * (-len(first["next_cursor"]) % 4)
    ).decode("ascii")
    assert "src/" not in decoded
    assert '"k":"finding_files"' in decoded

    pages = [first]
    cursor = first["next_cursor"]
    while cursor is not None:
        response = client.get(
            f"/v1/scans/{scan_id}/finding-files",
            params={"limit": 200, "cursor": cursor},
        )
        assert response.status_code == 200, response.text
        page = response.json()
        assert page["scan"]["findings_revision"] == 1
        assert page["total_findings"] == 405
        assert page["total_files"] == 405
        pages.append(page)
        cursor = page["next_cursor"]
    assert [len(page["items"]) for page in pages] == [200, 200, 5]
    assert pages[-1]["truncated"] is False

    items = [item for page in pages for item in page["items"]]
    assert len({item["file_path"] for item in items}) == 405
    assert len({item["first_scan_finding_number"] for item in items}) == 405
    assert {item["first_scan_finding_number"] for item in items} == set(range(1, 406))
    assert all(item["active"] + item["suppressed"] == item["total"] for item in items)
    assert all(item["blocking"] + item["gate_exempt"] == item["active"] for item in items)
    assert all(sum(item["severity_counts"].values()) == item["total"] for item in items)
    assert all(sum(item["lifecycle_counts"].values()) == item["total"] for item in items)

    by_path = {item["file_path"]: item for item in items}
    assert by_path[exact_path] == {
        "file_path": exact_path,
        "first_scan_finding_number": 1,
        "total": 1,
        "active": 0,
        "suppressed": 1,
        "gate_exempt": 0,
        "blocking": 0,
        "severity_counts": {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        "lifecycle_counts": {
            "open": 0,
            "needs_review": 0,
            "gate_exempt": 0,
            "accepted_risk": 0,
            "ignore": 1,
            "false_positive": 0,
            "fixed": 0,
        },
    }
    exact_file = client.get(
        f"/v1/scans/{scan_id}/findings",
        params={"file_path": exact_path, "expected_revision": 1},
    )
    assert exact_file.status_code == 200, exact_file.text
    assert exact_file.json()["total"] == 1
    assert exact_file.json()["items"][0]["file_path"] == exact_path


def test_finding_file_manifest_aggregates_duplicate_paths_and_fails_closed_on_bad_counts(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    _, scan_id, finding_ids = _seed_scan(runtime, name="file-aggregate", count=4)

    manifest = client.get(f"/v1/scans/{scan_id}/finding-files")
    assert manifest.status_code == 200, manifest.text
    body = manifest.json()
    assert body["total_findings"] == 4
    assert body["total_files"] == 2
    assert [(item["file_path"], item["total"]) for item in body["items"]] == [
        ("src/one.py", 2),
        ("src/two.py", 2),
    ]

    with runtime.session_factory() as db:
        invalid = db.get(Finding, finding_ids[0])
        assert invalid is not None
        invalid.severity = "unexpected"
        db.commit()
    rejected = client.get(f"/v1/scans/{scan_id}/finding-files")
    assert rejected.status_code == 500
    assert rejected.json()["detail"] == {
        "code": "finding_file_manifest_invalid",
        "message": "persisted finding file aggregates are inconsistent",
    }


def test_finding_file_manifest_does_not_repeat_paths_across_cursor_pages(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    _, scan_id, finding_ids = _seed_scan(
        runtime,
        name="file-page-deduplication",
        count=405,
        distinct_files=True,
    )
    with runtime.session_factory() as db:
        repeated = list(
            db.scalars(
                select(Finding)
                .where(Finding.id.in_(finding_ids[205:]))
                .order_by(Finding.scan_finding_number)
            )
        )
        assert len(repeated) == 200
        for index, finding in enumerate(repeated, start=1):
            finding.file_path = f"src/manifest/file-{index:05d}.py"
        db.commit()

    first = client.get(
        f"/v1/scans/{scan_id}/finding-files", params={"limit": 200}
    )
    assert first.status_code == 200, first.text
    first_page = first.json()
    assert first_page["total_findings"] == 405
    assert first_page["total_files"] == 205
    assert len(first_page["items"]) == 200
    assert first_page["truncated"] is True
    second = client.get(
        f"/v1/scans/{scan_id}/finding-files",
        params={"limit": 200, "cursor": first_page["next_cursor"]},
    )
    assert second.status_code == 200, second.text
    second_page = second.json()
    assert len(second_page["items"]) == 5
    assert second_page["truncated"] is False
    assert second_page["next_cursor"] is None
    items = [*first_page["items"], *second_page["items"]]
    assert len({item["file_path"] for item in items}) == 205
    assert sum(item["total"] for item in items) == 405
    assert first_page["items"][0]["total"] == 2


def test_finding_file_manifest_represents_an_empty_scan_exactly(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    with runtime.session_factory() as db:
        project = Project(
            name="empty-manifest",
            repo_path="/workspaces/empty-manifest",
            default_branch="main",
        )
        db.add(project)
        db.flush()
        scan = Scan(
            project_id=project.id,
            mode="full",
            status="completed",
            gate_decision="pass",
            gate_reasons=[],
            scanner_summary={},
        )
        db.add(scan)
        db.commit()
        project_id = project.id
        scan_id = scan.id

    manifest = client.get(f"/v1/scans/{scan_id}/finding-files")
    assert manifest.status_code == 200, manifest.text
    assert manifest.json() == {
        "scan": {
            "id": scan_id,
            "project_id": project_id,
            "status": "completed",
            "gate_decision": "pass",
            "gate_reasons": [],
            "error": None,
            "revision": 1,
            "findings_revision": 1,
        },
        "total_findings": 0,
        "total_files": 0,
        "items": [],
        "truncated": False,
        "next_cursor": None,
    }
    diagnostics = client.get(f"/v1/scans/{scan_id}/finding-diagnostics")
    assert diagnostics.status_code == 200, diagnostics.text
    assert diagnostics.json() == {
        "scan_id": scan_id,
        "items": [],
        "total": 0,
        "truncated": False,
        "next_cursor": None,
        "revision": 1,
    }


def test_finding_cursors_are_resource_bound_strict_and_integer_bounded(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    _, scan_id, _ = _seed_scan(
        runtime,
        name="cursor-resource",
        count=3,
        distinct_files=True,
    )
    finding_cursor = client.get(
        f"/v1/scans/{scan_id}/findings", params={"limit": 1}
    ).json()["next_cursor"]
    file_cursor = client.get(
        f"/v1/scans/{scan_id}/finding-files", params={"limit": 1}
    ).json()["next_cursor"]
    diagnostic_cursor = client.get(
        f"/v1/scans/{scan_id}/finding-diagnostics", params={"limit": 1}
    ).json()["next_cursor"]
    assert finding_cursor and file_cursor and diagnostic_cursor
    resources = (
        (f"/v1/scans/{scan_id}/findings", finding_cursor),
        (f"/v1/scans/{scan_id}/finding-files", file_cursor),
        (f"/v1/scans/{scan_id}/finding-diagnostics", diagnostic_cursor),
    )
    for source_index, (_, source_cursor) in enumerate(resources):
        for target_index, (target, _) in enumerate(resources):
            if source_index == target_index:
                continue
            response = client.get(target, params={"cursor": source_cursor})
            assert response.status_code == 400
            assert response.json()["detail"]["code"] == "cursor_invalid"

    _, other_scan_id, _ = _seed_scan(
        runtime,
        name="cursor-resource-other",
        count=1,
        distinct_files=True,
    )
    other_resources = (
        f"/v1/scans/{other_scan_id}/findings",
        f"/v1/scans/{other_scan_id}/finding-files",
        f"/v1/scans/{other_scan_id}/finding-diagnostics",
    )
    for target, (_, source_cursor) in zip(other_resources, resources, strict=True):
        response = client.get(target, params={"cursor": source_cursor})
        assert response.status_code == 400

    def decode_cursor(value: str) -> dict[str, object]:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        return json.loads(raw.decode("ascii"))

    def encode_cursor(document: dict[str, object]) -> str:
        raw = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("ascii")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    for target, (_, source_cursor) in zip(
        (resource[0] for resource in resources), resources, strict=True
    ):
        document_text = base64.urlsafe_b64decode(
            source_cursor + "=" * (-len(source_cursor) % 4)
        ).decode("ascii")
        duplicate_document = document_text.replace(
            f'"s":{scan_id}', f'"s":{scan_id},"s":{scan_id}', 1
        ).encode("ascii")
        duplicate_cursor = base64.urlsafe_b64encode(duplicate_document).rstrip(b"=").decode("ascii")
        duplicate = client.get(target, params={"cursor": duplicate_cursor})
        assert duplicate.status_code == 400
        assert duplicate.json()["detail"]["code"] == "cursor_invalid"

        valid_document = decode_cursor(source_cursor)
        boundary_document = {**valid_document, "a": 50_000}
        boundary = client.get(
            target, params={"cursor": encode_cursor(boundary_document)}
        )
        assert boundary.status_code == 200, boundary.text
        for key, value in (
            ("a", 50_001),
            ("s", 2_147_483_648),
            ("r", 2_147_483_648),
            ("a", True),
            ("a", float("nan")),
            ("a", 10**100),
        ):
            invalid_document = {**valid_document, key: value}
            rejected = client.get(
                target, params={"cursor": encode_cursor(invalid_document)}
            )
            assert rejected.status_code == 400, (key, value, rejected.text)
            assert rejected.json()["detail"]["code"] == "cursor_invalid"


def test_lifecycle_and_delete_revisions_reject_stale_mutations_atomically(
    finding_api: tuple[TestClient, Runtime],
) -> None:
    client, runtime = finding_api
    _, scan_id, finding_ids = _seed_scan(runtime, name="revisions", count=2)
    first_id, second_id = finding_ids

    missing_reason = client.patch(
        f"/v1/findings/{first_id}/lifecycle",
        json={"action": "accepted_risk", "expected_revision": 1},
    )
    assert missing_reason.status_code == 422
    changed = client.patch(
        f"/v1/findings/{first_id}/lifecycle",
        json={
            "action": "accepted_risk",
            "reason": "reviewed and documented",
            "expected_revision": 1,
        },
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["revision"] == 2
    assert changed.json()["gate_exempt"] is True
    assert changed.json()["gate_effect"] == "non_blocking"
    stale_single = client.patch(
        f"/v1/findings/{first_id}/lifecycle",
        json={"action": "open", "expected_revision": 1},
    )
    assert stale_single.status_code == 409
    assert stale_single.json()["detail"]["revision"] == 2
    stale_delete = client.delete(
        f"/v1/findings/{first_id}", params={"expected_revision": 1}
    )
    assert stale_delete.status_code == 409

    missing_map = client.post(
        "/v1/findings/bulk",
        json={"action": "needs_review", "finding_ids": [first_id, second_id]},
    )
    assert missing_map.status_code == 422
    stale_bulk = client.post(
        "/v1/findings/bulk",
        json={
            "action": "needs_review",
            "finding_ids": [first_id, second_id],
            "expected_revisions": {str(first_id): 1, str(second_id): 1},
        },
    )
    assert stale_bulk.status_code == 409
    assert stale_bulk.json()["detail"]["revisions"] == {str(first_id): 2}
    unchanged = client.get(f"/v1/findings/{second_id}")
    assert unchanged.status_code == 200
    assert unchanged.json()["revision"] == 1
    assert unchanged.json()["lifecycle_status"] == "open"

    updated = client.post(
        "/v1/findings/bulk",
        json={
            "action": "needs_review",
            "finding_ids": [first_id, second_id],
            "expected_revisions": {str(first_id): 2, str(second_id): 1},
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["updated"] == 2
    page = client.get(f"/v1/scans/{scan_id}/findings").json()
    assert page["revision"] == 3
    assert {item["revision"] for item in page["items"]} == {2, 3}
    assert {item["lifecycle_status"] for item in page["items"]} == {"needs_review"}


def _make_scan_evidence_incomplete(
    runtime: Runtime,
    scan_id: int,
    *,
    status: str = "partial",
) -> None:
    with runtime.session_factory() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        scan.status = status
        scan.gate_decision = "incomplete"
        scan.gate_reasons = [INCOMPLETE_GATE_REASON]
        db.add(
            GatePolicy(
                project_id=scan.project_id,
                active=True,
                max_critical=0,
                max_high=0,
                block_secrets=False,
            )
        )
        db.commit()


@pytest.mark.parametrize(
    ("action", "bulk"),
    [("ignore", False), ("false_positive", True), ("fixed", False)],
)
def test_suppressive_lifecycle_preserves_partial_gate_and_evidence_total(
    finding_api: tuple[TestClient, Runtime],
    action: str,
    bulk: bool,
) -> None:
    client, runtime = finding_api
    _, scan_id, finding_ids = _seed_scan(
        runtime,
        name=f"partial-{action}",
        count=1,
    )
    _make_scan_evidence_incomplete(runtime, scan_id)
    finding_id = finding_ids[0]
    if bulk:
        changed = client.post(
            "/v1/findings/bulk",
            json={
                "action": action,
                "reason": "reviewed incomplete evidence",
                "finding_ids": [finding_id],
                "expected_revisions": {str(finding_id): 1},
            },
        )
    else:
        changed = client.patch(
            f"/v1/findings/{finding_id}/lifecycle",
            json={
                "action": action,
                "reason": "reviewed incomplete evidence",
                "expected_revision": 1,
            },
        )
    assert changed.status_code == 200, changed.text

    scan = client.get(f"/v1/scans/{scan_id}").json()
    assert scan["status"] == "partial"
    assert scan["gate_decision"] == "incomplete"
    assert scan["gate_reasons"] == [INCOMPLETE_GATE_REASON]
    assert scan["scanner_summary"] == {
        "findings_total": 1,
        "severity_counts": {},
        "scanner_counts": {},
        "ignored_count": 1,
        "gate_exempt_count": 0,
    }
    summary = client.get(f"/v1/scans/{scan_id}/summary").json()
    assert summary["findings"]["total"] == 1
    assert summary["findings"]["active"] == 0
    assert summary["findings"]["suppressed"] == 1


@pytest.mark.parametrize("status", ["failed", "cancelled"])
def test_suppression_cannot_make_failed_or_cancelled_evidence_pass(
    finding_api: tuple[TestClient, Runtime],
    status: str,
) -> None:
    client, runtime = finding_api
    _, scan_id, finding_ids = _seed_scan(
        runtime,
        name=f"non-authoritative-{status}",
        count=1,
    )
    _make_scan_evidence_incomplete(runtime, scan_id, status=status)
    changed = client.patch(
        f"/v1/findings/{finding_ids[0]}/lifecycle",
        json={
            "action": "ignore",
            "reason": "reviewed incomplete evidence",
            "expected_revision": 1,
        },
    )
    assert changed.status_code == 200, changed.text
    scan = client.get(f"/v1/scans/{scan_id}").json()
    assert scan["status"] == status
    assert scan["gate_decision"] == "incomplete"
    assert scan["gate_reasons"] == [INCOMPLETE_GATE_REASON]


@pytest.mark.parametrize("bulk", [False, True])
def test_finding_delete_cannot_make_partial_evidence_pass(
    finding_api: tuple[TestClient, Runtime],
    bulk: bool,
) -> None:
    client, runtime = finding_api
    _, scan_id, finding_ids = _seed_scan(
        runtime,
        name=f"partial-delete-{'bulk' if bulk else 'single'}",
        count=1,
    )
    _make_scan_evidence_incomplete(runtime, scan_id)
    if bulk:
        deleted = client.post(
            "/v1/findings/bulk",
            json={
                "action": "delete",
                "finding_ids": finding_ids,
                "expected_revisions": {str(finding_ids[0]): 1},
            },
        )
    else:
        deleted = client.delete(
            f"/v1/findings/{finding_ids[0]}", params={"expected_revision": 1}
        )
    assert deleted.status_code == 200, deleted.text
    scan = client.get(f"/v1/scans/{scan_id}").json()
    assert scan["status"] == "partial"
    assert scan["gate_decision"] == "incomplete"
    assert scan["gate_reasons"] == [INCOMPLETE_GATE_REASON]
    assert scan["scanner_summary"]["findings_total"] == 0


@pytest.mark.parametrize(
    "surface", ["summary", "findings", "finding-files", "finding-diagnostics"]
)
def test_postgresql_read_resource_cannot_mix_lifecycle_revisions(
    postgres_finding_api: tuple[TestClient, Runtime],
    surface: str,
) -> None:
    client, runtime = postgres_finding_api
    _, scan_id, finding_ids = _seed_scan(
        runtime,
        name=f"revision-fence-{surface}",
        count=1,
    )
    reader_at_first_count = threading.Event()
    reader_holds_scan_lock = threading.Event()
    writer_attempted_scan_lock = threading.Event()
    release_reader = threading.Event()

    def coordinate_queries(_connection, _cursor, statement, _parameters, _context, _executemany):
        normalized = " ".join(str(statement).lower().split())
        if " from scans " in f" {normalized} " and " for share" in normalized:
            reader_holds_scan_lock.set()
        if (
            reader_holds_scan_lock.is_set()
            and "count(" in normalized
            and " from findings " in f" {normalized} "
            and not reader_at_first_count.is_set()
        ):
            reader_at_first_count.set()
            assert release_reader.wait(10), "reader coordination timed out"
        if (
            reader_at_first_count.is_set()
            and " from scans " in f" {normalized} "
            and " for update" in normalized
        ):
            writer_attempted_scan_lock.set()

    event.listen(runtime.engine, "before_cursor_execute", coordinate_queries)
    try:
        path = {
            "summary": f"/v1/scans/{scan_id}/summary",
            "findings": f"/v1/scans/{scan_id}/findings?limit=10",
            "finding-files": f"/v1/scans/{scan_id}/finding-files?limit=10",
            "finding-diagnostics": f"/v1/scans/{scan_id}/finding-diagnostics?limit=10",
        }[surface]
        with (
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="resource-reader") as reader,
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="lifecycle-writer") as writer,
        ):
            read_future = reader.submit(client.get, path)
            assert reader_at_first_count.wait(10), "resource reader did not reach its count query"
            write_future = writer.submit(
                client.patch,
                f"/v1/findings/{finding_ids[0]}/lifecycle",
                json={
                    "action": "accepted_risk",
                    "reason": "concurrent revision fence receipt",
                    "expected_revision": 1,
                },
            )
            assert writer_attempted_scan_lock.wait(10), "writer did not attempt the scan revision lock"
            assert not write_future.done(), "writer crossed the reader's shared scan lock"
            release_reader.set()
            before = read_future.result(timeout=10)
            changed = write_future.result(timeout=10)
    finally:
        release_reader.set()
        event.remove(runtime.engine, "before_cursor_execute", coordinate_queries)

    assert before.status_code == 200, before.text
    assert changed.status_code == 200, changed.text
    if surface == "summary":
        assert before.json()["revision"] == 1
        assert before.json()["findings_revision"] == 1
        assert before.json()["scan"]["gate_decision"] == "pass"
        assert before.json()["findings"]["gate_exempt"] == 0
        after = client.get(f"/v1/scans/{scan_id}/summary")
        assert after.status_code == 200, after.text
        assert after.json()["revision"] == 2
        assert after.json()["findings_revision"] == 2
        assert after.json()["scan"]["gate_decision"] == "not_configured"
        assert after.json()["findings"]["gate_exempt"] == 1
    elif surface == "findings":
        assert before.json()["revision"] == 1
        assert before.json()["items"][0]["revision"] == 1
        assert before.json()["items"][0]["lifecycle_status"] == "open"
        assert before.json()["items"][0]["gate_effect"] == "blocking"
        after = client.get(f"/v1/scans/{scan_id}/findings?limit=10")
        assert after.status_code == 200, after.text
        assert after.json()["revision"] == 2
        assert after.json()["items"][0]["revision"] == 2
        assert after.json()["items"][0]["lifecycle_status"] == "accepted_risk"
        assert after.json()["items"][0]["gate_effect"] == "non_blocking"
    elif surface == "finding-files":
        assert before.json()["scan"]["revision"] == 1
        assert before.json()["scan"]["findings_revision"] == 1
        assert before.json()["scan"]["gate_decision"] == "pass"
        assert before.json()["items"][0]["active"] == 1
        assert before.json()["items"][0]["gate_exempt"] == 0
        assert before.json()["items"][0]["blocking"] == 1
        after = client.get(f"/v1/scans/{scan_id}/finding-files?limit=10")
        assert after.status_code == 200, after.text
        assert after.json()["scan"]["revision"] == 2
        assert after.json()["scan"]["findings_revision"] == 2
        assert after.json()["scan"]["gate_decision"] == "not_configured"
        assert after.json()["items"][0]["active"] == 1
        assert after.json()["items"][0]["gate_exempt"] == 1
        assert after.json()["items"][0]["blocking"] == 0
    else:
        assert before.json()["scan_id"] == scan_id
        assert before.json()["revision"] == 1
        assert before.json()["items"][0]["revision"] == 1
        assert before.json()["items"][0]["display_id"] == f"S{scan_id}-F001"
        after = client.get(f"/v1/scans/{scan_id}/finding-diagnostics?limit=10")
        assert after.status_code == 200, after.text
        assert after.json()["scan_id"] == scan_id
        assert after.json()["revision"] == 2
        assert after.json()["items"][0]["revision"] == 2
        assert after.json()["items"][0]["display_id"] == f"S{scan_id}-F001"


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            {"start_line": 5, "start_column": 9},
            {"start_line": 5, "start_column": 9, "end_line": 5, "end_column": None},
        ),
        (
            {"start_line": 5, "end_column": 12},
            {"start_line": 5, "start_column": None, "end_line": 5, "end_column": None},
        ),
        (
            {"start_line": 5, "start_column": 9, "end_column": 8},
            {"start_line": 5, "start_column": None, "end_line": 5, "end_column": None},
        ),
        (
            {"start_line": 5, "start_column": 9, "end_column": 9},
            {"start_line": 5, "start_column": 9, "end_line": 5, "end_column": 9},
        ),
        (
            {"start_line": 5, "start_column": 9, "end_line": 7},
            {"start_line": 5, "start_column": 9, "end_line": 7, "end_column": None},
        ),
    ],
)
def test_worker_location_normalization_preserves_only_safe_ranges(
    payload: dict[str, int], expected: dict[str, int | None]
) -> None:
    assert _normalized_finding_location(payload) == expected


@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "/src/app.py",
        "../src/app.py",
        "src/../app.py",
        "src//app.py",
        "src/app.py/",
        "src\\app.py",
        "src\napp.py",
        "src/\u202eapp.py",
        "C:/src/app.py",
        "https:src/app.py",
    ],
)
def test_worker_rejects_noncanonical_finding_paths(path: str) -> None:
    assert _normalized_finding_path(path) is None


def test_worker_accepts_canonical_project_relative_finding_path() -> None:
    assert _normalized_finding_path("src/security/app.py") == "src/security/app.py"
    credential_path = "src/password=canonical-filename-secret.py"
    assert _normalized_finding_path(credential_path) == credential_path
    assert _normalized_finding_path("😀" * 1_024) == "😀" * 1_024
    assert _normalized_finding_path("😀" * 1_025) is None
