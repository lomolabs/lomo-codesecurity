from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from kodesec_api.db import Base, Runtime
from kodesec_api.advisor import providers
from kodesec_api.jobs.advisor import _ollama_payload, triage_finding_sync
from kodesec_api.jobs.repository import _redact_job_document
from kodesec_api.main import (
    _finding_packet,
    _finding_to_out,
    _job_to_out,
    _RedactionMemo,
    _redacted_json,
    _redacted_json_object,
    _scan_to_out,
    _scan_history_summary,
    get_project,
    list_projects,
    scanner_lifecycle,
)
from kodesec_api.models import (
    Finding,
    Job,
    Project,
    Scan,
    ScannerLifecycleState,
    ScannerToolState,
)
from kodesec_api.redaction import REDACTED
from kodesec_api.settings import Settings


RAW_FIXTURE = "fixture-credential-not-valid"
RAW_ASSIGNMENT = f"password={RAW_FIXTURE}"
SAFE_FINGERPRINT = "a" * 64
SAFE_PATH = "/workspace/generated/" + ("b" * 40) + "/handler.py"
INCREMENTAL_FALLBACK_WARNING = "incremental-diff-fallback-full"


def test_persisted_json_uses_cleaned_key_context_and_retains_collision_order() -> None:
    document = {
        "pass\x00word": {"message": "fixture-only"},
        "sha\x00256": SAFE_FINGERPRINT,
        "message": "first",
        "mes\x00sage": RAW_ASSIGNMENT,
        None: ["safe", {"to\x00ken": "fixture-only"}],
    }
    expected = {
        "password": REDACTED,
        "sha256": SAFE_FINGERPRINT,
        "message": f"password={REDACTED}",
        "": ["safe", {"token": REDACTED}],
    }
    assert _redacted_json(document) == expected
    assert _redacted_json_object(document) == expected


def test_scan_history_projection_preserves_cleaned_key_context_and_malformed_evidence() -> None:
    raw = {"tools": [], "to\x00ols": [
        {"error": "safe", "err\x00or": RAW_ASSIGNMENT, "status": "partial", "id": "bearer"},
        RAW_ASSIGNMENT, None,
    ], "scope": {"token": "fixture"}, "advisor": RAW_ASSIGNMENT}
    # Selecting before key normalization would erase the later failure record.
    assert _redacted_json_object(_scan_history_summary(raw)) == _redacted_json_object(raw)
    for malformed in [None, [RAW_ASSIGNMENT], RAW_ASSIGNMENT, 12]:
        assert _redacted_json_object(_scan_history_summary(malformed)) == _redacted_json_object(malformed)


def test_request_redaction_memo_preserves_key_context_depth_and_changed_rows() -> None:
    memo = _RedactionMemo()
    values = [SAFE_FINGERPRINT, RAW_ASSIGNMENT, "Bearer fixture-value", SAFE_PATH,
              "https://user:fixture@example.invalid/?token=fixture", "completed", "", "line\tα\n"]
    keys = ["sha256", "runtime_identity", "token", "id", "message", "nested", "Raw", "model-digest"]
    for value in values:
        for key in keys:
            document = {key: value, "rows": [{key: value}, {"password": value}]}
            assert _redacted_json_object(document, memo=memo) == _redacted_json(document)
    nested = {"message": RAW_ASSIGNMENT}
    for _ in range(66):
        nested = {"child": [nested]}
    assert _redacted_json_object(nested, memo=memo) == _redacted_json(nested)
    original = {"tools": [{"status": "completed"}]}
    first = _redacted_json_object(original, memo=memo)
    original["tools"][0]["status"] = RAW_ASSIGNMENT
    assert first == {"tools": [{"status": "completed"}]}
    assert _redacted_json_object(original, memo=memo) == {"tools": [{"status": "password=[REDACTED]"}]}


def test_request_redaction_memo_bounds_retention_without_skipping_uncached_redaction() -> None:
    memo = _RedactionMemo()
    for index in range(600):
        document = {f"field_{index}": f"password=fixture-{index}"}
        assert _redacted_json_object(document, memo=memo) == _redacted_json(document)
    assert len(memo.keys) <= 512
    assert len(memo.strings) <= 512
    for document in [{"x" * 257: RAW_ASSIGNMENT}, {"message": "prefix " * 100 + RAW_ASSIGNMENT}]:
        assert _redacted_json_object(document, memo=memo) == _redacted_json(document)
    assert all(len(key) <= 256 for key in memo.keys)
    assert all(len(key) <= 256 and len(value) <= 256 for key, value in memo.strings)
    assert _RedactionMemo().keys == {} and _RedactionMemo().strings == {}


def test_request_redaction_memo_reuses_only_identical_scalar_context() -> None:
    from kodesec_api import main
    memo = _RedactionMemo()
    with patch.object(main, "_redacted_json_text", wraps=main._redacted_json_text) as redact:
        for _ in range(100):
            assert _redacted_json_object({"id": SAFE_FINGERPRINT, "message": SAFE_FINGERPRINT}, memo=memo) == {
                "id": SAFE_FINGERPRINT, "message": REDACTED,
            }
        assert redact.call_count == 2


def _runtime() -> Runtime:
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
        SCANNER_URL="http://scanner:8091",
        KODESEC_ALLOWED_ROOTS="/workspace",
    )
    return Runtime.create(settings, engine=engine)


def _local_advisor_fixture() -> tuple[dict[str, object], dict[str, object]]:
    profile = providers.normalize_profile(
        {
            "id": "local-fixture",
            "name": "Local fixture",
            "transport": "local",
            "priority": 0,
            "enabled": True,
            "model": "fixture-model",
            "model_digest": "a" * 64,
        }
    )
    return profile, {
        "ai_mode": "on",
        "ollama_thinking": False,
        "advisor_providers": {
            "revision": 1,
            "active_provider_id": None,
            "providers": [profile],
        },
    }


def test_scanner_mode_fallback_receipt_survives_persisted_redaction() -> None:
    summary = _redacted_json_object(
        {
            "requested_mode": "incremental_diff",
            "effective_mode": "full",
            "warnings": [INCREMENTAL_FALLBACK_WARNING],
        }
    )

    assert summary == {
        "requested_mode": "incremental_diff",
        "effective_mode": "full",
        "warnings": [INCREMENTAL_FALLBACK_WARNING],
    }


def test_typed_scanner_checkpoint_digests_survive_without_widening_redaction() -> None:
    checkpoint = {
        "scanner_evidence": {
            "request_digest": "a" * 64,
            "preflight_revision": "F" * 64,
            "sha256": "b" * 64,
            "manifest_sha256": "C" * 64,
            "invalid_manifest_sha256": RAW_ASSIGNMENT,
        },
        "artifact_manifest": {"sha256": "c" * 64},
        "artifact_provenance": {"sha256": "d" * 64},
        "untyped_digest": "e" * 64,
        "token": "f" * 64,
    }

    redacted = _redacted_json_object(checkpoint)

    assert redacted["scanner_evidence"] == {
        "request_digest": "a" * 64,
        "preflight_revision": "f" * 64,
        "sha256": "b" * 64,
        "manifest_sha256": "c" * 64,
        "invalid_manifest_sha256": "password=[REDACTED]",
    }
    assert redacted["artifact_manifest"] == checkpoint["artifact_manifest"]
    assert redacted["artifact_provenance"] == checkpoint["artifact_provenance"]
    assert redacted["untyped_digest"] == REDACTED
    assert redacted["token"] == REDACTED


def test_typed_scanner_runtime_identity_survives_without_widening_redaction() -> None:
    summary = {
        "tools": [{"id": "fixture-tool", "runtime_identity": "D" * 64}],
        "nested": {"runtime_identity": RAW_ASSIGNMENT},
        "untyped_identity": "e" * 64,
        "runtime_identity_token": "f" * 64,
    }
    persisted = _redacted_json_object(summary)
    assert persisted == {
        "tools": [{"id": "fixture-tool", "runtime_identity": "d" * 64}],
        "nested": {"runtime_identity": "password=[REDACTED]"},
        "untyped_identity": REDACTED,
        "runtime_identity_token": REDACTED,
    }
    assert _redacted_json_object(persisted) == persisted
    for invalid in ("a" * 63, "a" * 65, "z" * 64, f"Bearer {RAW_FIXTURE}"):
        assert _redacted_json_object({"runtime_identity": invalid})["runtime_identity"] != invalid


@pytest.mark.parametrize("redact_document", [_redacted_json_object, _redact_job_document])
def test_typed_catalog_selection_survives_redaction_without_widening_it(redact_document) -> None:
    assert redact_document({
        "catalog_digest": "A" * 64,
        "nested": {"catalog_digest": RAW_ASSIGNMENT},
        "untyped_digest": "b" * 64,
        "token": "c" * 64,
    }) == {
        "catalog_digest": "a" * 64,
        "nested": {"catalog_digest": "password=[REDACTED]"},
        "untyped_digest": REDACTED,
        "token": REDACTED,
    }


def test_typed_native_snapshot_digest_survives_job_redaction_without_widening_it() -> None:
    redacted = _redact_job_document(
        {
            "source_snapshot_digest": "b" * 64,
            "untyped_digest": "c" * 64,
            "token": "d" * 64,
        }
    )

    assert redacted == {
        "source_snapshot_digest": "b" * 64,
        "untyped_digest": REDACTED,
        "token": REDACTED,
    }


def _seed_untrusted_persisted_rows(runtime: Runtime) -> tuple[int, int, int]:
    with runtime.session_factory() as db:
        project = Project(
            name="fixture-project",
            repo_path="/workspace/generated",
            remote_url=f"https://fixture:{RAW_FIXTURE}@example.invalid/repo.git",
            default_branch="main",
        )
        db.add(project)
        db.flush()
        scan = Scan(
            project_id=project.id,
            mode="full",
            status="failed",
            gate_reasons=[f"gate command failed: {RAW_ASSIGNMENT}"],
            scanner_summary={
                "fingerprint": SAFE_FINGERPRINT,
                "tools": [{"id": "fixture-tool", "error": RAW_ASSIGNMENT}],
                "external_runs": [{"id": "fixture-tool", "stderr": f"Bearer {RAW_FIXTURE}"}],
                "errors": [RAW_ASSIGNMENT],
            },
            error=f"scanner transport rejected {RAW_ASSIGNMENT}",
        )
        db.add(scan)
        db.flush()
        finding = Finding(
            scan_id=scan.id,
            scan_finding_number=1,
            scanner="fixture-tool",
            rule_id="fixture-rule",
            severity="high",
            file_path=SAFE_PATH,
            start_line=7,
            end_line=8,
            message=f"detector reported {RAW_ASSIGNMENT}",
            code_snippet=f"client = connect({RAW_ASSIGNMENT!r})",
            fingerprint=SAFE_FINGERPRINT,
            metadata_json={
                "authorization": f"Bearer {RAW_FIXTURE}",
                "path": SAFE_PATH,
                "lifecycle": {"status": "open", "gate_exempt_reason": RAW_ASSIGNMENT},
            },
            ai_verdict="needs_review",
            ai_reasoning=f"model copied Authorization: Bearer {RAW_FIXTURE}",
            ai_fix=f"replace {RAW_ASSIGNMENT}",
            suppression_reason=f"operator note {RAW_ASSIGNMENT}",
        )
        db.add(finding)
        db.flush()
        job = Job(
            kind="scan",
            title=f"Fixture scan {RAW_ASSIGNMENT}",
            status="failed",
            stage=f"scanner {RAW_ASSIGNMENT}",
            detail=f"tool stderr: Bearer {RAW_FIXTURE}",
            error=f"worker failed with {RAW_ASSIGNMENT}",
            error_detail=f"worker detail {RAW_ASSIGNMENT}",
            payload={
                "v": 1,
                "request_digest": SAFE_FINGERPRINT,
                "model": RAW_ASSIGNMENT,
            },
            checkpoint={"sha256": SAFE_FINGERPRINT, "output": RAW_ASSIGNMENT},
            idempotency_key="plaintext-fixture-command-key",
            client_id="browser:fixture",
            result_ref=f"scan:{RAW_ASSIGNMENT}",
            scan_id=scan.id,
            finding_id=finding.id,
            progress=40,
        )
        db.add(job)
        db.add(
            ScannerToolState(
                id="fixture-tool-state",
                enabled=True,
                current_version="1.0",
                latest_version="1.0",
                status="check_failed",
                last_error=f"registry failed with {RAW_ASSIGNMENT}",
            )
        )
        db.commit()
        return scan.id, finding.id, job.id


def test_api_serializers_defensively_redact_persisted_rows() -> None:
    runtime = _runtime()
    scan_id, finding_id, job_id = _seed_untrusted_persisted_rows(runtime)
    with runtime.session_factory() as db:
        scan = db.get(Scan, scan_id)
        finding = db.get(Finding, finding_id)
        job = db.get(Job, job_id)
        project = db.get(Project, scan.project_id) if scan else None
        assert scan and finding and job and project
        output = {
            "project_list": list_projects(db=db),
            "project_get": get_project(project.id, db=db),
            "scan": _scan_to_out(scan),
            "finding": _finding_to_out(finding, 1, {}),
            "job": _job_to_out(db, job),
            "packet": _finding_packet(finding, scan, project, "S1-F001"),
        }

    rendered = json.dumps(output, default=str, sort_keys=True)
    assert RAW_FIXTURE not in rendered
    assert REDACTED in rendered
    assert SAFE_FINGERPRINT in rendered
    assert SAFE_PATH in rendered
    runtime.engine.dispose()


def test_advisor_requests_exact_json_schema_from_ollama() -> None:
    payload = _ollama_payload("synthetic finding", "fixture-model", True)
    assert payload["model"] == "fixture-model"
    assert payload["stream"] is False
    assert payload["think"] is True
    assert payload["format"] == {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["true_positive", "false_positive", "needs_review"],
            },
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "reasoning": {"type": "string", "maxLength": 4000},
            "fix": {"type": "string", "maxLength": 4000},
        },
        "required": ["verdict", "confidence", "reasoning", "fix"],
        "additionalProperties": False,
    }


def test_advisor_output_is_redacted_before_commit_and_return() -> None:
    runtime = _runtime()
    _scan_id, finding_id, _job_id = _seed_untrusted_persisted_rows(runtime)
    profile = providers.normalize_profile(
        {
            "id": "local-fixture",
            "name": "Local fixture",
            "transport": "local",
            "priority": 0,
            "enabled": True,
            "model": "fixture-model",
            "model_digest": "a" * 64,
        }
    )
    advisor_result = {
        "response": json.dumps(
            {
                "verdict": "true_positive",
                "confidence": 0.8,
                "reasoning": RAW_ASSIGNMENT,
                "fix": RAW_ASSIGNMENT,
            }
        )
    }
    with runtime.session_factory() as db:
        finding = db.get(Finding, finding_id)
        assert finding
        with (
            patch(
                "kodesec_api.jobs.advisor.resolve_provider_sync",
                return_value=(profile, None, None),
            ),
            patch(
                "kodesec_api.jobs.advisor.revalidate_local_provider_sync",
                return_value=profile,
            ),
            patch(
                "kodesec_api.jobs.advisor.generate_with_provider_sync",
                return_value=advisor_result,
            ),
        ):
            result = triage_finding_sync(
                db,
                finding,
                runtime.settings,
                model="fixture-model",
                config={
                    "ai_mode": "on",
                    "ollama_thinking": False,
                    "advisor_providers": {
                        "revision": 1,
                        "active_provider_id": None,
                        "providers": [profile],
                    },
                },
            )
        db.expire_all()
        persisted = db.get(Finding, finding_id)
        assert persisted
        rendered = json.dumps(
            {
                "result": result,
                "reasoning": persisted.ai_reasoning,
                "fix": persisted.ai_fix,
                "metadata": persisted.metadata_json,
            },
            sort_keys=True,
        )
        assert persisted.metadata_json["advisor"] == {
            "model": "fixture-model",
            "prompt_version": "finding-triage-v5",
            "thinking": False,
            "model_digest": "a" * 64,
            "provider_id": "local-fixture",
            "provider_transport": "local",
        }
    assert RAW_FIXTURE not in rendered
    assert REDACTED in rendered
    runtime.engine.dispose()


def test_advisor_discards_output_when_revision_changes_during_model_call() -> None:
    runtime = _runtime()
    _scan_id, finding_id, _job_id = _seed_untrusted_persisted_rows(runtime)
    profile, config = _local_advisor_fixture()
    response = {
        "response": json.dumps(
            {
                "verdict": "true_positive",
                "confidence": 0.9,
                "reasoning": "Fresh-looking but stale model output.",
                "fix": "Do not publish this response.",
            }
        )
    }

    def mutate_finding_before_response(*_args, **_kwargs) -> dict[str, object]:
        with runtime.session_factory() as concurrent_db:
            concurrent_finding = concurrent_db.get(Finding, finding_id)
            assert concurrent_finding is not None
            concurrent_scan = concurrent_db.get(Scan, concurrent_finding.scan_id)
            assert concurrent_scan is not None
            concurrent_finding.message = "finding changed while Advisor was running"
            concurrent_finding.revision += 1
            concurrent_scan.revision += 1
            concurrent_scan.findings_revision += 1
            concurrent_db.commit()
        return response

    with runtime.session_factory() as db:
        finding = db.get(Finding, finding_id)
        assert finding is not None
        original_verdict = finding.ai_verdict
        with (
            patch(
                "kodesec_api.jobs.advisor.resolve_provider_sync",
                return_value=(profile, None, None),
            ),
            patch(
                "kodesec_api.jobs.advisor.revalidate_local_provider_sync",
                return_value=profile,
            ),
            patch(
                "kodesec_api.jobs.advisor.generate_with_provider_sync",
                side_effect=mutate_finding_before_response,
            ) as generation,
            pytest.raises(HTTPException) as rejected,
        ):
            triage_finding_sync(
                db,
                finding,
                runtime.settings,
                model="fixture-model",
                config=config,
                expected_revision=1,
            )
        generation.assert_called_once()
        assert rejected.value.status_code == 409
        assert rejected.value.detail["code"] == "finding_changed"
        db.rollback()
        db.expire_all()
        persisted = db.get(Finding, finding_id)
        assert persisted is not None
        assert persisted.revision == 2
        assert persisted.ai_verdict == original_verdict
    runtime.engine.dispose()


@pytest.mark.parametrize(
    "document",
    [
        {"verdict": "needs_review", "confidence": "0.5", "reasoning": "bounded", "fix": "review"},
        {"verdict": "needs_review", "confidence": True, "reasoning": "bounded", "fix": "review"},
        {"verdict": "needs_review", "confidence": float("nan"), "reasoning": "bounded", "fix": "review"},
        {"verdict": "needs_review", "confidence": float("inf"), "reasoning": "bounded", "fix": "review"},
        {"verdict": "needs_review", "confidence": -0.01, "reasoning": "bounded", "fix": "review"},
        {"verdict": "needs_review", "confidence": 1.01, "reasoning": "bounded", "fix": "review"},
        {"verdict": "suppress", "confidence": 0.5, "reasoning": "bounded", "fix": "review"},
        {"verdict": "needs_review", "confidence": 0.5, "reasoning": ["not text"], "fix": "review"},
        {"verdict": "needs_review", "confidence": 0.5, "reasoning": "bounded"},
        {"verdict": "needs_review", "confidence": 0.5, "reasoning": "bounded", "fix": "review", "gate": "pass"},
        {"verdict": "needs_review", "confidence": 0.5, "reasoning": "x" * 4001, "fix": "review"},
        {"verdict": "needs_review", "confidence": 0.5, "reasoning": "unsafe\x00text", "fix": "review"},
        {"verdict": "needs_review", "confidence": 0.5, "reasoning": "unsafe\x01text", "fix": "review"},
        {"verdict": "needs_review", "confidence": 0.5, "reasoning": "unsafe\u0085text", "fix": "review"},
        {"verdict": "needs_review", "confidence": 0.5, "reasoning": "unsafe\u202etext", "fix": "review"},
        {"verdict": "needs_review", "confidence": 0.5, "reasoning": "unsafe\ud800text", "fix": "review"},
        {"verdict": "needs_review", "confidence": 0.5, "reasoning": "unsafe\u2028text", "fix": "review"},
        {"verdict": "needs_review", "confidence": 0.5, "reasoning": "bounded", "fix": "unsafe\u2029text"},
    ],
)
def test_advisor_rejects_invalid_structured_output_without_replacing_review(document) -> None:
    runtime = _runtime()
    _scan_id, finding_id, _job_id = _seed_untrusted_persisted_rows(runtime)
    profile, config = _local_advisor_fixture()
    with runtime.session_factory() as db:
        finding = db.get(Finding, finding_id)
        assert finding
        finding.ai_verdict = "true_positive"
        finding.ai_confidence = 0.25
        finding.ai_reasoning = "Existing safe explanation."
        finding.ai_fix = "Existing safe fix."
        original_metadata = dict(finding.metadata_json or {})
        original_metadata["advisor"] = {
            "model": "existing-model",
            "prompt_version": "finding-triage-v1",
            "thinking": True,
        }
        finding.metadata_json = original_metadata
        db.commit()
        with (
            patch(
                "kodesec_api.jobs.advisor.resolve_provider_sync",
                return_value=(profile, None, None),
            ),
            patch(
                "kodesec_api.jobs.advisor.revalidate_local_provider_sync",
                return_value=profile,
            ),
            patch(
                "kodesec_api.jobs.advisor.generate_with_provider_sync",
                return_value={"response": json.dumps(document)},
            ),
        ):
            with pytest.raises(HTTPException) as error:
                triage_finding_sync(
                    db,
                    finding,
                    runtime.settings,
                    model="fixture-model",
                    config=config,
                )
        assert error.value.status_code == 502
        if (
            set(document) == {"verdict", "confidence", "reasoning", "fix"}
            and document["verdict"] == "needs_review"
            and document["confidence"] == 0.5
            and isinstance(document["reasoning"], str)
            and isinstance(document["fix"], str)
        ):
            assert error.value.detail["code"] == "advisor_output_invalid"
            assert error.value.detail["action"] == "retry_advisor"
        db.rollback()
        db.expire_all()
        persisted = db.get(Finding, finding_id)
        assert persisted
        assert (
            persisted.ai_verdict,
            persisted.ai_confidence,
            persisted.ai_reasoning,
            persisted.ai_fix,
        ) == (
            "true_positive",
            0.25,
            "Existing safe explanation.",
            "Existing safe fix.",
        )
        assert persisted.metadata_json["advisor"] == {
            "model": "existing-model",
            "prompt_version": "finding-triage-v1",
            "thinking": True,
        }
    runtime.engine.dispose()


@pytest.mark.parametrize(
    "response_text",
    [
        '<analysis>hidden</analysis>{"verdict":"needs_review","confidence":0.5,"reasoning":"ok","fix":"ok"}',
        '{"verdict":"needs_review","confidence":0.5,"reasoning":"ok","fix":"ok"}\ntrailing',
        '{"verdict":"needs_review","verdict":"true_positive","confidence":0.5,"reasoning":"ok","fix":"ok"}',
        "[]",
        "",
        " " * (16 * 1024 + 1),
    ],
)
def test_advisor_rejects_decorated_non_object_or_oversized_json(response_text: str) -> None:
    runtime = _runtime()
    _scan_id, finding_id, _job_id = _seed_untrusted_persisted_rows(runtime)
    profile, config = _local_advisor_fixture()
    with runtime.session_factory() as db:
        finding = db.get(Finding, finding_id)
        assert finding
        with (
            patch(
                "kodesec_api.jobs.advisor.resolve_provider_sync",
                return_value=(profile, None, None),
            ),
            patch(
                "kodesec_api.jobs.advisor.revalidate_local_provider_sync",
                return_value=profile,
            ),
            patch(
                "kodesec_api.jobs.advisor.generate_with_provider_sync",
                return_value={"response": response_text},
            ) as generation,
            pytest.raises(HTTPException) as error,
        ):
            triage_finding_sync(
                db, finding, runtime.settings, model="fixture-model", config=config,
            )
        generation.assert_called_once()
        assert error.value.status_code == 502
    runtime.engine.dispose()


def test_advisor_normalizes_safe_multiline_and_represents_empty_fix_without_html_interpretation() -> None:
    runtime = _runtime()
    _scan_id, finding_id, _job_id = _seed_untrusted_persisted_rows(runtime)
    profile, config = _local_advisor_fixture()
    hostile_reasoning = (
        f"<script>not markup</script> Authorization: Bearer {RAW_FIXTURE}\r\n"
        "\tline two\rline three"
    )
    response = {
        "response": json.dumps(
            {
                "verdict": "true_positive",
                "confidence": 0.875,
                "reasoning": hostile_reasoning,
                "fix": "",
            }
        )
    }
    with runtime.session_factory() as db:
        finding = db.get(Finding, finding_id)
        assert finding
        with (
            patch(
                "kodesec_api.jobs.advisor.resolve_provider_sync",
                return_value=(profile, None, None),
            ),
            patch(
                "kodesec_api.jobs.advisor.revalidate_local_provider_sync",
                return_value=profile,
            ),
            patch(
                "kodesec_api.jobs.advisor.generate_with_provider_sync",
                return_value=response,
            ),
        ):
            result = triage_finding_sync(
                db,
                finding,
                runtime.settings,
                model="fixture-model",
                config=config,
            )
        assert result["verdict"] == "true_positive"
        assert result["confidence"] == 0.875
        assert result["fix"] is None
        assert result["reasoning"]
        assert "\r" not in result["reasoning"]
        assert "\n\tline two\nline three" in result["reasoning"]
        assert "<script>not markup</script>" in result["reasoning"]
        assert RAW_FIXTURE not in result["reasoning"]
        db.expire_all()
        persisted = db.get(Finding, finding_id)
        assert persisted is not None
        assert persisted.ai_reasoning == result["reasoning"]
        assert "\r" not in persisted.ai_reasoning
    runtime.engine.dispose()


def test_scanner_lifecycle_errors_and_receipts_are_redacted_before_return() -> None:
    runtime = _runtime()
    with runtime.session_factory() as db:
        catalog = db.get(ScannerLifecycleState, "catalog")
        assert catalog is not None
        catalog.status = "failed"
        catalog.revision = 1
        catalog.receipt = {"diagnostic": f"registry rejected {RAW_ASSIGNMENT}"}
        catalog.error_code = "catalog_failed"
        catalog.error_detail = f"registry rejected {RAW_ASSIGNMENT}"
        db.commit()
        output = scanner_lifecycle(db=db)
        rendered = json.dumps(output, default=str, sort_keys=True)
    assert RAW_FIXTURE not in rendered
    assert REDACTED in rendered
    runtime.engine.dispose()
