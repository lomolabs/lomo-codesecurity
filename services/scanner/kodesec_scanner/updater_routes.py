"""Strict private HTTP routes for durable scanner lifecycle operations."""

from __future__ import annotations

import re
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Response

from .updater import (
    OperationCapacityError,
    OperationConflictError,
    OperationError,
    OperationNotFoundError,
    OperationRecord,
    OperationRequest,
)
from .updater_service import UpdaterExecutor
from .preparation_budget import PreparationDeadlineExceeded
from .cache_manifest import CacheValidationError


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _error(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status, {"code": code, "message": message})


def create_router(executor: UpdaterExecutor) -> APIRouter:
    router = APIRouter()

    @router.post(
        "/operations",
        response_model=OperationRecord,
        status_code=202,
        responses={200: {"model": OperationRecord}},
    )
    def create_operation(request: OperationRequest, response: Response) -> OperationRecord:
        try:
            record, accepted = executor.submit(request)
        except OperationConflictError as exc:
            raise _error(409, "operation_conflict", "operation identity conflicts with its durable binding") from exc
        except OperationCapacityError as exc:
            raise _error(503, "updater_capacity", "updater operation capacity is exhausted") from exc
        except OperationError as exc:
            raise _error(422, "operation_rejected", "operation is not admitted by the reviewed catalog") from exc
        if not accepted and record.status in {"completed", "failed", "cancelled"}:
            response.status_code = 200
        return record

    @router.get("/operations/{operation_id}/reconciliation-preview")
    def reconciliation_preview(
        operation_id: UUID,
        request_digest: str | None = Header(default=None, alias="X-KodeSec-Request-Digest"),
    ) -> dict:
        if request_digest is None or not _DIGEST.fullmatch(request_digest):
            raise _error(422, "request_digest_required", "an exact request digest is required")
        from .readonly_recovery import preview
        try:
            return preview(executor.store, operation_id, request_digest)
        except OperationNotFoundError as exc:
            raise _error(404, "operation_missing", "operation does not exist") from exc
        except OperationConflictError as exc:
            raise _error(409, "reconciliation_target_changed", "publication identity changed") from exc
        except PreparationDeadlineExceeded as exc:
            raise _error(503, "reconciliation_preview_deadline", "recovery metadata is temporarily unavailable") from exc
        except (OperationError, CacheValidationError, ValueError) as exc:
            raise _error(409, "reconciliation_not_available", "no uncertain publication is available") from exc

    @router.get("/operations/{operation_id}", response_model=OperationRecord)
    def get_operation(
        operation_id: UUID,
        request_digest: str | None = Header(default=None, alias="X-KodeSec-Request-Digest"),
    ) -> OperationRecord:
        if request_digest is None or not _DIGEST.fullmatch(request_digest):
            raise _error(422, "request_digest_required", "a lowercase request digest header is required")
        try:
            return executor.store.load(operation_id, request_digest=request_digest)
        except OperationNotFoundError as exc:
            raise _error(404, "operation_missing", "operation does not exist") from exc
        except OperationConflictError as exc:
            raise _error(409, "operation_conflict", "operation identity conflicts with its durable binding") from exc
        except OperationError as exc:
            raise _error(500, "operation_ledger_invalid", "operation ledger validation failed") from exc

    @router.delete("/operations/{operation_id}", response_model=OperationRecord)
    def cancel_operation(
        operation_id: UUID,
        request_digest: str | None = Header(default=None, alias="X-KodeSec-Request-Digest"),
    ) -> OperationRecord:
        if request_digest is None or not _DIGEST.fullmatch(request_digest):
            raise _error(422, "request_digest_required", "a lowercase request digest header is required")
        try:
            return executor.store.request_cancel(
                operation_id,
                request_digest=request_digest,
            )
        except OperationNotFoundError as exc:
            raise _error(404, "operation_missing", "operation does not exist") from exc
        except OperationConflictError as exc:
            raise _error(409, "operation_conflict", "operation identity conflicts with its durable binding") from exc
        except OperationError as exc:
            raise _error(500, "operation_ledger_invalid", "operation ledger validation failed") from exc

    return router
