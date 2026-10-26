"""ASGI entry point for the isolated source-blind scanner updater."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import __version__
from .cache_manifest import load_rules_lock, load_tool_lock, validate_lock_alignment
from .data_catalog import DataCatalogStore
from .settings import UpdaterSettings, get_updater_settings
from .updater import LockedLifecycleHandlers, OperationStore, prepare_cache_layout
from .updater_routes import create_router
from .updater_service import UpdaterExecutor


def create_app(
    settings: UpdaterSettings | None = None,
    *,
    allowed_hosts: frozenset[str] | None = None,
) -> FastAPI:
    configured = settings or get_updater_settings()
    configured.validate_boundaries()
    tools = load_tool_lock(Path(configured.tool_lock_path))
    rules = load_rules_lock(Path(configured.rules_lock_path))
    validate_lock_alignment(tools.value, rules.value)
    store = OperationStore(Path(configured.tool_cache_dir))
    handlers = LockedLifecycleHandlers(
        tools=tools,
        rules=rules,
        cache_root=Path(configured.tool_cache_dir),
        scratch_root=Path(configured.scratch_dir),
        timeout_seconds=configured.request_timeout_seconds,
        catalog_store=(DataCatalogStore(Path(configured.tool_cache_dir), tools, rules)
            if configured.data_catalog_mode == "signed" else None),
    )
    executor = UpdaterExecutor(
        tools=tools,
        rules=rules,
        store=store,
        handlers=handlers,
        max_active=configured.max_active,
        max_pending=configured.max_pending,
        shutdown_wait_seconds=configured.shutdown_wait_seconds,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        startup_started = time.monotonic()
        startup_log = logging.getLogger("uvicorn.error")
        startup_log.info("Updater initializing: recovering durable operations and cache retention")
        Path(configured.scratch_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
        prepare_cache_layout(Path(configured.tool_cache_dir))
        recovered = executor.recover()
        startup_log.info(
            "Updater initialization complete: recovered_operations=%d elapsed_seconds=%.3f; "
            "scanner readiness is verified independently",
            len(recovered), time.monotonic() - startup_started,
        )
        yield
        if not executor.shutdown():
            raise RuntimeError("updater shutdown exceeded its cleanup deadline")

    app = FastAPI(
        title="Lomo CodeSecurity Source-Blind Updater",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    admitted_hosts = allowed_hosts or configured.allowed_hosts

    @app.middleware("http")
    async def fixed_private_host(request: Request, call_next):  # type: ignore[no-untyped-def]
        host = request.headers.get("host", "").lower()
        if host not in admitted_hosts:
            return JSONResponse(
                status_code=400,
                content={
                    "detail": {
                        "code": "private_boundary",
                        "message": "request host is outside the fixed updater boundary",
                    }
                },
            )
        if any(
            name in request.headers
            for name in ("forwarded", "x-forwarded-host", "x-forwarded-proto")
        ):
            return JSONResponse(
                status_code=400,
                content={
                    "detail": {
                        "code": "private_boundary",
                        "message": "forwarded updater requests are not accepted",
                    }
                },
            )
        return await call_next(request)

    @app.get("/healthz")
    def healthz() -> dict[str, object]:
        return {"ok": True, "version": __version__, "service": "source-blind-updater", "preparation_budget_schema_version": 4}

    app.include_router(create_router(executor))
    app.state.executor = executor
    return app


def _default_app() -> FastAPI:
    return create_app()


# Uvicorn imports this module only in the immutable scanner image where the
# reviewed lock paths exist. Unit tests use ``create_app`` with isolated locks.
app = _default_app()
