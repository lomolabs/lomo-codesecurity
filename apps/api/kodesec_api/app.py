from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import __version__
from .auth import router as auth_router
from .db import Runtime
from .events import (
    EventConnectionLimiter,
    EventWakeBroker,
    install_outbox_listeners,
    router as events_router,
)
from .main import _startup, router as api_router
from .ide_source import router as ide_source_router
from .git_push_policy import router as git_push_policy_router
from .git_push_evidence import router as git_push_evidence_router
from .security import AdvisorRequestAudit, SecurityBoundaryMiddleware
from .settings import Settings, get_settings
from .static_files import mount_static_application


def create_app(
    settings_override: Settings | None = None,
    *,
    runtime_override: Runtime | None = None,
) -> FastAPI:
    if settings_override is not None and runtime_override is not None:
        raise ValueError("pass settings_override or runtime_override, not both")
    settings = runtime_override.settings if runtime_override is not None else settings_override or get_settings()
    settings.validate_security_material()
    runtime = runtime_override or Runtime.create(settings)
    runtime.claim_for_app()
    install_outbox_listeners()
    event_wake_broker: EventWakeBroker | None = None

    try:
        @asynccontextmanager
        async def lifespan(active_app: FastAPI) -> AsyncIterator[None]:
            active_runtime: Runtime = active_app.state.runtime
            try:
                _startup(active_runtime)
                await active_app.state.event_wake_broker.start()
                yield
            finally:
                active_app.state.event_wake_broker.close()
                active_runtime.dispose()

        app = FastAPI(
            title="Lomo CodeSecurity API",
            version=__version__,
            description="Local-first AppSec control plane.",
            docs_url=None,
            redoc_url=None,
            lifespan=lifespan,
        )
        app.state.runtime = runtime
        app.state.event_connection_limiter = EventConnectionLimiter()
        advisor_request_audit = AdvisorRequestAudit()
        app.state.advisor_request_audit = advisor_request_audit
        event_wake_broker = EventWakeBroker(runtime.engine, runtime.session_factory)
        app.state.event_wake_broker = event_wake_broker

        @app.exception_handler(RequestValidationError)
        async def sanitized_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
            # FastAPI's default 422 body repeats the submitted input. Authentication
            # payloads contain one-time credentials, so expose only the field path and
            # validation rule and make the response non-cacheable.
            errors = [
                {
                    "type": str(error.get("type", "validation_error")),
                    "loc": list(error.get("loc", ())),
                    "msg": str(error.get("msg", "Invalid input")),
                }
                for error in exc.errors()
            ]
            return JSONResponse(
                {"detail": errors},
                status_code=422,
                headers={"Cache-Control": "no-store"},
            )

        app.add_middleware(
            SecurityBoundaryMiddleware,
            runtime=runtime,
            advisor_request_audit=advisor_request_audit,
        )
        app.include_router(auth_router)
        app.include_router(api_router)
        app.include_router(ide_source_router)
        app.include_router(git_push_policy_router)
        app.include_router(git_push_evidence_router)
        app.include_router(events_router)
        mount_static_application(app, settings.static_dir)
        return app
    except BaseException:
        try:
            if event_wake_broker is not None:
                event_wake_broker.close()
            runtime.dispose()
        finally:
            runtime.release_failed_app_claim()
        raise
