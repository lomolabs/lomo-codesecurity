from __future__ import annotations

import argparse
import logging
import os
import secrets
import signal
import socket
import time
from threading import Event, Thread

from sqlalchemy.exc import SQLAlchemyError

from .advisor import providers as advisor_providers
from .db import Runtime, init_db
from .events import install_outbox_listeners
from .artifact_boundary import ARTIFACT_BOUNDARY_MARKER
from .jobs.execution import ClaimedJob, WorkerExecutor
from .jobs.advisor import (
    ConnectorRequestError,
    detect_local_models_sync,
    worker_ollama_available_sync,
)
from .jobs.liveness import (
    fresh_worker_id,
    record_worker_advisor_catalog,
    record_worker_advisor_status,
    record_worker_heartbeat,
    worker_advisor_catalog_failure_reason,
    worker_heartbeat_is_fresh,
)
from .main import _runtime_config_values
from .models import RuntimeConfig
from .jobs.repository import claim_next_job
from .settings import Settings, get_settings
from .worker_health import record_process_heartbeat


LOGGER = logging.getLogger("kodesec.worker")


def _worker_id() -> str:
    host = socket.gethostname().split(".", 1)[0][:48] or "local"
    return f"worker-{host}-{os.getpid()}-{secrets.token_hex(8)}"


class _AdvisorReceiptPublisher:
    """Publish bounded connector evidence independently of serial job work."""

    _DISCOVERY_TIMEOUT_SECONDS = 3.0
    _STATUS_TIMEOUT_SECONDS = 2.0

    def __init__(self, runtime: Runtime, worker_id: str) -> None:
        self.runtime = runtime
        self.worker_id = worker_id
        self._stop = Event()
        self._success_interval = max(60.0, runtime.settings.worker_liveness_seconds * 6)
        self._retry_interval = max(5.0, runtime.settings.worker_liveness_seconds)
        self._thread = Thread(
            target=self._run,
            name="kodesec-advisor-receipts",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(
            timeout=(
                self._DISCOVERY_TIMEOUT_SECONDS
                + max(self._STATUS_TIMEOUT_SECONDS, 3.0)
                + 1.0
            )
        )
        if self._thread.is_alive():
            raise RuntimeError(
                "Advisor receipt publisher did not stop within its bounded deadline"
            )

    def _publish_once(self) -> bool:
        settings = self.runtime.settings
        with self.runtime.session_factory() as db:
            advisor_config = _runtime_config_values(settings, db)
            collection = advisor_config.get("advisor_providers")
            if isinstance(collection, dict):
                advisor_config["advisor_provider_receipts"] = (
                    advisor_providers.load_valid_receipts(db, collection)
                )
                advisor_config["advisor_provider_consents"] = (
                    advisor_providers.load_valid_consents(db, collection)
                )
        try:
            catalog = detect_local_models_sync(
                settings, timeout=self._DISCOVERY_TIMEOUT_SECONDS
            )
            catalog_reason = None
        except ConnectorRequestError as exc:
            catalog = None
            catalog_reason = worker_advisor_catalog_failure_reason(exc.code)
        if catalog is None:
            available, models, reason = False, [], catalog_reason
        else:
            available, models, reason = worker_ollama_available_sync(
                advisor_config,
                timeout=self._STATUS_TIMEOUT_SECONDS,
                settings=settings,
            )
        with self.runtime.session_factory() as db, db.begin():
            current_worker_id = fresh_worker_id(
                db,
                stale_after_seconds=max(15.0, settings.worker_liveness_seconds * 3),
            )
            if current_worker_id != self.worker_id:
                return False
            record_worker_advisor_catalog(
                db,
                self.worker_id,
                catalog=catalog,
                reason=catalog_reason,
            )
            record_worker_advisor_status(
                db,
                self.worker_id,
                advisor_config,
                available=available,
                models=models,
                reason=reason,
            )
        return catalog is not None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                succeeded = self._publish_once()
            except (SQLAlchemyError, ValueError):
                LOGGER.exception("Advisor receipt publication failed")
                succeeded = False
            interval = self._success_interval if succeeded else self._retry_interval
            if self._stop.wait(interval):
                return


def run_worker(
    runtime: Runtime,
    *,
    once: bool = False,
    stop_event: Event | None = None,
    worker_id: str | None = None,
) -> int:
    """Claim and execute jobs serially; return the number claimed.

    Serial execution is intentional for the single-installation resource
    budget. The PostgreSQL repository still fences concurrent worker processes
    and enforces single-scan admission, so correctness does not depend on this
    loop alone.
    """

    settings = runtime.settings
    install_outbox_listeners()
    settings.validate_worker_configuration()
    init_db(runtime.engine)
    with runtime.session_factory() as db:
        missing_boundaries = (
            []
            if db.get(RuntimeConfig, ARTIFACT_BOUNDARY_MARKER) is not None
            else [ARTIFACT_BOUNDARY_MARKER]
        )
    if missing_boundaries:
        raise RuntimeError(
            "durable worker publication boundaries are not initialized; "
            "run python -m kodesec_api.schema_init first"
        )
    stopping = stop_event or Event()
    owner = worker_id or _worker_id()
    executor = WorkerExecutor(runtime, owner)
    claimed_count = 0
    with runtime.session_factory() as db, db.begin():
        record_worker_heartbeat(db, owner)
    record_process_heartbeat()
    last_liveness = time.monotonic()
    advisor_publisher = None if once else _AdvisorReceiptPublisher(runtime, owner)
    if advisor_publisher is not None:
        advisor_publisher.start()

    try:
        while not stopping.is_set():
            monotonic_now = time.monotonic()
            if monotonic_now - last_liveness >= settings.worker_liveness_seconds:
                with runtime.session_factory() as db, db.begin():
                    record_worker_heartbeat(db, owner)
                record_process_heartbeat()
                last_liveness = monotonic_now
            claimed: ClaimedJob | None = None
            try:
                with runtime.session_factory() as db, db.begin():
                    model = claim_next_job(
                        db,
                        worker_id=owner,
                        lease_seconds=settings.worker_lease_seconds,
                    )
                    if model is not None:
                        claimed = ClaimedJob.from_model(model)
            except Exception:
                LOGGER.exception("durable job claim failed")
                if once:
                    break
                stopping.wait(settings.worker_poll_seconds)
                continue

            if claimed is None:
                if once:
                    break
                stopping.wait(settings.worker_poll_seconds)
                continue

            claimed_count += 1
            LOGGER.info(
                "durable job claimed",
                extra={
                    "job_id": claimed.id,
                    "job_kind": claimed.kind,
                    "job_attempt": claimed.attempt,
                },
            )
            if claimed.stage == "recovery_exhausted":
                executor.recover_exhausted(claimed)
            else:
                executor.execute(claimed)
            if once:
                break
    finally:
        if advisor_publisher is not None:
            advisor_publisher.stop()

    return claimed_count


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the local PostgreSQL-leased CodeSecurity worker."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="claim at most one job and exit (integration and operator diagnostics)",
    )
    parser.add_argument(
        "--healthcheck",
        action="store_true",
        help="exit successfully only when a recent worker liveness receipt exists",
    )
    return parser.parse_args()


def main(settings_override: Settings | None = None) -> None:
    args = _arguments()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = settings_override or get_settings()
    runtime = Runtime.create(settings)
    if bool(args.healthcheck):
        try:
            with runtime.session_factory() as db:
                fresh = worker_heartbeat_is_fresh(
                    db,
                    stale_after_seconds=max(15.0, settings.worker_liveness_seconds * 3),
                )
        finally:
            runtime.dispose()
        raise SystemExit(0 if fresh else 1)
    stopping = Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stopping.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        run_worker(runtime, once=bool(args.once), stop_event=stopping)
    finally:
        runtime.dispose()


if __name__ == "__main__":
    main()
