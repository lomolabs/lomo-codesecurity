"""Run the browser review journey against an isolated API and temporary PostgreSQL cluster."""

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
from contextlib import contextmanager
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlencode

import uvicorn
from sqlalchemy import select

from kodesec_api.app import create_app
from kodesec_api.db import Runtime, initialize_database
from kodesec_api.models import Finding, GatePolicy, Project, Scan
from kodesec_api.settings import Settings


@contextmanager
def postgres(directory: Path):
    # Only this new cluster is initialized or stopped. Its socket is in the
    # mode-0700 test directory and the server has no TCP listener.
    bin_dir = os.environ.get("KODESEC_TEST_PG_BIN")
    if not bin_dir and not shutil.which("initdb"):
        raise RuntimeError("Set KODESEC_TEST_PG_BIN to the PostgreSQL bin directory")
    binaries = Path(bin_dir) if bin_dir else Path(shutil.which("initdb")).parent
    if len(os.fsencode(directory / ".s.PGSQL.5432")) >= 104:
        raise ValueError(
            "Use KODESEC_TEST_SCRATCH to select a shorter directory for the PostgreSQL socket"
        )
    data = str(directory / "pgdata")
    subprocess.run(
        [
            binaries / "initdb",
            "-D",
            data,
            "-A",
            "trust",
            "-U",
            "review",
            "--encoding=UTF8",
            "--no-locale",
        ],
        stdout=subprocess.DEVNULL,
        check=True,
    )
    socket_path = str(directory).replace("\\", "\\\\").replace("'", "''")
    with (Path(data) / "postgresql.conf").open("a", encoding="utf8") as config:
        config.write(
            f"\nlisten_addresses = ''\nunix_socket_directories = '{socket_path}'\n"
        )
    subprocess.run(
        [
            binaries / "pg_ctl",
            "-D",
            data,
            "-l",
            str(directory / "postgres.log"),
            "-w",
            "start",
        ],
        check=True,
    )
    try:
        yield "postgresql+psycopg2://review@/postgres?" + urlencode(
            {"host": str(directory)}
        )
    finally:
        subprocess.run(
            [binaries / "pg_ctl", "-D", data, "-m", "fast", "-w", "stop"], check=True
        )


def seed_filter_scan(db, project_id: int) -> int:
    """Cross the 200-row API cursor and include policy and lifecycle lookalikes."""
    scan = Scan(
        project_id=project_id, mode="full", status="completed", gate_decision="fail",
        gate_reasons=["critical findings: 2 > max 0", "secret findings: 2"], scanner_summary={},
    )
    db.add(scan)
    db.flush()
    for number in range(1, 225):
        severity = {2: "critical", 4: "critical", 5: "high", 30: "critical",
                    201: "low", 224: "critical"}.get(number, "medium")
        db.add(Finding(
            scan_id=scan.id, scan_finding_number=number,
            scanner={2: "checkov", 201: "gitleaks", 224: "gitleaks"}.get(number, "opengrep"),
            severity=severity, rule_id=f"fixture.rule.{number:03}",
            message="Connection token policy" if number in (5, 30, 201) else "Review item",
            file_path="shared/config.py" if number in (4, 5, 30, 224) else "app/main.py",
            start_line=number, end_line=number, fingerprint=f"filter-{number}",
            suppressed=number == 2, gate_exempt=number == 4,
            lifecycle_status={2: "ignore", 4: "gate_exempt"}.get(number, "open"),
        ))
    return scan.id


def run(browser_command: list[str]) -> None:
    root = Path(__file__).resolve().parents[3]
    scratch = Path(
        os.environ.get("KODESEC_TEST_SCRATCH", root / ".kodesec-test")
    ).resolve()
    scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (
        tempfile.TemporaryDirectory(dir=scratch, prefix="gate-review-") as temporary,
        postgres(Path(temporary)) as database,
        socket.socket() as listener,
    ):
        directory = Path(temporary)
        listener.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        key = secrets.token_urlsafe(48)
        settings = Settings(
            _env_file=None,
            DATABASE_URL=database,
            KODESEC_INSTALLATION_SECRET=secrets.token_urlsafe(48),
            KODESEC_INSTALLATION_ID=secrets.token_hex(6),
            KODESEC_BOOTSTRAP_TOKEN=key,
            KODESEC_CONTROL_ORIGINS=origin,
            KODESEC_STATIC_DIR=str(root / "apps/web/dist"),
            KODESEC_ARTIFACT_DIR=str(directory / "artifacts"),
            KODESEC_SOURCE_SNAPSHOT_DIR=str(directory / "source-snapshots"),
            KODESEC_ALLOWED_ROOTS="/workspaces/demo",
            SCANNER_URL="http://127.0.0.1:1",
        )
        runtime = Runtime.create(settings)
        initialize_database(runtime.engine)
        with runtime.session_factory() as db:
            project = Project(
                name="Blocker review demo",
                repo_path="/workspaces/demo",
                default_branch="main",
            )
            db.add(project)
            db.flush()
            db.add(
                GatePolicy(
                    project_id=project.id,
                    active=True,
                    max_critical=0,
                    max_high=1,
                    block_secrets=True,
                )
            )
            scan = Scan(
                project_id=project.id,
                mode="full",
                status="completed",
                gate_decision="fail",
                gate_reasons=["critical findings: 2 > max 0"],
                scanner_summary={},
            )
            db.add(scan)
            db.flush()
            for number, severity in enumerate(("critical", "critical", "medium"), 1):
                db.add(
                    Finding(
                        scan_id=scan.id,
                        scan_finding_number=number,
                        scanner="opengrep",
                        severity=severity,
                        rule_id=f"demo.rule.{number}",
                        message=f"Review example {number}",
                        file_path="example.py",
                        start_line=number,
                        end_line=number,
                        fingerprint=f"example-{number}",
                    )
                )
            filter_scan = seed_filter_scan(db, project.id)
            db.commit()
            scan_id = scan.id
        app = create_app(runtime_override=runtime)
        server = uvicorn.Server(
            uvicorn.Config(
                app, log_level="warning", access_log=False, timeout_graceful_shutdown=3
            )
        )
        thread = threading.Thread(
            target=server.run, kwargs={"sockets": [listener]}, daemon=True
        )
        thread.start()
        try:
            deadline = time.monotonic() + 15
            while not server.started:
                if not thread.is_alive() or time.monotonic() >= deadline:
                    raise RuntimeError("Isolated API failed to start")
                time.sleep(0.05)
            subprocess.run(
                browser_command,
                input=json.dumps({"origin": origin, "key": key, "scan": scan_id, "filterScan": filter_scan}),
                text=True,
                check=True,
                timeout=150,
            )
            with runtime.session_factory() as db:
                findings = db.scalars(
                    select(Finding)
                    .where(Finding.scan_id == scan_id)
                    .order_by(Finding.scan_finding_number)
                ).all()
                assert [row.lifecycle_status for row in findings] == [
                    "fixed",
                    "accepted_risk",
                    "open",
                ]
                assert db.get(Scan, scan_id).gate_decision == "pass"
                print(
                    "Database verified: two reviewed blockers, unaffected neighbour, passing gate."
                )
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            if thread.is_alive():
                raise RuntimeError("Isolated API did not stop")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--browser-command",
        nargs="+",
        default=["node", str(Path(__file__).with_name("gate-review-browser.mjs"))],
        help="Isolated browser runner receiving the disposable session details on stdin",
    )
    run(parser.parse_args().browser_command)
