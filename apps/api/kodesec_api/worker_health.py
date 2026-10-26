from __future__ import annotations

import os
from pathlib import Path
import stat
import time


DEFAULT_HEALTH_PATH = Path("/tmp/kodesec-worker-heartbeat")


def record_process_heartbeat(
    path: Path = DEFAULT_HEALTH_PATH,
    *,
    now_ns: int | None = None,
) -> None:
    """Stamp liveness only after the worker's durable heartbeat commits."""

    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise RuntimeError("worker health marker is not an owner-only regular file")
        timestamp = now_ns if now_ns is not None else time.time_ns()
        os.utime(descriptor, ns=(timestamp, timestamp))
    finally:
        os.close(descriptor)


def process_heartbeat_is_fresh(
    path: Path = DEFAULT_HEALTH_PATH,
    *,
    stale_after_seconds: float,
    now_ns: int | None = None,
) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        return False
    current = now_ns if now_ns is not None else time.time_ns()
    age_ns = current - metadata.st_mtime_ns
    return 0 <= age_ns <= int(stale_after_seconds * 1_000_000_000)


def main() -> None:
    try:
        liveness_seconds = float(os.environ.get("KODESEC_WORKER_LIVENESS_SECONDS", "10"))
    except ValueError:
        raise SystemExit(1) from None
    path = Path(os.environ.get("KODESEC_WORKER_HEALTH_PATH", str(DEFAULT_HEALTH_PATH)))
    healthy = process_heartbeat_is_fresh(
        path,
        stale_after_seconds=max(15.0, liveness_seconds * 3),
    )
    raise SystemExit(0 if healthy else 1)


if __name__ == "__main__":
    main()
