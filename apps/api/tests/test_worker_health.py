from __future__ import annotations

from pathlib import Path

from kodesec_api import worker_health


def test_process_health_marker_tracks_only_a_recent_owner_regular_file(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "worker-heartbeat"
    worker_health.record_process_heartbeat(marker, now_ns=20_000_000_000)

    assert worker_health.process_heartbeat_is_fresh(
        marker,
        stale_after_seconds=15.0,
        now_ns=35_000_000_000,
    )
    assert not worker_health.process_heartbeat_is_fresh(
        marker,
        stale_after_seconds=15.0,
        now_ns=35_000_000_001,
    )

    marker.unlink()
    marker.symlink_to(tmp_path / "absent")
    assert not worker_health.process_heartbeat_is_fresh(
        marker,
        stale_after_seconds=15.0,
        now_ns=20_000_000_000,
    )
