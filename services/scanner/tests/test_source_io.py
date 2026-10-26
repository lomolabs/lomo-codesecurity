from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from kodesec_scanner import source_io
from kodesec_scanner.external import ExecutionControl, RunCancelled, RunDeadlineExceeded


def test_fifo_source_is_refused_without_waiting_for_a_writer(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "source.py")
    code = """
import os, sys
from kodesec_scanner.source_io import read_regular_file_at, SourceEvidenceError
root = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    try:
        read_regular_file_at(root, 'source.py', 1048576)
    except SourceEvidenceError as error:
        assert error.reason == 'unsupported_source_type'
    else:
        raise AssertionError('FIFO admitted')
    os.fstat(root)
finally:
    os.close(root)
"""
    # The child has no descendants; subprocess.run owns and reaps it on timeout.
    result = subprocess.run([sys.executable, "-c", code, str(tmp_path)],
        capture_output=True, timeout=3, check=True)
    assert result.stdout == result.stderr == b""


@pytest.mark.parametrize("kind", ["cancelled", "expired"])
def test_terminal_source_read_does_not_duplicate_a_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    control = ExecutionControl.with_timeout(0 if kind == "expired" else 10)
    if kind == "cancelled":
        control.cancel_event.set()
    root = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        def forbidden(_descriptor):
            raise AssertionError("terminal owner cannot begin reading")
        monkeypatch.setattr(source_io.os, "dup", forbidden)
        with pytest.raises(RunCancelled if kind == "cancelled" else RunDeadlineExceeded):
            source_io.read_regular_file_at(root, "source.py", 1048576, checkpoint=control.checkpoint)
        os.fstat(root)
    finally:
        os.close(root)


def test_chunk_cancellation_closes_owned_descriptors_and_preserves_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub/source.py").write_bytes(b"x" * 131072)
    control = ExecutionControl.with_timeout(10)
    root = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    original_open, original_dup, original_read = os.open, os.dup, os.read
    owned = []

    def opening(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        owned.append(descriptor)
        return descriptor

    def duplicating(descriptor):
        duplicate = original_dup(descriptor)
        owned.append(duplicate)
        return duplicate

    def reading(*args):
        chunk = original_read(*args)
        control.cancel_event.set()
        return chunk

    try:
        monkeypatch.setattr(source_io.os, "open", opening)
        monkeypatch.setattr(source_io.os, "dup", duplicating)
        monkeypatch.setattr(source_io.os, "read", reading)
        with pytest.raises(RunCancelled):
            source_io.read_regular_file_at(root, "sub/source.py", 1048576, checkpoint=control.checkpoint)
        assert owned
        for descriptor in owned:
            with pytest.raises(OSError):
                os.fstat(descriptor)
        os.fstat(root)
    finally:
        os.close(root)
