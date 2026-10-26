#!/usr/bin/env python3
"""Emit one reviewable, read-only Docker/Buildx runtime observation receipt."""

from __future__ import annotations

import argparse
import hashlib
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Sequence

from docker_runtime_contract import (
    DockerRuntimeContractError,
    RuntimePaths,
    canonical_json_bytes,
    combined_observation,
    executable_argv,
    normalize_buildx_observation,
    normalize_daemon_observation,
    prepare_runtime,
    remove_runtime,
    revalidate_runtime,
)


MAX_OUTPUT_BYTES = 1024 * 1024
MAX_SECONDS = 60
READ_BYTES = 64 * 1024
RECEIPT_NAME = "docker-runtime-observation.json"
FAILURE_NAME = "docker-runtime-observation-failure.json"
MAX_FAILURE_BYTES = 4096
PROBE_PHASES = {
    ("docker", "version"): "version",
    ("docker", "info"): "info",
    ("buildx", "ls"): "buildx",
}


class ObservationError(RuntimeError):
    """The read-only runtime observation could not be proved."""

    def __init__(self, code: str, *, failure: dict[str, object] | None = None):
        super().__init__(code)
        self.failure = failure


class ObservationCleanupUncertain(ObservationError):
    """A probe process or its descendant may have survived."""


def _failure_projection(
    phase: str, captured: dict[str, bytearray], *, native_exit: int | None,
    natural_exit_observed: bool, process_cleanup_confirmed: bool,
) -> dict[str, object]:
    return {
        "schema": "kodesec.docker-runtime-observation-failure/v1",
        "phase": phase,
        "native_exit": native_exit if natural_exit_observed else None,
        "natural_exit_observed": natural_exit_observed,
        "process_cleanup_confirmed": process_cleanup_confirmed,
        "runtime_cleanup_confirmed": False,
        "capture_limit_bytes_per_stream": MAX_OUTPUT_BYTES,
        "stdout_captured_bytes": len(captured["stdout"]),
        "stdout_sha256": hashlib.sha256(captured["stdout"]).hexdigest(),
        "stderr_captured_bytes": len(captured["stderr"]),
        "stderr_sha256": hashlib.sha256(captured["stderr"]).hexdigest(),
    }


def _bounded(
    runtime: RuntimePaths,
    argv: Sequence[str],
    *,
    invoking_uid: int,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
) -> bytes:
    phase = PROBE_PHASES.get(tuple(argv[:2]))
    if phase is None:
        raise ObservationError("probe_phase_unsupported")
    revalidate_runtime(runtime, invoking_uid=invoking_uid)
    command = executable_argv(runtime, argv)
    try:
        process = popen(
            command,
            cwd=runtime.root,
            env=runtime.environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise ObservationError("probe_start_failed") from exc
    except BaseException as exc:
        raise ObservationCleanupUncertain("probe_start_uncertain") from exc
    selector: selectors.BaseSelector | None = None
    primary: BaseException | None = None
    natural = False
    native_exit: int | None = None
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        if process.stdout is None or process.stderr is None:
            raise ObservationError("probe_capture_unavailable")
        selector = selectors.DefaultSelector()
        streams = {
            process.stdout.fileno(): "stdout",
            process.stderr.fileno(): "stderr",
        }
        for descriptor in streams:
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + MAX_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ObservationError("probe_timeout")
            events = selector.select(remaining)
            if not events:
                raise ObservationError("probe_timeout")
            for key, _event in events:
                label = streams[key.fd]
                allowance = MAX_OUTPUT_BYTES - len(captured[label])
                chunk = os.read(key.fd, min(READ_BYTES, allowance + 1))
                if not chunk:
                    selector.unregister(key.fd)
                elif len(chunk) > allowance:
                    raise ObservationError("probe_output_oversized")
                else:
                    captured[label].extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ObservationError("probe_timeout")
        returncode = process.wait(timeout=remaining)
        native_exit = returncode
        natural = True
        if returncode != 0:
            raise ObservationError("probe_status_failed")
        if captured["stderr"]:
            raise ObservationError("probe_stderr_nonempty")
    except BaseException as exc:
        primary = exc

    # A naturally observed nonzero exit is an ordinary probe failure.  Only a
    # process whose completion was not observed needs the process-group
    # uncertainty path.
    forced = process.poll() is None or not natural
    cleanup_errors: list[BaseException] = []
    if forced:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except BaseException as exc:
            cleanup_errors.append(exc)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as exc:
                cleanup_errors.append(exc)
            try:
                process.wait(timeout=5)
            except BaseException as exc:
                cleanup_errors.append(exc)
        except BaseException as exc:
            cleanup_errors.append(exc)
    try:
        if process.poll() is None:
            cleanup_errors.append(ObservationError("probe_process_survived"))
    except BaseException as exc:
        cleanup_errors.append(exc)
    if selector is not None:
        try:
            selector.close()
        except BaseException as exc:
            cleanup_errors.append(exc)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except BaseException as exc:
                cleanup_errors.append(exc)
    try:
        revalidate_runtime(runtime, invoking_uid=invoking_uid)
    except BaseException as exc:
        cleanup_errors.append(exc)
    if cleanup_errors:
        raise ObservationCleanupUncertain(
            "probe_cleanup_uncertain",
            failure=_failure_projection(phase, captured, native_exit=native_exit,
                natural_exit_observed=natural, process_cleanup_confirmed=False),
        ) from cleanup_errors[0]
    if forced:
        raise ObservationCleanupUncertain(
            "probe_completion_uncertain",
            failure=_failure_projection(phase, captured, native_exit=native_exit,
                natural_exit_observed=natural, process_cleanup_confirmed=False),
        ) from primary
    if primary is not None:
        if isinstance(primary, ObservationError):
            primary.failure = _failure_projection(phase, captured, native_exit=native_exit,
                natural_exit_observed=natural, process_cleanup_confirmed=True)
        raise primary
    return bytes(captured["stdout"])


def observe(
    runtime: RuntimePaths,
    *,
    invoking_uid: int,
    runner: Callable[[RuntimePaths, Sequence[str]], bytes] | None = None,
) -> dict[str, object]:
    execute = runner or (
        lambda selected, argv: _bounded(
            selected, argv, invoking_uid=invoking_uid
        )
    )
    version = execute(runtime, ("docker", "version", "--format={{json .}}"))
    info = execute(runtime, ("docker", "info", "--format={{json .}}"))
    buildx = execute(
        runtime,
        ("buildx", "ls", "--format=json", "--no-trunc"),
    )
    return combined_observation(
        normalize_daemon_observation(version, info),
        normalize_buildx_observation(buildx),
    )


def _publish(path: Path, payload: bytes, *, uid: int) -> None:
    if path.exists() or path.is_symlink() or not 0 < len(payload) <= MAX_OUTPUT_BYTES:
        raise ObservationError("receipt_destination_invalid")
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        total = 0
        while total < len(payload):
            written = os.write(descriptor, payload[total:])
            if written <= 0:
                raise ObservationError("receipt_write_failed")
            total += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != uid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(payload)
        ):
            raise ObservationError("receipt_publication_unproven")
    finally:
        os.close(descriptor)
    os.link(temporary, path, follow_symlinks=False)
    temporary.unlink()
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _publish_failure(output_dir: Path, failure: dict[str, object], *, uid: int) -> None:
    # Only this fixed projection may be serialized; no argv, paths or raw native
    # output enter the failure artifact, including through an injected exception.
    fields = {"schema", "phase", "native_exit", "natural_exit_observed",
              "process_cleanup_confirmed", "runtime_cleanup_confirmed",
              "capture_limit_bytes_per_stream", "stdout_captured_bytes", "stdout_sha256",
              "stderr_captured_bytes", "stderr_sha256"}
    valid = (set(failure) == fields
             and failure["schema"] == "kodesec.docker-runtime-observation-failure/v1"
             and failure["phase"] in set(PROBE_PHASES.values())
             and failure["capture_limit_bytes_per_stream"] == MAX_OUTPUT_BYTES
             and all(type(failure[key]) is bool for key in
                     ("natural_exit_observed", "process_cleanup_confirmed", "runtime_cleanup_confirmed"))
             and (failure["native_exit"] is None or type(failure["native_exit"]) is int)
             and (failure["natural_exit_observed"] or failure["native_exit"] is None))
    for stream in ("stdout", "stderr"):
        count, digest = failure.get(f"{stream}_captured_bytes"), failure.get(f"{stream}_sha256")
        valid = (valid and type(count) is int and 0 <= count <= MAX_OUTPUT_BYTES
                 and isinstance(digest, str) and len(digest) == 64
                 and all(character in "0123456789abcdef" for character in digest))
    metadata = output_dir.lstat()
    if (not valid or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ObservationError("failure_projection_invalid")
    payload = canonical_json_bytes(failure)
    if len(payload) > MAX_FAILURE_BYTES:
        raise ObservationError("failure_projection_oversized")
    _publish(output_dir / FAILURE_NAME, payload, uid=uid)


def produce(
    output_dir: Path,
    *,
    docker_executable: Path,
    docker_sha256: str,
    buildx_executable: Path,
    buildx_sha256: str,
    docker_host: str,
) -> Path:
    uid = os.getuid()
    if not output_dir.is_absolute() or output_dir.exists() or output_dir.is_symlink():
        raise ObservationError("output_dir_invalid")
    parent = output_dir.parent.lstat()
    if (
        output_dir.parent.is_symlink()
        or parent.st_uid != uid
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise ObservationError("output_parent_not_private")
    output_dir.mkdir(mode=0o700)
    runtime: RuntimePaths | None = None
    try:
        runtime = prepare_runtime(
            output_dir / ".runtime",
            docker_executable=docker_executable,
            docker_sha256=docker_sha256,
            buildx_executable=buildx_executable,
            buildx_sha256=buildx_sha256,
            docker_host=docker_host,
            invoking_uid=uid,
        )
        observation = observe(runtime, invoking_uid=uid)
        execution = runtime.record()
        remove_runtime(runtime, invoking_uid=uid)
        runtime = None
        receipt: dict[str, object] = {
            "schema": "kodesec.docker-runtime-observation-receipt/v1",
            "authoritative": False,
            "execution": execution,
            "observation": observation,
        }
        receipt["receipt_sha256"] = hashlib.sha256(
            canonical_json_bytes(receipt)
        ).hexdigest()
        destination = output_dir / RECEIPT_NAME
        _publish(destination, canonical_json_bytes(receipt), uid=uid)
        return destination
    except BaseException as error:
        failure = error.failure if isinstance(error, ObservationError) else None
        runtime_removed = runtime is None
        if runtime is not None:
            # A failed revalidation intentionally preserves the private runtime
            # for diagnosis instead of making a false cleanup claim.
            try:
                remove_runtime(runtime, invoking_uid=uid)
                runtime_removed = True
            except BaseException:
                uncertain = ObservationCleanupUncertain(
                    f"runtime_forensic_state_preserved:{runtime.root}"
                )
                if failure is not None:
                    uncertain.failure = {**failure, "runtime_cleanup_confirmed": False}
                    try:
                        _publish_failure(output_dir, uncertain.failure, uid=uid)
                    except BaseException:
                        pass  # Cleanup uncertainty and the retained runtime stay authoritative.
                raise uncertain from error
        if failure is not None:
            failure = {**failure, "runtime_cleanup_confirmed": runtime_removed}
            try:
                _publish_failure(output_dir, failure, uid=uid)
            except BaseException as publication_error:
                if isinstance(error, ObservationCleanupUncertain):
                    raise error from publication_error
                raise ObservationError("failure_projection_publication_failed") from publication_error
        try:
            output_dir.rmdir()
        except OSError:
            pass
        raise


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--docker-executable", type=Path, required=True)
    parser.add_argument("--docker-sha256", required=True)
    parser.add_argument("--buildx-executable", type=Path, required=True)
    parser.add_argument("--buildx-sha256", required=True)
    parser.add_argument("--docker-host", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        path = produce(
            arguments.output_dir,
            docker_executable=arguments.docker_executable,
            docker_sha256=arguments.docker_sha256,
            buildx_executable=arguments.buildx_executable,
            buildx_sha256=arguments.buildx_sha256,
            docker_host=arguments.docker_host,
        )
    except ObservationCleanupUncertain as exc:
        print(str(exc), file=sys.stderr)
        return 75
    except (ObservationError, DockerRuntimeContractError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
