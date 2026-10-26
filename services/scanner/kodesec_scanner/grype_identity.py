"""Read-only identity for Grype v6's rowid-preserving database hydration.

Hydration may create secondary indexes in different orders. Their definitions
and full integrity matter; their physical page allocation does not. This is
not a generic SQLite equivalence algorithm: unsupported table layouts fail
closed, and rowids remain part of the reviewed dataset identity.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import sqlite3
import stat
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, get_args

import xxhash


GRYPE_LOGICAL_DB_ALGORITHM = "kodesec-grype-v6-logical-db-v1"
GRYPE_DATABASE_RELATIVE_PATH = "6/vulnerability.db"
MAX_DATABASE_BYTES = 4 * 1024 * 1024 * 1024
MAX_LOGICAL_BYTES = 8 * 1024 * 1024 * 1024
MAX_ROW_BYTES = 16 * 1024 * 1024
MAX_SCHEMA_OBJECTS = 128
MAX_COLUMNS = 64
MAX_ROWS = 100_000_000
MAX_SECONDS = 900
CHECKPOINT_INTERVAL_SECONDS = 0.1
SQL_PROGRESS_OPERATIONS = 10_000
ROW_CHECK_INTERVAL = 64
ROW_CHECK_BYTES = 64 * 1024
HASH_BUFFER_BYTES = 64 * 1024
SQLITE_PAGE_CACHE_KIB = 64 * 1024
SQLITE_MMAP_BYTES = 2 * 1024 * 1024 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_ROWID_ALIASES = frozenset({"rowid", "_rowid_", "oid"})
ErrorCode = Literal["file", "changed", "size", "deadline", "cancelled", "schema", "integrity", "data", "database"]
ValidationPhase = Literal["file_admission", "physical_hash", "sqlite_schema", "sqlite_integrity", "logical_rows", "final_fence"]
MAX_TIMING_MS = MAX_SECONDS * 1000


@dataclass(frozen=True)
class GrypeValidationTiming:
    phase: ValidationPhase
    phase_elapsed_ms: int
    validation_elapsed_ms: int
    capped: bool


def bounded_validation_timing(value: object) -> dict[str, str | int | bool] | None:
    """Project only fixed phases and bounded numbers, never database content."""
    if (type(value) is not GrypeValidationTiming or type(value.phase) is not str
            or value.phase not in get_args(ValidationPhase)
            or type(value.capped) is not bool
            or any(type(number) is not int or not 0 <= number <= MAX_TIMING_MS
                   for number in (value.phase_elapsed_ms, value.validation_elapsed_ms))
            or value.phase_elapsed_ms > value.validation_elapsed_ms):
        return None
    return {"phase": value.phase, "phase_elapsed_ms": value.phase_elapsed_ms,
            "validation_elapsed_ms": value.validation_elapsed_ms, "capped": value.capped}


def _annotate_timing(error: GrypeIdentityError, phase: ValidationPhase,
                     started: float, phase_started: float) -> GrypeIdentityError:
    elapsed = time.monotonic()
    total = max(0, math.ceil((elapsed - started) * 1000))
    stage = min(total, max(0, math.ceil((elapsed - phase_started) * 1000)))
    error.validation_timing = GrypeValidationTiming(
        phase, min(stage, MAX_TIMING_MS), min(total, MAX_TIMING_MS), total > MAX_TIMING_MS,
    )
    return error


class GrypeIdentityError(ValueError):
    """A bounded reason only; never include SQLite values or error messages."""

    def __init__(self, code: ErrorCode) -> None:
        self.code = code
        self.validation_timing: GrypeValidationTiming | None = None
        super().__init__(f"Grype logical database validation failed: {code}")


@dataclass(frozen=True)
class GrypeLogicalIdentity:
    algorithm: str
    sha256: str
    physical_sha256: str
    physical_xxh64: str
    schema_count: int
    table_count: int
    row_count: int
    logical_bytes: int


@dataclass(frozen=True)
class GrypeFileObservation:
    """Fresh byte hashes plus a same-call change fence, never a cache key by stat."""

    sha256: str
    xxh64: str
    size_bytes: int
    _path: Path
    _identity: tuple[int, ...]

    def require_unchanged(self) -> None:
        if _file_identity(_inspect_file(self._path)) != self._identity:
            raise GrypeIdentityError("changed")


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _inspect_file(path: Path) -> os.stat_result:
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise GrypeIdentityError("file")
        result = path.lstat()
        if not stat.S_ISREG(result.st_mode) or result.st_nlink != 1:
            raise GrypeIdentityError("file")
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = path.with_name(path.name + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                raise GrypeIdentityError("file")
        return result
    except OSError:
        raise GrypeIdentityError("file") from None


def _physical_identity(
    path: Path, before: os.stat_result, maximum_bytes: int, check: Callable[[], None],
) -> tuple[str, str]:
    sha256, xxh64 = hashlib.sha256(), xxhash.xxh64()
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        source = os.fdopen(descriptor, "rb")
    except OSError:
        raise GrypeIdentityError("file") from None
    with source:
        try:
            if _file_identity(os.fstat(source.fileno())) != _file_identity(before):
                raise GrypeIdentityError("changed")
        except OSError:
            raise GrypeIdentityError("file") from None
        read_bytes = 0
        while True:
            try:
                chunk = source.read(1024 * 1024)
            except OSError:
                raise GrypeIdentityError("file") from None
            if not chunk:
                break
            check()
            read_bytes += len(chunk)
            if read_bytes > maximum_bytes:
                raise GrypeIdentityError("size")
            sha256.update(chunk)
            xxh64.update(chunk)
        try:
            if (read_bytes != before.st_size
                    or _file_identity(os.fstat(source.fileno())) != _file_identity(before)):
                raise GrypeIdentityError("changed")
        except OSError:
            raise GrypeIdentityError("file") from None
    return sha256.hexdigest(), "xxh64:" + xxh64.hexdigest()


def _field(value: object) -> bytes:
    if value is None:
        prefix, payload = b"N\x00\x00\x00\x00\x00\x00\x00\x00", b""
    elif type(value) is int:
        prefix, payload = b"I\x00\x00\x00\x00\x00\x00\x00\x08", struct.pack(">q", value)
    elif type(value) is float and math.isfinite(value):
        prefix, payload = b"R\x00\x00\x00\x00\x00\x00\x00\x08", struct.pack(">d", value)
    elif type(value) is str:
        try:
            payload = value.encode("utf-8")
            prefix = b"T" + struct.pack(">Q", len(payload))
        except UnicodeError:
            raise GrypeIdentityError("data") from None
    elif type(value) is bytes:
        payload = value
        prefix = b"B" + struct.pack(">Q", len(payload))
    else:
        raise GrypeIdentityError("data")
    if len(payload) > MAX_ROW_BYTES:
        raise GrypeIdentityError("size")
    return prefix + payload


class _BufferedLogicalDigest:
    """Hash the same framed stream without a native hash call for every field."""

    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self._buffer = bytearray()

    def _flush(self) -> None:
        if self._buffer:
            self._digest.update(self._buffer)
            self._buffer.clear()

    def update(self, value: bytes) -> None:
        if len(value) >= HASH_BUFFER_BYTES:
            self._flush()
            self._digest.update(value)
        else:
            self._buffer.extend(value)
            # Each appended value is smaller than the threshold, so retained
            # bytes remain below twice the threshold, even before flushing.
            if len(self._buffer) >= HASH_BUFFER_BYTES:
                self._flush()

    def hexdigest(self) -> str:
        self._flush()
        return self._digest.hexdigest()


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise GrypeIdentityError("schema")
    return value


def _validation_checkpoint(
    maximum_bytes: int,
    timeout_seconds: float,
    checkpoint: Callable[[], object] | None,
) -> Callable[..., None]:
    if (type(maximum_bytes) is not int or not 0 < maximum_bytes <= MAX_DATABASE_BYTES
            or isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= MAX_SECONDS):
        raise ValueError("invalid Grype logical identity limits")
    if checkpoint is not None and not callable(checkpoint):
        raise TypeError("checkpoint must be callable")
    deadline = time.monotonic() + timeout_seconds
    next_checkpoint = 0.0

    def check(*, force: bool = False) -> None:
        nonlocal next_checkpoint
        now = time.monotonic()
        if now >= deadline:
            raise GrypeIdentityError("deadline")
        if checkpoint is not None and (force or now >= next_checkpoint):
            checkpoint()
            # A slow durable-state read must not make every subsequent SQL
            # row perform another read. Space checks from their completion;
            # callback time still counts against the original hard deadline.
            finished = time.monotonic()
            if finished >= deadline:
                raise GrypeIdentityError("deadline")
            next_checkpoint = finished + CHECKPOINT_INTERVAL_SECONDS

    return check


def observe_grype_file(
    path: Path,
    *,
    maximum_bytes: int,
    timeout_seconds: float,
    checkpoint: Callable[[], object] | None = None,
) -> GrypeFileObservation:
    """Hash an actual Grype file with the same bounds and alias/sidecar guards.

    The caller must call require_unchanged after its final checkpoint and
    before publishing or reusing a proof. Only these freshly read byte hashes,
    never the same-call metadata fence, may identify reusable validation.
    """
    check = _validation_checkpoint(maximum_bytes, timeout_seconds, checkpoint)
    started = phase_started = time.monotonic()
    phase: ValidationPhase = "file_admission"
    try:
        check(force=True)
        before = _inspect_file(path)
        if not 0 < before.st_size <= maximum_bytes:
            raise GrypeIdentityError("size")
        phase, phase_started = "physical_hash", time.monotonic()
        sha256, xxh64 = _physical_identity(path, before, maximum_bytes, check)
        observation = GrypeFileObservation(sha256, xxh64, before.st_size, path, _file_identity(before))
        phase, phase_started = "final_fence", time.monotonic()
        check(force=True)
        observation.require_unchanged()
        return observation
    except GrypeIdentityError as exc:
        _annotate_timing(exc, phase, started, phase_started)
        raise


def compute_grype_logical_identity(
    path: Path,
    *,
    maximum_bytes: int,
    timeout_seconds: float,
    checkpoint: Callable[[], object] | None = None,
    _observation_sink: list[GrypeFileObservation] | None = None,
) -> GrypeLogicalIdentity:
    """Hash actual database contents, without trusting an import/cache receipt.

    The caller owns archive authentication and the private, non-concurrent
    generation boundary. This reader also rejects path aliases, sidecars,
    hardlinks and changed file metadata. SQLite never writes this database.
    Known checkpoint exception families are relayed unchanged across SQLite's
    callback boundary; they are not converted to a generic database failure.
    """
    if _observation_sink is not None and (
        type(_observation_sink) is not list or _observation_sink
    ):
        raise ValueError("Grype observation sink must be an empty list")
    check = _validation_checkpoint(maximum_bytes, timeout_seconds, checkpoint)
    started = phase_started = time.monotonic()
    phase: ValidationPhase = "file_admission"
    callback_error: GrypeIdentityError | RuntimeError | ValueError | OSError | None = None

    def progress() -> int:
        nonlocal callback_error
        try:
            check()
        except (GrypeIdentityError, RuntimeError, ValueError, OSError) as exc:
            # sqlite3 replaces callback exceptions with "interrupted". Keep
            # these explicit caller-boundary failures for unchanged re-raise.
            callback_error = exc
            return 1
        return 0

    connection: sqlite3.Connection | None = None
    try:
        check(force=True)
        before = _inspect_file(path)
        if not 0 < before.st_size <= maximum_bytes:
            raise GrypeIdentityError("size")
        phase, phase_started = "physical_hash", time.monotonic()
        physical_sha256, physical_xxh64 = _physical_identity(path, before, maximum_bytes, check)
        observation = GrypeFileObservation(
            physical_sha256, physical_xxh64, before.st_size, path, _file_identity(before)
        )
        observation.require_unchanged()
        phase, phase_started = "sqlite_schema", time.monotonic()
        if sqlite3.sqlite_version_info < (3, 37, 0):
            raise GrypeIdentityError("schema")
        connection = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True,
                                     isolation_level=None, timeout=0)
        # Python builds without extension-loading support omit this API; that
        # is already the stronger boundary, not a reason to enable a fallback.
        if hasattr(connection, "enable_load_extension"):
            connection.enable_load_extension(False)
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_ROW_BYTES)
        connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, MAX_COLUMNS)
        connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 1024 * 1024)
        connection.set_progress_handler(progress, SQL_PROGRESS_OPERATIONS)
        # Read-only file-backed pages avoid copying the large hydrated database
        # into SQLite's heap cache. SQLite may clamp or disable this mapping;
        # remaining pages still use ordinary reads and the same full checks.
        for setting in ("query_only=ON", "trusted_schema=OFF", "temp_store=MEMORY",
                        f"cache_size=-{SQLITE_PAGE_CACHE_KIB}", f"mmap_size={SQLITE_MMAP_BYTES}"):
            connection.execute("PRAGMA " + setting)

        allowed_pragmas = {"table_list", "table_xinfo", "integrity_check"}

        def authorize(action: int, first: str | None, _second: str | None,
                      _database: str | None, _source: str | None) -> int:
            if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ):
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_PRAGMA and first in allowed_pragmas:
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        connection.set_authorizer(authorize)
        schema = connection.execute(
            "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type COLLATE BINARY,name COLLATE BINARY"
        ).fetchmany(MAX_SCHEMA_OBJECTS + 1)
        if not schema or len(schema) > MAX_SCHEMA_OBJECTS:
            raise GrypeIdentityError("schema")
        tables: dict[str, list[str]] = {}
        layouts = {row[1]: row for row in connection.execute("PRAGMA table_list") if row[0] == "main"}
        for kind, name, table, sql in schema:
            name, table = _identifier(name), _identifier(table)
            if kind not in ("table", "index") or (sql is not None and not isinstance(sql, str)):
                raise GrypeIdentityError("schema")
            if sql is None and not (kind == "index" and name.startswith("sqlite_autoindex_")):
                raise GrypeIdentityError("schema")
            if kind == "table":
                layout = layouts.get(name)
                if layout is None or layout[2] != "table" or layout[4] != 0:
                    raise GrypeIdentityError("schema")
                columns = list(connection.execute(f'PRAGMA table_xinfo("{name}")'))
                if not columns or len(columns) >= MAX_COLUMNS or any(row[6] != 0 for row in columns):
                    raise GrypeIdentityError("schema")
                names = [_identifier(row[1]) for row in columns]
                if any(name.lower() in _ROWID_ALIASES for name in names):
                    raise GrypeIdentityError("schema")
                tables[name] = names
        phase, phase_started = "sqlite_integrity", time.monotonic()
        integrity = connection.execute("PRAGMA integrity_check(1)")
        if integrity.fetchone() != ("ok",) or integrity.fetchone() is not None:
            raise GrypeIdentityError("integrity")
        phase, phase_started = "logical_rows", time.monotonic()
        digest = _BufferedLogicalDigest()
        logical_bytes = 0

        # Grype's largest relation tables commonly have five or six integer
        # fields including rowid. Pack those rows together; other storage
        # classes and widths retain the general, checked field encoder.
        integer_prefix = b"I\x00\x00\x00\x00\x00\x00\x00\x08"
        integer_row5 = struct.Struct(">" + "9sq" * 5)
        integer_row6 = struct.Struct(">" + "9sq" * 6)

        def record(header: bytes, values: tuple[object, ...]) -> None:
            nonlocal logical_bytes
            logical_bytes += len(header)
            digest.update(header)
            framed = None
            if len(values) == 5:
                a, b, c, d, e = values
                if (type(a) is int and type(b) is int and type(c) is int
                        and type(d) is int and type(e) is int):
                    framed = integer_row5.pack(
                        integer_prefix, a, integer_prefix, b, integer_prefix, c,
                        integer_prefix, d, integer_prefix, e,
                    )
            elif len(values) == 6:
                a, b, c, d, e, f = values
                if (type(a) is int and type(b) is int and type(c) is int
                        and type(d) is int and type(e) is int and type(f) is int):
                    framed = integer_row6.pack(
                        integer_prefix, a, integer_prefix, b, integer_prefix, c,
                        integer_prefix, d, integer_prefix, e, integer_prefix, f,
                    )
            if framed is not None:
                # Fixed framing exactly matches _field(int), byte for byte.
                logical_bytes += len(framed)
                if len(framed) > MAX_ROW_BYTES or logical_bytes > MAX_LOGICAL_BYTES:
                    raise GrypeIdentityError("size")
                digest.update(framed)
                return
            row_bytes = 0
            for value in values:
                encoded = _field(value)
                row_bytes += len(encoded)
                logical_bytes += len(encoded)
                if row_bytes > MAX_ROW_BYTES or logical_bytes > MAX_LOGICAL_BYTES:
                    raise GrypeIdentityError("size")
                digest.update(encoded)

        record(b"D" + struct.pack(">Q", 1), (GRYPE_LOGICAL_DB_ALGORITHM,))
        schema_header = b"S" + struct.pack(">Q", 4)
        for definition in schema:
            record(schema_header, definition)
        row_count = 0
        for table, columns in sorted(tables.items()):
            check()
            record(b"T" + struct.pack(">Q", len(columns) + 1), (table, *columns))
            row_header = b"R" + struct.pack(">Q", len(columns) + 1)
            selection = ",".join(f'"{name}"' for name in columns)
            cursor = connection.execute(
                f'SELECT _rowid_,{selection} FROM main."{table}" NOT INDEXED ORDER BY _rowid_'
            )
            table_rows = 0
            checked_rows = row_count
            checked_bytes = logical_bytes
            for row in cursor:
                row_count += 1
                table_rows += 1
                if row_count > MAX_ROWS:
                    raise GrypeIdentityError("size")
                record(row_header, row)
                # On nested Windows virtualization, reading the monotonic
                # clock can cost more than encoding a row. Bound work between
                # reads by both rows and bytes; a large row checks immediately.
                # SQLite progress and the final deadline fence remain active.
                if (row_count - checked_rows >= ROW_CHECK_INTERVAL
                        or logical_bytes - checked_bytes >= ROW_CHECK_BYTES):
                    check()
                    checked_rows = row_count
                    checked_bytes = logical_bytes
            record(b"E" + struct.pack(">Q", 1), (table_rows,))
        logical_sha256 = digest.hexdigest()
        phase, phase_started = "final_fence", time.monotonic()
        check(force=True)
        observation.require_unchanged()
        result = GrypeLogicalIdentity(
            GRYPE_LOGICAL_DB_ALGORITHM, logical_sha256, physical_sha256,
            physical_xxh64, len(schema), len(tables), row_count, logical_bytes,
        )
    except GrypeIdentityError as exc:
        _annotate_timing(exc, phase, started, phase_started)
        raise
    except sqlite3.Error:
        if callback_error is not None:
            if isinstance(callback_error, GrypeIdentityError):
                _annotate_timing(callback_error, phase, started, phase_started)
            raise callback_error
        raise _annotate_timing(GrypeIdentityError("database"), phase, started, phase_started) from None
    finally:
        if connection is not None:
            connection.close()
    if _observation_sink is not None:
        _observation_sink.append(observation)
    return result
