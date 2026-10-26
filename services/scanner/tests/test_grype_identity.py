from __future__ import annotations

import hashlib
import itertools
import os
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
import xxhash

from kodesec_scanner import grype_identity
from kodesec_scanner.grype_identity import GrypeIdentityError, compute_grype_logical_identity


def _database(path: Path, *, reversed_indexes: bool = False) -> Path:
    path = path.resolve()
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE packages (id INTEGER PRIMARY KEY, name TEXT, version TEXT, value)")
        db.executemany("INSERT INTO packages VALUES (?,?,?,?)", [
            (1, "alpha", "1", None), (2, "beta", "2", 42),
            (3, "gamma", "3", 1.5), (4, "delta", "4", b"binary\x00value"),
        ])
        db.execute("CREATE TABLE metadata (value TEXT UNIQUE)")
        db.execute("INSERT INTO metadata VALUES ('synthetic-v6')")
        indexes = ["CREATE INDEX packages_name ON packages (name)",
                   "CREATE INDEX packages_version ON packages (version)"]
        for sql in reversed(indexes) if reversed_indexes else indexes:
            db.execute(sql)
        db.commit()
    return path


def _identity(path: Path, **kwargs: object):
    return compute_grype_logical_identity(path, maximum_bytes=8 * 1024 * 1024,
                                          timeout_seconds=10, **kwargs)


def test_index_allocation_changes_physical_bytes_not_logical_identity(tmp_path: Path) -> None:
    first = _database(tmp_path / "first.db")
    second = _database(tmp_path / "second.db", reversed_indexes=True)
    first_bytes, second_bytes = first.read_bytes(), second.read_bytes()
    assert first_bytes != second_bytes

    left, right = _identity(first), _identity(second)

    assert left.algorithm == right.algorithm == "kodesec-grype-v6-logical-db-v1"
    assert left.sha256 == right.sha256
    assert left.physical_sha256 == hashlib.sha256(first_bytes).hexdigest()
    assert right.physical_sha256 == hashlib.sha256(second_bytes).hexdigest()
    assert left.physical_sha256 != right.physical_sha256
    assert left.physical_xxh64 == "xxh64:" + xxhash.xxh64(first_bytes).hexdigest()
    assert right.physical_xxh64 == "xxh64:" + xxhash.xxh64(second_bytes).hexdigest()
    assert left.schema_count == right.schema_count == 5
    assert left.table_count == right.table_count == 2
    assert left.row_count == right.row_count == 5
    assert left.logical_bytes == right.logical_bytes > 0
    assert first.read_bytes() == first_bytes and second.read_bytes() == second_bytes
    assert sorted(item.name for item in tmp_path.iterdir()) == ["first.db", "second.db"]


def test_typed_fixture_has_stable_logical_framing(tmp_path: Path) -> None:
    identity = _identity(_database(tmp_path / "golden.db"))
    assert identity.sha256 == "77aedfd66cbb1f849351f9a196d41fecc4f93b106e42b16227aeb8f4763fbc28"
    assert identity.logical_bytes == 1175
    assert (identity.schema_count, identity.table_count, identity.row_count) == (5, 2, 5)


@pytest.mark.parametrize("change", [
    "UPDATE packages SET name='changed' WHERE id=1",
    "UPDATE packages SET id=9 WHERE id=1",
    "INSERT INTO packages(name,version,value) SELECT name,version,value FROM packages WHERE id=1",
    "DROP INDEX packages_name",
    "CREATE INDEX packages_value ON packages (value)",
])
def test_data_rowid_multiplicity_and_index_schema_are_authenticated(tmp_path: Path, change: str) -> None:
    path = _database(tmp_path / "db")
    before = _identity(path)
    with closing(sqlite3.connect(path)) as db:
        db.execute(change)
        db.commit()
    assert _identity(path).sha256 != before.sha256


def test_sqlite_storage_types_have_distinct_framing(tmp_path: Path) -> None:
    identities = set()
    for index, value in enumerate([None, 1, 1.0, "1", b"1", "a\x00b", b"a\x00b"]):
        path = tmp_path.resolve() / str(index)
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE sample (value)")
            db.execute("INSERT INTO sample VALUES (?)", (value,))
            db.commit()
        identities.add(_identity(path).sha256)
    assert len(identities) == 7


@pytest.mark.parametrize('mmap_bytes', [0, 2 * 1024 * 1024 * 1024])
def test_full_integrity_check_rejects_inconsistent_secondary_index(tmp_path: Path, monkeypatch, mmap_bytes) -> None:
    monkeypatch.setattr(grype_identity, 'SQLITE_MMAP_BYTES', mmap_bytes)
    path = _database(tmp_path / "db")
    with closing(sqlite3.connect(path)) as db:
        # Only the synthetic fixture writer is allowed to damage its index.
        db.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, False)
        db.execute("PRAGMA writable_schema=ON")
        db.execute("UPDATE sqlite_schema SET sql='CREATE INDEX packages_name ON packages (version)' "
                   "WHERE name='packages_name'")
        db.commit()
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("PRAGMA quick_check").fetchall() == [("ok",)]
        assert db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]
    with pytest.raises(GrypeIdentityError) as error:
        _identity(path)
    assert error.value.code == "integrity"
    assert str(error.value) == "Grype logical database validation failed: integrity"


@pytest.mark.parametrize("sql", [
    "CREATE TABLE sample (id INTEGER PRIMARY KEY) WITHOUT ROWID",
    "CREATE TABLE sample (rowid INTEGER, value TEXT)",
    "CREATE TABLE sample (_ROWID_ INTEGER, value TEXT)",
    "CREATE TABLE sample (OID INTEGER, value TEXT)",
    "CREATE TABLE sample (value INTEGER, calculated INTEGER GENERATED ALWAYS AS (value+1))",
    "CREATE VIEW sample AS SELECT 1",
    "CREATE VIRTUAL TABLE sample USING fts5(value)",
    "CREATE TABLE sample (value); CREATE TRIGGER sample_insert AFTER INSERT ON sample BEGIN SELECT 1; END",
])
def test_unsupported_sqlite_layouts_do_not_fall_back(tmp_path: Path, sql: str) -> None:
    path = tmp_path.resolve() / "db"
    with closing(sqlite3.connect(path)) as db:
        db.executescript(sql)
        db.commit()
    with pytest.raises(GrypeIdentityError) as error:
        _identity(path)
    assert error.value.code == "schema"


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_sidecar_databases_are_not_treated_as_immutable(tmp_path: Path, suffix: str) -> None:
    path = _database(tmp_path / "db")
    path.with_name(path.name + suffix).write_bytes(b"synthetic")
    with pytest.raises(GrypeIdentityError, match=": file$"):
        _identity(path)


@pytest.mark.parametrize("alias", ["symlink", "hardlink"])
def test_file_aliases_are_rejected(tmp_path: Path, alias: str) -> None:
    path = _database(tmp_path / "db")
    target = tmp_path.resolve() / "alias"
    if alias == "symlink":
        target.symlink_to(path)
    else:
        os.link(path, target)
    with pytest.raises(GrypeIdentityError, match=": file$"):
        _identity(target)


def test_physical_and_logical_size_limits_are_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _database(tmp_path / "db")
    with pytest.raises(GrypeIdentityError, match=": size$"):
        compute_grype_logical_identity(path, maximum_bytes=path.stat().st_size - 1, timeout_seconds=10)
    monkeypatch.setattr(grype_identity, "MAX_LOGICAL_BYTES", 100)
    with pytest.raises(GrypeIdentityError, match=": size$"):
        _identity(path)


def test_deadline_does_not_depend_on_wall_clock_sleeps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _database(tmp_path / "db")
    monotonic = itertools.count()
    monkeypatch.setattr(grype_identity.time, "monotonic", lambda: next(monotonic))
    with pytest.raises(GrypeIdentityError, match=": deadline$"):
        compute_grype_logical_identity(path, maximum_bytes=path.stat().st_size, timeout_seconds=0.5)


@pytest.mark.parametrize("error_type", [RuntimeError, ValueError, OSError, GrypeIdentityError])
@pytest.mark.parametrize("in_sqlite", [False, True])
@pytest.mark.parametrize('mmap_bytes', [0, 2 * 1024 * 1024 * 1024])
def test_checkpoint_errors_retain_identity_across_python_and_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_type: type[Exception], in_sqlite: bool, mmap_bytes,
) -> None:
    monkeypatch.setattr(grype_identity, 'SQLITE_MMAP_BYTES', mmap_bytes)
    path = _database(tmp_path / "db")
    before = path.read_bytes()
    failure = error_type("cancelled")
    inside_progress = False
    connections = []
    connect = sqlite3.connect

    class ObservedConnection(sqlite3.Connection):
        def set_progress_handler(self, callback, operations):
            def observe():
                nonlocal inside_progress
                inside_progress = True
                try:
                    return callback()
                finally:
                    inside_progress = False
            super().set_progress_handler(observe, operations)

    def observed_connect(*args, **kwargs):
        result = connect(*args, **kwargs, factory=ObservedConnection)
        connections.append(result)
        return result

    calls = 0

    def checkpoint():
        nonlocal calls
        calls += 1
        if (in_sqlite and inside_progress) or (not in_sqlite and calls == 2):
            raise failure

    monkeypatch.setattr(grype_identity.sqlite3, "connect", observed_connect)
    monkeypatch.setattr(grype_identity, "CHECKPOINT_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(grype_identity, "SQL_PROGRESS_OPERATIONS", 1)
    with pytest.raises(error_type) as error:
        _identity(path, checkpoint=checkpoint)
    assert error.value is failure
    assert bool(connections) == in_sqlite
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
    assert path.read_bytes() == before


def test_changed_file_is_rejected_during_physical_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _database(tmp_path / "db")
    calls = 0

    def checkpoint():
        nonlocal calls
        calls += 1
        if calls == 2:
            with path.open("ab") as output:
                output.write(b"changed")

    monkeypatch.setattr(grype_identity, "CHECKPOINT_INTERVAL_SECONDS", 0)
    with pytest.raises(GrypeIdentityError, match=": changed$"):
        _identity(path, checkpoint=checkpoint)


def test_database_errors_are_redacted(tmp_path: Path) -> None:
    path = tmp_path.resolve() / "db"
    path.write_bytes(b"not SQLite; synthetic sensitive error context")
    with pytest.raises(GrypeIdentityError) as error:
        _identity(path)
    assert error.value.code == "database"
    assert str(error.value) == "Grype logical database validation failed: database"


@pytest.mark.parametrize("observe_only", [False, True])
def test_physical_hash_failure_records_phase_without_replacing_error(tmp_path, monkeypatch, observe_only):
    path = _database(tmp_path / "db")
    failure = GrypeIdentityError("deadline")

    def fail(*_args):
        raise failure

    monkeypatch.setattr(grype_identity, "_physical_identity", fail)
    with pytest.raises(GrypeIdentityError) as caught:
        if observe_only:
            grype_identity.observe_grype_file(path, maximum_bytes=path.stat().st_size, timeout_seconds=10)
        else:
            _identity(path)
    assert caught.value is failure
    timing = grype_identity.bounded_validation_timing(failure.validation_timing)
    assert timing["phase"] == "physical_hash"
    assert 0 <= timing["phase_elapsed_ms"] <= timing["validation_elapsed_ms"] <= 900_000


@pytest.mark.parametrize(("marker", "phase"), [
    ("SELECT type,name", "sqlite_schema"),
    ("PRAGMA integrity_check", "sqlite_integrity"),
    ("SELECT _rowid_", "logical_rows"),
])
@pytest.mark.parametrize('mmap_bytes', [0, 2 * 1024 * 1024 * 1024])
def test_sql_failure_phase_preserves_deadline_and_closes_connection(tmp_path, monkeypatch, marker, phase, mmap_bytes):
    monkeypatch.setattr(grype_identity, 'SQLITE_MMAP_BYTES', mmap_bytes)
    path = _database(tmp_path / "db")
    original = sqlite3.connect
    connections = []
    failure = GrypeIdentityError("deadline")

    class ObservedConnection(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith(marker):
                raise failure
            return super().execute(sql, *args)

    def connect(*args, **kwargs):
        connection = original(*args, **kwargs, factory=ObservedConnection)
        connections.append(connection)
        return connection

    monkeypatch.setattr(grype_identity.sqlite3, "connect", connect)
    with pytest.raises(GrypeIdentityError) as caught:
        _identity(path)
    assert caught.value is failure
    assert grype_identity.bounded_validation_timing(failure.validation_timing)["phase"] == phase
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


@pytest.mark.parametrize("timing", [
    None, {"phase": "logical_rows"},
    grype_identity.GrypeValidationTiming("untrusted/private/path", 0, 0, False),
    grype_identity.GrypeValidationTiming("logical_rows", True, 1, False),
    grype_identity.GrypeValidationTiming("logical_rows", -1, 0, False),
    grype_identity.GrypeValidationTiming("logical_rows", 1, 0, False),
    grype_identity.GrypeValidationTiming("logical_rows", 0, 900_001, False),
])
def test_timing_projection_rejects_unbounded_or_untrusted_fields(timing):
    assert grype_identity.bounded_validation_timing(timing) is None


def test_phase_timing_caps_overrun_explicitly_without_changing_error(monkeypatch):
    failure = GrypeIdentityError("deadline")
    monkeypatch.setattr(grype_identity.time, "monotonic", lambda: 901.0)
    assert grype_identity._annotate_timing(failure, "logical_rows", 0.0, 10.0) is failure
    assert grype_identity.bounded_validation_timing(failure.validation_timing) == {
        "phase": "logical_rows", "phase_elapsed_ms": 891_000,
        "validation_elapsed_ms": 900_000, "capped": True,
    }


def _integer_width_fixture(path: Path) -> Path:
    path = path.resolve()
    with closing(sqlite3.connect(path)) as db:
        # The reader includes rowid, giving actual record widths five and six.
        db.execute("CREATE TABLE ints4 (a,b,c,d)")
        db.execute("CREATE TABLE ints5 (a,b,c,d,e)")
        db.executemany("INSERT INTO ints4 VALUES (?,?,?,?)", [
            (0, -1, 2**63 - 1, -2**63), (4, 5, 6, 7),
            (None, "text", 1.5, b"bytes"),
        ])
        db.executemany("INSERT INTO ints5 VALUES (?,?,?,?,?)", [
            (1, 2, 3, 4, 5), (0, -1, 2**63 - 1, -2**63, 17),
            (6, None, b"x", 1.25, "text"),
        ])
        db.commit()
    return path


def test_integer_widths_and_mixed_fallback_have_stable_identity(tmp_path: Path) -> None:
    path = _integer_width_fixture(tmp_path / "integer-widths.db")
    identity = _identity(path)
    assert identity.sha256 == "dbd441af1bda4e6aca5a70aa63b1b862be3159ae24079d933121c7306b08adc3"
    assert identity.logical_bytes == 995
    assert (identity.schema_count, identity.table_count, identity.row_count) == (2, 2, 6)


def test_integer_widths_preserve_row_size_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _integer_width_fixture(tmp_path / "integer-widths.db")
    monkeypatch.setattr(grype_identity, "MAX_ROW_BYTES", 84)
    with pytest.raises(GrypeIdentityError) as error:
        _identity(path)
    assert error.value.code == "size"


def test_integer_row_crossing_total_limit_still_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = (tmp_path / "two-integer-rows.db").resolve()
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE ints4 (a,b,c,d)")
        db.executemany("INSERT INTO ints4 VALUES (?,?,?,?)", [(1, 2, 3, 4), (5, 6, 7, 8)])
        db.commit()
    full = _identity(path)
    # One final footer is 9-byte header plus 17-byte integer. This cap is
    # one byte below the end of the second 85-byte integer record, so the
    # failure occurs in a width-five row, not in the footer.
    monkeypatch.setattr(grype_identity, "MAX_LOGICAL_BYTES", full.logical_bytes - 27)
    with pytest.raises(GrypeIdentityError) as error:
        _identity(path)
    assert error.value.code == "size"


def test_slow_checkpoint_does_not_repeat_for_every_database_row(monkeypatch):
    now = 0.0
    calls = 0

    def checkpoint():
        nonlocal now, calls
        calls += 1
        now += .15  # Slow VM filesystem read exceeds the normal poll interval.

    monkeypatch.setattr(grype_identity.time, 'monotonic', lambda: now)
    check = grype_identity._validation_checkpoint(1024, 10, checkpoint)
    check()
    for _ in range(1000):
        check()
    assert calls == 1
    now += .1
    check()
    assert calls == 2
    check(force=True)
    assert calls == 3


def test_checkpoint_time_counts_toward_original_deadline(monkeypatch):
    now = 0.0

    def checkpoint():
        nonlocal now
        now = 10.0

    monkeypatch.setattr(grype_identity.time, 'monotonic', lambda: now)
    check = grype_identity._validation_checkpoint(1024, 10, checkpoint)
    with pytest.raises(GrypeIdentityError) as error:
        check()
    assert error.value.code == 'deadline'


def test_expensive_clock_reads_do_not_dominate_small_row_validation(tmp_path, monkeypatch):
    path = (tmp_path / 'clock.db').resolve()
    with closing(sqlite3.connect(path)) as db:
        db.execute('CREATE TABLE ints (a,b,c,d)')
        db.executemany('INSERT INTO ints VALUES (?,?,?,?)',
                       ((i, i + 1, -i, i % 7) for i in range(20_000)))
        db.commit()
    now = 0.0
    def costly_clock():
        nonlocal now
        now += 0.00005  # Observed WSL clock cost, modeled without wall sleeps.
        return now
    monkeypatch.setattr(grype_identity.time, 'monotonic', costly_clock)
    identity = compute_grype_logical_identity(path, maximum_bytes=path.stat().st_size,
                                              timeout_seconds=0.2)
    # Golden captured with the unchanged, per-row-clock implementation.
    assert identity.sha256 == '0a9cbdd385699707c924c7b3c9b1964153314f28f168607847e549fe17e9e738'
    assert identity.row_count == 20_000 and identity.logical_bytes == 1_880_221
    assert now < 0.2


@pytest.mark.parametrize('payload_size,maximum_rows', [(1, 64), (70_000, 1)])
def test_row_and_byte_batches_keep_cancellation_bounded(tmp_path, monkeypatch, payload_size, maximum_rows):
    path = (tmp_path / 'cancel.db').resolve()
    payload = 'x' * payload_size
    with closing(sqlite3.connect(path)) as db:
        db.execute('CREATE TABLE content (value TEXT)')
        db.executemany('INSERT INTO content VALUES (?)', [(payload,)] * 100)
        db.commit()
    original = path.read_bytes()
    encoded_rows = 0
    encode = grype_identity._field
    def field(value):
        nonlocal encoded_rows
        if value == payload:
            encoded_rows += 1
        return encode(value)
    stopped = RuntimeError('owned cancellation')
    def checkpoint():
        if encoded_rows:
            raise stopped
    monkeypatch.setattr(grype_identity, '_field', field)
    monkeypatch.setattr(grype_identity, 'CHECKPOINT_INTERVAL_SECONDS', 0)
    with pytest.raises(RuntimeError) as error:
        _identity(path, checkpoint=checkpoint)
    assert error.value is stopped
    assert 1 <= encoded_rows <= maximum_rows
    assert path.read_bytes() == original


def test_final_short_batch_cannot_publish_after_original_deadline(tmp_path, monkeypatch):
    path = _database(tmp_path / 'late.db')
    now = 0.0
    encode = grype_identity._field
    def field(value):
        nonlocal now
        encoded = encode(value)
        if value == b'binary\x00value':
            now = 11.0
        return encoded
    monkeypatch.setattr(grype_identity.time, 'monotonic', lambda: now)
    monkeypatch.setattr(grype_identity, '_field', field)
    with pytest.raises(GrypeIdentityError, match=': deadline$'):
        _identity(path)


@pytest.mark.parametrize('sizes', [
    [0, 1, 2047, 2048, 2049, 17],
    [65535, 1, 65536, 65537, 3],
    [17] * 8000,
    [1, 1024 * 1024, 1],
])
def test_buffered_logical_digest_preserves_stream_across_boundaries(sizes):
    expected = hashlib.sha256()
    actual = grype_identity._BufferedLogicalDigest()
    for index, size in enumerate(sizes):
        value = bytes([index % 251]) * size
        expected.update(value)
        actual.update(value)
        assert len(actual._buffer) < grype_identity.HASH_BUFFER_BYTES
    assert actual.hexdigest() == expected.hexdigest()
    assert actual.hexdigest() == expected.hexdigest()
    actual.update(b'after flush')
    expected.update(b'after flush')
    assert actual.hexdigest() == expected.hexdigest()


def test_final_hash_flush_cannot_publish_after_original_deadline(tmp_path, monkeypatch):
    path = _database(tmp_path / 'late-flush.db')
    now = 0.0
    finish = grype_identity._BufferedLogicalDigest.hexdigest

    def late_finish(self):
        nonlocal now
        result = finish(self)
        now = 11.0
        return result

    monkeypatch.setattr(grype_identity.time, 'monotonic', lambda: now)
    monkeypatch.setattr(grype_identity._BufferedLogicalDigest, 'hexdigest', late_finish)
    with pytest.raises(GrypeIdentityError, match=': deadline$'):
        _identity(path)


def test_larger_fixed_page_cache_preserves_the_exact_logical_and_physical_identity(tmp_path, monkeypatch):
    path = _database(tmp_path / 'page-cache.db')
    monkeypatch.setattr(grype_identity, 'SQLITE_PAGE_CACHE_KIB', 8192)
    baseline = _identity(path)
    monkeypatch.setattr(grype_identity, 'SQLITE_PAGE_CACHE_KIB', 65536)
    candidate = _identity(path)
    assert candidate == baseline


def test_readonly_mapping_preserves_identity_and_never_writes_the_database(tmp_path, monkeypatch):
    path = _database(tmp_path / 'mapped.db')
    original_bytes = path.read_bytes()
    monkeypatch.setattr(grype_identity, 'SQLITE_MMAP_BYTES', 0)
    baseline = _identity(path)
    monkeypatch.setattr(grype_identity, 'SQLITE_MMAP_BYTES', 2 * 1024 * 1024 * 1024)
    assert _identity(path) == baseline
    assert path.read_bytes() == original_bytes
    assert [item.name for item in tmp_path.iterdir()] == ['mapped.db']


@pytest.mark.parametrize('code', ['cancelled', 'deadline'])
@pytest.mark.parametrize('mmap_bytes', [0, 2 * 1024 * 1024 * 1024])
def test_full_integrity_callback_still_interrupts_with_mapping(tmp_path, monkeypatch, code, mmap_bytes):
    path = _database(tmp_path / 'interrupted.db')
    original_bytes = path.read_bytes()
    original_connect = sqlite3.connect
    inside_integrity = False
    failure = GrypeIdentityError(code)

    class IntegrityConnection(sqlite3.Connection):
        def execute(self, sql, *args):
            nonlocal inside_integrity
            inside_integrity = sql == 'PRAGMA integrity_check(1)'
            try:
                return super().execute(sql, *args)
            finally:
                inside_integrity = False

    def checkpoint():
        if inside_integrity:
            raise failure

    monkeypatch.setattr(grype_identity, 'SQLITE_MMAP_BYTES', mmap_bytes)
    monkeypatch.setattr(grype_identity, 'SQL_PROGRESS_OPERATIONS', 1)
    monkeypatch.setattr(grype_identity, 'CHECKPOINT_INTERVAL_SECONDS', 0)
    monkeypatch.setattr(grype_identity.sqlite3, 'connect',
        lambda *args, **kwargs: original_connect(*args, **kwargs, factory=IntegrityConnection))
    with pytest.raises(GrypeIdentityError) as caught:
        _identity(path, checkpoint=checkpoint)
    assert caught.value is failure
    assert grype_identity.bounded_validation_timing(failure.validation_timing)['phase'] == 'sqlite_integrity'
    assert path.read_bytes() == original_bytes
