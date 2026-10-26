from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import CheckConstraint, Column, MetaData, Table, Text, create_engine, inspect, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateSchema

from conftest import API_ROOT
from kodesec_api import models  # noqa: F401
from kodesec_api.db import (
    Base,
    SchemaDialectError,
    SchemaIdentityError,
    SchemaInitializationError,
    SchemaNamespaceError,
    SchemaStructureError,
    assert_database_schema_current,
    initialize_database,
    schema_fingerprint,
)
from kodesec_api.models import INITIAL_SCHEMA_IDENTITY


# The initial schema includes the durable IDE enrollment table and its constraints.
EXPECTED_SCHEMA_FINGERPRINT = "7bc3a623198fdc10b22dd8662ff86565b2165feccd19b61a40590c857dc74c32"


def _table_oids(engine) -> dict[str, int]:
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT relname, oid FROM pg_class "
                "WHERE relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema()) "
                "AND relkind = 'r' ORDER BY relname"
            )
        )
        return {str(name): int(oid) for name, oid in rows}


def _sentinel_state(engine) -> tuple[set[str], list[tuple[int, str]], dict[str, int]]:
    tables = set(inspect(engine).get_table_names())
    rows: list[tuple[int, str]] = []
    if "preexisting_data" in tables:
        with engine.connect() as connection:
            rows = [
                (int(row.id), str(row.value))
                for row in connection.execute(
                    text("SELECT id, value FROM preexisting_data ORDER BY id")
                )
            ]
    return tables, rows, _table_oids(engine)


def test_initial_schema_identity_and_fingerprint_are_stable() -> None:
    assert INITIAL_SCHEMA_IDENTITY == "lomo-kodesec-0.1.0-initial"
    assert schema_fingerprint() == EXPECTED_SCHEMA_FINGERPRINT
    assert len(schema_fingerprint()) == 64
    assert set(schema_fingerprint()) <= set("0123456789abcdef")


def test_schema_fingerprint_preserves_whitespace_inside_constraint_literals() -> None:
    def fingerprint_for(literal: str) -> str:
        metadata = MetaData()
        Table(
            "literal_fixture",
            metadata,
            Column("value", Text(), nullable=False),
            CheckConstraint(
                f"value <> '{literal}'",
                name="ck_literal_fixture_value",
            ),
        )
        return schema_fingerprint(metadata)

    assert fingerprint_for("a  b") != fingerprint_for("a b")


def test_non_postgresql_schema_init_is_rejected() -> None:
    sqlite_engine = create_engine("sqlite://", future=True)
    try:
        with pytest.raises(SchemaDialectError, match="requires PostgreSQL"):
            initialize_database(sqlite_engine)
        with pytest.raises(SchemaDialectError, match="requires PostgreSQL"):
            assert_database_schema_current(sqlite_engine)
    finally:
        sqlite_engine.dispose()


def test_empty_postgresql_is_created_from_metadata_with_exact_seeds(postgres_engine) -> None:
    with pytest.raises(SchemaStructureError, match="schema is empty"):
        assert_database_schema_current(postgres_engine)

    verification = initialize_database(postgres_engine)
    assert verification.identity == INITIAL_SCHEMA_IDENTITY
    assert verification.fingerprint == EXPECTED_SCHEMA_FINGERPRINT
    assert set(inspect(postgres_engine).get_table_names()) == set(Base.metadata.tables)
    assert assert_database_schema_current(postgres_engine) == verification

    with postgres_engine.connect() as connection:
        identity = connection.execute(
            text(
                "SELECT id, schema_id, schema_fingerprint, initialized_at "
                "FROM schema_identity"
            )
        ).one()
        lifecycle_rows = connection.execute(
            text(
                "SELECT id, status, revision, receipt, job_id "
                "FROM scanner_lifecycle_state ORDER BY id"
            )
        ).mappings().all()
        dispatch_row = connection.execute(
            text("SELECT id, next_event_id FROM event_dispatch_state")
        ).one()
    assert identity.id == 1
    assert identity.schema_id == INITIAL_SCHEMA_IDENTITY
    assert identity.schema_fingerprint == EXPECTED_SCHEMA_FINGERPRINT
    assert identity.initialized_at is not None
    assert [dict(row) for row in lifecycle_rows] == [
        {"id": "cache", "status": "idle", "revision": 1, "receipt": {}, "job_id": None},
        {"id": "catalog", "status": "idle", "revision": 1, "receipt": {}, "job_id": None},
    ]
    assert dispatch_row == (1, 1)


def test_postgresql_finding_constraint_persists_points_and_rejects_reversed_ranges(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    with Session(postgres_engine) as session:
        project = models.Project(name="point-range", repo_path="/fixture/point-range")
        session.add(project)
        session.flush()
        scan = models.Scan(project_id=project.id, status="completed")
        session.add(scan)
        session.flush()
        point = models.Finding(
            scan_id=scan.id,
            scan_finding_number=1,
            scanner="trivy",
            rule_id="fixture.insertion-point",
            severity="high",
            file_path="Dockerfile",
            start_line=1,
            start_column=1,
            end_line=1,
            end_column=1,
            message="fixture insertion point",
            fingerprint="f" * 64,
        )
        session.add(point)
        session.commit()
        point_id = point.id
        scan_id = scan.id

    with Session(postgres_engine) as session:
        persisted = session.get(models.Finding, point_id)
        assert persisted is not None
        assert (persisted.start_line, persisted.start_column) == (1, 1)
        assert (persisted.end_line, persisted.end_column) == (1, 1)

    with pytest.raises(IntegrityError):
        with Session(postgres_engine) as session:
            session.add(
                models.Finding(
                    scan_id=scan_id,
                    scan_finding_number=2,
                    scanner="fixture",
                    rule_id="fixture.reversed-range",
                    severity="high",
                    file_path="Dockerfile",
                    start_line=1,
                    start_column=2,
                    end_line=1,
                    end_column=1,
                    message="fixture reversed range",
                    fingerprint="e" * 64,
                )
            )
            session.commit()


def test_exact_schema_restart_is_verification_only_and_preserves_live_singletons(
    postgres_engine,
) -> None:
    first = initialize_database(postgres_engine)
    before_oids = _table_oids(postgres_engine)
    with postgres_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO runtime_config (key, value) "
                "VALUES ('schema-restart-preservation', 'preserve-me')"
            )
        )
        connection.execute(
            text("UPDATE event_dispatch_state SET next_event_id = 41 WHERE id = 1")
        )
        connection.execute(
            text(
                "UPDATE scanner_lifecycle_state "
                "SET status = 'completed', revision = 7, receipt = '{\"schema_version\": 1}' "
                "WHERE id = 'catalog'"
            )
        )

    second = initialize_database(postgres_engine)
    assert second == first
    assert _table_oids(postgres_engine) == before_oids
    with postgres_engine.connect() as connection:
        assert connection.scalar(
            text("SELECT value FROM runtime_config WHERE key = 'schema-restart-preservation'")
        ) == "preserve-me"
        assert connection.scalar(
            text("SELECT next_event_id FROM event_dispatch_state WHERE id = 1")
        ) == 41
        assert connection.execute(
            text(
                "SELECT status, revision, receipt FROM scanner_lifecycle_state "
                "WHERE id = 'catalog'"
            )
        ).one() == ("completed", 7, {"schema_version": 1})


def test_nonempty_unknown_database_is_rejected_without_mutation(postgres_engine) -> None:
    with postgres_engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE preexisting_data (id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.exec_driver_sql(
            "INSERT INTO preexisting_data (id, value) VALUES (1, 'preserve-me')"
        )
    before = _sentinel_state(postgres_engine)

    with pytest.raises(SchemaStructureError, match="does not exactly match"):
        initialize_database(postgres_engine)

    assert _sentinel_state(postgres_engine) == before
    assert "schema_identity" not in inspect(postgres_engine).get_table_names()


def test_standalone_namespace_object_prevents_initial_creation(postgres_engine) -> None:
    with postgres_engine.begin() as connection:
        connection.exec_driver_sql('CREATE COLLATION unexpected_collation FROM "C"')

    with pytest.raises(SchemaStructureError, match="does not exactly match"):
        initialize_database(postgres_engine)

    assert inspect(postgres_engine).get_table_names() == []
    with postgres_engine.connect() as connection:
        assert connection.scalar(
            text(
                "SELECT count(*) FROM pg_catalog.pg_collation "
                "WHERE collnamespace = (SELECT oid FROM pg_catalog.pg_namespace "
                "WHERE nspname = pg_catalog.current_schema()) "
                "AND collname = 'unexpected_collation'"
            )
        ) == 1


def test_standalone_namespace_object_is_rejected_after_initialization(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    with postgres_engine.begin() as connection:
        connection.exec_driver_sql('CREATE COLLATION unexpected_collation FROM "C"')

    with pytest.raises(SchemaStructureError, match="does not exactly match"):
        assert_database_schema_current(postgres_engine)

    with postgres_engine.connect() as connection:
        assert connection.scalar(
            text(
                "SELECT count(*) FROM pg_catalog.pg_collation "
                "WHERE collnamespace = (SELECT oid FROM pg_catalog.pg_namespace "
                "WHERE nspname = pg_catalog.current_schema()) "
                "AND collname = 'unexpected_collation'"
            )
        ) == 1


@pytest.mark.parametrize(
    "statement",
    [
        "DROP INDEX ix_findings_fingerprint",
        "ALTER TABLE projects ALTER COLUMN default_branch DROP NOT NULL",
        "ALTER TABLE projects ALTER COLUMN revision SET DEFAULT 9",
    ],
    ids=["missing-index", "wrong-nullability", "wrong-default"],
)
def test_structural_drift_is_rejected_without_mutation(postgres_engine, statement: str) -> None:
    initialize_database(postgres_engine)
    with postgres_engine.begin() as connection:
        connection.exec_driver_sql(statement)
    before_oids = _table_oids(postgres_engine)

    with pytest.raises(SchemaStructureError, match="does not exactly match"):
        initialize_database(postgres_engine)
    with pytest.raises(SchemaStructureError, match="does not exactly match"):
        assert_database_schema_current(postgres_engine)

    assert _table_oids(postgres_engine) == before_oids


@pytest.mark.parametrize(
    "statements",
    [
        ("CREATE VIEW unexpected_view AS SELECT 1 AS value",),
        ("CREATE MATERIALIZED VIEW unexpected_materialized AS SELECT 1 AS value",),
        ("CREATE SEQUENCE unexpected_sequence",),
        ("ALTER TABLE projects ENABLE ROW LEVEL SECURITY",),
        (
            "CREATE FUNCTION format_type(oid, integer) RETURNS text LANGUAGE plpgsql "
            "AS 'BEGIN RAISE EXCEPTION ''catalog shadow invoked''; END'",
        ),
        (
            "CREATE FUNCTION unexpected_trigger_fn() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'",
            "CREATE TRIGGER unexpected_trigger BEFORE INSERT ON projects FOR EACH ROW EXECUTE FUNCTION unexpected_trigger_fn()",
        ),
        (
            "ALTER TABLE projects ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY unexpected_policy ON projects USING (true)",
        ),
    ],
    ids=[
        "view",
        "materialized-view",
        "sequence",
        "row-security",
        "hostile-catalog-shadow",
        "trigger",
        "row-policy",
    ],
)
def test_unexpected_namespace_objects_are_rejected(
    postgres_engine,
    statements: tuple[str, ...],
) -> None:
    initialize_database(postgres_engine)
    with postgres_engine.begin() as connection:
        for statement in statements:
            connection.exec_driver_sql(statement)

    with pytest.raises(SchemaStructureError, match="does not exactly match"):
        initialize_database(postgres_engine)


def test_schema_drift_error_is_bounded_and_does_not_expose_definition_body(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    marker = "fixture-private-schema-body"
    body = marker + (" x" * 4000)
    with postgres_engine.begin() as connection:
        connection.execute(
            text(
                "CREATE FUNCTION unexpected_private_body() RETURNS text LANGUAGE sql "
                "AS :body"
            ),
            {"body": f"SELECT '{body}'::text"},
        )

    with pytest.raises(SchemaStructureError) as failure:
        initialize_database(postgres_engine)
    rendered = str(failure.value)
    assert marker not in rendered
    assert len(rendered) < 2000


def test_missing_seed_is_rejected_without_runtime_recreation(postgres_engine) -> None:
    initialize_database(postgres_engine)
    with postgres_engine.begin() as connection:
        connection.execute(text("DELETE FROM event_dispatch_state WHERE id = 1"))

    with pytest.raises(SchemaIdentityError, match="event_dispatch_state"):
        initialize_database(postgres_engine)
    with postgres_engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM event_dispatch_state")) == 0


def test_schema_identity_rejects_non_hex_fingerprint(postgres_engine) -> None:
    verification = initialize_database(postgres_engine)
    with pytest.raises(IntegrityError):
        with postgres_engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE schema_identity SET schema_fingerprint = :fingerprint "
                    "WHERE id = 1"
                ),
                {"fingerprint": "z" * 64},
            )
    assert assert_database_schema_current(postgres_engine) == verification


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        (
            "UPDATE schema_identity SET schema_fingerprint = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' WHERE id = 1",
            "schema_identity",
        ),
        (
            "DELETE FROM scanner_lifecycle_state WHERE id = 'cache'",
            "scanner_lifecycle_state",
        ),
    ],
    ids=["wrong-fingerprint", "missing-lifecycle-seed"],
)
def test_invalid_initial_identity_state_is_rejected_without_replacement(
    postgres_engine,
    statement: str,
    message: str,
) -> None:
    initialize_database(postgres_engine)
    with postgres_engine.begin() as connection:
        connection.execute(text(statement))

    with pytest.raises(SchemaIdentityError, match=message):
        initialize_database(postgres_engine)


def test_connection_verification_restores_exact_search_path(postgres_engine) -> None:
    initialize_database(postgres_engine)
    with postgres_engine.begin() as connection:
        before = connection.execute(
            text("SELECT current_setting('search_path'), current_schema()")
        ).one()
        assert_database_schema_current(connection)
        after = connection.execute(
            text("SELECT current_setting('search_path'), current_schema()")
        ).one()
        assert after == before
        assert connection.scalar(text("SELECT count(*) FROM schema_identity")) == 1


def test_connection_verification_restores_search_path_after_drift_error(
    postgres_engine,
) -> None:
    initialize_database(postgres_engine)
    with postgres_engine.begin() as connection:
        connection.execute(text("DROP INDEX ix_findings_fingerprint"))
        before = connection.execute(
            text("SELECT current_setting('search_path'), current_schema()")
        ).one()
        with pytest.raises(SchemaStructureError):
            assert_database_schema_current(connection)
        after = connection.execute(
            text("SELECT current_setting('search_path'), current_schema()")
        ).one()
        assert after == before
        assert connection.scalar(text("SELECT count(*) FROM schema_identity")) == 1


def test_ambiguous_search_path_is_rejected_without_rewriting_it(postgres_engine) -> None:
    initialize_database(postgres_engine)
    with postgres_engine.begin() as connection:
        namespace = connection.scalar(text("SELECT current_schema()"))
        assert isinstance(namespace, str)
        quoted = connection.dialect.identifier_preparer.quote_schema(namespace)
        requested_path = f"{quoted}, public"
        connection.execute(
            text("SELECT set_config('search_path', :value, true)"),
            {"value": requested_path},
        )
        before = connection.scalar(text("SHOW search_path"))
        with pytest.raises(SchemaNamespaceError, match="exactly one explicit namespace"):
            assert_database_schema_current(connection)
        assert connection.scalar(text("SHOW search_path")) == before


def test_scratch_namespace_is_removed_after_verification(postgres_engine) -> None:
    initialize_database(postgres_engine)
    assert_database_schema_current(postgres_engine)
    with postgres_engine.connect() as connection:
        assert connection.scalar(
            text(
                "SELECT count(*) FROM pg_namespace "
                "WHERE nspname LIKE 'lomo_schema_check_%'"
            )
        ) == 0


def test_scratch_namespace_permission_failure_is_typed_and_leaves_no_scratch(
    postgres_engine,
    monkeypatch,
) -> None:
    initialize_database(postgres_engine)
    original_execute = Connection.execute

    def deny_scratch(self, statement, *args, **kwargs):
        if isinstance(statement, CreateSchema):
            raise SQLAlchemyError("fixture create-schema denial")
        return original_execute(self, statement, *args, **kwargs)

    monkeypatch.setattr(Connection, "execute", deny_scratch)
    with pytest.raises(SchemaInitializationError, match="verification could not complete"):
        assert_database_schema_current(postgres_engine)
    with postgres_engine.connect() as connection:
        assert connection.scalar(
            text(
                "SELECT count(*) FROM pg_namespace "
                "WHERE nspname LIKE 'lomo_schema_check_%'"
            )
        ) == 0


def test_initial_ddl_and_seed_failure_roll_back_together(
    postgres_engine,
    monkeypatch,
) -> None:
    monkeypatch.setattr("kodesec_api.db.schema_fingerprint", lambda: "invalid")
    with pytest.raises(SchemaInitializationError, match="creation or verification"):
        initialize_database(postgres_engine)
    assert inspect(postgres_engine).get_table_names() == []


def test_concurrent_empty_schema_initialization_is_serialized(postgres_engine) -> None:
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(lambda _: initialize_database(postgres_engine), range(2))
        )

    assert results == [results[0], results[0]]
    assert results[0].identity == INITIAL_SCHEMA_IDENTITY
    assert assert_database_schema_current(postgres_engine) == results[0]


def test_initializer_uses_one_metadata_creation_path_without_preflight_checks() -> None:
    source = (API_ROOT / "kodesec_api" / "db.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    create_all_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "create_all"
    ]
    assert len(create_all_calls) == 2
    for call in create_all_calls:
        keywords = {item.arg: item.value for item in call.keywords if item.arg is not None}
        assert isinstance(keywords.get("checkfirst"), ast.Constant)
        assert keywords["checkfirst"].value is False
