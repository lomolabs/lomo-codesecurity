from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
from threading import Lock
from typing import Any
from uuid import uuid4

from fastapi import Request
from sqlalchemy import create_engine, select, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.schema import CreateIndex, CreateSchema, CreateTable, DropSchema, MetaData

from .schema_inventory import (
    CatalogInventory,
    catalog_inventory_difference,
    catalog_inventory_is_empty,
    read_catalog_inventory,
)
from .settings import Settings


class Base(DeclarativeBase):
    pass


@dataclass(slots=True)
class Runtime:
    """Application-scoped resources shared by one control-plane instance."""

    settings: Settings
    engine: Engine
    session_factory: sessionmaker[Session]
    owns_engine: bool = False
    schema_identity: str | None = field(default=None, init=False)
    schema_fingerprint: str | None = field(default=None, init=False)
    schema_initialized_at: datetime | None = field(default=None, init=False)
    _state_lock: Any = field(default_factory=Lock, init=False, repr=False, compare=False)
    _app_claimed: bool = field(default=False, init=False, repr=False, compare=False)
    _engine_disposed: bool = field(default=False, init=False, repr=False, compare=False)

    @classmethod
    def create(cls, settings: Settings, *, engine: Engine | None = None) -> Runtime:
        owns_engine = engine is None
        active_engine = engine
        if active_engine is None:
            active_engine = create_engine(
                settings.database_url,
                pool_pre_ping=True,
                future=True,
            )
        return cls(
            settings=settings,
            engine=active_engine,
            session_factory=sessionmaker(
                bind=active_engine,
                autoflush=False,
                autocommit=False,
                future=True,
            ),
            owns_engine=owns_engine,
        )

    def claim_for_app(self) -> None:
        """Reserve this runtime for one application factory."""

        with self._state_lock:
            if self._engine_disposed:
                raise RuntimeError("application runtime has already been disposed")
            if self._app_claimed:
                raise RuntimeError("application runtime is already attached to an app")
            self._app_claimed = True

    def release_failed_app_claim(self) -> None:
        """Permit retry only when factory assembly never returned an app."""

        with self._state_lock:
            self._app_claimed = False

    def dispose(self) -> None:
        """Dispose an internally owned engine at most once."""

        with self._state_lock:
            if not self.owns_engine or self._engine_disposed:
                return
            # Mark first so concurrent shutdown paths cannot dispose the same pool.
            self._engine_disposed = True
        self.engine.dispose()


def get_runtime(request: Request) -> Runtime:
    runtime = getattr(request.app.state, "runtime", None)
    if not isinstance(runtime, Runtime):
        raise RuntimeError("application runtime is not initialized")
    return runtime


def get_runtime_settings(request: Request) -> Settings:
    return get_runtime(request).settings


class SchemaInitializationError(RuntimeError):
    """The database cannot be initialized or verified as the initial schema."""


class SchemaDialectError(SchemaInitializationError):
    """The configured database cannot host the initial schema contract."""


class SchemaNamespaceError(SchemaInitializationError):
    """The configured PostgreSQL namespace is ambiguous or unavailable."""


class SchemaStructureError(SchemaInitializationError):
    """The pinned namespace does not exactly match the model-owned structure."""


class SchemaIdentityError(SchemaInitializationError):
    """A required immutable schema identity or singleton seed is invalid."""


class SchemaSingletonStateError(SchemaInitializationError):
    """A required initialized singleton row disappeared at runtime."""


@dataclass(frozen=True, slots=True)
class SchemaVerification:
    """Verified immutable database identity returned to API and worker startup."""

    identity: str
    fingerprint: str
    initialized_at: datetime


_SCHEMA_INIT_LOCK_ID = 21297445770945859


def _require_postgresql(connection: Connection) -> None:
    if connection.dialect.name != "postgresql":
        raise SchemaDialectError(
            f"unsupported database dialect {connection.dialect.name!r}; schema-init requires PostgreSQL"
        )


def _lock_schema_initialization(connection: Connection) -> None:
    _require_postgresql(connection)
    connection.exec_driver_sql(
        f"SELECT pg_catalog.pg_advisory_xact_lock({_SCHEMA_INIT_LOCK_ID})"
    )


def _stable_ddl_text(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n").strip()


def schema_fingerprint(metadata: MetaData | None = None) -> str:
    """Return a stable digest of the PostgreSQL DDL owned by ``Base.metadata``."""

    from . import models  # noqa: F401

    target = metadata or Base.metadata
    dialect = postgresql.dialect()
    statements: list[str] = []
    for table in target.sorted_tables:
        statements.append(_stable_ddl_text(str(CreateTable(table).compile(dialect=dialect))))
        for index in sorted(table.indexes, key=lambda item: item.name or ""):
            statements.append(
                _stable_ddl_text(str(CreateIndex(index).compile(dialect=dialect)))
            )
    document = json.dumps(
        {"dialect": "postgresql", "ddl": statements},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(document).hexdigest()


@dataclass(frozen=True, slots=True)
class _PinnedNamespace:
    name: str
    oid: int


def _pin_namespace(connection: Connection) -> _PinnedNamespace:
    row = connection.execute(
        text(
            "SELECT pg_catalog.current_schema() AS name, "
            "pg_catalog.current_schemas(false) AS explicit_schemas, "
            "(SELECT oid FROM pg_catalog.pg_namespace "
            "WHERE nspname = pg_catalog.current_schema()) AS oid"
        )
    ).one()
    if not isinstance(row.name, str) or not row.name or not isinstance(row.oid, int):
        raise SchemaNamespaceError(
            "schema-init requires one existing PostgreSQL namespace selected by search_path"
        )
    if row.name in {"pg_catalog", "information_schema"} or row.name.startswith("pg_"):
        raise SchemaNamespaceError("schema-init refuses PostgreSQL system namespaces")
    if list(row.explicit_schemas or []) != [row.name]:
        raise SchemaNamespaceError(
            "schema-init requires search_path to resolve to exactly one explicit namespace"
        )
    return _PinnedNamespace(name=row.name, oid=row.oid)


def _schema_connection(connection: Connection, namespace: str) -> Connection:
    return connection.execution_options(schema_translate_map={None: namespace})


def _catalog_inventory_with_visible_namespace(
    connection: Connection,
    namespace: _PinnedNamespace,
) -> CatalogInventory:
    original_search_path = connection.scalar(text("SHOW search_path"))
    if not isinstance(original_search_path, str):
        raise SchemaNamespaceError("PostgreSQL did not return its current search_path")
    quoted = connection.dialect.identifier_preparer.quote_schema(namespace.name)
    connection.execute(
        text("SELECT pg_catalog.set_config('search_path', :value, true)"),
        {"value": f"pg_catalog, {quoted}"},
    )
    try:
        return read_catalog_inventory(
            connection,
            namespace_oid=namespace.oid,
            visible_namespace=namespace.name,
        )
    finally:
        connection.execute(
            text("SELECT pg_catalog.set_config('search_path', :value, true)"),
            {"value": original_search_path},
        )


def _scratch_inventory(connection: Connection) -> CatalogInventory:
    scratch_name = f"lomo_schema_check_{uuid4().hex}"
    scratch_created = False
    try:
        connection.execute(CreateSchema(scratch_name))
        scratch_created = True
        Base.metadata.create_all(
            _schema_connection(connection, scratch_name),
            checkfirst=False,
        )
        scratch_oid = connection.scalar(
            text("SELECT oid FROM pg_catalog.pg_namespace WHERE nspname = :name"),
            {"name": scratch_name},
        )
        if not isinstance(scratch_oid, int):
            raise SchemaNamespaceError("schema verifier scratch namespace disappeared")
        return _catalog_inventory_with_visible_namespace(
            connection,
            _PinnedNamespace(name=scratch_name, oid=scratch_oid),
        )
    finally:
        if scratch_created:
            connection.execute(DropSchema(scratch_name, cascade=True))


def _verify_seed_rows(
    connection: Connection,
    namespace: _PinnedNamespace,
) -> SchemaVerification:
    from .models import (
        INITIAL_SCHEMA_IDENTITY,
        EventDispatchState,
        ScannerLifecycleState,
        SchemaIdentity,
    )

    scoped = _schema_connection(connection, namespace.name)
    identities = list(
        scoped.execute(
            select(
                SchemaIdentity.id,
                SchemaIdentity.schema_id,
                SchemaIdentity.schema_fingerprint,
                SchemaIdentity.initialized_at,
            )
        )
    )
    expected_fingerprint = schema_fingerprint()
    if len(identities) != 1:
        raise SchemaIdentityError("schema_identity must contain exactly one initial identity")
    row_id, identity, fingerprint, initialized_at = identities[0]
    if (
        row_id != 1
        or identity != INITIAL_SCHEMA_IDENTITY
        or fingerprint != expected_fingerprint
    ):
        raise SchemaIdentityError("schema_identity does not match this 0.1.0 model shape")
    if not isinstance(initialized_at, datetime):
        raise SchemaIdentityError("schema_identity initialized_at is invalid")

    dispatch_rows = list(
        scoped.execute(select(EventDispatchState.id, EventDispatchState.next_event_id))
    )
    if len(dispatch_rows) != 1 or dispatch_rows[0].id != 1:
        raise SchemaIdentityError("event_dispatch_state must contain only singleton id 1")
    if not isinstance(dispatch_rows[0].next_event_id, int) or dispatch_rows[0].next_event_id < 1:
        raise SchemaIdentityError("event_dispatch_state has an invalid next event id")

    lifecycle_ids = list(
        scoped.scalars(select(ScannerLifecycleState.id).order_by(ScannerLifecycleState.id))
    )
    if lifecycle_ids != ["cache", "catalog"]:
        raise SchemaIdentityError(
            "scanner_lifecycle_state must contain exactly cache and catalog"
        )
    return SchemaVerification(
        identity=identity,
        fingerprint=fingerprint,
        initialized_at=initialized_at,
    )


def _verify_or_initialize_connection(
    connection: Connection,
    *,
    allow_initialize: bool,
) -> SchemaVerification:
    from . import models  # noqa: F401

    _lock_schema_initialization(connection)
    namespace = _pin_namespace(connection)
    initial_inventory = _catalog_inventory_with_visible_namespace(
        connection, namespace
    )
    if catalog_inventory_is_empty(initial_inventory):
        if not allow_initialize:
            raise SchemaStructureError(
                "database schema is empty; run the one-shot schema-init service first"
            )
        Base.metadata.create_all(
            _schema_connection(connection, namespace.name),
            checkfirst=False,
        )

    expected_inventory = _scratch_inventory(connection)
    # PostgreSQL catalog renderers are visibility-sensitive. Render each
    # namespace while it is the sole user namespace in search_path; both sides
    # then use the same unqualified identifier form without rewriting literals.
    actual_inventory = _catalog_inventory_with_visible_namespace(connection, namespace)
    difference = catalog_inventory_difference(actual_inventory, expected_inventory)
    if difference:
        raise SchemaStructureError(
            f"database schema does not exactly match the initial model shape: {difference}"
        )
    return _verify_seed_rows(connection, namespace)


def assert_database_schema_current(
    bind: Engine | Connection,
) -> SchemaVerification:
    """Verify the sole initial PostgreSQL schema without changing product state."""

    try:
        if isinstance(bind, Connection):
            return _verify_or_initialize_connection(bind, allow_initialize=False)
        with bind.begin() as connection:
            return _verify_or_initialize_connection(connection, allow_initialize=False)
    except SchemaInitializationError:
        raise
    except SQLAlchemyError as exc:
        raise SchemaInitializationError(
            "database schema verification could not complete"
        ) from exc


def init_db(bind: Engine | Connection) -> SchemaVerification:
    """Fail closed unless the initial database schema is exactly current."""

    return assert_database_schema_current(bind)


def initialize_database(bind: Engine) -> SchemaVerification:
    """Create the initial schema only in a truly empty PostgreSQL namespace."""

    try:
        with bind.begin() as connection:
            return _verify_or_initialize_connection(connection, allow_initialize=True)
    except SchemaInitializationError:
        raise
    except SQLAlchemyError as exc:
        raise SchemaInitializationError(
            "database initial-schema creation or verification could not complete"
        ) from exc


def get_db(request: Request) -> Generator[Session, None, None]:
    db = get_runtime(request).session_factory()
    try:
        yield db
    finally:
        db.close()
