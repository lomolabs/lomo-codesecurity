from __future__ import annotations

import hashlib
from typing import Any, NamedTuple, TypeAlias

from sqlalchemy import text
from sqlalchemy.engine import Connection


class RelationRecord(NamedTuple):
    name: str
    kind: str
    persistence: str
    replica_identity: str
    row_security: bool
    force_row_security: bool
    options: tuple[str, ...]
    access_method: str | None
    tablespace: str | None
    partition_key: str | None
    partition_bound: str | None


class ColumnRecord(NamedTuple):
    relation_name: str
    ordinal: int
    name: str
    formatted_type: str | None
    not_null: bool
    default_expression: str | None
    identity: str
    generated: str
    collation_schema: str | None
    collation_name: str | None


class ConstraintRecord(NamedTuple):
    relation_name: str
    name: str
    kind: str
    definition: str | None
    deferrable: bool
    deferred: bool
    validated: bool
    local: bool
    inherited_count: int
    no_inherit: bool


class IndexRecord(NamedTuple):
    relation_name: str
    name: str
    unique: bool
    primary: bool
    valid: bool
    ready: bool
    live: bool
    replica_identity: bool
    nulls_not_distinct: bool
    clustered: bool
    exclusion: bool
    immediate: bool
    key_attribute_count: int
    attribute_count: int
    key: str
    collation: str
    operator_classes: str
    options_bits: str
    access_method: str
    relation_options: tuple[str, ...]
    tablespace: str | None
    columns: tuple[str | None, ...]
    predicate: str | None


class SequenceRecord(NamedTuple):
    name: str
    formatted_type: str | None
    start: Any
    increment: Any
    maximum: Any
    minimum: Any
    cache: Any
    cycles: bool
    owner_table: str | None
    owner_column: str | None


class TypeRecord(NamedTuple):
    name: str
    kind: str
    category: str
    not_null: bool
    base_type: str | None
    element_type: str | None
    type_modifier: int
    dimensions: int
    default: str | None
    composite_relation_kind: str | None
    collation_schema: str | None
    collation_name: str | None
    enum_labels: tuple[str, ...]
    range_subtype: str | None
    multirange_type: str | None


class TypeConstraintRecord(NamedTuple):
    type_name: str
    name: str
    kind: str
    definition: str | None
    validated: bool


class ViewRecord(NamedTuple):
    name: str
    kind: str
    populated: bool
    definition: str | None


class ForeignTableRecord(NamedTuple):
    relation_name: str
    server_name: str
    table_options: tuple[str, ...]
    server_options: tuple[str, ...]
    wrapper_name: str
    wrapper_options: tuple[str, ...]


class RoutineRecord(NamedTuple):
    name: str
    identity_arguments: str | None
    kind: str
    language: str
    return_type: str | None
    security_definer: bool
    leakproof: bool
    volatility: str
    parallel: str
    configuration: tuple[str | None, ...]
    definition: str | None


class TriggerRecord(NamedTuple):
    relation_name: str
    name: str
    enabled: str
    definition: str | None


class PolicyRecord(NamedTuple):
    relation_name: str
    name: str
    command: str
    permissive: bool
    roles: tuple[str, ...]
    qualifier: str | None
    with_check: str | None


class NamespaceDependencyClassRecord(NamedTuple):
    catalog_name: str
    object_count: int


CatalogRecord: TypeAlias = (
    RelationRecord
    | ColumnRecord
    | ConstraintRecord
    | IndexRecord
    | SequenceRecord
    | TypeRecord
    | TypeConstraintRecord
    | ViewRecord
    | ForeignTableRecord
    | RoutineRecord
    | TriggerRecord
    | PolicyRecord
    | NamespaceDependencyClassRecord
)
CatalogInventory: TypeAlias = dict[str, list[CatalogRecord]]


def _stable_definition(value: str | None) -> str | None:
    if value is None:
        return None
    return value.replace("\r\n", "\n").replace("\r", "\n").strip()


def _read_relations(connection: Connection, namespace_oid: int) -> list[CatalogRecord]:
    return [
        RelationRecord(
            row.relname,
            row.relkind,
            row.relpersistence,
            row.relreplident,
            row.relrowsecurity,
            row.relforcerowsecurity,
            tuple(sorted(row.reloptions or [])),
            row.access_method,
            row.tablespace,
            _stable_definition(row.partition_key),
            _stable_definition(row.partition_bound),
        )
        for row in connection.execute(
            text(
                "SELECT c.relname, c.relkind, c.relpersistence, c.relreplident, "
                "c.relrowsecurity, c.relforcerowsecurity, c.reloptions, "
                "am.amname AS access_method, ts.spcname AS tablespace, "
                "pg_catalog.pg_get_partkeydef(c.oid) AS partition_key, "
                "pg_catalog.pg_get_expr(c.relpartbound, c.oid, true) AS partition_bound "
                "FROM pg_catalog.pg_class c "
                "LEFT JOIN pg_catalog.pg_am am ON am.oid = c.relam "
                "LEFT JOIN pg_catalog.pg_tablespace ts ON ts.oid = c.reltablespace "
                "WHERE c.relnamespace = :namespace_oid "
                "AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f', 'c') "
                "ORDER BY c.relkind, c.relname"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def _read_columns(
    connection: Connection,
    namespace_oid: int,
    visible_namespace: str,
) -> list[CatalogRecord]:
    return [
        ColumnRecord(
            row.relname,
            row.attnum,
            row.attname,
            _stable_definition(row.formatted_type),
            row.attnotnull,
            _stable_definition(row.default_expression),
            row.attidentity,
            row.attgenerated,
            "<schema>" if row.collation_schema == visible_namespace else row.collation_schema,
            row.collation_name,
        )
        for row in connection.execute(
            text(
                "SELECT c.relname, a.attnum, a.attname, "
                "pg_catalog.format_type(a.atttypid, a.atttypmod) AS formatted_type, "
                "a.attnotnull, pg_catalog.pg_get_expr(d.adbin, d.adrelid, true) AS default_expression, "
                "a.attidentity, a.attgenerated, cn.nspname AS collation_schema, "
                "coll.collname AS collation_name "
                "FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid "
                "LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum "
                "LEFT JOIN pg_catalog.pg_collation coll "
                "ON coll.oid = a.attcollation AND a.attcollation <> 0 "
                "LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid = coll.collnamespace "
                "WHERE c.relnamespace = :namespace_oid "
                "AND c.relkind IN ('r', 'p', 'f') AND a.attnum > 0 AND NOT a.attisdropped "
                "ORDER BY c.relname, a.attnum"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def _read_constraints(connection: Connection, namespace_oid: int) -> list[CatalogRecord]:
    return [
        ConstraintRecord(
            row.relname,
            row.conname,
            row.contype,
            _stable_definition(row.definition),
            row.condeferrable,
            row.condeferred,
            row.convalidated,
            row.conislocal,
            row.coninhcount,
            row.connoinherit,
        )
        for row in connection.execute(
            text(
                "SELECT c.relname, k.conname, k.contype, "
                "pg_catalog.pg_get_constraintdef(k.oid, true) AS definition, "
                "k.condeferrable, k.condeferred, k.convalidated, "
                "k.conislocal, k.coninhcount, k.connoinherit "
                "FROM pg_catalog.pg_constraint k "
                "JOIN pg_catalog.pg_class c ON c.oid = k.conrelid "
                "WHERE c.relnamespace = :namespace_oid "
                "ORDER BY c.relname, k.conname"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def _read_indexes(connection: Connection, namespace_oid: int) -> list[CatalogRecord]:
    return [
        IndexRecord(
            row.relname,
            row.index_name,
            row.indisunique,
            row.indisprimary,
            row.indisvalid,
            row.indisready,
            row.indislive,
            row.indisreplident,
            row.indnullsnotdistinct,
            row.indisclustered,
            row.indisexclusion,
            row.indimmediate,
            row.indnkeyatts,
            row.indnatts,
            row.indkey,
            row.indcollation,
            row.indclass,
            row.indoption,
            row.access_method,
            tuple(sorted(row.reloptions or [])),
            row.tablespace,
            tuple(_stable_definition(item) for item in row.index_columns),
            _stable_definition(row.predicate),
        )
        for row in connection.execute(
            text(
                "SELECT c.relname, i.relname AS index_name, x.indisunique, "
                "x.indisprimary, x.indisvalid, x.indisready, x.indislive, "
                "x.indisreplident, x.indnullsnotdistinct, "
                "x.indisclustered, x.indisexclusion, x.indimmediate, "
                "x.indnkeyatts, x.indnatts, x.indkey::text AS indkey, "
                "x.indcollation::text AS indcollation, x.indclass::text AS indclass, "
                "x.indoption::text AS indoption, am.amname AS access_method, "
                "i.reloptions, ts.spcname AS tablespace, "
                "ARRAY(SELECT pg_catalog.pg_get_indexdef(i.oid, position, true) "
                "FROM pg_catalog.generate_series(1, x.indnatts) AS position "
                "ORDER BY position) AS index_columns, "
                "pg_catalog.pg_get_expr(x.indpred, x.indrelid, true) AS predicate "
                "FROM pg_catalog.pg_index x "
                "JOIN pg_catalog.pg_class i ON i.oid = x.indexrelid "
                "JOIN pg_catalog.pg_class c ON c.oid = x.indrelid "
                "JOIN pg_catalog.pg_am am ON am.oid = i.relam "
                "LEFT JOIN pg_catalog.pg_tablespace ts ON ts.oid = i.reltablespace "
                "WHERE c.relnamespace = :namespace_oid "
                "ORDER BY c.relname, i.relname"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def _read_sequences(connection: Connection, namespace_oid: int) -> list[CatalogRecord]:
    return [
        SequenceRecord(
            row.sequence_name,
            _stable_definition(row.sequence_type),
            row.seqstart,
            row.seqincrement,
            row.seqmax,
            row.seqmin,
            row.seqcache,
            row.seqcycle,
            row.owner_table,
            row.owner_column,
        )
        for row in connection.execute(
            text(
                "SELECT c.relname AS sequence_name, "
                "pg_catalog.format_type(s.seqtypid, NULL) AS sequence_type, "
                "s.seqstart, s.seqincrement, "
                "s.seqmax, s.seqmin, s.seqcache, s.seqcycle, "
                "owner.relname AS owner_table, a.attname AS owner_column "
                "FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_sequence s ON s.seqrelid = c.oid "
                "LEFT JOIN pg_catalog.pg_depend d "
                "ON d.objid = c.oid AND d.deptype IN ('a', 'i') "
                "LEFT JOIN pg_catalog.pg_class owner ON owner.oid = d.refobjid "
                "LEFT JOIN pg_catalog.pg_attribute a "
                "ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid "
                "WHERE c.relnamespace = :namespace_oid ORDER BY c.relname"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def _read_types(
    connection: Connection,
    namespace_oid: int,
    visible_namespace: str,
) -> list[CatalogRecord]:
    return [
        TypeRecord(
            row.typname,
            row.typtype,
            row.typcategory,
            row.typnotnull,
            _stable_definition(row.base_type),
            _stable_definition(row.element_type),
            row.typtypmod,
            row.typndims,
            _stable_definition(row.typdefault),
            row.composite_relkind,
            "<schema>" if row.collation_schema == visible_namespace else row.collation_schema,
            row.collation_name,
            tuple(row.enum_labels or []),
            _stable_definition(row.range_subtype),
            _stable_definition(row.multirange_type),
        )
        for row in connection.execute(
            text(
                "SELECT t.typname, t.typtype, t.typcategory, t.typnotnull, "
                "CASE WHEN t.typbasetype = 0 THEN NULL "
                "ELSE pg_catalog.format_type(t.typbasetype, NULL) END AS base_type, "
                "CASE WHEN t.typelem = 0 THEN NULL "
                "ELSE pg_catalog.format_type(t.typelem, NULL) END AS element_type, "
                "t.typtypmod, t.typndims, t.typdefault, c.relkind AS composite_relkind, "
                "cn.nspname AS collation_schema, coll.collname AS collation_name, "
                "ARRAY(SELECT e.enumlabel FROM pg_catalog.pg_enum e "
                "WHERE e.enumtypid = t.oid "
                "ORDER BY e.enumsortorder) AS enum_labels, "
                "pg_catalog.format_type(r.rngsubtype, NULL) AS range_subtype, "
                "pg_catalog.format_type(r.rngmultitypid, NULL) AS multirange_type "
                "FROM pg_catalog.pg_type t "
                "LEFT JOIN pg_catalog.pg_class c ON c.oid = t.typrelid "
                "LEFT JOIN pg_catalog.pg_collation coll "
                "ON coll.oid = t.typcollation AND t.typcollation <> 0 "
                "LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid = coll.collnamespace "
                "LEFT JOIN pg_catalog.pg_range r ON r.rngtypid = t.oid "
                "WHERE t.typnamespace = :namespace_oid ORDER BY t.typname"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def _read_type_constraints(
    connection: Connection, namespace_oid: int
) -> list[CatalogRecord]:
    return [
        TypeConstraintRecord(
            row.typname,
            row.conname,
            row.contype,
            _stable_definition(row.definition),
            row.convalidated,
        )
        for row in connection.execute(
            text(
                "SELECT t.typname, k.conname, k.contype, "
                "pg_catalog.pg_get_constraintdef(k.oid, true) AS definition, "
                "k.convalidated FROM pg_catalog.pg_constraint k "
                "JOIN pg_catalog.pg_type t ON t.oid = k.contypid "
                "WHERE t.typnamespace = :namespace_oid ORDER BY t.typname, k.conname"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def _read_views(connection: Connection, namespace_oid: int) -> list[CatalogRecord]:
    return [
        ViewRecord(
            row.relname,
            row.relkind,
            row.relispopulated,
            _stable_definition(row.definition),
        )
        for row in connection.execute(
            text(
                "SELECT c.relname, c.relkind, c.relispopulated, "
                "pg_catalog.pg_get_viewdef(c.oid, false) AS definition "
                "FROM pg_catalog.pg_class c WHERE c.relnamespace = :namespace_oid "
                "AND c.relkind IN ('v', 'm') ORDER BY c.relname"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def _read_foreign_tables(
    connection: Connection, namespace_oid: int
) -> list[CatalogRecord]:
    return [
        ForeignTableRecord(
            row.relname,
            row.server_name,
            tuple(sorted(row.table_options or [])),
            tuple(sorted(row.server_options or [])),
            row.wrapper_name,
            tuple(sorted(row.wrapper_options or [])),
        )
        for row in connection.execute(
            text(
                "SELECT c.relname, s.srvname AS server_name, ft.ftoptions AS table_options, "
                "s.srvoptions AS server_options, w.fdwname AS wrapper_name, "
                "w.fdwoptions AS wrapper_options FROM pg_catalog.pg_foreign_table ft "
                "JOIN pg_catalog.pg_class c ON c.oid = ft.ftrelid "
                "JOIN pg_catalog.pg_foreign_server s ON s.oid = ft.ftserver "
                "JOIN pg_catalog.pg_foreign_data_wrapper w ON w.oid = s.srvfdw "
                "WHERE c.relnamespace = :namespace_oid ORDER BY c.relname"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def _read_routines(connection: Connection, namespace_oid: int) -> list[CatalogRecord]:
    return [
        RoutineRecord(
            row.proname,
            _stable_definition(row.identity_arguments),
            row.prokind,
            row.language,
            _stable_definition(row.return_type),
            row.prosecdef,
            row.proleakproof,
            row.provolatile,
            row.proparallel,
            tuple(_stable_definition(item) for item in (row.proconfig or [])),
            _stable_definition(row.definition),
        )
        for row in connection.execute(
            text(
                "SELECT p.proname, "
                "pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_arguments, "
                "p.prokind, l.lanname AS language, "
                "pg_catalog.pg_get_function_result(p.oid) AS return_type, "
                "p.prosecdef, p.proleakproof, p.provolatile, p.proparallel, p.proconfig, "
                "pg_catalog.pg_get_functiondef(p.oid) AS definition "
                "FROM pg_catalog.pg_proc p "
                "JOIN pg_catalog.pg_language l ON l.oid = p.prolang "
                "WHERE p.pronamespace = :namespace_oid "
                "ORDER BY p.proname, "
                "pg_catalog.pg_get_function_identity_arguments(p.oid), p.prokind"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def _read_triggers(connection: Connection, namespace_oid: int) -> list[CatalogRecord]:
    return [
        TriggerRecord(
            row.relname,
            row.trigger_name,
            row.tgenabled,
            _stable_definition(row.definition),
        )
        for row in connection.execute(
            text(
                "SELECT c.relname, t.tgname AS trigger_name, t.tgenabled, "
                "pg_catalog.pg_get_triggerdef(t.oid, true) AS definition "
                "FROM pg_catalog.pg_trigger t "
                "JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid "
                "WHERE c.relnamespace = :namespace_oid AND NOT t.tgisinternal "
                "ORDER BY c.relname, t.tgname"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def _read_policies(connection: Connection, namespace_oid: int) -> list[CatalogRecord]:
    return [
        PolicyRecord(
            row.relname,
            row.polname,
            row.polcmd,
            row.polpermissive,
            tuple(row.roles or []),
            _stable_definition(row.qual),
            _stable_definition(row.with_check),
        )
        for row in connection.execute(
            text(
                "SELECT c.relname, p.polname, p.polcmd, p.polpermissive, "
                "ARRAY(SELECT CASE WHEN listed.role_oid = 0 THEN 'PUBLIC' "
                "ELSE pg_catalog.pg_get_userbyid(listed.role_oid) END AS role_name "
                "FROM pg_catalog.unnest(p.polroles) AS listed(role_oid) "
                "ORDER BY role_name) AS roles, "
                "pg_catalog.pg_get_expr(p.polqual, p.polrelid, true) AS qual, "
                "pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid, true) AS with_check "
                "FROM pg_catalog.pg_policy p "
                "JOIN pg_catalog.pg_class c ON c.oid = p.polrelid "
                "WHERE c.relnamespace = :namespace_oid ORDER BY c.relname, p.polname"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def _read_namespace_dependency_classes(
    connection: Connection, namespace_oid: int
) -> list[CatalogRecord]:
    return [
        NamespaceDependencyClassRecord(row.catalog_name, row.object_count)
        for row in connection.execute(
            text(
                "SELECT catalog.relname AS catalog_name, count(*) AS object_count "
                "FROM pg_catalog.pg_depend d "
                "JOIN pg_catalog.pg_class catalog ON catalog.oid = d.classid "
                "JOIN pg_catalog.pg_namespace catalog_namespace "
                "ON catalog_namespace.oid = catalog.relnamespace "
                "JOIN pg_catalog.pg_class referenced_catalog "
                "ON referenced_catalog.oid = d.refclassid "
                "JOIN pg_catalog.pg_namespace referenced_namespace "
                "ON referenced_namespace.oid = referenced_catalog.relnamespace "
                "WHERE catalog_namespace.nspname = 'pg_catalog' "
                "AND referenced_namespace.nspname = 'pg_catalog' "
                "AND referenced_catalog.relname = 'pg_namespace' "
                "AND d.refobjid = :namespace_oid "
                "GROUP BY catalog.relname ORDER BY catalog.relname"
            ),
            {"namespace_oid": namespace_oid},
        )
    ]


def read_catalog_inventory(
    connection: Connection,
    *,
    namespace_oid: int,
    visible_namespace: str,
) -> CatalogInventory:
    """Read the exact ordered PostgreSQL catalog contract for one namespace."""

    return {
        "relations": _read_relations(connection, namespace_oid),
        "columns": _read_columns(connection, namespace_oid, visible_namespace),
        "constraints": _read_constraints(connection, namespace_oid),
        "indexes": _read_indexes(connection, namespace_oid),
        "sequences": _read_sequences(connection, namespace_oid),
        "types": _read_types(connection, namespace_oid, visible_namespace),
        "type_constraints": _read_type_constraints(connection, namespace_oid),
        "views": _read_views(connection, namespace_oid),
        "foreign_tables": _read_foreign_tables(connection, namespace_oid),
        "routines": _read_routines(connection, namespace_oid),
        "triggers": _read_triggers(connection, namespace_oid),
        "policies": _read_policies(connection, namespace_oid),
        "namespace_dependency_classes": _read_namespace_dependency_classes(
            connection, namespace_oid
        ),
    }


def catalog_inventory_is_empty(inventory: CatalogInventory) -> bool:
    return all(not entries for entries in inventory.values())


def _inventory_digest(rows: list[CatalogRecord]) -> str:
    # NamedTuple records retain the former tuple digest representation exactly.
    encoded = repr([tuple(row) for row in rows]).encode("utf-8", errors="strict")
    return hashlib.sha256(encoded).hexdigest()[:16]


def catalog_inventory_difference(
    actual: CatalogInventory,
    expected: CatalogInventory,
) -> str:
    differences: list[str] = []
    for section in expected:
        if actual[section] == expected[section]:
            continue
        actual_rows = set(actual[section])
        expected_rows = set(expected[section])
        missing_count = len(expected_rows - actual_rows)
        unexpected_count = len(actual_rows - expected_rows)
        differences.append(
            f"{section} differs: expected={len(expected_rows)} actual={len(actual_rows)} "
            f"missing={missing_count} unexpected={unexpected_count} "
            f"expected_digest={_inventory_digest(expected[section])} "
            f"actual_digest={_inventory_digest(actual[section])}"
        )
        if len(differences) >= 8:
            break
    return " | ".join(differences)
