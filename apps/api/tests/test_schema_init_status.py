from __future__ import annotations

import pytest
from sqlalchemy import create_engine, delete, text
from sqlalchemy.exc import IntegrityError

from kodesec_api.db import Base, Runtime, schema_fingerprint
from kodesec_api.main import _schema_init_status
from kodesec_api.models import INITIAL_SCHEMA_IDENTITY, SchemaIdentity
from kodesec_api.schemas import SchemaInitStatusOut
from kodesec_api.settings import Settings


def _runtime() -> Runtime:
    engine = create_engine("sqlite+pysqlite://", future=True)
    Base.metadata.create_all(engine, checkfirst=False)
    runtime = Runtime.create(Settings(_env_file=None), engine=engine)
    with runtime.session_factory() as db:
        identity = db.get(SchemaIdentity, 1)
        assert identity is not None
        runtime.schema_identity = identity.schema_id
        runtime.schema_fingerprint = identity.schema_fingerprint
        runtime.schema_initialized_at = identity.initialized_at
    return runtime


def test_schema_init_status_uses_immutable_identity_and_startup_verification() -> None:
    runtime = _runtime()
    try:
        with runtime.session_factory() as db:
            completed = SchemaInitStatusOut.model_validate(_schema_init_status(db, runtime))
        assert completed.state == "completed"
        assert completed.startable is False
        assert completed.message == "Completed successfully; expected to stop."
        assert completed.schema_id == INITIAL_SCHEMA_IDENTITY
        assert completed.schema_fingerprint == schema_fingerprint()
        assert completed.initialized_at is not None
        assert completed.evidence == "schema-identity-and-api-startup-verification"

        with pytest.raises(IntegrityError):
            with runtime.engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE schema_identity SET schema_fingerprint = :fingerprint "
                        "WHERE id = 1"
                    ),
                    {"fingerprint": "z" * 64},
                )
        with runtime.session_factory() as db:
            still_completed = SchemaInitStatusOut.model_validate(
                _schema_init_status(db, runtime)
            )
        assert still_completed.state == "completed"

        with runtime.engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE schema_identity "
                    "SET initialized_at = datetime(initialized_at, '+1 second') "
                    "WHERE id = 1"
                )
            )
        with runtime.session_factory() as db:
            changed_timestamp = SchemaInitStatusOut.model_validate(
                _schema_init_status(db, runtime)
            )
        assert changed_timestamp.state == "unverified"
        assert changed_timestamp.schema_id is None
        assert changed_timestamp.schema_fingerprint is None
        assert changed_timestamp.initialized_at is None
        assert changed_timestamp.evidence is None

        with runtime.session_factory() as db, db.begin():
            db.execute(delete(SchemaIdentity))
        with runtime.session_factory() as db:
            unverified = SchemaInitStatusOut.model_validate(_schema_init_status(db, runtime))
        assert unverified.state == "unverified"
        assert unverified.evidence is None
        assert "Completed successfully" not in unverified.message
    finally:
        runtime.engine.dispose()
