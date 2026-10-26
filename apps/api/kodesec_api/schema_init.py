from __future__ import annotations

from sqlalchemy import create_engine

from .db import Runtime, initialize_database
from .main import enforce_runtime_publication_boundaries
from .settings import get_settings


def main() -> None:
    settings = get_settings()
    settings.validate_database_configuration()
    engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
    try:
        verification = initialize_database(engine)
        runtime = Runtime.create(settings, engine=engine)
        runtime.schema_identity = verification.identity
        runtime.schema_fingerprint = verification.fingerprint
        runtime.schema_initialized_at = verification.initialized_at
        enforce_runtime_publication_boundaries(runtime)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
