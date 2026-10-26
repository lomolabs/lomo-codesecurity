#!/usr/bin/env sh
set -eu

if [ "${KODESEC_DISPOSABLE_RECOVERY_TEST:-}" != "1" ]; then
  echo "Backup is unavailable for normal use: this non-atomic helper is unvalidated. For disposable testing only, explicitly set KODESEC_DISPOSABLE_RECOVERY_TEST=1. See docs/PERSISTENCE.md." >&2
  exit 2
fi

umask 077

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STATE_DIR="${KODESEC_STATE_DIR:-${XDG_STATE_HOME:-${HOME}/.local/state}/lomo-kodesec}"
RUNTIME_ENV="${KODESEC_RUNTIME_ENV:-$STATE_DIR/runtime.env}"
DEST="${BACKUP_DEST:-$STATE_DIR/backups/$STAMP}"

if [ -L "$RUNTIME_ENV" ] || [ ! -f "$RUNTIME_ENV" ]; then
  echo "Runtime configuration is not initialized. Run 'make init'." >&2
  exit 2
fi

runtime_value() {
  sed -n "s/^$1=//p" "$RUNTIME_ENV" | tail -n 1
}

PROJECT="${COMPOSE_PROJECT_NAME:-$(runtime_value COMPOSE_PROJECT_NAME)}"
PROJECT="${PROJECT:-lomo-code-security}"
POSTGRES_USER_VALUE="${POSTGRES_USER:-$(runtime_value POSTGRES_USER)}"
POSTGRES_USER_VALUE="${POSTGRES_USER_VALUE:-kodesec}"
POSTGRES_DB_VALUE="${POSTGRES_DB:-$(runtime_value POSTGRES_DB)}"
POSTGRES_DB_VALUE="${POSTGRES_DB_VALUE:-kodesec}"

case "$PROJECT" in
  *[!A-Za-z0-9_-]*|'') echo "Invalid Compose project name in runtime configuration." >&2; exit 2 ;;
esac

compose() {
  docker compose --env-file "$RUNTIME_ENV" "$@"
}

mkdir -p "$DEST"
chmod 700 "$DEST"

echo "Writing Postgres dump to $DEST/postgres.sql"
compose exec -T postgres pg_dump -U "$POSTGRES_USER_VALUE" "$POSTGRES_DB_VALUE" > "$DEST/postgres.sql"

echo "Archiving artifact volume"
docker run --rm \
  -v "${PROJECT}_artifacts:/volumes/artifacts:ro" \
  -v "$DEST:/backup" \
  alpine:3.21 sh -c "cd /volumes && tar czf /backup/volumes.tar.gz artifacts"

if docker volume inspect "${PROJECT}_gitea_data" >/dev/null 2>&1; then
  echo "Archiving Gitea data volume"
  docker run --rm \
    -v "${PROJECT}_gitea_data:/volumes/gitea_data:ro" \
    -v "${PROJECT}_gitea_config:/volumes/gitea_config:ro" \
    -v "$DEST:/backup" \
    alpine:3.21 sh -c "cd /volumes && tar czf /backup/gitea.tar.gz gitea_data gitea_config"
fi

echo "Runtime secrets are intentionally excluded; restore into an initialized installation."
echo "$DEST"
