#!/usr/bin/env sh
set -eu

if [ "${KODESEC_DISPOSABLE_RECOVERY_TEST:-}" != "1" ]; then
  echo "Restore is unavailable for normal use: this destructive helper is unvalidated. For disposable testing only, explicitly set KODESEC_DISPOSABLE_RECOVERY_TEST=1. See docs/PERSISTENCE.md." >&2
  exit 2
fi

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

BACKUP_DIR="${1:-}"
STATE_DIR="${KODESEC_STATE_DIR:-${XDG_STATE_HOME:-${HOME}/.local/state}/lomo-kodesec}"
RUNTIME_ENV="${KODESEC_RUNTIME_ENV:-$STATE_DIR/runtime.env}"

if [ -z "$BACKUP_DIR" ] || [ ! -d "$BACKUP_DIR" ] || [ ! -f "$BACKUP_DIR/postgres.sql" ]; then
  echo "Usage: scripts/restore.sh <backup-dir>" >&2
  exit 2
fi
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

echo "Stopping services that depend on restored state"
compose --profile git-proxy stop api-ingress worker api scanner scanner-updater gitea 2>/dev/null || true

compose up -d --wait postgres

echo "Restoring Postgres"
compose exec -T postgres psql -U "$POSTGRES_USER_VALUE" "$POSTGRES_DB_VALUE" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
compose exec -T postgres psql -U "$POSTGRES_USER_VALUE" "$POSTGRES_DB_VALUE" < "$BACKUP_DIR/postgres.sql"

if [ -f "$BACKUP_DIR/volumes.tar.gz" ]; then
  echo "Restoring artifact volume"
  docker run --rm \
    -v "${PROJECT}_artifacts:/volumes/artifacts" \
    -v "$BACKUP_DIR:/backup:ro" \
    alpine:3.21 sh -c "find /volumes/artifacts -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + && cd /volumes && tar xzf /backup/volumes.tar.gz"
fi

if [ -f "$BACKUP_DIR/gitea.tar.gz" ]; then
  echo "Restoring Gitea volumes"
  compose --profile git-proxy stop gitea 2>/dev/null || true
  docker run --rm \
    -v "${PROJECT}_gitea_data:/volumes/gitea_data" \
    -v "${PROJECT}_gitea_config:/volumes/gitea_config" \
    -v "$BACKUP_DIR:/backup:ro" \
    alpine:3.21 sh -c "rm -rf /volumes/gitea_data/* /volumes/gitea_config/* && cd /volumes && tar xzf /backup/gitea.tar.gz"
  compose --profile git-proxy up -d gitea
fi

compose up -d scanner scanner-updater advisor-connector worker api api-ingress
echo "Restore complete"
