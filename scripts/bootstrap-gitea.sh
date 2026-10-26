#!/usr/bin/env sh
set -eu
umask 077

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
STATE_DIR=${KODESEC_STATE_DIR:-${XDG_STATE_HOME:-${HOME}/.local/state}/lomo-kodesec}
RUNTIME_ENV=${KODESEC_RUNTIME_ENV:-$STATE_DIR/runtime.env}
if [ -L "$RUNTIME_ENV" ] || [ ! -f "$RUNTIME_ENV" ]; then
  echo "Runtime configuration is not initialized. Run 'make init'." >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for loopback URL validation." >&2
  exit 2
fi

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}
file_owner() {
  stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"
}
file_links() {
  stat -c '%h' "$1" 2>/dev/null || stat -f '%l' "$1"
}
if [ "$(file_mode "$RUNTIME_ENV")" != "600" ] || \
   [ "$(file_owner "$RUNTIME_ENV")" != "$(id -u)" ] || \
   [ "$(file_links "$RUNTIME_ENV")" != "1" ]; then
  echo "Runtime configuration must be owner-controlled, mode 0600, and single-link." >&2
  exit 2
fi

runtime_value() {
  sed -n "s/^$1=//p" "$RUNTIME_ENV" | tail -n 1
}

compose() {
  docker compose --env-file "$RUNTIME_ENV" --profile git-proxy "$@"
}

GITEA_URL=${GITEA_URL:-http://127.0.0.1:3000}
if ! GITEA_URL=$(python3 "$ROOT_DIR/scripts/validate-loopback-url.py" "$GITEA_URL"); then
  echo "Refusing to send Gitea credentials outside an exact HTTP loopback origin." >&2
  exit 2
fi
GITEA_USER=${GITEA_TEST_USER:-$(runtime_value GITEA_TEST_USER)}
GITEA_USER=${GITEA_USER:-kodesec-test}
GITEA_PASS=${GITEA_TEST_PASSWORD:-$(runtime_value GITEA_TEST_PASSWORD)}
: "${GITEA_PASS:?runtime configuration is missing GITEA_TEST_PASSWORD}"
GITEA_EMAIL=${GITEA_TEST_EMAIL:-kodesec-test@example.local}
WORKDIR=${GITEA_TEST_DIR:-$STATE_DIR/gitea-smoke}
case "$WORKDIR" in
  /*) ;;
  *) WORKDIR="$(pwd)/$WORKDIR" ;;
esac
case "$STATE_DIR" in
  /*) ;;
  *) STATE_DIR="$(pwd)/$STATE_DIR" ;;
esac
mkdir -p "$STATE_DIR"
STATE_DIR=$(CDPATH= cd -- "$STATE_DIR" && pwd -P)
work_parent=$(dirname -- "$WORKDIR")
mkdir -p "$work_parent"
work_parent=$(CDPATH= cd -- "$work_parent" && pwd -P)
WORKDIR="$work_parent/$(basename -- "$WORKDIR")"
case "$WORKDIR" in
  "$STATE_DIR"/gitea-smoke|"$STATE_DIR"/gitea-smoke-*) ;;
  *)
    echo "GITEA_TEST_DIR must be a dedicated gitea-smoke directory directly under the owner state directory." >&2
    exit 2
    ;;
esac
KEY_PATH="$WORKDIR/id_ed25519"
KNOWN_HOSTS="$WORKDIR/known_hosts"
REPO_NAME=${GITEA_TEST_REPO:-kodesec-smoke}
DO_SMOKE=0

if [ "${1:-}" = "--smoke" ]; then
  DO_SMOKE=1
fi

mkdir -p "$WORKDIR"
chmod 700 "$WORKDIR"
GITEA_HOST=${GITEA_URL#*://}
GITEA_HOST=${GITEA_HOST%%:*}
NETRC="$WORKDIR/curl.netrc"
{
  echo "machine $GITEA_HOST"
  echo "login $GITEA_USER"
  echo "password $GITEA_PASS"
} > "$NETRC"
chmod 600 "$NETRC"
cleanup() {
  rm -f "$NETRC"
}
trap cleanup EXIT HUP INT TERM

echo "Migrating Gitea database"
compose exec -T gitea gitea migrate -c /etc/gitea/app.ini -w /var/lib/gitea

if curl --proto '=http' --max-redirs 0 -fsS --netrc-file "$NETRC" "$GITEA_URL/api/v1/user" >/dev/null 2>&1; then
  echo "Gitea test user already exists: $GITEA_USER"
else
  echo "Creating Gitea test user: $GITEA_USER"
  compose exec -T gitea gitea admin user create \
    -c /etc/gitea/app.ini \
    -w /var/lib/gitea \
    --username "$GITEA_USER" \
    --password "$GITEA_PASS" \
    --email "$GITEA_EMAIL" \
    --admin \
    --must-change-password=false
fi

if [ ! -f "$KEY_PATH" ]; then
  echo "Generating test SSH key: $KEY_PATH"
  ssh-keygen -t ed25519 -N "" -C "$GITEA_USER@lomo-code-security" -f "$KEY_PATH" >/dev/null
fi

PUB_KEY=$(cat "$KEY_PATH.pub")
KEY_FINGERPRINT=$(ssh-keygen -lf "$KEY_PATH.pub" | awk '{print $2}' | tr -c 'A-Za-z0-9_.-' '_')
KEY_TITLE="kodesec-smoke-$KEY_FINGERPRINT"
if curl --proto '=http' --max-redirs 0 -fsS --netrc-file "$NETRC" "$GITEA_URL/api/v1/user/keys" | grep -F "$PUB_KEY" >/dev/null; then
  echo "Gitea test SSH key already registered"
else
  echo "Registering Gitea test SSH key"
  status=$(curl --proto '=http' --max-redirs 0 -sS -o "$WORKDIR/key-create.json" -w "%{http_code}" \
    --netrc-file "$NETRC" \
    -H "content-type: application/json" \
    -X POST "$GITEA_URL/api/v1/user/keys" \
    -d "{\"title\":\"$KEY_TITLE\",\"key\":\"$PUB_KEY\"}")
  case "$status" in
    201|422) ;;
    *) cat "$WORKDIR/key-create.json"; echo; exit 1 ;;
  esac
fi

echo "Ensuring smoke repository exists"
status=$(curl --proto '=http' --max-redirs 0 -sS -o "$WORKDIR/repo-create.json" -w "%{http_code}" \
  --netrc-file "$NETRC" \
  -H "content-type: application/json" \
  -X POST "$GITEA_URL/api/v1/user/repos" \
  -d "{\"name\":\"$REPO_NAME\",\"private\":true,\"auto_init\":false}")
case "$status" in
  201|409|422) ;;
  *) cat "$WORKDIR/repo-create.json"; echo; exit 1 ;;
esac

if [ "$DO_SMOKE" -eq 0 ]; then
  echo "Gitea bootstrap complete"
  exit 0
fi

echo "Running SSH push/pull smoke test"
rm -rf "$WORKDIR/repo" "$WORKDIR/clone"
mkdir -p "$WORKDIR/repo"
git -C "$WORKDIR/repo" init -b main >/dev/null
git -C "$WORKDIR/repo" config user.name "Lomo CodeSecurity Smoke"
git -C "$WORKDIR/repo" config user.email "$GITEA_EMAIL"
printf "gitea smoke %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$WORKDIR/repo/README.md"
git -C "$WORKDIR/repo" add README.md
git -C "$WORKDIR/repo" commit -m "gitea smoke" >/dev/null
git -C "$WORKDIR/repo" remote add origin "ssh://git@localhost:2222/$GITEA_USER/$REPO_NAME.git"

GIT_SSH_COMMAND="ssh -i $KEY_PATH -o IdentitiesOnly=yes -o UserKnownHostsFile=$KNOWN_HOSTS -o StrictHostKeyChecking=accept-new" \
  git -C "$WORKDIR/repo" push -f origin main >/dev/null

GIT_SSH_COMMAND="ssh -i $KEY_PATH -o IdentitiesOnly=yes -o UserKnownHostsFile=$KNOWN_HOSTS -o StrictHostKeyChecking=accept-new" \
  git clone "ssh://git@localhost:2222/$GITEA_USER/$REPO_NAME.git" "$WORKDIR/clone" >/dev/null

test -f "$WORKDIR/clone/README.md"
echo "Gitea SSH smoke test passed"
