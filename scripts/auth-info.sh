#!/bin/sh
set -eu

state_dir=${KODESEC_STATE_DIR:-${XDG_STATE_HOME:-${HOME}/.local/state}/lomo-kodesec}
runtime_env=${KODESEC_RUNTIME_ENV:-$state_dir/runtime.env}

if [ -L "$runtime_env" ] || [ ! -f "$runtime_env" ]; then
  echo "Runtime configuration is not initialized. Run 'make init'." >&2
  exit 2
fi

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

file_owner() {
  if stat -c '%u' "$1" >/dev/null 2>&1; then
    stat -c '%u' "$1"
  else
    stat -f '%u' "$1"
  fi
}

file_links() {
  if stat -c '%h' "$1" >/dev/null 2>&1; then
    stat -c '%h' "$1"
  else
    stat -f '%l' "$1"
  fi
}

if [ "$(file_mode "$runtime_env")" != "600" ] || \
   [ "$(file_owner "$runtime_env")" != "$(id -u)" ] || \
   [ "$(file_links "$runtime_env")" != "1" ]; then
  echo "Refusing runtime configuration that is not owner-controlled, mode 0600, and single-link." >&2
  exit 2
fi

bootstrap=$(sed -n 's/^KODESEC_BOOTSTRAP_TOKEN=//p' "$runtime_env")
port=$(sed -n 's/^CONTROL_PORT=//p' "$runtime_env")
port=${port:-8080}

if [ -z "$bootstrap" ]; then
  echo "Runtime configuration is missing browser bootstrap material." >&2
  exit 2
fi

echo "Browser bootstrap URL (fragment is not sent in HTTP requests):"
echo "http://127.0.0.1:${port}/#bootstrap=${bootstrap}"
