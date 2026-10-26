#!/bin/sh
set -eu

umask 077
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

python3 - "$runtime_env" <<'PY'
from pathlib import Path
import os
import secrets
import sys
import tempfile

path = Path(sys.argv[1]).resolve(strict=True)
keys = {"KODESEC_BOOTSTRAP_TOKEN"}
seen: set[str] = set()
output: list[str] = []
for line in path.read_text(encoding="utf-8").splitlines():
    key = line.split("=", 1)[0] if "=" in line else ""
    if key in keys:
        if key in seen:
            raise SystemExit(f"duplicate authentication field: {key}")
        seen.add(key)
        line = f"{key}={secrets.token_urlsafe(32)}"
    output.append(line)
missing = keys - seen
if missing:
    raise SystemExit(f"missing authentication fields: {', '.join(sorted(missing))}")

descriptor, temporary = tempfile.mkstemp(prefix=".runtime.env.", dir=path.parent, text=True)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write("\n".join(output) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY

python3 - "$state_dir" <<'PY'
from pathlib import Path
import os
import stat
import sys

artifact = Path(sys.argv[1]) / "first-owner-browser-v1.json"
try:
    metadata = os.lstat(artifact)
except FileNotFoundError:
    pass
else:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
    ):
        raise SystemExit("Refusing to remove an insecure first-owner bootstrap artifact.")
    artifact.unlink()
PY

echo "Rotated one-time browser bootstrap material."
echo "Recreate the control service with 'make up' before using the new values."
