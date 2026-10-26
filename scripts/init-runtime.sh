#!/bin/sh
set -eu

umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(dirname "$script_dir")
state_dir=${KODESEC_STATE_DIR:-${XDG_STATE_HOME:-${HOME}/.local/state}/lomo-kodesec}

case "$state_dir" in
  /*) ;;
  *) state_dir="$(pwd -P)/$state_dir" ;;
esac

# A copied Web command belongs to one existing installation. Check before any
# mkdir/chmod/initialization, then authorization checks again under its lock.
if [ "${KODESEC_EXPECT_INSTALLATION_ID+x}" = x ]; then
  KODESEC_STATE_DIR="$state_dir" \
    KODESEC_RUNTIME_ENV="${KODESEC_RUNTIME_ENV:-$state_dir/runtime.env}" \
    python3 "$script_dir/authorize-source.py" --check-installation
fi

canonical_state=$(python3 - "$state_dir" <<'PY'
from pathlib import Path
import sys

print(Path(sys.argv[1]).resolve(strict=False))
PY
)

case "$canonical_state" in
  "$repo_root"|"$repo_root"/*)
    case "$state_dir" in
      "$repo_root/.kodesec-test"/*)
        if [ "${KODESEC_ALLOW_TEST_STATE:-0}" != "1" ]; then
          echo "Refusing repository-local runtime secrets outside an explicit test run." >&2
          exit 2
        fi
        ;;
      *)
        echo "Runtime secrets must live outside the source tree." >&2
        exit 2
        ;;
    esac
    ;;
esac

if [ -L "$state_dir" ]; then
  echo "Refusing symlink runtime state directory: $state_dir" >&2
  exit 2
fi

mkdir -p "$canonical_state"
chmod 700 "$canonical_state"
python3 - "$canonical_state" <<'PY'
from pathlib import Path
import os
import stat
import sys

state = Path(sys.argv[1])
auth = state / "advisor-auth"
try:
    auth.mkdir(mode=0o700)
except FileExistsError:
    pass
metadata = os.lstat(auth)
if (
    not stat.S_ISDIR(metadata.st_mode)
    or stat.S_ISLNK(metadata.st_mode)
    or stat.S_IMODE(metadata.st_mode) != 0o700
    or metadata.st_uid != os.getuid()
    or auth.resolve(strict=True).parent != state.resolve(strict=True)
):
    raise SystemExit("Advisor authorization directory must be an owner-only non-symlink directory.")
PY
state_dir=$(cd "$canonical_state" && pwd -P)
runtime_env=${KODESEC_RUNTIME_ENV:-$state_dir/runtime.env}
runtime_parent=$(dirname "$runtime_env")
runtime_name=$(basename "$runtime_env")
if [ ! -d "$runtime_parent" ] || [ "$(cd "$runtime_parent" && pwd -P)" != "$state_dir" ] || [ "$runtime_name" = "." ] || [ "$runtime_name" = ".." ]; then
  echo "Runtime environment must be a direct child of the runtime state directory." >&2
  exit 2
fi
runtime_env="$state_dir/$runtime_name"

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

file_links() {
  if stat -c '%h' "$1" >/dev/null 2>&1; then
    stat -c '%h' "$1"
  else
    stat -f '%l' "$1"
  fi
}

if [ -e "$runtime_env" ] || [ -L "$runtime_env" ]; then
  if [ -L "$runtime_env" ] || [ ! -f "$runtime_env" ]; then
    echo "Refusing non-regular runtime environment: $runtime_env" >&2
    exit 2
  fi
  if [ "$(file_mode "$runtime_env")" != "600" ]; then
    echo "Runtime environment must have mode 0600: $runtime_env" >&2
    exit 2
  fi
  if [ "$(file_links "$runtime_env")" != "1" ]; then
    echo "Runtime environment must not have hard links: $runtime_env" >&2
    exit 2
  fi
  python3 - "$runtime_env" "$script_dir" <<'PY'
from pathlib import Path
import os
import re
import sys

sys.path.insert(0, sys.argv[2])
from source_roots import SourceRootError, configured_source_roots

required_secrets = {
    "POSTGRES_PASSWORD",
    "KODESEC_INSTALLATION_SECRET",
    "KODESEC_BOOTSTRAP_TOKEN",
    "KODESEC_ADVISOR_GRANT_SECRET",
    "GRAFANA_ADMIN_PASSWORD",
    "GITEA_SECRET_KEY",
    "GITEA_INTERNAL_TOKEN",
    "GITEA_TEST_PASSWORD",
}
required_configuration = {
    "KODESEC_RUNTIME_CONFIG_VERSION",
    "OLLAMA_MODEL_DIGEST",
    "KODESEC_ADVISOR_DIRECT_HOSTS",
    "KODESEC_ADVISOR_SSH_PROVIDER_IDS",
    "KODESEC_ADVISOR_AUTH_DIR",
    "KODESEC_HOST_UID",
    "KODESEC_HOST_GID",
    "KODESEC_INSTALLATION_ID",
    "COMPOSE_PROJECT_NAME",
    "KODESEC_CONTROL_IMAGE",
    "KODESEC_SCANNER_IMAGE",
    "KODESEC_REPO_ROOT",
    "KODESEC_ALLOWED_ROOTS",
}
runtime_path = Path(sys.argv[1])
original_text = runtime_path.read_text(encoding="utf-8")
values: dict[str, str] = {}
configuration: dict[str, str] = {}
for line in original_text.splitlines():
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    if key in configuration:
        raise SystemExit(f"duplicate runtime field: {key}")
    configuration[key] = value
    if key in required_secrets:
        values[key] = value
missing_secrets = required_secrets - values.keys()
if missing_secrets:
    raise SystemExit(
        f"missing generated secret fields: {', '.join(sorted(missing_secrets))}; "
        "preserve the non-current file, move it aside, then run make init"
    )
missing_configuration = required_configuration - configuration.keys()
if missing_configuration:
    raise SystemExit(
        "existing runtime configuration does not match the current format; missing fields: "
        f"{', '.join(sorted(missing_configuration))}; preserve the file, move it aside, "
        "then run make init"
    )
weak = [key for key, value in values.items() if not re.fullmatch(r"[A-Za-z0-9_-]{43,}", value)]
if weak:
    raise SystemExit(f"weak or malformed generated secret fields: {', '.join(sorted(weak))}")
source_root = configuration.get("KODESEC_REPO_ROOT", "")
try:
    configured_source_roots(source_root, configuration.get("KODESEC_ALLOWED_ROOTS", ""))
except SourceRootError as error:
    raise SystemExit(str(error)) from error
project_name = configuration.get("COMPOSE_PROJECT_NAME", "")
control_image = configuration.get("KODESEC_CONTROL_IMAGE", "")
scanner_image = configuration.get("KODESEC_SCANNER_IMAGE", "")
installation_id = configuration.get("KODESEC_INSTALLATION_ID", "")
if not re.fullmatch(r"[a-f0-9]{12}", installation_id):
    raise SystemExit("missing or malformed generated KODESEC_INSTALLATION_ID")
if not re.fullmatch(r"lomo-[a-z0-9][a-z0-9_-]{2,62}", project_name):
    raise SystemExit("missing or malformed generated COMPOSE_PROJECT_NAME")
if not re.fullmatch(r"lomo-kodesec-control:[A-Za-z0-9][A-Za-z0-9._-]{0,127}", control_image):
    raise SystemExit("missing or malformed generated KODESEC_CONTROL_IMAGE")
if not re.fullmatch(r"lomo-kodesec-scanner:[A-Za-z0-9][A-Za-z0-9._-]{0,127}", scanner_image):
    raise SystemExit(
        "missing or malformed KODESEC_SCANNER_IMAGE; "
        "preserve the non-current file, move it aside, then run make init"
    )
if configuration["KODESEC_RUNTIME_CONFIG_VERSION"] != "1":
    raise SystemExit(
        "unsupported KODESEC_RUNTIME_CONFIG_VERSION; preserve the non-current file, "
        "move it aside, then run make init"
    )
advisor_auth = Path(configuration["KODESEC_ADVISOR_AUTH_DIR"])
if (
    not advisor_auth.is_absolute()
    or advisor_auth.resolve(strict=False) != (runtime_path.parent / "advisor-auth").resolve(strict=False)
):
    raise SystemExit("KODESEC_ADVISOR_AUTH_DIR must name this runtime state's advisor-auth directory")
if configuration["KODESEC_HOST_UID"] != str(os.getuid()):
    raise SystemExit("KODESEC_HOST_UID does not match the current runtime owner")
if configuration["KODESEC_HOST_GID"] != str(os.getgid()):
    raise SystemExit("KODESEC_HOST_GID does not match the current runtime owner group")
if configuration.get("KODESEC_PREPARATION_PLATFORM", "mac") not in {"mac", "linux", "windows"}:
    raise SystemExit("KODESEC_PREPARATION_PLATFORM must be mac, linux, or windows (including WSL)")
model_digest = configuration["OLLAMA_MODEL_DIGEST"]
if model_digest and not re.fullmatch(r"[0-9a-f]{64}", model_digest):
    raise SystemExit("OLLAMA_MODEL_DIGEST must be empty or an exact lowercase SHA-256 digest")
PY
  echo "Runtime configuration already initialized at $runtime_env"
  exit 0
fi

template="$repo_root/.env.example"
if [ ! -f "$template" ]; then
  echo "Missing runtime configuration template: $template" >&2
  exit 2
fi

tmp=$(mktemp "$state_dir/.runtime.env.XXXXXX")
cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT HUP INT TERM

python3 - "$template" "$tmp" "$repo_root" <<'PY'
from pathlib import Path
import os
import secrets
import sys
import platform

template = Path(sys.argv[1]).read_text(encoding="utf-8").rstrip()
destination = Path(sys.argv[2])
repo_root = str(Path(sys.argv[3]).resolve(strict=True))
template = template.replace("__INITIALIZED_BY_MAKE_INIT__", repo_root)
installation_id = secrets.token_hex(6)
template = template.replace("__INITIALIZED_INSTALLATION_ID__", installation_id)
template = template.replace(
    "__INITIALIZED_COMPOSE_PROJECT__", f"lomo-code-security-{installation_id}"
)
template = template.replace(
    "__INITIALIZED_CONTROL_IMAGE__", f"lomo-kodesec-control:{installation_id}"
)
template = template.replace(
    "__INITIALIZED_SCANNER_IMAGE__", f"lomo-kodesec-scanner:{installation_id}"
)
template = template.replace(
    "__INITIALIZED_ADVISOR_AUTH_DIR__", str(destination.parent / "advisor-auth")
)
preparation_platform = "mac" if platform.system() == "Darwin" else (
    "windows" if "microsoft" in platform.release().lower() else "linux"
)
template = template.replace("__INITIALIZED_PREPARATION_PLATFORM__", preparation_platform)
template = template.replace("__INITIALIZED_HOST_UID__", str(os.getuid()))
template = template.replace("__INITIALIZED_HOST_GID__", str(os.getgid()))
generated = {
    "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
    "KODESEC_INSTALLATION_SECRET": secrets.token_urlsafe(48),
    "KODESEC_BOOTSTRAP_TOKEN": secrets.token_urlsafe(32),
    "KODESEC_ADVISOR_GRANT_SECRET": secrets.token_urlsafe(48),
    "GRAFANA_ADMIN_PASSWORD": secrets.token_urlsafe(32),
    "GITEA_SECRET_KEY": secrets.token_urlsafe(48),
    "GITEA_INTERNAL_TOKEN": secrets.token_urlsafe(48),
    "GITEA_TEST_PASSWORD": secrets.token_urlsafe(32),
}
lines = [template, "", "# Generated installation secrets. Never copy this file into source control."]
lines.extend(f"{key}={value}" for key, value in generated.items())
destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

chmod 600 "$tmp"
mv "$tmp" "$runtime_env"
python3 "$script_dir/publish-first-owner-bootstrap.py" "$state_dir" "$runtime_env"
trap - EXIT HUP INT TERM
echo "Initialized owner-only runtime configuration at $runtime_env"
echo "The first local VS Code profile can now open the owner browser without copying a terminal value."
echo "Use 'make auth-info' only for explicit browser recovery."
