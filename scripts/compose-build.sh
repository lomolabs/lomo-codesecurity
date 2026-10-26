#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

if [ "$#" -eq 0 ]; then
  echo "Usage: scripts/compose-build.sh <docker compose command...>" >&2
  exit 2
fi

exec python3 "$script_dir/source_provenance.py" --exec "$@"
