#!/bin/sh
set -eu

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: fetch-locked-asset URL DESTINATION SHA256 [MAX_BYTES]" >&2
  exit 64
fi

url="$1"
destination="$2"
expected_sha256="$3"
maximum_bytes="${4:-}"
attempt_timeout="${SCANNER_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS:-900}"
retry_window="${SCANNER_DOWNLOAD_RETRY_WINDOW_SECONDS:-1800}"
maximum_attempts="${SCANNER_DOWNLOAD_MAX_ATTEMPTS:-10}"
connect_timeout="${SCANNER_DOWNLOAD_CONNECT_TIMEOUT_SECONDS:-20}"
retry_base_delay="${SCANNER_DOWNLOAD_RETRY_BASE_DELAY_SECONDS:-1}"

for value in \
  "$attempt_timeout" \
  "$retry_window" \
  "$maximum_attempts" \
  "$connect_timeout" \
  "$retry_base_delay"
do
  case "$value" in
    ''|*[!0-9]*) echo "download policy is not an unsigned integer" >&2; exit 64 ;;
  esac
done
case "$expected_sha256" in
  ''|*[!0-9a-f]*) echo "expected SHA-256 is invalid" >&2; exit 64 ;;
esac
if [ "${#expected_sha256}" -ne 64 ] || [ "$attempt_timeout" -eq 0 ] || \
   [ "$retry_window" -eq 0 ] || [ "$maximum_attempts" -eq 0 ] || \
   [ "$connect_timeout" -eq 0 ]; then
  echo "download policy is outside its admitted bounds" >&2
  exit 64
fi
if [ -n "$maximum_bytes" ]; then
  case "$maximum_bytes" in
    ''|*[!0-9]*) echo "maximum byte count is invalid" >&2; exit 64 ;;
  esac
  if [ "$maximum_bytes" -eq 0 ]; then
    echo "maximum byte count is invalid" >&2
    exit 64
  fi
fi
if [ -L "$destination" ] || { [ -e "$destination" ] && [ ! -f "$destination" ]; }; then
  echo "download destination is not a regular file" >&2
  exit 64
fi

started_at="$(date +%s)"
attempt=1
last_status=1
while [ "$attempt" -le "$maximum_attempts" ]; do
  now="$(date +%s)"
  remaining=$((retry_window - (now - started_at)))
  if [ "$remaining" -le 0 ]; then
    break
  fi
  transfer_timeout="$attempt_timeout"
  if [ "$remaining" -lt "$transfer_timeout" ]; then
    transfer_timeout="$remaining"
  fi
  transfer_connect_timeout="$connect_timeout"
  if [ "$transfer_timeout" -lt "$transfer_connect_timeout" ]; then
    transfer_connect_timeout="$transfer_timeout"
  fi

  if [ -n "$maximum_bytes" ]; then
    if curl --fail --location --silent --show-error --http1.1 \
      --continue-at - --connect-timeout "$transfer_connect_timeout" \
      --max-time "$transfer_timeout" --max-filesize "$maximum_bytes" \
      "$url" --output "$destination"; then
      transfer_status=0
    else
      transfer_status=$?
    fi
  elif curl --fail --location --silent --show-error --http1.1 \
    --continue-at - --connect-timeout "$transfer_connect_timeout" \
    --max-time "$transfer_timeout" "$url" --output "$destination"; then
    transfer_status=0
  else
    transfer_status=$?
  fi

  if [ "$transfer_status" -eq 0 ]; then
    if printf '%s  %s\n' "$expected_sha256" "$destination" | \
      sha256sum --check --strict -; then
      exit 0
    fi
    echo "download checksum mismatch" >&2
    exit 65
  fi
  last_status="$transfer_status"
  # Curl status 33 means the origin did not honor the exact resume range.
  if [ "$transfer_status" -eq 33 ] || [ "$attempt" -eq "$maximum_attempts" ]; then
    break
  fi

  now="$(date +%s)"
  remaining=$((retry_window - (now - started_at)))
  delay=$((retry_base_delay * attempt))
  if [ "$delay" -gt 5 ]; then
    delay=5
  fi
  if [ "$delay" -ge "$remaining" ]; then
    break
  fi
  if [ "$delay" -gt 0 ]; then
    sleep "$delay"
  fi
  attempt=$((attempt + 1))
done

echo "download retry policy exhausted" >&2
exit "$last_status"
