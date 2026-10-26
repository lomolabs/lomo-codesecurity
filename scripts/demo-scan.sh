#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${KODESEC_STATE_DIR:-${XDG_STATE_HOME:-${HOME}/.local/state}/lomo-kodesec}"
RUNTIME_ENV="${KODESEC_RUNTIME_ENV:-$STATE_DIR/runtime.env}"
runtime_port="$(sed -n 's/^CONTROL_PORT=//p' "$RUNTIME_ENV" 2>/dev/null | tail -n 1)"
API_URL="${KODESEC_API_URL:-http://127.0.0.1:${runtime_port:-8080}}"
PROJECT_NAME="${DEMO_PROJECT_NAME:-codesecurity-vulnerable-demo}"
DEMO_PATH="${DEMO_PATH:-$ROOT_DIR/examples/vulnerable-demo}"
USE_AI="${DEMO_USE_AI:-false}"
CAPABILITY_FILE="${KODESEC_CAPABILITY_FILE:-$STATE_DIR/cli-capability}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for JSON payload handling" >&2
  exit 2
fi

if ! API_URL="$(python3 "$ROOT_DIR/scripts/validate-loopback-url.py" "$API_URL")"; then
  echo "Refusing to send a capability outside an exact HTTP loopback origin." >&2
  exit 2
fi

secure_file_value() {
  local path="$1" mode owner links value
  if [[ -L "$path" || ! -f "$path" ]]; then
    return 1
  fi
  mode="$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path")"
  owner="$(stat -c '%u' "$path" 2>/dev/null || stat -f '%u' "$path")"
  links="$(stat -c '%h' "$path" 2>/dev/null || stat -f '%l' "$path")"
  if [[ "$mode" != "600" || "$owner" != "$(id -u)" || "$links" != "1" ]]; then
    return 1
  fi
  value="$(<"$path")"
  printf '%s' "$value"
}

if [[ -n "${KODESEC_API_CAPABILITY:-}" ]]; then
  capability="$KODESEC_API_CAPABILITY"
elif capability="$(secure_file_value "$CAPABILITY_FILE")"; then
  :
else
  echo "A CLI bearer capability is required in KODESEC_API_CAPABILITY or an owner-only, mode-0600, single-link KODESEC_CAPABILITY_FILE." >&2
  echo "The script will not consume or log browser bootstrap and IDE pairing values." >&2
  exit 2
fi
if [[ ! "$capability" =~ ^kc1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43,}$ ]]; then
  echo "The CLI capability is malformed." >&2
  exit 2
fi

header_file="$(mktemp "${TMPDIR:-/tmp}/kodesec-demo-headers.XXXXXX")"
chmod 600 "$header_file"
printf 'Authorization: Bearer %s\n' "$capability" > "$header_file"
unset capability KODESEC_API_CAPABILITY
cleanup() {
  rm -f "$header_file" "${tmp_project:-}"
}
trap cleanup EXIT HUP INT TERM

api_curl() {
  curl --proto '=http' --max-redirs 0 -H "@$header_file" "$@"
}

if ! curl --proto '=http' --max-redirs 0 -fsS "$API_URL/healthz" >/dev/null; then
  echo "CodeSecurity API is not reachable at $API_URL. Start the stack with: make up" >&2
  exit 2
fi

payload="$(
  PROJECT_NAME="$PROJECT_NAME" DEMO_PATH="$DEMO_PATH" python3 - <<'PY'
import json
import os

print(json.dumps({
    "name": os.environ["PROJECT_NAME"],
    "repo_path": os.environ["DEMO_PATH"],
    "remote_url": "local://examples/vulnerable-demo",
    "default_branch": "main",
}))
PY
)"

tmp_project="$(mktemp)"
status="$(api_curl -sS -o "$tmp_project" -w "%{http_code}" \
  -X POST "$API_URL/v1/projects" \
  -H "content-type: application/json" \
  -d "$payload")"

if [ "$status" = "201" ]; then
  project_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$tmp_project")"
elif [ "$status" = "409" ]; then
  resolve_payload="$(
    DEMO_PATH="$DEMO_PATH" python3 - <<'PY'
import json
import os

print(json.dumps({"repo_path": os.environ["DEMO_PATH"]}))
PY
  )"
  project_id="$(api_curl -fsS -X POST "$API_URL/v1/projects/resolve" \
    -H "content-type: application/json" \
    -d "$resolve_payload" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
else
  cat "$tmp_project" >&2
  rm -f "$tmp_project"
  exit 1
fi
rm -f "$tmp_project"

scan_payload="$(
  PROJECT_ID="$project_id" USE_AI="$USE_AI" python3 - <<'PY'
import json
import os

print(json.dumps({
    "project_id": int(os.environ["PROJECT_ID"]),
    "mode": "full",
    "use_ai": os.environ["USE_AI"].lower() in {"1", "true", "yes", "on"},
}))
PY
)"

scan_command_id="demo-$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
scan_id="$(api_curl -fsS -X POST "$API_URL/v1/scans" \
  -H "content-type: application/json" \
  -H "Idempotency-Key: $scan_command_id" \
  -d "$scan_payload" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
echo "Started demo scan #$scan_id for $DEMO_PATH"

for _ in $(seq 1 240); do
  scan_json="$(api_curl -fsS "$API_URL/v1/scans/$scan_id")"
  scan_status="$(printf '%s' "$scan_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
  if [ "$scan_status" != "pending" ] && [ "$scan_status" != "running" ] && [ "$scan_status" != "analyzing" ]; then
    findings="$(api_curl -fsS "$API_URL/v1/scans/$scan_id/findings?limit=12")"
    SCAN_JSON="$scan_json" python3 - <<'PY'
import json
import os
import sys

required_external = {
    "trivy",
    "gitleaks",
    "opengrep",
    "bearer",
    "grype",
    "checkov",
    "trufflehog",
    "syft",
}
successful_tool_statuses = {"completed", "completed_with_exit_code"}
scan = json.loads(os.environ["SCAN_JSON"])
summary = scan.get("scanner_summary") or {}
print(f"Scan status: {scan['status']}")
print(f"Gate: {scan.get('gate_decision') or 'pending'}")
print(f"Findings: {summary.get('findings_total', 0)}")
print(f"Severity: {summary.get('severity_counts', {})}")
print("Scanners:")
for tool in summary.get("tools", []):
    print(f"  - {tool['id']}: {tool.get('findings_count', 0)} findings ({tool.get('status', 'unknown')})")

violations = []
if scan.get("status") != "completed":
    violations.append(f"terminal status is {scan.get('status')!r}, not 'completed'")
if scan.get("error") not in (None, ""):
    violations.append("the scan has a top-level execution error")
if summary.get("errors") != []:
    violations.append("scanner_summary.errors is missing or non-empty")
if summary.get("requested_mode") != "full" or summary.get("effective_mode") != "full":
    violations.append("the canonical scan did not execute as a full scan")

tools = summary.get("tools")
if not isinstance(tools, list):
    tools = []
    violations.append("scanner_summary.tools is missing or malformed")
tool_rows = {
    item.get("id"): item
    for item in tools
    if isinstance(item, dict) and isinstance(item.get("id"), str)
}
if len(tool_rows) != sum(
    1
    for item in tools
    if isinstance(item, dict) and isinstance(item.get("id"), str)
):
    violations.append("scanner_summary.tools contains duplicate tool identifiers")
observed_external = {
    tool_id for tool_id, item in tool_rows.items() if item.get("source") == "external"
}
if observed_external != required_external:
    missing = sorted(required_external - observed_external)
    unexpected = sorted(observed_external - required_external)
    violations.append(
        f"external scanner inventory mismatch (missing={missing}, unexpected={unexpected})"
    )
for tool_id in sorted(required_external):
    item = tool_rows.get(tool_id)
    if item is None:
        continue
    if item.get("enabled") is not True:
        violations.append(f"{tool_id} was not enabled")
    if item.get("available") is not True:
        violations.append(f"{tool_id} was not runtime-ready")
    if item.get("status") not in successful_tool_statuses:
        violations.append(f"{tool_id} ended as {item.get('status')!r}")
    if item.get("error") not in (None, ""):
        violations.append(f"{tool_id} reported an execution error")

syft = tool_rows.get("syft") or {}
if not isinstance(syft.get("artifacts_count"), int) or syft.get("artifacts_count", 0) < 1:
    violations.append("Syft did not report a published artifact")
artifacts = summary.get("artifacts")
if not isinstance(artifacts, list) or not any(
    isinstance(item, dict)
    and item.get("scanner") == "syft"
    and item.get("artifact_type") == "sbom"
    and item.get("format") == "cyclonedx-json"
    for item in artifacts
):
    violations.append("the scan summary has no Syft CycloneDX SBOM evidence")

external_runs = summary.get("external_runs")
run_ids = [
    item.get("id")
    for item in external_runs
    if isinstance(item, dict) and isinstance(item.get("id"), str)
] if isinstance(external_runs, list) else []
if set(run_ids) != required_external or len(run_ids) != len(required_external):
    violations.append("external_runs does not contain exactly one run for each required scanner")
elif run_ids.index("syft") > run_ids.index("grype"):
    violations.append("Grype ran before its required same-scan Syft SBOM producer")

if violations:
    print("Demo scan qualification failed:", file=sys.stderr)
    for violation in violations:
        print(f"  - {violation}", file=sys.stderr)
    raise SystemExit(1)
PY
    FINDINGS_JSON="$findings" python3 - <<'PY'
import json
import os
import sys

page = json.loads(os.environ["FINDINGS_JSON"])
if not isinstance(page, dict):
    raise SystemExit("findings endpoint did not return a paginated envelope")
items = page.get("items")
if not isinstance(items, list):
    raise SystemExit("findings page is missing its items array")
total = page.get("total")
truncated = page.get("truncated")
next_cursor = page.get("next_cursor")
if not isinstance(total, int) or isinstance(total, bool) or total < len(items):
    raise SystemExit("findings page has an invalid total")
if truncated is not (next_cursor is not None):
    raise SystemExit("findings page truncation and cursor state disagree")
for item in items[:12]:
    loc = f"{item['file_path']}:{item.get('start_line') or ''}".rstrip(":")
    print(f"- {item['severity']:8} {item['rule_id']:34} {loc}")
PY
    echo "Open $API_URL/findings?scan=$scan_id"
    exit 0
  fi
  sleep 2
done

echo "Timed out waiting for demo scan #$scan_id" >&2
exit 1
