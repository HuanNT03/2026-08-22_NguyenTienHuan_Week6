#!/usr/bin/env bash
# Run bounded sqlmap detection and DBMS fingerprinting against the running pinned Compose target.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

VERSIONS_FILE="$PROJECT_ROOT/configs/tool-versions.env"
REPORT_DIR="$PROJECT_ROOT/reports/raw"
REPORT_FILE="$REPORT_DIR/sqlmap.json"
LOG_DIR="$PROJECT_ROOT/logs"
LOG_FILE="$LOG_DIR/sqlmap-runner.log"
TARGET_URL="http://juice-shop:3000/rest/products/search?q=apple"
NETWORK_NAME="sentinel-security"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
compose_command=(docker compose --project-directory "$PROJECT_ROOT" -f "$PROJECT_ROOT/docker-compose.yml" --env-file "$VERSIONS_FILE" --profile scan)

load_tool_versions "$VERSIONS_FILE"
"$SCRIPT_DIR/verify-target.sh"

container_id="$(docker compose --project-directory "$PROJECT_ROOT" -f "$PROJECT_ROOT/docker-compose.yml" ps -q juice-shop)"
if [[ -z "$container_id" ]] || [[ "$(docker inspect -f '{{.State.Running}}' "$container_id" 2>/dev/null || true)" != "true" ]]; then
  die "Juice Shop is not running. Run: make build && make up && make wait && make smoke && make dast-sqlmap"
fi
docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || \
  die "Docker network '$NETWORK_NAME' does not exist. Run 'make up' first."

"$SCRIPT_DIR/wait-for-target.sh"
"$SCRIPT_DIR/smoke-test.sh"
mkdir -p "$REPORT_DIR" "$LOG_DIR"
touch "$REPORT_DIR/.gitkeep" "$LOG_DIR/.gitkeep"
rm -f -- "$REPORT_FILE" "$LOG_FILE"

HOST_UID="$HOST_UID" HOST_GID="$HOST_GID" "${compose_command[@]}" build sqlmap-scan

if ! sqlmap_version_output="$(HOST_UID="$HOST_UID" HOST_GID="$HOST_GID" "${compose_command[@]}" run --rm --no-deps sqlmap-scan --version 2>&1)"; then
  printf '%s\n' "$sqlmap_version_output" >&2
  die "Unable to read the sqlmap version from image '$SQLMAP_IMAGE'."
fi
printf '%s\n' "$sqlmap_version_output"
actual_sqlmap_version="$(grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' <<<"$sqlmap_version_output" | head -n 1 || true)"
[[ "$actual_sqlmap_version" == "$SQLMAP_VERSION" ]] || \
  die "sqlmap image version mismatch: expected '$SQLMAP_VERSION', found '${actual_sqlmap_version:-unknown}'."

log "Running bounded sqlmap scan against the pinned Juice Shop search parameter."
set +e
HOST_UID="$HOST_UID" HOST_GID="$HOST_GID" "${compose_command[@]}" run --rm --no-deps sqlmap-scan \
  -u "$TARGET_URL" \
  -p q \
  --batch \
  --level=1 \
  --risk=1 \
  --technique=BEU \
  --fingerprint \
  --threads=1 \
  --timeout=10 \
  --retries=1 \
  --time-limit=600 \
  --output-dir=/tmp/sqlmap-output \
  --report-json=/workspace/reports/raw/sqlmap.json \
  --disable-coloring \
  -v 2 \
  2>&1 | tee "$LOG_FILE"
sqlmap_exit_code="${PIPESTATUS[0]}"
set -e

if ((sqlmap_exit_code != 0)); then
  die "sqlmap exited with code $sqlmap_exit_code. See $LOG_FILE."
fi
[[ -s "$REPORT_FILE" ]] || die "sqlmap completed without a non-empty JSON report: $REPORT_FILE"
jq empty "$REPORT_FILE" >/dev/null 2>&1 || die "sqlmap report is not valid JSON: $REPORT_FILE"
jq -e 'type == "object"' "$REPORT_FILE" >/dev/null 2>&1 || \
  die "sqlmap report must be a JSON object: $REPORT_FILE"

log "sqlmap scan completed. Raw report: $REPORT_FILE; runner log: $LOG_FILE"
