#!/usr/bin/env bash
# Run pinned ZAP Full Scan with Admin authentication against the running Compose target.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

VERSIONS_FILE="$PROJECT_ROOT/configs/tool-versions.env"
REPORT_DIR="$PROJECT_ROOT/reports/raw"
REPORT_FILE="$REPORT_DIR/zap.json"
META_FILE="$REPORT_DIR/zap.meta.json"
ENDPOINTS_FILE="$REPORT_DIR/zap-endpoints.txt"
SITE_TREE_FILE="$REPORT_DIR/zap-site-tree.yaml"
ZAP_CONFIG_DIR="$PROJECT_ROOT/configs/zap"
ZAP_AUTOMATION_PLAN="$ZAP_CONFIG_DIR/full-admin.yaml"
ZAP_AUTOMATION_PLAN_CONTAINER="/zap/configs/full-admin.yaml"
LOG_DIR="$PROJECT_ROOT/logs"
ZAP_DAEMON_LOG="$LOG_DIR/zap-fullscan-zap.out"
ZAP_RUNNER_LOG="$LOG_DIR/zap-fullscan-runner.log"
HOST_USER="$(id -u):$(id -g)"
NETWORK_NAME="sentinel-security"
TARGET_URL="http://juice-shop:3000"
readonly ZAP_CLIENT_SPIDER_MIN_BYTES=$((4 * 1024 * 1024 * 1024))

load_tool_versions "$VERSIONS_FILE"
"$SCRIPT_DIR/verify-target.sh"

docker_memory_bytes="$(docker info --format '{{.MemTotal}}')"
if ((docker_memory_bytes < ZAP_CLIENT_SPIDER_MIN_BYTES)); then
  die "ZAP Full Scan requires at least 4 GiB Docker memory for mandatory -j --client-spider; found ${docker_memory_bytes} bytes."
fi
log "ZAP Client Spider required and enabled (${docker_memory_bytes} bytes available)."

container_id="$(docker compose --project-directory "$PROJECT_ROOT" -f "$PROJECT_ROOT/docker-compose.yml" ps -q juice-shop)"
if [[ -z "$container_id" ]] || [[ "$(docker inspect -f '{{.State.Running}}' "$container_id" 2>/dev/null || true)" != "true" ]]; then
  die "Juice Shop is not running. Run: make build && make up && make wait && make smoke && make dast-zap-fullscan-admin"
fi
docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || \
  die "Docker network '$NETWORK_NAME' does not exist. Run 'make up' first."

"$SCRIPT_DIR/wait-for-target.sh"
"$SCRIPT_DIR/smoke-test.sh"
mkdir -p "$REPORT_DIR" "$LOG_DIR"
touch "$REPORT_DIR/.gitkeep"
touch "$LOG_DIR/.gitkeep"
rm -f -- "$REPORT_FILE" "$META_FILE" "$ENDPOINTS_FILE" "$SITE_TREE_FILE" "$ZAP_DAEMON_LOG" "$ZAP_RUNNER_LOG"
: >"$ZAP_DAEMON_LOG"
: >"$ZAP_RUNNER_LOG"
"$SCRIPT_DIR/write-scan-metadata.sh" \
  --tool zap \
  --scan-profile full-admin \
  --report reports/raw/zap.json \
  --base-url "$TARGET_URL"

log "ZAP image: $ZAP_IMAGE"
if ! zap_version_output="$(docker run --rm \
    --user "$HOST_USER" \
    -e HOME=/tmp \
    -e JAVA_TOOL_OPTIONS=-Duser.home=/tmp \
    "$ZAP_IMAGE" \
    zap.sh -version 2>&1)"; then
  printf '%s\n' "$zap_version_output" >&2
  die "Unable to read the ZAP version from image '$ZAP_IMAGE'."
fi
printf '%s\n' "$zap_version_output"
actual_zap_version="$(awk '/^[0-9]+\.[0-9]+\.[0-9]+\r?$/ { gsub(/\r/, ""); version=$0 } END { print version }' <<<"$zap_version_output")"
[[ "$actual_zap_version" == "$ZAP_VERSION" ]] || \
  die "ZAP image version mismatch: expected '$ZAP_VERSION', found '${actual_zap_version:-unknown}'."

if ! zap_automation_check="$(docker run --rm \
    --user "$HOST_USER" \
    -e HOME=/tmp \
    -e JAVA_TOOL_OPTIONS=-Duser.home=/tmp \
    --mount "type=bind,src=$ZAP_CONFIG_DIR,dst=/zap/configs,ro" \
    "$ZAP_IMAGE" \
    zap.sh -cmd -silent -autocheck "$ZAP_AUTOMATION_PLAN_CONTAINER" 2>&1)"; then
  printf '%s\n' "$zap_automation_check" >&2
  die "ZAP Automation plan failed validation: $ZAP_AUTOMATION_PLAN"
fi
printf '%s\n' "$zap_automation_check"
log "ZAP Full Scan Admin preflight passed (version $actual_zap_version, Automation plan valid)."

set +e
docker run --rm \
  --user "$HOST_USER" \
  -e HOME=/tmp \
  -e JAVA_TOOL_OPTIONS=-Duser.home=/tmp \
  --network "$NETWORK_NAME" \
  -v "$REPORT_DIR:/zap/wrk:rw" \
  --mount "type=bind,src=$ZAP_CONFIG_DIR,dst=/zap/configs,ro" \
  --mount "type=bind,src=$ZAP_DAEMON_LOG,dst=/zap/zap.out" \
  "$ZAP_IMAGE" \
  zap.sh -cmd -silent -autorun "$ZAP_AUTOMATION_PLAN_CONTAINER" \
  2>&1 | tee "$ZAP_RUNNER_LOG"
zap_exit_code="${PIPESTATUS[0]}"
set -e

log "ZAP Full Scan Admin exit code: $zap_exit_code"
case "$zap_exit_code" in
  0|2) "$SCRIPT_DIR/validate-reports.sh" zap ;;
  *) die "ZAP Full Scan Admin returned unexpected exit code $zap_exit_code. See $ZAP_RUNNER_LOG and $ZAP_DAEMON_LOG." ;;
esac

case "$zap_exit_code" in
  0) log "ZAP Full Scan Admin Automation plan completed successfully." ;;
  2) log "ZAP Full Scan Admin Automation plan completed with warnings." ;;
esac
