#!/usr/bin/env bash
# Run pinned ZAP Baseline against the already-running Compose target and write reports/raw/zap.json.

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
ZAP_AUTOMATION_PLAN="$ZAP_CONFIG_DIR/baseline.yaml"
ZAP_AUTOMATION_PLAN_CONTAINER="/zap/configs/baseline.yaml"
HOST_USER="$(id -u):$(id -g)"
NETWORK_NAME="sentinel-security"

readonly ZAP_MODERN_SPIDER_MIN_BYTES=$((4 * 1024 * 1024 * 1024))
docker_memory_bytes="$(docker info --format '{{.MemTotal}}')"
if (( docker_memory_bytes >= ZAP_MODERN_SPIDER_MIN_BYTES )); then
  log "ZAP modern spider enabled (${docker_memory_bytes} bytes available)."
else
  ZAP_AUTOMATION_PLAN="$ZAP_CONFIG_DIR/baseline-low-memory.yaml"
  ZAP_AUTOMATION_PLAN_CONTAINER="/zap/configs/baseline-low-memory.yaml"
  log "ZAP modern spider disabled: ${docker_memory_bytes} bytes available; using traditional spider."
fi

load_tool_versions "$VERSIONS_FILE"
"$SCRIPT_DIR/verify-target.sh"

container_id="$(docker compose --project-directory "$PROJECT_ROOT" -f "$PROJECT_ROOT/docker-compose.yml" ps -q juice-shop)"
if [[ -z "$container_id" ]] || [[ "$(docker inspect -f '{{.State.Running}}' "$container_id" 2>/dev/null || true)" != "true" ]]; then
  die "Juice Shop is not running. Run: make build && make up && make wait && make smoke && make dast"
fi
docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || \
  die "Docker network '$NETWORK_NAME' does not exist. Run 'make up' first."

"$SCRIPT_DIR/wait-for-target.sh"
"$SCRIPT_DIR/smoke-test.sh"
mkdir -p "$REPORT_DIR"
touch "$REPORT_DIR/.gitkeep"
rm -f -- "$REPORT_FILE" "$META_FILE" "$ENDPOINTS_FILE" "$SITE_TREE_FILE"
"$SCRIPT_DIR/write-scan-metadata.sh" --tool zap --scan-profile baseline --report reports/raw/zap.json --base-url http://juice-shop:3000

HOST_PROJECT_ROOT="$(resolve_host_project_root "$PROJECT_ROOT")"
HOST_REPORT_DIR="$HOST_PROJECT_ROOT/reports/raw"
HOST_ZAP_CONFIG_DIR="$HOST_PROJECT_ROOT/configs/zap"

log "ZAP image: $ZAP_IMAGE"
docker run --rm \
  --user "$HOST_USER" \
  -e HOME=/tmp \
  -e JAVA_TOOL_OPTIONS=-Duser.home=/tmp \
  "$ZAP_IMAGE" \
  zap.sh -version

log "ZAP Automation plan: $ZAP_AUTOMATION_PLAN"
docker run --rm \
  --user "$HOST_USER" \
  -e HOME=/tmp \
  -e JAVA_TOOL_OPTIONS=-Duser.home=/tmp \
  --mount "type=bind,src=$HOST_ZAP_CONFIG_DIR,dst=/zap/configs,ro" \
  "$ZAP_IMAGE" \
  zap.sh -cmd -silent -autocheck "$ZAP_AUTOMATION_PLAN_CONTAINER"

set +e
docker run --rm \
  --user "$HOST_USER" \
  -e HOME=/tmp \
  -e JAVA_TOOL_OPTIONS=-Duser.home=/tmp \
  --network "$NETWORK_NAME" \
  -v "$HOST_REPORT_DIR:/zap/wrk:rw" \
  --mount "type=bind,src=$HOST_ZAP_CONFIG_DIR,dst=/zap/configs,ro" \
  "$ZAP_IMAGE" \
  zap.sh -cmd -silent -autorun "$ZAP_AUTOMATION_PLAN_CONTAINER"
zap_exit_code=$?
set -e

log "ZAP Baseline exit code: $zap_exit_code"
"$SCRIPT_DIR/validate-reports.sh" zap

case "$zap_exit_code" in
  0) log "ZAP Baseline Automation plan completed successfully." ;;
  2) log "ZAP Baseline Automation plan completed with warnings." ;;
  *) die "ZAP Baseline Automation plan failed (exit code $zap_exit_code)." ;;
esac
