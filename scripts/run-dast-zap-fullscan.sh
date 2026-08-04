#!/usr/bin/env bash
# Run pinned ZAP Full Scan with mandatory Client Spider against the running Compose target.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

VERSIONS_FILE="$PROJECT_ROOT/configs/tool-versions.env"
REPORT_DIR="$PROJECT_ROOT/reports/raw"
REPORT_FILE="$REPORT_DIR/zap.json"
META_FILE="$REPORT_DIR/zap.meta.json"
HOST_USER="$(id -u):$(id -g)"
NETWORK_NAME="sentinel-security"
TARGET_URL="http://juice-shop:3000"
readonly ZAP_CLIENT_SPIDER_MIN_BYTES=$((4 * 1024 * 1024 * 1024))
readonly ZAP_SPIDER_MAX_MINUTES=10
readonly ZAP_PASSIVE_MAX_MINUTES=10
readonly ZAP_ACTIVE_MAX_MINUTES=30

load_tool_versions "$VERSIONS_FILE"
"$SCRIPT_DIR/verify-target.sh"

docker_memory_bytes="$(docker info --format '{{.MemTotal}}')"
if ((docker_memory_bytes < ZAP_CLIENT_SPIDER_MIN_BYTES)); then
  die "ZAP Full Scan requires at least 4 GiB Docker memory for mandatory -j --client-spider; found ${docker_memory_bytes} bytes."
fi
log "ZAP Client Spider required and enabled (${docker_memory_bytes} bytes available)."

container_id="$(docker compose --project-directory "$PROJECT_ROOT" -f "$PROJECT_ROOT/docker-compose.yml" ps -q juice-shop)"
if [[ -z "$container_id" ]] || [[ "$(docker inspect -f '{{.State.Running}}' "$container_id" 2>/dev/null || true)" != "true" ]]; then
  die "Juice Shop is not running. Run: make build && make up && make wait && make smoke && make dast-zap-fullscan"
fi
docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || \
  die "Docker network '$NETWORK_NAME' does not exist. Run 'make up' first."

"$SCRIPT_DIR/wait-for-target.sh"
"$SCRIPT_DIR/smoke-test.sh"
mkdir -p "$REPORT_DIR"
touch "$REPORT_DIR/.gitkeep"
rm -f -- "$REPORT_FILE" "$META_FILE"
"$SCRIPT_DIR/write-scan-metadata.sh" \
  --tool zap \
  --scan-profile full \
  --report reports/raw/zap.json \
  --base-url "$TARGET_URL"

log "ZAP image: $ZAP_IMAGE"
docker run --rm \
  --user "$HOST_USER" \
  -e HOME=/tmp \
  -e JAVA_TOOL_OPTIONS=-Duser.home=/tmp \
  "$ZAP_IMAGE" \
  zap.sh -version

set +e
docker run --rm \
  --user "$HOST_USER" \
  -e HOME=/tmp \
  -e JAVA_TOOL_OPTIONS=-Duser.home=/tmp \
  --network "$NETWORK_NAME" \
  -v "$REPORT_DIR:/zap/wrk:rw" \
  "$ZAP_IMAGE" \
  zap-full-scan.py \
  -t "$TARGET_URL" \
  -j \
  --client-spider \
  -m "$ZAP_SPIDER_MAX_MINUTES" \
  -T "$ZAP_PASSIVE_MAX_MINUTES" \
  -J zap.json \
  -z "-silent -config scanner.maxScanDurationInMins=$ZAP_ACTIVE_MAX_MINUTES"
zap_exit_code=$?
set -e

log "ZAP Full Scan exit code: $zap_exit_code"
"$SCRIPT_DIR/validate-reports.sh" zap

case "$zap_exit_code" in
  0) log "ZAP Full Scan completed without WARN or FAIL findings." ;;
  1) log "ZAP Full Scan completed with FAIL findings; report accepted." ;;
  2) log "ZAP Full Scan completed with WARN findings; report accepted." ;;
  3) die "ZAP Full Scan execution failed (exit code 3)." ;;
  *) die "ZAP Full Scan returned unexpected exit code: $zap_exit_code" ;;
esac
