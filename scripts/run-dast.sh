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
HOST_USER="$(id -u):$(id -g)"
NETWORK_NAME="sentinel-security"

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
rm -f -- "$REPORT_FILE"

log "ZAP image: $ZAP_IMAGE"
docker run --rm --user "$HOST_USER" -e HOME=/tmp "$ZAP_IMAGE" zap.sh -version

set +e
docker run --rm \
  --user "$HOST_USER" \
  -e HOME=/tmp \
  --network "$NETWORK_NAME" \
  -v "$REPORT_DIR:/zap/wrk:rw" \
  "$ZAP_IMAGE" \
  zap-baseline.py \
  -t http://juice-shop:3000 \
  -J zap.json \
  -z "-silent"
zap_exit_code=$?
set -e

log "ZAP Baseline exit code: $zap_exit_code"
"$SCRIPT_DIR/validate-reports.sh" zap

case "$zap_exit_code" in
  0) log "ZAP Baseline completed without WARN or FAIL findings." ;;
  1) log "ZAP Baseline completed with FAIL findings; accepted for Week 1." ;;
  2) log "ZAP Baseline completed with WARN findings; accepted for Week 1." ;;
  3) die "ZAP Baseline execution failed (exit code 3)." ;;
  *) die "ZAP Baseline returned unexpected exit code: $zap_exit_code" ;;
esac
