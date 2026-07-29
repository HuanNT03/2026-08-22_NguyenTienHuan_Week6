#!/usr/bin/env bash
# Poll the target over HTTP until it is ready. Inputs: WAIT_* and JUICE_SHOP_PORT. Exits on timeout.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-120}"
WAIT_INTERVAL_SECONDS="${WAIT_INTERVAL_SECONDS:-2}"
[[ "$WAIT_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] || die "WAIT_TIMEOUT_SECONDS must be a positive integer"
[[ "$WAIT_INTERVAL_SECONDS" =~ ^[1-9][0-9]*$ ]] || die "WAIT_INTERVAL_SECONDS must be a positive integer"

port="$(resolve_juice_shop_port "$PROJECT_ROOT")"
target_url="http://127.0.0.1:$port/"
deadline=$((SECONDS + WAIT_TIMEOUT_SECONDS))

log "Waiting up to ${WAIT_TIMEOUT_SECONDS}s for HTTP readiness at $target_url"
while ((SECONDS < deadline)); do
  status_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$target_url" 2>/dev/null || true)"
  if [[ "$status_code" =~ ^[23][0-9][0-9]$ ]]; then
    log "Target is ready (HTTP $status_code)."
    exit 0
  fi
  sleep "$WAIT_INTERVAL_SECONDS"
done

printf '[sentinel] ERROR: Timed out waiting for %s\n' "$target_url" >&2
printf '[sentinel] Compose status:\n' >&2
docker compose --project-directory "$PROJECT_ROOT" -f "$PROJECT_ROOT/docker-compose.yml" ps >&2 || true
printf '[sentinel] Recent Juice Shop logs:\n' >&2
docker compose --project-directory "$PROJECT_ROOT" -f "$PROJECT_ROOT/docker-compose.yml" logs --tail 50 juice-shop >&2 || true
exit 1
