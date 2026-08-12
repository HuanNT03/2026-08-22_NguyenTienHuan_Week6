#!/usr/bin/env bash
# Verify host HTTP access and a non-empty response body. Input: JUICE_SHOP_PORT. Exits non-zero on failure.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

port="$(resolve_juice_shop_port "$PROJECT_ROOT")"
candidate_urls=(
  "http://127.0.0.1:$port/"
  "http://juice-shop:3000/"
  "http://host.docker.internal:$port/"
)
response_body="$(mktemp "${TMPDIR:-/tmp}/sentinel-smoke.XXXXXX")"
trap 'rm -f -- "$response_body"' EXIT

for target_url in "${candidate_urls[@]}"; do
  : >"$response_body"
  status_code="$(curl -sS -o "$response_body" -w '%{http_code}' --max-time 15 "$target_url" 2>/dev/null || true)"
  if [[ "$status_code" =~ ^[23][0-9][0-9]$ ]] && [[ -s "$response_body" ]]; then
    log "Smoke test passed at $target_url: HTTP $status_code with a non-empty response body."
    exit 0
  fi
done

die "Smoke test failed for all attempted target URLs: ${candidate_urls[*]}"
