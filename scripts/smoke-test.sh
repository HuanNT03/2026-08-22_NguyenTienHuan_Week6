#!/usr/bin/env bash
# Verify host HTTP access and a non-empty response body. Input: JUICE_SHOP_PORT. Exits non-zero on failure.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

port="$(resolve_juice_shop_port "$PROJECT_ROOT")"
target_url="http://127.0.0.1:$port/"
response_body="$(mktemp "${TMPDIR:-/tmp}/sentinel-smoke.XXXXXX")"
trap 'rm -f -- "$response_body"' EXIT

status_code="$(curl -sS -o "$response_body" -w '%{http_code}' --max-time 15 "$target_url")" || \
  die "Unable to reach target at $target_url"

[[ "$status_code" =~ ^[23][0-9][0-9]$ ]] || die "Smoke test received HTTP $status_code from $target_url"
[[ -s "$response_body" ]] || die "Smoke test received an empty response body from $target_url"

log "Smoke test passed: HTTP $status_code with a non-empty response body."
