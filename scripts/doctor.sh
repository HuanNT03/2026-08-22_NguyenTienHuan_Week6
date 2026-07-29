#!/usr/bin/env bash
# Check all Week 1 host prerequisites and Docker availability. Exits non-zero if any check fails.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

missing=0
for command_name in git bash make docker curl jq; do
  if command -v "$command_name" >/dev/null 2>&1; then
    log "Found $command_name"
  else
    printf '[sentinel] ERROR: Required command not found: %s\n' "$command_name" >&2
    missing=1
  fi
done
((missing == 0)) || exit 1

docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is unavailable; expected 'docker compose'"
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable or the current user lacks permission"
log "All Week 1 prerequisites are available."
