#!/usr/bin/env bash
# Clone the pinned Juice Shop target when absent, then verify it. Exits non-zero on any mismatch.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

LOCK_FILE="$PROJECT_ROOT/target-app/TARGET.lock"
TARGET_DIR="$PROJECT_ROOT/target-app/juice-shop"

load_target_lock "$LOCK_FILE"

if [[ -e "$TARGET_DIR" ]]; then
  [[ -d "$TARGET_DIR" ]] || die "Target path exists but is not a directory: $TARGET_DIR"
  log "Target already exists; verifying without modifying it."
  exec "$SCRIPT_DIR/verify-target.sh"
fi

log "Cloning $REPOSITORY_URL tag $TAG into $TARGET_DIR"
git clone --branch "$TAG" --depth 1 --single-branch "$REPOSITORY_URL" "$TARGET_DIR"

# Preserve an explicit local annotated tag ref across Git version differences.
git -C "$TARGET_DIR" fetch --depth 1 origin tag "$TAG" --no-tags
git -C "$TARGET_DIR" checkout --detach "$COMMIT_SHA"

exec "$SCRIPT_DIR/verify-target.sh"
