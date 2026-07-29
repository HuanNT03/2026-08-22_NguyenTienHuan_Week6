#!/usr/bin/env bash
# Verify target origin, commit, annotated tag, cleanliness and package version. Never modifies the target.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

LOCK_FILE="$PROJECT_ROOT/target-app/TARGET.lock"
TARGET_DIR="$PROJECT_ROOT/target-app/juice-shop"

load_target_lock "$LOCK_FILE"

[[ -d "$TARGET_DIR" ]] || die "Target directory not found: $TARGET_DIR. Run 'make setup-target'."
git -C "$TARGET_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1 || \
  die "Target is not a Git repository: $TARGET_DIR"

actual_origin="$(git -C "$TARGET_DIR" remote get-url origin 2>/dev/null || true)"
[[ "$actual_origin" == "$REPOSITORY_URL" ]] || \
  die "Target origin mismatch (expected: $REPOSITORY_URL, actual: ${actual_origin:-<missing>})"

actual_head="$(git -C "$TARGET_DIR" rev-parse HEAD)"
[[ "$actual_head" == "$COMMIT_SHA" ]] || \
  die "Target commit mismatch (expected: $COMMIT_SHA, actual: $actual_head)"

actual_tag_commit="$(git -C "$TARGET_DIR" rev-parse "$TAG^{commit}" 2>/dev/null || true)"
[[ "$actual_tag_commit" == "$COMMIT_SHA" ]] || \
  die "Target tag mismatch for $TAG (expected commit: $COMMIT_SHA, actual: ${actual_tag_commit:-<unresolved>})"

dirty_state="$(git -C "$TARGET_DIR" status --porcelain --untracked-files=all)"
[[ -z "$dirty_state" ]] || die "Target working tree is dirty; do not modify files under target-app/juice-shop"

[[ -f "$TARGET_DIR/package.json" ]] || die "Target package.json not found"
actual_version="$(jq -er '.version | strings' "$TARGET_DIR/package.json" 2>/dev/null || true)"
[[ "$actual_version" == "20.1.1" ]] || \
  die "Target package version mismatch (expected: 20.1.1, actual: ${actual_version:-<invalid>})"

log "Target verified: $TAG at $COMMIT_SHA"
