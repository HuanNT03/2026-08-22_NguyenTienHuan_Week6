#!/usr/bin/env bash
# Remove generated reports, or perform the explicit full reset. Input: reports|full. Preserves project sources.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

RAW_DIR="$PROJECT_ROOT/reports/raw"
NORMALIZED_DIR="$PROJECT_ROOT/reports/normalized"
TARGET_DIR="$PROJECT_ROOT/target-app/juice-shop"

assert_exact_path() {
  local actual="$1"
  local expected="$2"
  [[ -n "$actual" && "$actual" == "$expected" && "$actual" == "$PROJECT_ROOT/"* ]] || \
    die "Refusing unsafe cleanup path: $actual"
}

clean_report_directory() {
  local report_dir="$1"
  assert_exact_path "$report_dir" "$2"
  mkdir -p "$report_dir"
  find "$report_dir" -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf -- {} +
  touch "$report_dir/.gitkeep"
  log "Cleaned generated report contents: $report_dir"
}

mode="${1:-}"
case "$mode" in
  reports)
    clean_report_directory "$RAW_DIR" "$PROJECT_ROOT/reports/raw"
    clean_report_directory "$NORMALIZED_DIR" "$PROJECT_ROOT/reports/normalized"
    ;;
  full)
    docker compose --project-directory "$PROJECT_ROOT" -f "$PROJECT_ROOT/docker-compose.yml" down --volumes --remove-orphans
    clean_report_directory "$RAW_DIR" "$PROJECT_ROOT/reports/raw"
    clean_report_directory "$NORMALIZED_DIR" "$PROJECT_ROOT/reports/normalized"
    assert_exact_path "$TARGET_DIR" "$PROJECT_ROOT/target-app/juice-shop"
    if [[ -e "$TARGET_DIR" ]]; then
      rm -rf -- "$TARGET_DIR"
      log "Removed generated target clone: $TARGET_DIR"
    else
      log "Target clone already absent: $TARGET_DIR"
    fi
    ;;
  *) die "Usage: $0 {reports|full}" ;;
esac
