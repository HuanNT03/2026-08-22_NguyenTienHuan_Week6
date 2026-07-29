#!/usr/bin/env bash
# Validate raw Semgrep and/or ZAP JSON structure. Input: semgrep|zap|all. Exits non-zero on invalid reports.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

REPORT_DIR="${SENTINEL_REPORT_DIR:-$PROJECT_ROOT/reports/raw}"

validate_json_file() {
  local report_name="$1"
  local report_path="$2"
  local jq_expression="$3"

  [[ -e "$report_path" ]] || die "$report_name report is missing: $report_path"
  [[ -s "$report_path" ]] || die "$report_name report is empty: $report_path"
  jq empty "$report_path" >/dev/null 2>&1 || die "$report_name report contains invalid JSON: $report_path"
  jq -e "$jq_expression" "$report_path" >/dev/null 2>&1 || \
    die "$report_name report has an invalid top-level structure: $report_path"
  log "$report_name report is valid: $report_path"
}

validate_semgrep() {
  validate_json_file "Semgrep" "$REPORT_DIR/semgrep.json" \
    'type == "object" and (.results | type == "array")'
}

validate_zap() {
  validate_json_file "ZAP" "$REPORT_DIR/zap.json" \
    'type == "object" and (.site | (type == "array" or type == "object"))'
}

case "${1:-}" in
  semgrep) validate_semgrep ;;
  zap) validate_zap ;;
  all)
    validate_semgrep
    validate_zap
    ;;
  *) die "Usage: $0 {semgrep|zap|all}" ;;
esac
