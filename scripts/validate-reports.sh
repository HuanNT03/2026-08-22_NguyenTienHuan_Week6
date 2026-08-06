#!/usr/bin/env bash
# Validate raw scanner reports and their metadata sidecars. Input: semgrep|zap|codeql|all.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

REPORT_DIR="${SENTINEL_REPORT_DIR:-$PROJECT_ROOT/reports/raw}"
VALIDATION_ERRORS=0

load_target_lock "$PROJECT_ROOT/target-app/TARGET.lock"
load_tool_versions "$PROJECT_ROOT/configs/tool-versions.env"
TARGET_NAME="${REPOSITORY_URL##*/}"
TARGET_NAME="${TARGET_NAME%.git}"
TARGET_VERSION="${TAG#v}"

report_error() {
  printf '[sentinel] ERROR: %s\n' "$*" >&2
  VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
}

validate_json_file() {
  local artifact_name="$1"
  local artifact_path="$2"
  local jq_expression="$3"
  local log_success="${4:-true}"

  if [[ ! -e "$artifact_path" ]]; then
    report_error "$artifact_name is missing: $artifact_path"
    return 1
  fi
  if [[ ! -s "$artifact_path" ]]; then
    report_error "$artifact_name is empty: $artifact_path"
    return 1
  fi
  if ! jq empty "$artifact_path" >/dev/null 2>&1; then
    report_error "$artifact_name contains invalid JSON: $artifact_path"
    return 1
  fi
  if ! jq -e "$jq_expression" "$artifact_path" >/dev/null 2>&1; then
    report_error "$artifact_name has an invalid top-level structure: $artifact_path"
    return 1
  fi
  [[ "$log_success" != true ]] || log "$artifact_name is valid: $artifact_path"
}

validate_metadata() {
  local tool="$1"
  local report_name="$2"
  local expected_version="$3"
  local metadata_path="$REPORT_DIR/$tool.meta.json"
  local tool_expression='true'

  case "$tool" in
    zap) tool_expression='(.scan_profile == "baseline" or .scan_profile == "full")' ;;
    codeql) tool_expression='(.query_suite == "javascript-security-extended.qls" and (.query_packs | type == "object"))' ;;
  esac

  if ! validate_json_file "$tool metadata" "$metadata_path" 'type == "object"' false; then
    return
  fi
  if ! jq -e \
    --arg report_path "reports/raw/$report_name" \
    --arg target_name "$TARGET_NAME" \
    --arg target_version "$TARGET_VERSION" \
    --arg commit_sha "$COMMIT_SHA" \
    --arg cli_version "$expected_version" \
    "
      (.run_id | type == \"string\" and length > 0) and
      (.pipeline_run_id | type == \"null\" or type == \"string\") and
      (.scanned_at | type == \"string\" and test(\"^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*(Z|[+-][0-9]{2}:[0-9]{2})$\")) and
      (.cli_version == \$cli_version) and
      (.report_path == \$report_path) and
      (.target | type == \"object\") and
      (.target.name == \$target_name) and
      (.target.version == \$target_version) and
      (.target.commit_sha == \$commit_sha) and
      (.target.base_url | type == \"null\" or type == \"string\") and
      $tool_expression
    " "$metadata_path" >/dev/null 2>&1; then
    report_error "$tool metadata is invalid or does not match the pinned report: $metadata_path"
    return
  fi
  log "$tool metadata matches $report_name: $metadata_path"
}

validate_semgrep() {
  validate_json_file "Semgrep report" "$REPORT_DIR/semgrep.json" \
    'type == "object" and (.results | type == "array")' || true
  validate_metadata semgrep semgrep.json "$SEMGREP_VERSION"
}

validate_zap() {
  validate_json_file "ZAP report" "$REPORT_DIR/zap.json" \
    'type == "object" and (.site | (type == "array" or type == "object"))' || true
  validate_metadata zap zap.json "$ZAP_VERSION"

  local endpoints_path="$REPORT_DIR/zap-endpoints.txt"
  local site_tree_path="$REPORT_DIR/zap-site-tree.yaml"
  if [[ ! -s "$endpoints_path" ]]; then
    report_error "ZAP endpoint inventory is missing or empty: $endpoints_path"
  elif ! grep -Eq '^http://juice-shop:3000($|[/?#])' "$endpoints_path"; then
    report_error "ZAP endpoint inventory does not contain a Juice Shop URL: $endpoints_path"
  elif awk '
    NF && $0 !~ /^http:\/\/juice-shop:3000($|[\/?#])/ { exit 1 }
  ' "$endpoints_path"; then
    log "ZAP endpoint inventory is limited to the Juice Shop origin: $endpoints_path"
  else
    report_error "ZAP endpoint inventory contains a URL outside the Juice Shop origin: $endpoints_path"
  fi

  if [[ ! -s "$site_tree_path" ]]; then
    report_error "ZAP site tree is missing or empty: $site_tree_path"
  elif ! grep -Fq 'http://juice-shop:3000' "$site_tree_path"; then
    report_error "ZAP site tree does not contain the Juice Shop origin: $site_tree_path"
  elif grep -Eo 'https?://[^"[:space:]]+' "$site_tree_path" | \
      awk '$0 !~ /^http:\/\/juice-shop:3000($|[\/?#])/ { exit 1 }'; then
    log "ZAP site tree is limited to the Juice Shop origin: $site_tree_path"
  else
    report_error "ZAP site tree contains a URL outside the Juice Shop origin: $site_tree_path"
  fi
}

validate_codeql() {
  validate_json_file "CodeQL report" "$REPORT_DIR/codeql.sarif" \
    'type == "object" and .version == "2.1.0" and (.runs | type == "array")' || true
  validate_metadata codeql codeql.sarif "$CODEQL_VERSION"
}

case "${1:-}" in
  semgrep) validate_semgrep ;;
  zap) validate_zap ;;
  codeql) validate_codeql ;;
  all)
    validate_semgrep
    validate_zap
    validate_codeql
    ;;
  *) die "Usage: $0 {semgrep|zap|codeql|all}" ;;
esac

if ((VALIDATION_ERRORS > 0)); then
  report_error_count="$VALIDATION_ERRORS"
  printf '[sentinel] Validation failed with %d artifact error(s).\n' "$report_error_count" >&2
  exit 1
fi
log "All requested scanner reports and metadata are valid."
