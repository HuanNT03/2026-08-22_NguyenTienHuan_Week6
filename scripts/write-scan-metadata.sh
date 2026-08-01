#!/usr/bin/env bash
# Create authoritative scan metadata at the scanner boundary.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

tool=""
report_path=""
base_url=""
pipeline_run_id="${SENTINEL_PIPELINE_RUN_ID:-}"

while (($#)); do
  case "$1" in
    --tool) tool="${2:-}"; shift 2 ;;
    --report) report_path="${2:-}"; shift 2 ;;
    --base-url) base_url="${2:-}"; shift 2 ;;
    --pipeline-run-id) pipeline_run_id="${2:-}"; shift 2 ;;
    *) die "Unknown metadata option: $1" ;;
  esac
done

case "$tool" in
  semgrep|zap|codeql) ;;
  *) die "--tool must be semgrep, zap, or codeql" ;;
esac
[[ -n "$report_path" ]] || die "--report is required"

lock_file="$PROJECT_ROOT/target-app/TARGET.lock"
versions_file="$PROJECT_ROOT/configs/tool-versions.env"
validate_config_file "$lock_file" REPOSITORY_URL TAG COMMIT_SHA
load_tool_versions "$versions_file"

case "$tool" in
  semgrep) cli_version="$SEMGREP_VERSION" ;;
  zap) cli_version="$ZAP_VERSION" ;;
  codeql) cli_version="$CODEQL_VERSION" ;;
esac

repository_url="$(config_value "$lock_file" REPOSITORY_URL)"
target_name="${repository_url##*/}"
target_name="${target_name%.git}"
target_version="$(config_value "$lock_file" TAG)"
target_version="${target_version#v}"
commit_sha="$(config_value "$lock_file" COMMIT_SHA)"
scanned_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
run_timestamp="$(date -u +'%Y%m%d_%H%M%S')"
run_id="${tool}_${run_timestamp}"

absolute_report="$PROJECT_ROOT/$report_path"
metadata_path="${absolute_report%.*}.meta.json"
metadata_tmp="${metadata_path}.tmp"
mkdir -p "$(dirname -- "$metadata_path")"
rm -f -- "$metadata_path" "$metadata_tmp"

jq -n   --arg run_id "$run_id"   --arg pipeline_run_id "$pipeline_run_id"   --arg scanned_at "$scanned_at"   --arg cli_version "$cli_version"   --arg report_path "$report_path"   --arg target_name "$target_name"   --arg target_version "$target_version"   --arg commit_sha "$commit_sha"   --arg base_url "$base_url"   --arg tool "$tool"   '{
    run_id: $run_id,
    pipeline_run_id: (if $pipeline_run_id == "" then null else $pipeline_run_id end),
    scanned_at: $scanned_at,
    cli_version: $cli_version,
    report_path: $report_path,
    target: {
      name: $target_name,
      version: $target_version,
      commit_sha: $commit_sha,
      base_url: (if $base_url == "" then null else $base_url end)
    }
  } + (if $tool == "codeql" then {
    query_suite: "javascript-security-extended.qls",
    query_packs: {}
  } else {} end)' >"$metadata_tmp"

mv -- "$metadata_tmp" "$metadata_path"
log "Scan metadata created: $metadata_path"
