#!/usr/bin/env bash
# Contract group: cleanup and report validation

set -Eeuo pipefail
CONTRACT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=tests/contracts/common.sh
source "$CONTRACT_DIR/common.sh"

TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-contracts.XXXXXX")"
trap 'rm -rf -- "$TEST_TMP"' EXIT

grep -A2 '^clean-reports:' "$PROJECT_ROOT/Makefile" | grep -q 'clean.sh reports' || \
  fail "clean-reports must use the reports-only cleanup mode"
grep -A2 '^clean:' "$PROJECT_ROOT/Makefile" | grep -q 'clean.sh target' || \
  fail "clean must use the target-only cleanup mode"
target_cleanup="$(sed -n '/  target)/,/    ;;/p' "$PROJECT_ROOT/scripts/clean.sh")"
grep -q 'down --volumes --remove-orphans' <<<"$target_cleanup" || \
  fail "target cleanup must remove Compose volumes"
if grep -q 'clean_report_directory' <<<"$target_cleanup"; then
  fail "target cleanup must not remove reports"
fi
grep -q 'assert_exact_path "$TARGET_DIR"' <<<"$target_cleanup" || \
  fail "target cleanup must protect the target clone path"
pass "target cleanup removes runtime data and clone without removing reports"

set +e
verify_output="$(SENTINEL_TARGET_DIR="$TEST_TMP/missing-target" "$PROJECT_ROOT/scripts/verify-target.sh" 2>&1)"
verify_status=$?
set -e
((verify_status != 0)) || fail "verify-target unexpectedly accepted a missing target"
[[ "$verify_output" == *"Target directory not found"* ]] || fail "verify-target missing-target error is unclear"
pass "target verifier rejects a missing target clearly"

report_dir="$TEST_TMP/reports"
mkdir -p "$report_dir"

write_test_metadata() {
  local tool="$1"
  local report_name="$2"
  local cli_version="$3"
  local base_url=""
  [[ "$tool" == "zap" ]] && base_url="http://juice-shop:3000"
  jq -n \
    --arg tool "$tool" \
    --arg report_path "reports/raw/$report_name" \
    --arg cli_version "$cli_version" \
    --arg base_url "$base_url" \
    '{
      run_id: ($tool + "_test"),
      pipeline_run_id: null,
      scanned_at: "2026-08-05T00:00:00Z",
      cli_version: $cli_version,
      report_path: $report_path,
      target: {
        name: "juice-shop",
        version: "20.1.1",
        commit_sha: "f915bddd82790d0f3018902d36ae9b4241a5f51f",
        base_url: (if $base_url == "" then null else $base_url end)
      }
    } +
    (if $tool == "zap" then {scan_profile: "full"}
     elif $tool == "codeql" then {query_suite: "javascript-security-extended.qls", query_packs: {}}
     else {} end)' >"$report_dir/$tool.meta.json"
}

set +e
missing_output="$(SENTINEL_REPORT_DIR="$report_dir" "$PROJECT_ROOT/scripts/validate-reports.sh" all 2>&1)"
missing_status=$?
set -e
((missing_status != 0)) || fail "validator unexpectedly accepted missing scanner artifacts"
for missing_name in semgrep.json semgrep.meta.json zap.json zap.meta.json zap-endpoints.txt zap-site-tree.yaml codeql.sarif codeql.meta.json; do
  [[ "$missing_output" == *"$missing_name"* ]] || fail "validator did not report missing $missing_name"
done

write_test_metadata semgrep semgrep.json 1.171.0

: >"$report_dir/semgrep.json"
set +e
empty_output="$(SENTINEL_REPORT_DIR="$report_dir" "$PROJECT_ROOT/scripts/validate-reports.sh" semgrep 2>&1)"
empty_status=$?
set -e
((empty_status != 0)) && [[ "$empty_output" == *"is empty"* ]] || fail "validator did not distinguish an empty report"

printf '{broken\n' >"$report_dir/semgrep.json"
set +e
invalid_output="$(SENTINEL_REPORT_DIR="$report_dir" "$PROJECT_ROOT/scripts/validate-reports.sh" semgrep 2>&1)"
invalid_status=$?
set -e
((invalid_status != 0)) && [[ "$invalid_output" == *"invalid JSON"* ]] || fail "validator did not distinguish invalid JSON"

printf '{"results":{}}\n' >"$report_dir/semgrep.json"
set +e
structure_output="$(SENTINEL_REPORT_DIR="$report_dir" "$PROJECT_ROOT/scripts/validate-reports.sh" semgrep 2>&1)"
structure_status=$?
set -e
((structure_status != 0)) && [[ "$structure_output" == *"invalid top-level structure"* ]] || \
  fail "validator did not distinguish invalid structure"

printf '{"results":[]}\n' >"$report_dir/semgrep.json"
SENTINEL_REPORT_DIR="$report_dir" "$PROJECT_ROOT/scripts/validate-reports.sh" semgrep >/dev/null || \
  fail "validator rejected a valid Semgrep report"

printf '{"site":[]}\n' >"$report_dir/zap.json"
write_test_metadata zap zap.json 2.17.0
printf '\n' >"$report_dir/zap-endpoints.txt"
printf '%s\n' '- node: "http://juice-shop:3000"' '  url: "http://juice-shop:3000/"' >"$report_dir/zap-site-tree.yaml"
set +e
blank_inventory_output="$(SENTINEL_REPORT_DIR="$report_dir" "$PROJECT_ROOT/scripts/validate-reports.sh" zap 2>&1)"
blank_inventory_status=$?
set -e
((blank_inventory_status != 0)) && [[ "$blank_inventory_output" == *"does not contain a Juice Shop URL"* ]] || \
  fail "validator accepted an endpoint inventory without URLs"

printf 'http://juice-shop:3000/\n' >"$report_dir/zap-endpoints.txt"
SENTINEL_REPORT_DIR="$report_dir" "$PROJECT_ROOT/scripts/validate-reports.sh" zap >/dev/null || \
  fail "validator rejected a valid ZAP report"

printf 'https://github.com/juice-shop/juice-shop\n' >>"$report_dir/zap-endpoints.txt"
set +e
scope_output="$(SENTINEL_REPORT_DIR="$report_dir" "$PROJECT_ROOT/scripts/validate-reports.sh" zap 2>&1)"
scope_status=$?
set -e
((scope_status != 0)) && [[ "$scope_output" == *"outside the Juice Shop origin"* ]] || \
  fail "validator accepted an out-of-scope URL export"
printf 'http://juice-shop:3000/\n' >"$report_dir/zap-endpoints.txt"

printf '{"version":"2.1.0","runs":[]}\n' >"$report_dir/codeql.sarif"
write_test_metadata codeql codeql.sarif 2.26.0
SENTINEL_REPORT_DIR="$report_dir" "$PROJECT_ROOT/scripts/validate-reports.sh" codeql >/dev/null || \
  fail "validator rejected a valid CodeQL report"

jq '.report_path = "reports/raw/wrong.sarif"' "$report_dir/codeql.meta.json" \
  >"$report_dir/codeql.meta.json.tmp"
mv -- "$report_dir/codeql.meta.json.tmp" "$report_dir/codeql.meta.json"
set +e
metadata_output="$(SENTINEL_REPORT_DIR="$report_dir" "$PROJECT_ROOT/scripts/validate-reports.sh" codeql 2>&1)"
metadata_status=$?
set -e
((metadata_status != 0)) && [[ "$metadata_output" == *"metadata is invalid"* ]] || \
  fail "validator accepted CodeQL metadata for the wrong report"

pass "report validator covers all scanners, metadata, missing files and malformed inputs"

semgrep_env_root="$TEST_TMP/semgrep-env"
mkdir -p "$semgrep_env_root"
printf 'SEMGREP_APP_TOKEN=file-token\n' >"$semgrep_env_root/.env"

resolved_token="$(
  SEMGREP_APP_TOKEN=exported-token resolve_semgrep_app_token "$semgrep_env_root"
)"
[[ "$resolved_token" == "exported-token" ]] || fail "exported Semgrep token must take precedence over .env"

resolved_token="$(
  unset SEMGREP_APP_TOKEN
  resolve_semgrep_app_token "$semgrep_env_root"
)"
[[ "$resolved_token" == "file-token" ]] || fail "Semgrep token must fall back to .env"

: >"$semgrep_env_root/.env"
set +e
missing_token_output="$(
  unset SEMGREP_APP_TOKEN
  resolve_semgrep_app_token "$semgrep_env_root" 2>&1
)"
missing_token_status=$?
set -e
((missing_token_status != 0)) && [[ "$missing_token_output" == *"SEMGREP_APP_TOKEN is required"* ]] || \
  fail "missing Semgrep token must fail clearly"

printf 'SEMGREP_APP_TOKEN=your-semgrep-app-token-here\n' >"$semgrep_env_root/.env"
set +e
placeholder_token_output="$(
  unset SEMGREP_APP_TOKEN
  resolve_semgrep_app_token "$semgrep_env_root" 2>&1
)"
placeholder_token_status=$?
set -e
((placeholder_token_status != 0)) && [[ "$placeholder_token_output" == *"placeholder"* ]] || \
  fail "Semgrep token placeholder must be rejected"

printf 'SEMGREP_APP_TOKEN=first\nSEMGREP_APP_TOKEN=second\n' >"$semgrep_env_root/.env"
set +e
duplicate_token_output="$(
  unset SEMGREP_APP_TOKEN
  resolve_semgrep_app_token "$semgrep_env_root" 2>&1
)"
duplicate_token_status=$?
set -e
((duplicate_token_status != 0)) && [[ "$duplicate_token_output" == *"Duplicate SEMGREP_APP_TOKEN"* ]] || \
  fail "duplicate Semgrep token entries must be rejected"
pass "Semgrep token resolution is deterministic and fails safely"
