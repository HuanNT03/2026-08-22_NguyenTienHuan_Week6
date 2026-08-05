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
set +e
missing_output="$(SENTINEL_REPORT_DIR="$report_dir" "$PROJECT_ROOT/scripts/validate-reports.sh" semgrep 2>&1)"
missing_status=$?
set -e
((missing_status != 0)) && [[ "$missing_output" == *"is missing"* ]] || fail "validator did not distinguish a missing report"

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
SENTINEL_REPORT_DIR="$report_dir" "$PROJECT_ROOT/scripts/validate-reports.sh" zap >/dev/null || \
  fail "validator rejected a valid ZAP report"
pass "report validator distinguishes missing, empty, malformed, invalid-structure and valid reports"

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

