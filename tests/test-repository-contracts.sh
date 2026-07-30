#!/usr/bin/env bash
# Validate Week 1 repository contracts without cloning Juice Shop or starting Docker resources.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-contracts.XXXXXX")"
trap 'rm -rf -- "$TEST_TMP"' EXIT
# shellcheck source=scripts/common.sh
source "$PROJECT_ROOT/scripts/common.sh"

pass_count=0
fail() {
  printf 'not ok - %s\n' "$*" >&2
  exit 1
}

pass() {
  pass_count=$((pass_count + 1))
  printf 'ok %d - %s\n' "$pass_count" "$*"
}

assert_file() {
  [[ -f "$PROJECT_ROOT/$1" ]] || fail "Required file missing: $1"
}

required_files=(
  .dockerignore .env.example .gitattributes .gitignore Makefile README.md docker-compose.yml
  configs/tool-versions.env target-app/TARGET.lock target-app/README.md
  scripts/setup-target.sh scripts/verify-target.sh scripts/wait-for-target.sh scripts/smoke-test.sh
  scripts/run-sast.sh scripts/run-dast.sh scripts/validate-reports.sh scripts/clean.sh
  docs/architecture.md docs/endpoints.md docs/week-1-findings.md
  .github/workflows/ci.yml .github/workflows/sast-scan.yml .github/workflows/dast-scan.yml
)
for required_file in "${required_files[@]}"; do
  assert_file "$required_file"
done
pass "required Week 1 files exist"

lock_file="$PROJECT_ROOT/target-app/TARGET.lock"
validate_config_file "$lock_file" REPOSITORY_URL TAG COMMIT_SHA
commit_sha="$(awk -F= '$1 == "COMMIT_SHA" {print $2}' "$lock_file")"
[[ "$commit_sha" =~ ^[0-9a-fA-F]{40}$ ]] || fail "TARGET.lock COMMIT_SHA is not 40 hexadecimal characters"
pass "target lock keys and commit format are valid"

versions_file="$PROJECT_ROOT/configs/tool-versions.env"
validate_config_file "$versions_file" SEMGREP_VERSION SEMGREP_IMAGE ZAP_VERSION ZAP_IMAGE
if awk -F= '/_IMAGE=/ && $2 ~ /:(latest|stable|weekly|canary)$/ {bad = 1} END {exit !bad}' "$versions_file"; then
  fail "scanner image uses a moving tag"
fi
pass "scanner versions are complete and immutable tags are used"

git -C "$PROJECT_ROOT" check-ignore -q target-app/juice-shop/package.json || fail "target clone is not ignored"
git -C "$PROJECT_ROOT" check-ignore -q reports/raw/example.json || fail "raw reports are not ignored"
git -C "$PROJECT_ROOT" check-ignore -q logs/example.log || fail "runtime logs are not ignored"
if git -C "$PROJECT_ROOT" check-ignore -q reports/raw/.gitkeep || \
  git -C "$PROJECT_ROOT" check-ignore -q logs/.gitkeep; then
  fail ".gitkeep files must not be ignored"
fi
pass "generated target, reports and logs have correct ignore rules"

ci_workflow="$PROJECT_ROOT/.github/workflows/ci.yml"
grep -A2 '^  sast:$' "$ci_workflow" | grep -q 'needs: quality' || fail "SAST job must depend directly on quality"
grep -A2 '^  dast:$' "$ci_workflow" | grep -q 'needs: quality' || fail "DAST job must depend directly on quality"
if grep -A2 '^  dast:$' "$ci_workflow" | grep -q 'needs: sast'; then
  fail "DAST must not wait for SAST"
fi
grep -q -- '--user "$HOST_USER"' "$PROJECT_ROOT/scripts/run-sast.sh" || fail "SAST container must use host UID/GID"
grep -q -- '--dataflow-traces' "$PROJECT_ROOT/scripts/run-sast.sh" || fail "SAST must emit dataflow traces"
grep -q -- '--sarif-output /src/reports/raw/semgrep.sarif' "$PROJECT_ROOT/scripts/run-sast.sh" || fail "SAST must emit a SARIF report"
grep -q -- 'reports/raw/semgrep.sarif' "$PROJECT_ROOT/.github/workflows/sast-scan.yml" || fail "SAST workflow must upload the SARIF report"
grep -q -- '--user "$HOST_USER"' "$PROJECT_ROOT/scripts/run-dast.sh" || fail "DAST container must use host UID/GID"
[[ "$(grep -c -- 'JAVA_TOOL_OPTIONS=-Duser.home=/tmp' "$PROJECT_ROOT/scripts/run-dast.sh")" -eq 2 ]] || \
  fail "DAST must set a writable Java home for both ZAP invocations"
grep -q -- '-z "-silent"' "$PROJECT_ROOT/scripts/run-dast.sh" || fail "DAST must disable automatic add-on updates"
grep -q -- '/nodejs/bin/node' "$PROJECT_ROOT/docker-compose.yml" || fail "healthcheck must use the distroless Node executable"
grep -q -- "-w '%{http_code}'" "$PROJECT_ROOT/scripts/wait-for-target.sh" || fail "wait must poll HTTP status"
grep -q 'touch "$REPORT_DIR/.gitkeep"' "$PROJECT_ROOT/scripts/run-sast.sh" || fail "SAST must restore raw report .gitkeep"
grep -q 'touch "$REPORT_DIR/.gitkeep"' "$PROJECT_ROOT/scripts/run-dast.sh" || fail "DAST must restore raw report .gitkeep"

setup_line="$(grep -n 'make -C "$PROJECT_ROOT" setup-target' "$PROJECT_ROOT/scripts/run-week1.sh" | cut -d: -f1)"
sast_line="$(grep -n 'make -C "$PROJECT_ROOT" sast' "$PROJECT_ROOT/scripts/run-week1.sh" | cut -d: -f1)"
build_line="$(grep -n 'make -C "$PROJECT_ROOT" build' "$PROJECT_ROOT/scripts/run-week1.sh" | cut -d: -f1)"
[[ -n "$setup_line" && -n "$sast_line" && -n "$build_line" ]] || fail "week1 orchestration steps are missing"
((setup_line < sast_line && sast_line < build_line)) || fail "week1 must run setup-target, then SAST, then build"
pass "implementation preserves parallel scans, file ownership, HTTP readiness and optimized ordering"

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

printf '1..%d\n' "$pass_count"
