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
  .dockerignore .env.example .gitattributes .gitignore .githooks/pre-commit
  .githooks/pre-push .githooks/lib/gitleaks-common.sh Makefile README.md docker-compose.yml
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
grep -q -- '-e SEMGREP_APP_TOKEN' "$PROJECT_ROOT/scripts/run-sast.sh" || fail "SAST container must receive SEMGREP_APP_TOKEN"
grep -q -- 'contains metadata that requires login' "$PROJECT_ROOT/scripts/run-sast.sh" || \
  fail "SAST must reject unauthenticated finding metadata"
grep -q -- 'reports/raw/semgrep.sarif' "$PROJECT_ROOT/.github/workflows/sast-scan.yml" || fail "SAST workflow must upload the SARIF report"
grep -A3 '^  workflow_call:$' "$PROJECT_ROOT/.github/workflows/sast-scan.yml" | \
  grep -q 'SEMGREP_APP_TOKEN:' || fail "SAST reusable workflow must declare SEMGREP_APP_TOKEN"
grep -A5 '^  sast:$' "$ci_workflow" | grep -q 'SEMGREP_APP_TOKEN:.*secrets.SEMGREP_APP_TOKEN' || \
  fail "CI must pass SEMGREP_APP_TOKEN explicitly to the SAST workflow"
grep -A3 'name: Run Semgrep' "$PROJECT_ROOT/.github/workflows/sast-scan.yml" | \
  grep -q 'SEMGREP_APP_TOKEN:.*secrets.SEMGREP_APP_TOKEN' || \
  fail "SAST workflow must expose the GitHub secret only to the scan step"
grep -q -- '--user "$HOST_USER"' "$PROJECT_ROOT/scripts/run-dast.sh" || fail "DAST container must use host UID/GID"
[[ "$(grep -c -- 'JAVA_TOOL_OPTIONS=-Duser.home=/tmp' "$PROJECT_ROOT/scripts/run-dast.sh")" -eq 2 ]] || \
  fail "DAST must set a writable Java home for both ZAP invocations"
grep -q -- '-z "-silent"' "$PROJECT_ROOT/scripts/run-dast.sh" || fail "DAST must disable automatic add-on updates"
grep -q -- '/nodejs/bin/node' "$PROJECT_ROOT/docker-compose.yml" || fail "healthcheck must use the distroless Node executable"
grep -q -- "-w '%{http_code}'" "$PROJECT_ROOT/scripts/wait-for-target.sh" || fail "wait must poll HTTP status"
grep -q 'touch "$REPORT_DIR/.gitkeep"' "$PROJECT_ROOT/scripts/run-sast.sh" || fail "SAST must restore raw report .gitkeep"
grep -q 'touch "$REPORT_DIR/.gitkeep"' "$PROJECT_ROOT/scripts/run-dast.sh" || fail "DAST must restore raw report .gitkeep"
grep -q '^## Gitleaks Git hooks$' "$PROJECT_ROOT/README.md" || fail "README must document Gitleaks hooks"
grep -q 'git config --local core.hooksPath .githooks' "$PROJECT_ROOT/README.md" || \
  fail "README must document tracked hook activation"
grep -q 'gitleaks version' "$PROJECT_ROOT/README.md" || fail "README must document the version check"

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

[[ -x "$PROJECT_ROOT/.githooks/pre-commit" ]] || fail "pre-commit hook must be executable"

hook_repo="$TEST_TMP/hook-repo"
fake_bin="$TEST_TMP/fake-bin"
missing_bin="$TEST_TMP/missing-bin"
mkdir -p "$hook_repo" "$fake_bin" "$missing_bin"
git -C "$hook_repo" init -q
git -C "$hook_repo" config user.name "Sentinel Hook Test"
git -C "$hook_repo" config user.email "sentinel-hook-test@example.invalid"

cat >"$fake_bin/gitleaks" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "version" ]]; then
  printf '%s\n' "${FAKE_GITLEAKS_VERSION:-8.30.1}"
  exit "${FAKE_GITLEAKS_VERSION_STATUS:-0}"
fi

printf '%s\n' "$*" >>"${FAKE_GITLEAKS_LOG:?}"
exit "${FAKE_GITLEAKS_SCAN_STATUS:-0}"
EOF
chmod +x "$fake_bin/gitleaks"

for required_command in sh dirname git; do
  ln -s "$(command -v "$required_command")" "$missing_bin/$required_command"
done

set +e
missing_output="$(cd "$hook_repo" && PATH="$missing_bin" "$PROJECT_ROOT/.githooks/pre-commit" 2>&1)"
missing_status=$?
set -e
((missing_status == 0)) || fail "pre-commit must allow commits when Gitleaks is missing"
[[ "$missing_output" == *"secret scan was skipped"* ]] || \
  fail "pre-commit did not warn when Gitleaks was missing"

hook_log="$TEST_TMP/pre-commit-gitleaks.log"
set +e
old_version_output="$(
  cd "$hook_repo" &&
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.29.0 FAKE_GITLEAKS_LOG="$hook_log" \
      "$PROJECT_ROOT/.githooks/pre-commit" 2>&1
)"
old_version_status=$?
set -e
((old_version_status == 0)) || fail "pre-commit must allow commits when Gitleaks is outdated"
[[ "$old_version_output" == *"secret scan was skipped"* ]] || \
  fail "pre-commit did not warn when Gitleaks was outdated"
[[ ! -e "$hook_log" ]] || fail "pre-commit invoked an outdated Gitleaks binary"

(
  cd "$hook_repo"
  PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$hook_log" \
    "$PROJECT_ROOT/.githooks/pre-commit" >/dev/null
)
grep -Fxq 'git --pre-commit --redact --staged --verbose' "$hook_log" || \
  fail "pre-commit invoked Gitleaks with unexpected arguments"

set +e
(
  cd "$hook_repo" &&
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$hook_log" \
      FAKE_GITLEAKS_SCAN_STATUS=1 "$PROJECT_ROOT/.githooks/pre-commit" >/dev/null 2>&1
)
scan_status=$?
set -e
((scan_status == 1)) || fail "pre-commit did not propagate a Gitleaks finding"
pass "pre-commit skips unavailable Gitleaks and blocks on scan findings"

[[ -x "$PROJECT_ROOT/.githooks/pre-push" ]] || fail "pre-push hook must be executable"

local_oid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
remote_oid=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
zero_oid=0000000000000000000000000000000000000000
pre_push_log="$TEST_TMP/pre-push-gitleaks.log"

printf 'refs/heads/main %s refs/heads/main %s\n' "$local_oid" "$remote_oid" |
  (
    cd "$hook_repo"
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$pre_push_log" \
      "$PROJECT_ROOT/.githooks/pre-push" origin example.invalid >/dev/null
  )
grep -Fxq "git --redact --verbose --log-opts=$remote_oid..$local_oid ." "$pre_push_log" || \
  fail "pre-push did not scan the outgoing commit range"

: >"$pre_push_log"
printf 'refs/heads/feature %s refs/heads/feature %s\n' "$local_oid" "$zero_oid" |
  (
    cd "$hook_repo"
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$pre_push_log" \
      "$PROJECT_ROOT/.githooks/pre-push" origin example.invalid >/dev/null
  )
grep -Fxq "git --redact --verbose --log-opts=$local_oid ." "$pre_push_log" || \
  fail "pre-push did not scan full reachable history for a new ref"

: >"$pre_push_log"
printf 'refs/heads/main %s refs/heads/main %s\n' "$zero_oid" "$remote_oid" |
  (
    cd "$hook_repo"
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$pre_push_log" \
      "$PROJECT_ROOT/.githooks/pre-push" origin example.invalid >/dev/null
  )
[[ ! -s "$pre_push_log" ]] || fail "pre-push must skip deleted refs"

: >"$pre_push_log"
set +e
outdated_push_output="$(
  printf 'refs/heads/main %s refs/heads/main %s\n' "$local_oid" "$remote_oid" |
    (
      cd "$hook_repo"
      PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.29.0 FAKE_GITLEAKS_LOG="$pre_push_log" \
        "$PROJECT_ROOT/.githooks/pre-push" origin example.invalid 2>&1
    )
)"
outdated_push_status=$?
set -e
((outdated_push_status == 0)) || fail "pre-push must allow pushes when Gitleaks is outdated"
[[ "$outdated_push_output" == *"secret scan was skipped"* ]] || \
  fail "pre-push did not warn when Gitleaks was outdated"
[[ ! -s "$pre_push_log" ]] || fail "pre-push invoked an outdated Gitleaks binary"

: >"$pre_push_log"
printf 'refs/heads/main %s refs/heads/main %s\nrefs/tags/v1 %s refs/tags/v1 %s\n' \
  "$local_oid" "$remote_oid" "$local_oid" "$zero_oid" |
  (
    cd "$hook_repo"
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$pre_push_log" \
      "$PROJECT_ROOT/.githooks/pre-push" origin example.invalid >/dev/null
  )
[[ "$(wc -l <"$pre_push_log")" -eq 2 ]] || fail "pre-push did not scan every updated ref"
grep -Fxq "git --redact --verbose --log-opts=$remote_oid..$local_oid ." "$pre_push_log" || \
  fail "pre-push omitted the existing ref from a multi-ref push"
grep -Fxq "git --redact --verbose --log-opts=$local_oid ." "$pre_push_log" || \
  fail "pre-push omitted the new ref from a multi-ref push"

set +e
printf 'refs/heads/main %s refs/heads/main %s\n' "$local_oid" "$remote_oid" |
  (
    cd "$hook_repo"
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$pre_push_log" \
      FAKE_GITLEAKS_SCAN_STATUS=2 "$PROJECT_ROOT/.githooks/pre-push" origin example.invalid \
      >/dev/null 2>&1
  )
push_scan_status=$?
set -e
((push_scan_status == 2)) || fail "pre-push did not propagate a Gitleaks scan error"
pass "pre-push scans outgoing history, skips deletions and enforces scan results"

printf '1..%d\n' "$pass_count"
