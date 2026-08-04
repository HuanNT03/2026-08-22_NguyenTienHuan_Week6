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
  configs/semgrep/includes.txt configs/semgrep/.semgrepignore configs/codeql/code-scanning.yml
  scripts/setup-target.sh scripts/verify-target.sh scripts/wait-for-target.sh scripts/smoke-test.sh
  scripts/run-sast.sh scripts/run-dast.sh scripts/run-dast-zap-fullscan.sh scripts/validate-reports.sh scripts/validate-sast-scope.py
  scripts/clean.sh docker/codeql/Dockerfile
  docs/reports/week1/architecture.md docs/reports/week1/endpoints.md
  docs/reports/week1/week-1-findings.md
  .github/workflows/ci.yml .github/workflows/sast-scan.yml .github/workflows/dast-scan.yml
  pyproject.toml schemas/unified_findings.schema.json scripts/write-scan-metadata.sh
  src/normalizers/cli.py src/normalizers/semgrep.py src/normalizers/zap.py src/normalizers/codeql.py
)
for required_file in "${required_files[@]}"; do
  assert_file "$required_file"
done
pass "required Week 1 and Week 2 files exist"

jq -e '."$schema" == "https://json-schema.org/draft/2020-12/schema" and .properties.fingerprint.pattern' \
  "$PROJECT_ROOT/schemas/unified_findings.schema.json" >/dev/null || fail "unified finding schema is invalid or incomplete"
grep -q '^normalize:' "$PROJECT_ROOT/Makefile" || fail "Makefile normalize target is missing"
grep -q 'normalize-all' "$PROJECT_ROOT/Makefile" || fail "Makefile does not invoke aggregate normalization"
pass "normalizer schema and local entrypoint are present"

lock_file="$PROJECT_ROOT/target-app/TARGET.lock"
validate_config_file "$lock_file" REPOSITORY_URL TAG COMMIT_SHA
commit_sha="$(awk -F= '$1 == "COMMIT_SHA" {print $2}' "$lock_file")"
[[ "$commit_sha" =~ ^[0-9a-fA-F]{40}$ ]] || fail "TARGET.lock COMMIT_SHA is not 40 hexadecimal characters"
pass "target lock keys and commit format are valid"

versions_file="$PROJECT_ROOT/configs/tool-versions.env"
validate_config_file "$versions_file" SEMGREP_VERSION SEMGREP_IMAGE ZAP_VERSION ZAP_IMAGE CODEQL_VERSION
if awk -F= '/_IMAGE=/ && $2 ~ /:(latest|stable|weekly|canary)$/ {bad = 1} END {exit !bad}' "$versions_file"; then
  fail "scanner image uses a moving tag"
fi
codeql_version="$(config_value "$versions_file" CODEQL_VERSION)"
[[ "$codeql_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "CODEQL_VERSION is not semantic version"
[[ "$(grep -c '^CODEQL_VERSION=' "$versions_file")" -eq 1 ]] || fail "CODEQL_VERSION must be declared once"
if grep -q '^CODEQL_BUNDLE_URL=' "$versions_file"; then
  fail "CodeQL bundle URL must be derived from CODEQL_VERSION by each installer"
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
grep -q 'configs/semgrep/includes.txt' "$PROJECT_ROOT/scripts/run-sast.sh" || fail "Semgrep include config is not loaded"
grep -q 'configs/semgrep/.semgrepignore' "$PROJECT_ROOT/scripts/run-sast.sh" || fail "Semgrep exclude config is not loaded"
grep -q 'validate-sast-scope.py.*--tool semgrep' "$PROJECT_ROOT/scripts/run-sast.sh" || fail "Semgrep scope is not validated"
grep -q -- '-e SEMGREP_APP_TOKEN' "$PROJECT_ROOT/scripts/run-sast.sh" || fail "SAST container must receive SEMGREP_APP_TOKEN"
grep -q -- 'contains metadata that requires login' "$PROJECT_ROOT/scripts/run-sast.sh" || \
  fail "SAST must reject unauthenticated finding metadata"
grep -q -- 'reports/raw/semgrep.sarif' "$PROJECT_ROOT/.github/workflows/sast-scan.yml" || fail "SAST workflow must upload the SARIF report"
grep -A3 '^  workflow_call:$' "$PROJECT_ROOT/.github/workflows/sast-scan.yml" | \
  grep -q 'SEMGREP_APP_TOKEN:' || fail "SAST reusable workflow must declare SEMGREP_APP_TOKEN"
grep -A9 '^  sast:$' "$ci_workflow" | grep -q 'SEMGREP_APP_TOKEN:.*secrets.SEMGREP_APP_TOKEN' || \
  fail "CI must pass SEMGREP_APP_TOKEN explicitly to the SAST workflow"
grep -A3 'name: Run Semgrep' "$PROJECT_ROOT/.github/workflows/sast-scan.yml" | \
  grep -q 'SEMGREP_APP_TOKEN:.*secrets.SEMGREP_APP_TOKEN' || \
  fail "SAST workflow must expose the GitHub secret only to the scan step"
codeql_dockerfile="$PROJECT_ROOT/docker/codeql/Dockerfile"
grep -q '^FROM ubuntu:24.04$' "$codeql_dockerfile" || fail "CodeQL image must use Ubuntu 24.04"
grep -q '^ARG CODEQL_VERSION$' "$codeql_dockerfile" || fail "CodeQL image must receive the pinned version"
grep -q 'github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}' "$codeql_dockerfile" || \
  fail "CodeQL image must derive the official bundle URL from CODEQL_VERSION"
grep -q 'sha256sum -c' "$codeql_dockerfile" || fail "CodeQL image must verify the official checksum"
grep -q 'install.*nodejs' "$codeql_dockerfile" || fail "CodeQL image must provide Node.js for TypeScript extraction"
grep -q 'chmod -R a+rX /opt/codeql' "$codeql_dockerfile" || fail "Non-root scanner must read precompiled CodeQL queries"
grep -q 'ln -s /opt/codeql/codeql /usr/local/bin/codeql' "$codeql_dockerfile" || \
  fail "CodeQL image must expose the CLI on PATH"

compose_file="$PROJECT_ROOT/docker-compose.yml"
grep -q '^  codeql-scan:$' "$compose_file" || fail "Compose must define codeql-scan"
grep -A3 '^  codeql-scan:$' "$compose_file" | grep -q 'profiles: \["scan"\]' || \
  fail "CodeQL service must be opt-in through the scan profile"
grep -q './target-app/juice-shop:/workspace/target-app/juice-shop:ro' "$compose_file" || \
  fail "CodeQL source mount must be read-only"
grep -q './configs/codeql:/workspace/configs/codeql:ro' "$compose_file" || \
  fail "CodeQL config mount must be read-only"
grep -q './reports/raw:/workspace/reports/raw:rw' "$compose_file" || fail "CodeQL report mount must be writable"
grep -q -- '--codescanning-config=/workspace/configs/codeql/code-scanning.yml' "$compose_file" || \
  fail "CodeQL must use the repository scope config"
grep -q 'javascript-typescript' "$compose_file" || fail "CodeQL must scan JavaScript and TypeScript"
grep -q 'javascript-security-extended.qls' "$compose_file" || fail "CodeQL must use security-extended queries"
grep -q -- '--ram=3000' "$compose_file" || fail "CodeQL must receive an explicit memory budget"
grep -q -- '--sarif-add-query-help' "$compose_file" || fail "CodeQL SARIF must contain query help"
grep -q -- '--output=reports/raw/codeql.sarif' "$compose_file" || fail "CodeQL output path is incorrect"

codeql_build_line="$(grep -n -- '--profile scan build codeql-scan' "$PROJECT_ROOT/Makefile" | cut -d: -f1)"
codeql_run_line="$(grep -n -- '--profile scan run --rm codeql-scan' "$PROJECT_ROOT/Makefile" | cut -d: -f1)"
[[ -n "$codeql_build_line" && -n "$codeql_run_line" ]] || fail "CodeQL Make commands are missing"
((codeql_build_line < codeql_run_line)) || fail "CodeQL image must always build before scan"
grep -q '@$(MAKE) sast-semgrep' "$PROJECT_ROOT/Makefile" || fail "aggregate SAST must run Semgrep"
grep -q '@$(MAKE) sast-codeql' "$PROJECT_ROOT/Makefile" || fail "aggregate SAST must run CodeQL"

sast_workflow="$PROJECT_ROOT/.github/workflows/sast-scan.yml"
grep -q '^  codeql:$' "$sast_workflow" || fail "SAST workflow must define an independent CodeQL job"
grep -q 'CODEQL_VERSION=.*grep.*configs/tool-versions.env' "$sast_workflow" || fail "CI must read the pinned CodeQL version"
grep -q 'sha256sum -c' "$sast_workflow" || fail "CI must verify the CodeQL checksum"
grep -q 'sudo chmod -R a+rX /opt/codeql' "$sast_workflow" || fail "CI runner must read precompiled CodeQL queries"
grep -q 'github/codeql-action/upload-sarif@v4' "$sast_workflow" || fail "CI must upload CodeQL SARIF"
grep -q 'reports/raw/codeql.sarif' "$sast_workflow" || fail "CI must retain the CodeQL report"
grep -q -- '--codescanning-config=configs/codeql/code-scanning.yml' "$sast_workflow" || \
  fail "CI CodeQL must use the repository scope config"
grep -q -- '--ram=3000' "$sast_workflow" || fail "CI CodeQL must receive the same memory budget"
grep -q 'validate-sast-scope.py.*--tool codeql' "$sast_workflow" || fail "CI must validate CodeQL scope"
grep -q 'validate-sast-scope.py.*--tool codeql' "$PROJECT_ROOT/Makefile" || fail "Local CodeQL scope is not validated"
if grep -q 'github/codeql-action/init' "$sast_workflow"; then fail "CI must not use CodeQL init"; fi
grep -A5 '^  sast:$' "$ci_workflow" | grep -q 'security-events: write' || fail "SAST caller must grant SARIF upload permission"
grep -A5 '^  sast:$' "$ci_workflow" | grep -q 'actions: read' || fail "SAST caller must allow private-repository SARIF upload"
grep -q -- '--user "$HOST_USER"' "$PROJECT_ROOT/scripts/run-dast.sh" || fail "DAST container must use host UID/GID"
[[ "$(grep -c -- 'JAVA_TOOL_OPTIONS=-Duser.home=/tmp' "$PROJECT_ROOT/scripts/run-dast.sh")" -eq 2 ]] || \
  fail "DAST must set a writable Java home for both ZAP invocations"
grep -q -- '-z "-silent"' "$PROJECT_ROOT/scripts/run-dast.sh" || fail "DAST must disable automatic add-on updates"
zap_baseline_command="$(sed -n '/zap-baseline.py \\/,/zap_exit_code=/p' "$PROJECT_ROOT/scripts/run-dast.sh")"
grep -q -- 'zap_spider_args=(-j --client-spider)' "$PROJECT_ROOT/scripts/run-dast.sh" || \
  fail "DAST must enable both modern ZAP spider modes when memory permits"
grep -Fq -- '"${zap_spider_args[@]}" \' <<<"$zap_baseline_command" || \
  fail "DAST must pass the memory-aware spider arguments to ZAP"
grep -q -- '--scan-profile baseline' "$PROJECT_ROOT/scripts/run-dast.sh" || \
  fail "ZAP Baseline metadata must declare its scan profile"
fullscan_script="$PROJECT_ROOT/scripts/run-dast-zap-fullscan.sh"
grep -q '^dast-zap-fullscan:' "$PROJECT_ROOT/Makefile" || fail "ZAP Full Scan Make target is missing"
grep -q 'ZAP_CLIENT_SPIDER_MIN_BYTES' "$fullscan_script" || fail "Full Scan must enforce its Client Spider memory floor"
grep -q 'requires at least 4 GiB Docker memory' "$fullscan_script" || fail "Full Scan must fail clearly below the memory floor"
zap_fullscan_command="$(sed -n '/zap-full-scan.py \\/,/zap_exit_code=/p' "$fullscan_script")"
grep -Fq -- '  -j \' <<<"$zap_fullscan_command" || fail "Full Scan must pass -j to ZAP"
grep -Fq -- '  --client-spider \' <<<"$zap_fullscan_command" || fail "Full Scan must select the Client Spider"
grep -Fq -- '-m "$ZAP_SPIDER_MAX_MINUTES"' <<<"$zap_fullscan_command" || fail "Full Scan spider limit is missing"
grep -Fq -- '-T "$ZAP_PASSIVE_MAX_MINUTES"' <<<"$zap_fullscan_command" || fail "Full Scan passive limit is missing"
grep -q 'scanner.maxScanDurationInMins=\$ZAP_ACTIVE_MAX_MINUTES' <<<"$zap_fullscan_command" || \
  fail "Full Scan active scanner limit is missing"
grep -q -- '--scan-profile full' "$fullscan_script" || fail "ZAP Full Scan metadata must declare its scan profile"
grep -q 'scan_profile: \$scan_profile' "$PROJECT_ROOT/scripts/write-scan-metadata.sh" || \
  fail "ZAP metadata must persist the scan profile"
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
grep -q 'semgrep.meta.json' "$sast_workflow" || fail "Semgrep artifact must include scan metadata"
grep -q 'codeql.meta.json' "$sast_workflow" || fail "CodeQL artifact must include scan metadata"
grep -q 'zap.meta.json' "$PROJECT_ROOT/.github/workflows/dast-scan.yml" || fail "ZAP artifact must include scan metadata"
grep -q '^  normalize:$' "$ci_workflow" || fail "CI normalize job is missing"
grep -A3 '^  normalize:$' "$ci_workflow" | grep -q 'needs: \[sast, dast\]' || fail "normalize must wait for SAST and DAST"
grep -q 'normalized-findings-.*github.run_id' "$ci_workflow" || fail "CI unified findings artifact is missing"
pass "implementation preserves parallel scans, metadata provenance and normalized artifacts"

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
grep -Fxq -- 'git --pre-commit --redact --staged --verbose' "$hook_log" || \
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
