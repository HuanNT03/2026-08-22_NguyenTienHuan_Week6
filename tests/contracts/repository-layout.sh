#!/usr/bin/env bash
# Contract group: repository layout and pinned versions

set -Eeuo pipefail
CONTRACT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=tests/contracts/common.sh
source "$CONTRACT_DIR/common.sh"

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
  .github/workflows/dast-zap-fullscan.yml
  pyproject.toml schemas/unified_findings.schema.json scripts/write-scan-metadata.sh
  src/normalizers/cli.py src/normalizers/semgrep.py src/normalizers/zap.py src/normalizers/codeql.py
  tests/fixtures/scanners/semgrep.json tests/fixtures/scanners/zap.json
  tests/fixtures/scanners/codeql.sarif tests/integration/test_codeql_normalizer.py
  tests/contracts/common.sh tests/contracts/repository-layout.sh tests/contracts/sast-ci.sh
  tests/contracts/dast.sh tests/contracts/cleanup-validation.sh tests/contracts/git-hooks.sh
)
for required_file in "${required_files[@]}"; do
  assert_file "$required_file"
done
pass "required Week 1 and Week 2 files exist"

jq -e '."$schema" == "https://json-schema.org/draft/2020-12/schema" and .properties.fingerprint.pattern' \
  "$PROJECT_ROOT/schemas/unified_findings.schema.json" >/dev/null || fail "unified finding schema is invalid or incomplete"
grep -q '^normalize:' "$PROJECT_ROOT/Makefile" || fail "Makefile normalize target is missing"
grep -q 'normalize-all' "$PROJECT_ROOT/Makefile" || fail "Makefile does not invoke aggregate normalization"
grep -q '^test-python: kb-python-check' "$PROJECT_ROOT/Makefile" || \
  fail "Python tests must validate the project virtual environment"
grep -A2 '^test-python:' "$PROJECT_ROOT/Makefile" | grep -q '\$(VENV_PYTHON).*pytest' || \
  fail "Python tests must run through VENV_PYTHON"
grep -A2 'name: Install Python development dependencies' "$PROJECT_ROOT/.github/workflows/ci.yml" | \
  grep -q 'run: make install' || fail "CI quality must install the project virtual environment"
grep -q 'zap-fullscan-raw-<run_id>' "$PROJECT_ROOT/README.md" || \
  fail "README must document Full Scan report and metadata download"
grep -q 'reason: "missing_input"' "$PROJECT_ROOT/docs/reports/week2/week-2-normalization.md" || \
  fail "normalization documentation must define missing-input behavior"
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

for generated_report in semgrep.json zap.json codeql.sarif; do
  if git -C "$PROJECT_ROOT" ls-files --error-unmatch "reports/raw/$generated_report" >/dev/null 2>&1; then
    fail "generated scanner report must not be tracked: reports/raw/$generated_report"
  fi
  git -C "$PROJECT_ROOT" check-ignore -q "reports/raw/$generated_report" || \
    fail "generated scanner report must remain ignored: reports/raw/$generated_report"
done
for scanner_fixture in semgrep.json zap.json codeql.sarif; do
  git -C "$PROJECT_ROOT" ls-files --error-unmatch "tests/fixtures/scanners/$scanner_fixture" >/dev/null 2>&1 || \
    fail "scanner fixture must be tracked: tests/fixtures/scanners/$scanner_fixture"
done
pass "scanner fixtures are tracked separately from ignored runtime reports"
