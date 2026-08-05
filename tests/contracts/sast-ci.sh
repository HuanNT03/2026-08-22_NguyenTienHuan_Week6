#!/usr/bin/env bash
# Contract group: SAST and CI orchestration

set -Eeuo pipefail
CONTRACT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=tests/contracts/common.sh
source "$CONTRACT_DIR/common.sh"

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
grep -q -- '/nodejs/bin/node' "$PROJECT_ROOT/docker-compose.yml" || fail "healthcheck must use the distroless Node executable"
grep -q -- "-w '%{http_code}'" "$PROJECT_ROOT/scripts/wait-for-target.sh" || fail "wait must poll HTTP status"
grep -q 'touch "$REPORT_DIR/.gitkeep"' "$PROJECT_ROOT/scripts/run-sast.sh" || fail "SAST must restore raw report .gitkeep"
grep -q 'touch "$REPORT_DIR/.gitkeep"' "$PROJECT_ROOT/scripts/run-dast.sh" || fail "DAST must restore raw report .gitkeep"
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

