#!/usr/bin/env bash
# Contract group: DAST workflows

set -Eeuo pipefail
CONTRACT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=tests/contracts/common.sh
source "$CONTRACT_DIR/common.sh"

baseline_script="$PROJECT_ROOT/scripts/run-dast.sh"
grep -q -- '--user "$HOST_USER"' "$baseline_script" || fail "DAST container must use host UID/GID"
grep -q 'baseline-low-memory.yaml' "$baseline_script" || fail "Baseline must preserve its low-memory fallback"
grep -q 'ZAP_AUTOMATION_PLAN=.*baseline.yaml' "$baseline_script" || fail "Baseline Automation plan is missing"
grep -q -- '-autorun "$ZAP_AUTOMATION_PLAN_CONTAINER"' "$baseline_script" || \
  fail "Baseline must run the selected Automation plan"
grep -q -- '-autocheck "$ZAP_AUTOMATION_PLAN_CONTAINER"' "$baseline_script" || \
  fail "Baseline must validate the selected Automation plan"
grep -Fq -- 'dst=/zap/configs,ro' "$baseline_script" || fail "Baseline must mount ZAP plans read-only"
grep -q -- '--scan-profile baseline' "$PROJECT_ROOT/scripts/run-dast.sh" || \
  fail "ZAP Baseline metadata must declare its scan profile"
fullscan_script="$PROJECT_ROOT/scripts/run-dast-zap-fullscan.sh"
grep -q -- '--user "$HOST_USER"' "$fullscan_script" || fail "Full Scan container must use host UID/GID"
grep -q 'ZAP_DAEMON_LOG=.*zap-fullscan-zap.out' "$fullscan_script" || fail "Full Scan daemon log path is missing"
grep -Fq 'dst=/zap/zap.out' "$fullscan_script" || fail "Full Scan must bind a writable ZAP daemon log"
grep -q 'actual_zap_version=.*awk' "$fullscan_script" || fail "Full Scan must verify the ZAP core version"
grep -q 'ZAP_AUTOMATION_PLAN=.*full.yaml' "$fullscan_script" || fail "Full Scan Automation plan is missing"
grep -q -- '-autorun "$ZAP_AUTOMATION_PLAN_CONTAINER"' "$fullscan_script" || \
  fail "Full Scan must run its Automation plan"
grep -q -- '-autocheck "$ZAP_AUTOMATION_PLAN_CONTAINER"' "$fullscan_script" || \
  fail "Full Scan must validate its Automation plan"
grep -Fq -- 'dst=/zap/configs,ro' "$fullscan_script" || fail "Full Scan must mount ZAP plans read-only"
grep -Fq 'zap_exit_code="${PIPESTATUS[0]}"' "$fullscan_script" || fail "Full Scan must preserve the Docker exit code through tee"
fullscan_case_line="$(grep -n 'case "$zap_exit_code" in' "$fullscan_script" | head -n1 | cut -d: -f1)"
fullscan_validate_line="$(grep -n 'validate-reports.sh.*zap' "$fullscan_script" | head -n1 | cut -d: -f1)"
((fullscan_validate_line > fullscan_case_line)) || fail "Full Scan must classify the scanner exit code before validating its report"
grep -q '^dast-zap-fullscan:' "$PROJECT_ROOT/Makefile" || fail "ZAP Full Scan Make target is missing"
grep -q 'ZAP_CLIENT_SPIDER_MIN_BYTES' "$fullscan_script" || fail "Full Scan must enforce its Client Spider memory floor"
grep -q 'requires at least 4 GiB Docker memory' "$fullscan_script" || fail "Full Scan must fail clearly below the memory floor"
grep -q -- '--scan-profile full' "$fullscan_script" || fail "ZAP Full Scan metadata must declare its scan profile"
grep -q 'scan_profile: \$scan_profile' "$PROJECT_ROOT/scripts/write-scan-metadata.sh" || \
  fail "ZAP metadata must persist the scan profile"
fullscan_workflow="$PROJECT_ROOT/.github/workflows/dast-zap-fullscan.yml"
grep -q '^  workflow_dispatch:$' "$fullscan_workflow" || fail "Full Scan workflow must support manual dispatch"
if grep -Eq '^  (push|pull_request|schedule|workflow_call):' "$fullscan_workflow"; then
  fail "Full Scan workflow must be manual-only"
fi
grep -q '^    timeout-minutes: 75$' "$fullscan_workflow" || fail "Full Scan workflow timeout is incorrect"
grep -q 'run: make dast-zap-fullscan' "$fullscan_workflow" || fail "Full Scan workflow must use the local Make target"
grep -q 'zap-fullscan-raw-.*github.run_id' "$fullscan_workflow" || fail "Full Scan raw artifact is missing"
grep -q 'reports/raw/zap.meta.json' "$fullscan_workflow" || fail "Full Scan metadata artifact is missing"
grep -A2 'name: Validate ZAP report' "$fullscan_workflow" | grep -q 'if: success()' || \
  fail "Full Scan workflow must not validate a missing report after scanner failure"
grep -A2 'name: Stop Compose resources' "$fullscan_workflow" | grep -q 'if: always()' || \
  fail "Full Scan workflow must always stop Compose resources"
grep -q '^### Chạy ZAP Baseline local (passive)$' "$PROJECT_ROOT/README.md" || fail "README must separate the local Baseline flow"
grep -q '^### Chạy ZAP Full Scan local (active)$' "$PROJECT_ROOT/README.md" || fail "README must separate the local Full Scan flow"
pass "ZAP Full Scan workflow is manual-only, bounded, auditable and always cleaned up"
