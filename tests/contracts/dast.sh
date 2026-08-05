#!/usr/bin/env bash
# Contract group: DAST workflows

set -Eeuo pipefail
CONTRACT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=tests/contracts/common.sh
source "$CONTRACT_DIR/common.sh"

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
grep -q -- '--user "$HOST_USER"' "$fullscan_script" || fail "Full Scan container must use host UID/GID"
grep -q 'ZAP_DAEMON_LOG=.*zap-fullscan-zap.out' "$fullscan_script" || fail "Full Scan daemon log path is missing"
grep -Fq 'dst=/zap/zap.out' "$fullscan_script" || fail "Full Scan must bind a writable ZAP daemon log"
grep -q 'actual_zap_version=.*awk' "$fullscan_script" || fail "Full Scan must verify the ZAP core version"
grep -q "grep -Fq -- '--client-spider'" "$fullscan_script" || fail "Full Scan must preflight Client Spider support"
grep -Fq 'zap_exit_code="${PIPESTATUS[0]}"' "$fullscan_script" || fail "Full Scan must preserve the Docker exit code through tee"
fullscan_case_line="$(grep -n 'case "$zap_exit_code" in' "$fullscan_script" | head -n1 | cut -d: -f1)"
fullscan_validate_line="$(grep -n 'validate-reports.sh.*zap' "$fullscan_script" | head -n1 | cut -d: -f1)"
((fullscan_validate_line > fullscan_case_line)) || fail "Full Scan must classify the scanner exit code before validating its report"
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

