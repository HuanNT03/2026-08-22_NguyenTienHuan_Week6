#!/usr/bin/env bash
# Run pinned Semgrep against only Juice Shop and write reports/raw/semgrep.json. Exits on scanner/report failure.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/common.sh"

VERSIONS_FILE="$PROJECT_ROOT/configs/tool-versions.env"
SEMGREP_INCLUDE_FILE="$PROJECT_ROOT/configs/semgrep/includes.txt"
SEMGREP_IGNORE_FILE="$PROJECT_ROOT/configs/semgrep/.semgrepignore"
REPORT_DIR="$PROJECT_ROOT/reports/raw"
REPORT_FILE="$REPORT_DIR/semgrep.json"
SARIF_FILE="$REPORT_DIR/semgrep.sarif"
META_FILE="$REPORT_DIR/semgrep.meta.json"
HOST_USER="$(id -u):$(id -g)"

declare -a SEMGREP_SCOPE_ARGS=()

load_scope_patterns() {
  local pattern_file="$1"
  local option="$2"
  local pattern
  local pattern_count=0

  [[ -f "$pattern_file" ]] || die "Semgrep scope file not found: $pattern_file"
  while IFS= read -r pattern || [[ -n "$pattern" ]]; do
    [[ -z "$pattern" || "$pattern" == \#* ]] && continue
    [[ "$pattern" != \!* && "$pattern" != :* ]] || \
      die "Unsupported Semgrep scope directive in $pattern_file: $pattern"
    SEMGREP_SCOPE_ARGS+=("$option=$pattern")
    pattern_count=$((pattern_count + 1))
  done <"$pattern_file"
  ((pattern_count > 0)) || die "Semgrep scope file has no patterns: $pattern_file"
}

load_scope_patterns "$SEMGREP_INCLUDE_FILE" --include
load_scope_patterns "$SEMGREP_IGNORE_FILE" --exclude

load_tool_versions "$VERSIONS_FILE"
SEMGREP_APP_TOKEN="$(resolve_semgrep_app_token "$PROJECT_ROOT")"
export SEMGREP_APP_TOKEN
"$SCRIPT_DIR/verify-target.sh"
mkdir -p "$REPORT_DIR"
touch "$REPORT_DIR/.gitkeep"
rm -f -- "$REPORT_FILE" "$SARIF_FILE" "$META_FILE"
"$SCRIPT_DIR/write-scan-metadata.sh" --tool semgrep --report reports/raw/semgrep.json

log "Semgrep image: $SEMGREP_IMAGE"
docker run --rm --user "$HOST_USER" -e HOME=/tmp "$SEMGREP_IMAGE" semgrep --version

docker run --rm \
  --user "$HOST_USER" \
  -e HOME=/tmp \
  -e SEMGREP_APP_TOKEN \
  -v "$PROJECT_ROOT:/src:ro" \
  -v "$REPORT_DIR:/src/reports/raw:rw" \
  "$SEMGREP_IMAGE" \
  semgrep scan \
  --config p/owasp-top-ten \
  --config p/javascript \
  --config p/nodejs \
  --config p/expressjs \
  "${SEMGREP_SCOPE_ARGS[@]}" \
  --dataflow-traces \
  --sarif-output /src/reports/raw/semgrep.sarif \
  --json-output=/src/reports/raw/semgrep.json \
  /src/target-app/juice-shop

"$SCRIPT_DIR/validate-reports.sh" semgrep
python3 "$SCRIPT_DIR/validate-sast-scope.py" --tool semgrep --report "$REPORT_FILE"

jq -e 'all(.results[]; (.extra.fingerprint // "") != "requires login" and (.extra.lines // "") != "requires login")' \
  "$REPORT_FILE" >/dev/null || die "Semgrep report contains metadata that requires login"
log "Semgrep report contains authenticated finding metadata."

[[ -s "$SARIF_FILE" ]] || die "Semgrep SARIF report is missing or empty: $SARIF_FILE"
jq -e ".version == \"2.1.0\" and (.runs | type == \"array\")" "$SARIF_FILE" >/dev/null || \
  die "Semgrep SARIF report has an invalid top-level structure: $SARIF_FILE"
log "Semgrep SARIF report is valid: $SARIF_FILE"
