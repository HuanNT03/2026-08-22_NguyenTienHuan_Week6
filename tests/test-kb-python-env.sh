#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
TEST_VENV="$PROJECT_ROOT/.venv-bootstrap-test"
TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-kb-python.XXXXXX")"
trap 'rm -rf -- "$TEST_TMP" "$TEST_VENV"' EXIT

fail() {
  printf 'not ok - %s\n' "$*" >&2
  exit 1
}

set +e
missing_output="$("$PROJECT_ROOT/scripts/check-kb-python.sh" "$TEST_TMP/missing/python" 2>&1)"
missing_status=$?
set -e
((missing_status != 0)) || fail "preflight accepted a missing Python runtime"
[[ "$missing_output" == *"Run: make install"* ]] || fail "preflight omitted repair instructions"
[[ "$missing_output" != *"Traceback"* ]] || fail "preflight exposed a Python traceback"

printf '#!/usr/bin/env bash\nexit 1\n' >"$TEST_TMP/broken-python"
chmod +x "$TEST_TMP/broken-python"

setup_output="$("$PROJECT_ROOT/scripts/setup-kb-venv.sh" "$TEST_TMP/broken-python" "$TEST_VENV")"
[[ "$setup_output" == *"using "* ]] || fail "bootstrap did not report its fallback interpreter"

sqlite_version="$("$TEST_VENV/bin/python" -c 'import sqlite3; print(sqlite3.sqlite_version)')"
[[ -n "$sqlite_version" ]] || fail "repaired environment cannot import sqlite3"

printf 'ok - KB Python bootstrap falls back and preflight gives actionable errors\n'
