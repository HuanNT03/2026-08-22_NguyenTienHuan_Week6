#!/usr/bin/env bash
set -Eeuo pipefail

CONTRACT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$CONTRACT_DIR/../.." && pwd -P)"
# shellcheck source=scripts/common.sh
source "$PROJECT_ROOT/scripts/common.sh"

fail() {
  printf 'not ok - %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'ok - %s\n' "$*"
}

assert_file() {
  [[ -f "$PROJECT_ROOT/$1" ]] || fail "Required file missing: $1"
}

