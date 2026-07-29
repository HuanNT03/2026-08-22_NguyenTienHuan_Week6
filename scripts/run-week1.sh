#!/usr/bin/env bash
# Run the complete Week 1 flow with SAST before runtime startup and always stop Compose resources after up.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"

runtime_started=0
cleanup_runtime() {
  if ((runtime_started == 1)); then
    make -C "$PROJECT_ROOT" down || true
  fi
}
trap cleanup_runtime EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

make -C "$PROJECT_ROOT" doctor
make -C "$PROJECT_ROOT" quality
make -C "$PROJECT_ROOT" setup-target
make -C "$PROJECT_ROOT" sast
make -C "$PROJECT_ROOT" build
make -C "$PROJECT_ROOT" up
runtime_started=1
make -C "$PROJECT_ROOT" wait
make -C "$PROJECT_ROOT" smoke
make -C "$PROJECT_ROOT" dast
make -C "$PROJECT_ROOT" validate-reports
make -C "$PROJECT_ROOT" down
runtime_started=0
