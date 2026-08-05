#!/usr/bin/env bash
# Validate repository contracts without cloning Juice Shop or starting Docker resources.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
for contract in \
  repository-layout \
  sast-ci \
  dast \
  cleanup-validation \
  git-hooks; do
  bash "$SCRIPT_DIR/contracts/$contract.sh"
done
