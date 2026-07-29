#!/usr/bin/env bash
# Shared helpers for parsing pinned configuration without executing it.

set -Eeuo pipefail

log() {
  printf '[sentinel] %s\n' "$*"
}

die() {
  printf '[sentinel] ERROR: %s\n' "$*" >&2
  exit 1
}

validate_config_file() {
  local config_file="$1"
  shift
  local allowed_keys="$*"

  [[ -f "$config_file" ]] || die "Configuration file not found: $config_file"

  awk -F= -v allowed="$allowed_keys" '
    BEGIN {
      count = split(allowed, expected, " ")
      for (i = 1; i <= count; i++) wanted[expected[i]] = 1
    }
    /^[[:space:]]*$/ { next }
    NF < 2 || $1 == "" { printf "Malformed configuration line %d\n", NR > "/dev/stderr"; bad = 1; next }
    !($1 in wanted) { printf "Unsupported configuration key on line %d: %s\n", NR, $1 > "/dev/stderr"; bad = 1; next }
    seen[$1]++ > 0 { printf "Duplicate configuration key: %s\n", $1 > "/dev/stderr"; bad = 1 }
    END {
      for (key in wanted) {
        if (!(key in seen)) {
          printf "Missing configuration key: %s\n", key > "/dev/stderr"
          bad = 1
        }
      }
      exit bad
    }
  ' "$config_file" || die "Invalid configuration file: $config_file"
}

config_value() {
  local config_file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, length($1) + 2) }' "$config_file"
}

load_target_lock() {
  local lock_file="$1"
  validate_config_file "$lock_file" REPOSITORY_URL TAG COMMIT_SHA

  REPOSITORY_URL="$(config_value "$lock_file" REPOSITORY_URL)"
  TAG="$(config_value "$lock_file" TAG)"
  COMMIT_SHA="$(config_value "$lock_file" COMMIT_SHA)"

  [[ "$REPOSITORY_URL" == "https://github.com/juice-shop/juice-shop.git" ]] || \
    die "Unexpected REPOSITORY_URL: $REPOSITORY_URL"
  [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid TAG: $TAG"
  [[ "$COMMIT_SHA" =~ ^[0-9a-fA-F]{40}$ ]] || die "COMMIT_SHA must be 40 hexadecimal characters"
}

load_tool_versions() {
  local versions_file="$1"
  validate_config_file "$versions_file" SEMGREP_VERSION SEMGREP_IMAGE ZAP_VERSION ZAP_IMAGE

  SEMGREP_VERSION="$(config_value "$versions_file" SEMGREP_VERSION)"
  SEMGREP_IMAGE="$(config_value "$versions_file" SEMGREP_IMAGE)"
  ZAP_VERSION="$(config_value "$versions_file" ZAP_VERSION)"
  ZAP_IMAGE="$(config_value "$versions_file" ZAP_IMAGE)"

  [[ "$SEMGREP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid SEMGREP_VERSION: $SEMGREP_VERSION"
  [[ "$ZAP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid ZAP_VERSION: $ZAP_VERSION"
  [[ "$SEMGREP_IMAGE" == *":$SEMGREP_VERSION" ]] || die "SEMGREP_IMAGE is not pinned to SEMGREP_VERSION"
  [[ "$ZAP_IMAGE" == *":$ZAP_VERSION" ]] || die "ZAP_IMAGE is not pinned to ZAP_VERSION"
}
