#!/usr/bin/env sh

GITLEAKS_REQUIRED_VERSION="8.30.1"

gitleaks_warn_and_skip() {
  printf 'WARNING: %s\n' "$1" >&2
  printf 'WARNING: Gitleaks secret scan was skipped. See README.md#git-hooks-voi-gitleaks for setup instructions.\n' >&2
}

gitleaks_version_is_supported() {
  actual_version="$1"
  required_version="$2"
  previous_ifs="$IFS"

  IFS=.
  set -- $actual_version
  actual_major="${1:-0}"
  actual_minor="${2:-0}"
  actual_patch="${3:-0}"

  set -- $required_version
  required_major="${1:-0}"
  required_minor="${2:-0}"
  required_patch="${3:-0}"
  IFS="$previous_ifs"

  [ "$actual_major" -gt "$required_major" ] ||
    { [ "$actual_major" -eq "$required_major" ] &&
      { [ "$actual_minor" -gt "$required_minor" ] ||
        { [ "$actual_minor" -eq "$required_minor" ] &&
          [ "$actual_patch" -ge "$required_patch" ]; }; }; }
}

gitleaks_is_ready() {
  if ! command -v gitleaks >/dev/null 2>&1; then
    gitleaks_warn_and_skip "Gitleaks is not installed or is not available in PATH."
    return 1
  fi

  version_output="$(gitleaks version 2>/dev/null)" || {
    gitleaks_warn_and_skip "Unable to determine the installed Gitleaks version."
    return 1
  }
  installed_version="$(
    printf '%s\n' "$version_output" |
      sed -n 's/[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' |
      head -n 1
  )"

  if [ -z "$installed_version" ]; then
    gitleaks_warn_and_skip "Unable to parse the installed Gitleaks version: $version_output"
    return 1
  fi

  if ! gitleaks_version_is_supported "$installed_version" "$GITLEAKS_REQUIRED_VERSION"; then
    gitleaks_warn_and_skip \
      "Gitleaks $installed_version is older than the required version $GITLEAKS_REQUIRED_VERSION."
    return 1
  fi

  return 0
}
