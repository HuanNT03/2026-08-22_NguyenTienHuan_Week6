#!/usr/bin/env bash
# Contract group: Gitleaks Git hooks

set -Eeuo pipefail
CONTRACT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=tests/contracts/common.sh
source "$CONTRACT_DIR/common.sh"

TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-contracts.XXXXXX")"
trap 'rm -rf -- "$TEST_TMP"' EXIT

grep -q '^## Gitleaks Git hooks$' "$PROJECT_ROOT/README.md" || fail "README must document Gitleaks hooks"
grep -q 'git config --local core.hooksPath .githooks' "$PROJECT_ROOT/README.md" || \
  fail "README must document tracked hook activation"
grep -q 'gitleaks version' "$PROJECT_ROOT/README.md" || fail "README must document the version check"
[[ -x "$PROJECT_ROOT/.githooks/pre-commit" ]] || fail "pre-commit hook must be executable"

hook_repo="$TEST_TMP/hook-repo"
fake_bin="$TEST_TMP/fake-bin"
missing_bin="$TEST_TMP/missing-bin"
mkdir -p "$hook_repo" "$fake_bin" "$missing_bin"
git -C "$hook_repo" init -q
git -C "$hook_repo" config user.name "Sentinel Hook Test"
git -C "$hook_repo" config user.email "sentinel-hook-test@example.invalid"

cat >"$fake_bin/gitleaks" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "version" ]]; then
  printf '%s\n' "${FAKE_GITLEAKS_VERSION:-8.30.1}"
  exit "${FAKE_GITLEAKS_VERSION_STATUS:-0}"
fi

printf '%s\n' "$*" >>"${FAKE_GITLEAKS_LOG:?}"
exit "${FAKE_GITLEAKS_SCAN_STATUS:-0}"
EOF
chmod +x "$fake_bin/gitleaks"

for required_command in sh dirname git; do
  ln -s "$(command -v "$required_command")" "$missing_bin/$required_command"
done

set +e
missing_output="$(cd "$hook_repo" && PATH="$missing_bin" "$PROJECT_ROOT/.githooks/pre-commit" 2>&1)"
missing_status=$?
set -e
((missing_status == 0)) || fail "pre-commit must allow commits when Gitleaks is missing"
[[ "$missing_output" == *"secret scan was skipped"* ]] || \
  fail "pre-commit did not warn when Gitleaks was missing"

hook_log="$TEST_TMP/pre-commit-gitleaks.log"
set +e
old_version_output="$(
  cd "$hook_repo" &&
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.29.0 FAKE_GITLEAKS_LOG="$hook_log" \
      "$PROJECT_ROOT/.githooks/pre-commit" 2>&1
)"
old_version_status=$?
set -e
((old_version_status == 0)) || fail "pre-commit must allow commits when Gitleaks is outdated"
[[ "$old_version_output" == *"secret scan was skipped"* ]] || \
  fail "pre-commit did not warn when Gitleaks was outdated"
[[ ! -e "$hook_log" ]] || fail "pre-commit invoked an outdated Gitleaks binary"

(
  cd "$hook_repo"
  PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$hook_log" \
    "$PROJECT_ROOT/.githooks/pre-commit" >/dev/null
)
grep -Fxq -- 'git --pre-commit --redact --staged --verbose' "$hook_log" || \
  fail "pre-commit invoked Gitleaks with unexpected arguments"

set +e
(
  cd "$hook_repo" &&
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$hook_log" \
      FAKE_GITLEAKS_SCAN_STATUS=1 "$PROJECT_ROOT/.githooks/pre-commit" >/dev/null 2>&1
)
scan_status=$?
set -e
((scan_status == 1)) || fail "pre-commit did not propagate a Gitleaks finding"
pass "pre-commit skips unavailable Gitleaks and blocks on scan findings"

[[ -x "$PROJECT_ROOT/.githooks/pre-push" ]] || fail "pre-push hook must be executable"

local_oid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
remote_oid=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
zero_oid=0000000000000000000000000000000000000000
pre_push_log="$TEST_TMP/pre-push-gitleaks.log"

printf 'refs/heads/main %s refs/heads/main %s\n' "$local_oid" "$remote_oid" |
  (
    cd "$hook_repo"
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$pre_push_log" \
      "$PROJECT_ROOT/.githooks/pre-push" origin example.invalid >/dev/null
  )
grep -Fxq "git --redact --verbose --log-opts=$remote_oid..$local_oid ." "$pre_push_log" || \
  fail "pre-push did not scan the outgoing commit range"

: >"$pre_push_log"
printf 'refs/heads/feature %s refs/heads/feature %s\n' "$local_oid" "$zero_oid" |
  (
    cd "$hook_repo"
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$pre_push_log" \
      "$PROJECT_ROOT/.githooks/pre-push" origin example.invalid >/dev/null
  )
grep -Fxq "git --redact --verbose --log-opts=$local_oid ." "$pre_push_log" || \
  fail "pre-push did not scan full reachable history for a new ref"

: >"$pre_push_log"
printf 'refs/heads/main %s refs/heads/main %s\n' "$zero_oid" "$remote_oid" |
  (
    cd "$hook_repo"
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$pre_push_log" \
      "$PROJECT_ROOT/.githooks/pre-push" origin example.invalid >/dev/null
  )
[[ ! -s "$pre_push_log" ]] || fail "pre-push must skip deleted refs"

: >"$pre_push_log"
set +e
outdated_push_output="$(
  printf 'refs/heads/main %s refs/heads/main %s\n' "$local_oid" "$remote_oid" |
    (
      cd "$hook_repo"
      PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.29.0 FAKE_GITLEAKS_LOG="$pre_push_log" \
        "$PROJECT_ROOT/.githooks/pre-push" origin example.invalid 2>&1
    )
)"
outdated_push_status=$?
set -e
((outdated_push_status == 0)) || fail "pre-push must allow pushes when Gitleaks is outdated"
[[ "$outdated_push_output" == *"secret scan was skipped"* ]] || \
  fail "pre-push did not warn when Gitleaks was outdated"
[[ ! -s "$pre_push_log" ]] || fail "pre-push invoked an outdated Gitleaks binary"

: >"$pre_push_log"
printf 'refs/heads/main %s refs/heads/main %s\nrefs/tags/v1 %s refs/tags/v1 %s\n' \
  "$local_oid" "$remote_oid" "$local_oid" "$zero_oid" |
  (
    cd "$hook_repo"
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$pre_push_log" \
      "$PROJECT_ROOT/.githooks/pre-push" origin example.invalid >/dev/null
  )
[[ "$(wc -l <"$pre_push_log")" -eq 2 ]] || fail "pre-push did not scan every updated ref"
grep -Fxq "git --redact --verbose --log-opts=$remote_oid..$local_oid ." "$pre_push_log" || \
  fail "pre-push omitted the existing ref from a multi-ref push"
grep -Fxq "git --redact --verbose --log-opts=$local_oid ." "$pre_push_log" || \
  fail "pre-push omitted the new ref from a multi-ref push"

set +e
printf 'refs/heads/main %s refs/heads/main %s\n' "$local_oid" "$remote_oid" |
  (
    cd "$hook_repo"
    PATH="$fake_bin:$PATH" FAKE_GITLEAKS_VERSION=8.30.1 FAKE_GITLEAKS_LOG="$pre_push_log" \
      FAKE_GITLEAKS_SCAN_STATUS=2 "$PROJECT_ROOT/.githooks/pre-push" origin example.invalid \
      >/dev/null 2>&1
  )
push_scan_status=$?
set -e
((push_scan_status == 2)) || fail "pre-push did not propagate a Gitleaks scan error"
pass "pre-push scans outgoing history, skips deletions and enforces scan results"

