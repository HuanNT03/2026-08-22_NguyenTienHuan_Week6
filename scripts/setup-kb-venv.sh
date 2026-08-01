#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
REQUESTED_PYTHON="${1:-python3}"
VENV_PATH="${2:-.venv}"

log() {
  printf '[sentinel] %s\n' "$*"
}

check_python() {
  local python_bin="$1"
  "$python_bin" - >/dev/null 2>&1 <<'PY'
import sqlite3
import sys

if sys.version_info < (3, 11):
    raise SystemExit(1)

connection = sqlite3.connect(":memory:")
try:
    if connection.execute("SELECT value FROM json_each('[1]')").fetchone() != (1,):
        raise SystemExit(1)
    connection.execute("CREATE VIRTUAL TABLE fts_check USING fts5(content)")
    connection.execute("INSERT INTO fts_check(content) VALUES ('SQL Injection')")
    if connection.execute(
        "SELECT rowid FROM fts_check WHERE fts_check MATCH ?",
        ('"SQL" "Injection"',),
    ).fetchone() is None:
        raise SystemExit(1)
finally:
    connection.close()
PY
}

resolve_python() {
  local candidate resolved
  local -a candidates=(
    "$REQUESTED_PYTHON"
    /usr/bin/python3
    /usr/local/bin/python3
    /opt/homebrew/bin/python3
    python3.13
    python3.12
    python3.11
    python3
  )
  local seen=':'

  for candidate in "${candidates[@]}"; do
    resolved="$(command -v -- "$candidate" 2>/dev/null || true)"
    [[ -n "$resolved" && -x "$resolved" ]] || continue
    case "$seen" in
      *":$resolved:"*) continue ;;
    esac
    seen+="$resolved:"
    if check_python "$resolved"; then
      printf '%s\n' "$resolved"
      return 0
    fi
  done
  return 1
}

case "$VENV_PATH" in
  /*) venv_abs="$VENV_PATH" ;;
  *) venv_abs="$PROJECT_ROOT/$VENV_PATH" ;;
esac

venv_parent="$(cd -- "$(dirname -- "$venv_abs")" && pwd -P)"
venv_name="$(basename -- "$venv_abs")"
if [[ "$venv_parent" != "$PROJECT_ROOT" || "$venv_name" != .venv* ]]; then
  log "ERROR: refusing to create or clear unsafe virtualenv path: $venv_abs" >&2
  log "VENV must be a direct child of the repository and start with .venv." >&2
  exit 1
fi

if [[ -x "$venv_abs/bin/python" ]] && check_python "$venv_abs/bin/python"; then
  log "Using existing SQLite-capable environment: $venv_abs"
  exit 0
fi

selected_python="$(resolve_python || true)"
if [[ -z "$selected_python" ]]; then
  log "ERROR: no Python >= 3.11 runtime with SQLite JSON and FTS5 support was found." >&2
  log "Install Python with SQLite development libraries, then run 'make install' again." >&2
  log "Ubuntu/Debian: sudo apt-get install libsqlite3-dev python3-venv" >&2
  log "pyenv users must reinstall their Python version after installing libsqlite3-dev." >&2
  exit 1
fi

requested_resolved="$(command -v -- "$REQUESTED_PYTHON" 2>/dev/null || true)"
if [[ -n "$requested_resolved" && "$selected_python" != "$requested_resolved" ]]; then
  log "WARNING: $REQUESTED_PYTHON lacks Python >=3.11 or SQLite JSON/FTS5; using $selected_python."
fi

if [[ -e "$venv_abs" ]]; then
  log "Rebuilding incompatible environment: $venv_abs"
fi
if ! "$selected_python" -m venv --clear "$venv_abs"; then
  log "ERROR: failed to create $venv_abs with $selected_python." >&2
  log "Install the venv package for this interpreter (for example python3-venv), then retry." >&2
  exit 1
fi

if ! check_python "$venv_abs/bin/python"; then
  log "ERROR: the newly created environment still lacks SQLite JSON/FTS5 support." >&2
  exit 1
fi
log "Created SQLite-capable environment with $selected_python: $venv_abs"
