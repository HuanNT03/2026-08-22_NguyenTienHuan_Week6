#!/usr/bin/env bash

set -Eeuo pipefail

VENV_PYTHON="${1:-.venv/bin/python}"

fail() {
  printf '[sentinel] ERROR: %s\n' "$1" >&2
  printf '[sentinel] Run: make install\n' >&2
  printf '[sentinel] Explicit system-Python fallback: make install PYTHON=/usr/bin/python3\n' >&2
  printf '[sentinel] Note: sqlite3 cannot be fixed with pip; it is part of the Python build.\n' >&2
  exit 1
}

[[ -x "$VENV_PYTHON" ]] || fail "$VENV_PYTHON does not exist."

if ! "$VENV_PYTHON" - >/dev/null 2>&1 <<'PY'
import sqlite3
import importlib.util
import sys

if sys.version_info < (3, 11):
    raise SystemExit(1)
connection = sqlite3.connect(":memory:")
try:
    assert connection.execute("SELECT value FROM json_each('[1]')").fetchone() == (1,)
    connection.execute("CREATE VIRTUAL TABLE fts_check USING fts5(content)")
finally:
    connection.close()

required_modules = (
    "bs4",
    "jsonschema",
    "markdown_it",
    "pydantic",
    "pytest",
    "ruff",
    "typer",
    "yaml",
)
if any(importlib.util.find_spec(module) is None for module in required_modules):
    raise SystemExit(1)
PY
then
  fail "$VENV_PYTHON is missing Python >=3.11, SQLite JSON/FTS5, or project dependencies."
fi
