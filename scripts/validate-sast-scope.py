#!/usr/bin/env python3
"""Validate that Semgrep and CodeQL artifacts stay within the approved runtime scope."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INCLUDE_PATH = PROJECT_ROOT / "configs" / "semgrep" / "includes.txt"
EXCLUDE_PATH = PROJECT_ROOT / "configs" / "semgrep" / ".semgrepignore"
TARGET_MARKER = re.compile(r"(?:^|/)target-app/juice-shop/(.*)$")


class ScopeValidationError(ValueError):
    """Raised when a report or scope configuration is invalid."""


def _read_patterns(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ScopeValidationError(f"Unable to read scope configuration {path}: {error}") from error
    patterns: list[str] = []
    for line_number, raw_line in enumerate(lines, start=1):
        pattern = raw_line.strip()
        if not pattern or pattern.startswith("#"):
            continue
        if pattern.startswith(("!", ":")):
            raise ScopeValidationError(f"Unsupported scope directive in {path}:{line_number}: {pattern}")
        patterns.append(pattern.lstrip("/"))
    if not patterns:
        raise ScopeValidationError(f"Scope configuration has no patterns: {path}")
    return patterns


def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile the subset of gitignore globs used by Sentinel scope files."""
    expression: list[str] = ["^"]
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            expression.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            expression.append(".*")
            index += 2
        elif pattern[index] == "*":
            expression.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            expression.append("[^/]")
            index += 1
        else:
            expression.append(re.escape(pattern[index]))
            index += 1
    expression.append("$")
    return re.compile("".join(expression))


def _normalize_path(raw_path: object) -> str:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ScopeValidationError(f"SAST artifact has an invalid path: {raw_path!r}")
    value = raw_path.strip().replace("\\", "/")
    if value.startswith("file:"):
        value = unquote(urlparse(value).path)
    else:
        value = unquote(value)
    value = re.sub(r"/+", "/", value)
    marker = TARGET_MARKER.search(value)
    if marker is not None:
        value = marker.group(1)
    else:
        value = value.lstrip("/")
    while value.startswith("./"):
        value = value[2:]
    parts = [part for part in value.split("/") if part not in {"", "."}]
    if not parts or ".." in parts:
        raise ScopeValidationError(f"SAST artifact path is unsafe: {raw_path!r}")
    return "/".join(parts)


class ScopePolicy:
    def __init__(self, includes: Iterable[str], excludes: Iterable[str]) -> None:
        self.includes = [(pattern, _glob_regex(pattern)) for pattern in includes]
        self.excludes = [(pattern, _glob_regex(pattern)) for pattern in excludes]

    @classmethod
    def from_repository(cls) -> ScopePolicy:
        return cls(_read_patterns(INCLUDE_PATH), _read_patterns(EXCLUDE_PATH))

    def accepts(self, path: str) -> bool:
        if any(regex.fullmatch(path) for _, regex in self.excludes):
            return False
        return any(regex.fullmatch(path) for _, regex in self.includes)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ScopeValidationError(f"Unable to read SAST report {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ScopeValidationError(f"SAST report is invalid JSON {path}: {error}") from error
    if not isinstance(payload, dict):
        raise ScopeValidationError(f"SAST report must be a JSON object: {path}")
    return payload


def _semgrep_paths(report: dict[str, Any]) -> tuple[list[str], int]:
    paths = report.get("paths")
    scanned = paths.get("scanned") if isinstance(paths, dict) else None
    results = report.get("results")
    if not isinstance(scanned, list) or not scanned:
        raise ScopeValidationError("Semgrep report paths.scanned must be a non-empty array")
    if not isinstance(results, list):
        raise ScopeValidationError("Semgrep report results must be an array")
    raw_paths: list[object] = list(scanned)
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ScopeValidationError(f"Semgrep result {index} must be an object")
        raw_paths.append(result.get("path"))
    return [_normalize_path(path) for path in raw_paths], len(results)


def _artifact_uris(value: object) -> Iterable[object]:
    if isinstance(value, dict):
        artifact = value.get("artifactLocation")
        if isinstance(artifact, dict) and "uri" in artifact:
            yield artifact.get("uri")
        for child in value.values():
            yield from _artifact_uris(child)
    elif isinstance(value, list):
        for child in value:
            yield from _artifact_uris(child)


def _codeql_paths(report: dict[str, Any]) -> tuple[list[str], int]:
    runs = report.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ScopeValidationError("CodeQL SARIF runs must be a non-empty array")
    raw_paths: list[object] = []
    result_count = 0
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ScopeValidationError(f"CodeQL SARIF run {run_index} must be an object")
        artifacts = run.get("artifacts")
        if isinstance(artifacts, list):
            for artifact in artifacts:
                if isinstance(artifact, dict):
                    location = artifact.get("location")
                    if isinstance(location, dict) and "uri" in location:
                        raw_paths.append(location.get("uri"))
        results = run.get("results")
        if not isinstance(results, list):
            raise ScopeValidationError(f"CodeQL SARIF run {run_index}.results must be an array")
        result_count += len(results)
        raw_paths.extend(_artifact_uris(results))
    if not raw_paths:
        raise ScopeValidationError("CodeQL SARIF contains no source artifacts or result locations")
    return [_normalize_path(path) for path in raw_paths], result_count


def validate_report(tool: str, report_path: Path, policy: ScopePolicy) -> tuple[int, int]:
    report = _load_json(report_path)
    paths, finding_count = _semgrep_paths(report) if tool == "semgrep" else _codeql_paths(report)
    rejected = sorted({path for path in paths if not policy.accepts(path)})
    if rejected:
        preview = "\n  - ".join(rejected[:20])
        suffix = f"\n  ... and {len(rejected) - 20} more" if len(rejected) > 20 else ""
        raise ScopeValidationError(
            f"{tool} report contains {len(rejected)} out-of-scope path(s):\n  - {preview}{suffix}"
        )
    return len(set(paths)), finding_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", choices=("semgrep", "codeql"), required=True)
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        path_count, finding_count = validate_report(
            arguments.tool,
            arguments.report,
            ScopePolicy.from_repository(),
        )
    except ScopeValidationError as error:
        print(f"[sentinel] ERROR: {error}", file=sys.stderr)
        return 1
    print(f"[sentinel] {arguments.tool} scope is valid: {path_count} unique paths, {finding_count} findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
