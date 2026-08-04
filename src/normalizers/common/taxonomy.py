import re
from collections.abc import Iterable
from typing import Any

_CWE_PATTERN = re.compile(r"(?:cwe(?:[-_/]cwe)?[-_/]?)?0*([0-9]+)", re.IGNORECASE)
_WASC_PATTERN = re.compile(r"(?:wasc[-_/]?)?0*([0-9]+)", re.IGNORECASE)
_OWASP_PATTERN = re.compile(r"(?:owasp[-_/]?)?a(0?[1-9]|10)\s*[:_-]\s*([0-9]{4})", re.IGNORECASE)


def _values(raw: Any) -> Iterable[Any]:
    if raw is None:
        return ()
    if isinstance(raw, (list, tuple, set)):
        return raw
    return (raw,)


def _numeric_taxonomy(raw: Any, pattern: re.Pattern[str], prefix: str) -> list[str]:
    result: set[int] = set()
    for value in _values(raw):
        if isinstance(value, bool):
            continue
        text = str(value).strip() if isinstance(value, (str, int)) else ""
        if not text or text.startswith("-"):
            continue
        match = pattern.search(text)
        if match:
            number = int(match.group(1))
            if number > 0:
                result.add(number)
    return [f"{prefix}-{number}" for number in sorted(result)]


def normalize_cwe_ids(values: Any) -> list[str]:
    return _numeric_taxonomy(values, _CWE_PATTERN, "CWE")


def normalize_wasc_ids(values: Any) -> list[str]:
    return _numeric_taxonomy(values, _WASC_PATTERN, "WASC")


def normalize_owasp_categories(values: Any) -> list[str]:
    result: set[tuple[int, int]] = set()
    for value in _values(values):
        if not isinstance(value, str):
            continue
        match = _OWASP_PATTERN.search(value.strip())
        if match:
            number = int(match.group(1))
            year = int(match.group(2))
            result.add((year, number))
    return [f"OWASP-A{number:02d}:{year}" for year, number in sorted(result)]
