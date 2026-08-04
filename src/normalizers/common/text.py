import html
import re
from dataclasses import dataclass
from typing import Any

_HTML_TAG_PATTERN = re.compile(r"<[^>]*>")


@dataclass(frozen=True)
class TextParseResult:
    value: str | None
    had_error: bool


def _clean_whitespace(value: str) -> str | None:
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", value)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned or None


def strip_html_with_status(value: Any) -> TextParseResult:
    if value is None:
        return TextParseResult(None, False)
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:  # noqa: BLE001  # Untrusted objects may fail during conversion.
            return TextParseResult(None, True)
    value = value.strip()
    if not value:
        return TextParseResult(None, False)
    try:
        decoded = html.unescape(value)
        return TextParseResult(_clean_whitespace(_HTML_TAG_PATTERN.sub(" ", decoded)), False)
    except Exception:  # noqa: BLE001  # Preserve parse-error reporting at the trust boundary.
        try:
            return TextParseResult(_clean_whitespace(value), True)
        except Exception:  # noqa: BLE001  # Untrusted objects may fail during conversion.
            return TextParseResult(None, True)


def strip_html(value: Any) -> str | None:
    return strip_html_with_status(value).value
