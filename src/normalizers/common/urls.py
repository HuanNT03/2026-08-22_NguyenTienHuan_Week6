import html
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


_URL_PATTERN = re.compile(r"https?://[^\s<>'\"\)]+", flags=re.IGNORECASE)


@dataclass(frozen=True)
class UrlParseResult:
    urls: list[str]
    had_error: bool


def canonicalize_endpoint(raw_uri: str | None) -> str | None:
    if raw_uri is None or not isinstance(raw_uri, str):
        return None
    value = raw_uri.strip()
    if not value:
        return None
    try:
        parsed = urlparse(value)
    except Exception:
        return None
    return parsed.path or "/"


def extract_urls_with_status(value: Any) -> UrlParseResult:
    if value is None or not isinstance(value, str):
        return UrlParseResult([], False)
    value = value.strip()
    if not value:
        return UrlParseResult([], False)
    try:
        candidates = _URL_PATTERN.findall(html.unescape(value))
        urls: set[str] = set()
        for candidate in candidates:
            cleaned = candidate.rstrip(".,;:")
            try:
                parsed = urlparse(cleaned)
            except Exception:
                continue
            if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
                urls.add(cleaned)
        return UrlParseResult(sorted(urls), False)
    except Exception:
        return UrlParseResult([], True)


def extract_urls(value: Any) -> list[str]:
    return extract_urls_with_status(value).urls
