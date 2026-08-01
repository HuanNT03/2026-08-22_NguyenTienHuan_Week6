import html
import re
from typing import Any
from urllib.parse import urlparse


_URL_PATTERN = re.compile(r"https?://[^\s<>'\"\)]+", flags=re.IGNORECASE)


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


def extract_urls(value: Any) -> list[str]:
    if value is None or not isinstance(value, str):
        return []
    value = value.strip()
    if not value:
        return []
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
        return sorted(urls)
    except Exception:
        return []
