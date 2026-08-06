import html
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, quote, urlparse, urlsplit, urlunsplit

_URL_PATTERN = re.compile(r"https?://[^\s<>'\"\)]+", flags=re.IGNORECASE)


@dataclass(frozen=True)
class UrlParseResult:
    urls: list[str]
    had_error: bool


def normalized_http_origin(raw_uri: str | None) -> tuple[str, str, int] | None:
    """Return a comparable HTTP origin or ``None`` for invalid, relative, or credentialed input.

    ``raw_uri`` must be an absolute HTTP(S) URL without user information. The output contains
    lowercase scheme and hostname plus an explicit effective port, so omitted default ports
    compare consistently. Parsing is side-effect free and treats scanner-controlled text as
    untrusted; malformed ports never escape as exceptions.
    """
    if not isinstance(raw_uri, str) or not raw_uri.strip():
        return None
    try:
        parsed = urlsplit(raw_uri.strip())
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or parsed.hostname is None:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        port = parsed.port
    except ValueError:
        return None
    return scheme, parsed.hostname.lower(), port if port is not None else (80 if scheme == "http" else 443)


def sanitize_uri_for_summary(raw_uri: str) -> str:
    """Return a deterministic audit URI without credentials, fragments, or query values.

    The output preserves the HTTP(S) scheme, host, explicit port, path, and sorted unique query
    parameter names. Invalid scanner-controlled URLs are represented by ``<invalid-uri>`` rather
    than echoed into logs or summaries. This function performs no I/O.
    """
    try:
        parsed = urlsplit(raw_uri.strip())
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
        if scheme not in {"http", "https"} or hostname is None:
            return "<invalid-uri>"
    except (AttributeError, ValueError):
        return "<invalid-uri>"

    display_host = f"[{hostname.lower()}]" if ":" in hostname else hostname.lower()
    netloc = f"{display_host}:{port}" if port is not None else display_host
    query_names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    redacted_query = "&".join(quote(name, safe="") for name in query_names)
    return urlunsplit((scheme, netloc, parsed.path or "/", redacted_query, ""))


def canonicalize_endpoint(raw_uri: str | None) -> str | None:
    if raw_uri is None or not isinstance(raw_uri, str):
        return None
    value = raw_uri.strip()
    if not value:
        return None
    try:
        parsed = urlparse(value)
    except Exception:  # noqa: BLE001  # Treat malformed untrusted URL values as absent.
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
            except Exception:  # noqa: BLE001, S112  # Ignore malformed untrusted URLs.
                continue
            if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
                urls.add(cleaned)
        return UrlParseResult(sorted(urls), False)
    except Exception:  # noqa: BLE001  # Preserve structured parse-error reporting.
        return UrlParseResult([], True)


def extract_urls(value: Any) -> list[str]:
    return extract_urls_with_status(value).urls
