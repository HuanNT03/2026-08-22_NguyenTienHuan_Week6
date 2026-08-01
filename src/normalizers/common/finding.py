from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from src.normalizers.context import NormalizationContext


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def optional_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def native_string(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list, tuple, set, bool)):
        return None
    value = str(value).strip()
    return value or None


def string_array(value: Any) -> list[str]:
    values = value if isinstance(value, (list, tuple, set)) else [value]
    return sorted({item.strip() for item in values if isinstance(item, str) and item.strip()})


def reference_urls(value: Any) -> list[str]:
    urls: set[str] = set()
    for item in value if isinstance(value, (list, tuple, set)) else []:
        if not isinstance(item, str):
            continue
        cleaned = item.strip()
        try:
            parsed = urlparse(cleaned)
        except Exception:
            continue
        if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
            urls.add(cleaned)
    return sorted(urls)


def positive_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def base_finding(
    *,
    context: NormalizationContext,
    normalized_at: str,
    tool_name: str,
    tool_version: str | None,
    scan_type: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": context.schema_version,
        "finding_id": f"fnd_{uuid4().hex}",
        "tool": {"name": tool_name, "version": tool_version, "scan_type": scan_type},
        "scan": {
            "run_id": context.run_id,
            "pipeline_run_id": context.pipeline_run_id,
            "scanned_at": context.scanned_at,
        },
        "target": {
            "name": context.target_name,
            "version": context.target_version,
            "commit_sha": context.target_commit_sha,
            "base_url": context.target_base_url,
        },
        "rule": rule,
        "normalization": {
            "normalizer_version": context.normalizer_version,
            "normalized_at": normalized_at,
        },
    }


def fingerprint_collision_count(findings: list[dict[str, Any]]) -> int:
    fingerprints = [finding["fingerprint"] for finding in findings]
    return len(fingerprints) - len(set(fingerprints))
