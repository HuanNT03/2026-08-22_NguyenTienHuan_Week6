import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse

KNOWN_SOURCE_PREFIXES = (
    "/src/target-app/juice-shop/",
    "/workspace/target-app/juice-shop/",
)


@dataclass(frozen=True)
class CodeEvidenceRead:
    content: str | None
    context_before: list[dict[str, Any]]
    context_after: list[dict[str, Any]]
    source_succeeded: bool
    warning: str | None


def nullable_text(value: Any) -> str | None:
    """Return non-empty text without changing its original formatting."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value


def _relative_source_path(raw_path: Any) -> tuple[PurePosixPath | None, str | None]:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None, "source path is missing"
    value = raw_path.strip().replace("\\", "/")
    parsed = urlparse(value)
    if parsed.scheme:
        if parsed.scheme.lower() != "file":
            return None, f"unsupported source URI scheme: {parsed.scheme!r}"
        value = unquote(parsed.path).replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", value):
        return None, "absolute source path is not allowed"
    if value.startswith("/"):
        matched_prefix = next((prefix for prefix in KNOWN_SOURCE_PREFIXES if value.startswith(prefix)), None)
        if matched_prefix is None:
            return None, "absolute source path is outside known scanner prefixes"
        value = value[len(matched_prefix):]
    while value.startswith("./"):
        value = value[2:]
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        return None, "source path traversal is not allowed"
    return relative, None


def resolve_source_path(source_root: str | Path | None, raw_path: Any) -> tuple[Path | None, str | None]:
    if source_root is None:
        return None, "source root is not configured"
    root = Path(source_root).resolve()
    relative, error = _relative_source_path(raw_path)
    if relative is None:
        return None, error
    candidate = (root / Path(*relative.parts)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None, "resolved source path escapes source root"
    if not candidate.exists():
        return None, "source file does not exist"
    if not candidate.is_file():
        return None, "resolved source path is not a regular file"
    return candidate, None


def _failed_read(reason: str) -> CodeEvidenceRead:
    return CodeEvidenceRead(
        content=None,
        context_before=[],
        context_after=[],
        source_succeeded=False,
        warning=reason,
    )


def read_code_evidence(
    source_root: str | Path | None,
    path: Any,
    start_line: Any,
    end_line: Any,
    radius: int = 5,
) -> CodeEvidenceRead:
    resolved, error = resolve_source_path(source_root, path)
    if resolved is None:
        return _failed_read(error or "source path could not be resolved")
    if (
        isinstance(start_line, bool)
        or isinstance(end_line, bool)
        or not isinstance(start_line, int)
        or not isinstance(end_line, int)
        or start_line < 1
        or end_line < start_line
    ):
        return _failed_read("source location is invalid")
    if isinstance(radius, bool) or not isinstance(radius, int) or radius < 0:
        return _failed_read("context radius is invalid")
    try:
        lines = resolved.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return _failed_read(f"source file could not be read: {type(exc).__name__}")
    total_lines = len(lines)
    if start_line > total_lines or end_line > total_lines:
        return _failed_read(f"source location {start_line}-{end_line} is outside file bounds 1-{total_lines}")

    before_start = max(1, start_line - radius)
    after_end = min(total_lines, end_line + radius)
    context_before = [
        {"line": line_number, "content": lines[line_number - 1]}
        for line_number in range(before_start, start_line)
    ]
    context_after = [
        {"line": line_number, "content": lines[line_number - 1]}
        for line_number in range(end_line + 1, after_end + 1)
    ]
    content = nullable_text("\n".join(lines[start_line - 1:end_line]))
    return CodeEvidenceRead(
        content=content,
        context_before=context_before,
        context_after=context_after,
        source_succeeded=content is not None,
        warning=None,
    )
