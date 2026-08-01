"""Shared parser helpers."""

import html
import re
from pathlib import Path

from bs4 import BeautifulSoup
from markdown_it import MarkdownIt

from src.retrieval.config import PROJECT_ROOT

_WHITESPACE = re.compile(r"[ \t]+")
_BLANK_LINES = re.compile(r"\n{3,}")
_STRUCTURED_KEY = re.compile(r"::([A-Z][A-Z _-]*):")


def repository_path(path: Path) -> str:
    """Return a portable repository-relative path, or a fixture filename."""
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return path.name


def normalize_plain_text(value: str) -> str:
    """Convert embedded HTML and irregular whitespace to deterministic plain text."""
    plain = BeautifulSoup(html.unescape(value), "html.parser").get_text(" ", strip=True)
    return _WHITESPACE.sub(" ", plain).strip()


def markdown_to_text(value: str) -> str:
    """Render Markdown and return readable deterministic plain text."""
    rendered = MarkdownIt("commonmark").render(value)
    soup = BeautifulSoup(rendered, "html.parser")
    for code in soup.find_all("code"):
        code.string = code.get_text()
    text = soup.get_text("\n", strip=True)
    lines = [_WHITESPACE.sub(" ", line).strip() for line in text.splitlines()]
    return _BLANK_LINES.sub("\n\n", "\n".join(line for line in lines if line)).strip()


def normalize_structured_text(value: str) -> str:
    """Turn MITRE's colon-delimited mini-language into labeled plain text."""
    if not value.strip():
        return ""
    text = normalize_plain_text(value)
    text = _STRUCTURED_KEY.sub(lambda match: f"\n{match.group(1).title()}: ", text)
    text = text.replace("::", "\n")
    lines = [_WHITESPACE.sub(" ", line).strip(" :") for line in text.splitlines()]
    return "\n".join(line for line in lines if line).strip()


def unique_casefold(values: list[str]) -> list[str]:
    """Deduplicate strings case-insensitively while preserving source order."""
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        clean = value.strip()
        key = clean.casefold()
        if clean and key not in seen:
            seen.add(key)
            result.append(clean)
    return result
