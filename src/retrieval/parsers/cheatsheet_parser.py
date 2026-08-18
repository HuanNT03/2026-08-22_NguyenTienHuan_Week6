"""Parser for OWASP Cheat Sheet Markdown files."""

import re
from pathlib import Path

from src.retrieval.exceptions import SourceValidationError
from src.retrieval.models import KnowledgeDocument, KnowledgeIdentifiers, KnowledgeSource
from src.retrieval.parsers.base import markdown_to_text, normalize_plain_text, repository_path, unique_casefold


def parse_cheatsheet_file(path: Path) -> KnowledgeDocument:
    """Parse one OWASP cheat sheet Markdown file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise SourceValidationError(f"Unable to read cheatsheet {path}: {error}") from error

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise SourceValidationError(f"{path}: cheatsheet file is empty")

    title = path.stem.replace("_", " ")
    for line in lines:
        if line.startswith("# "):
            title = line.removeprefix("# ").strip()
            break

    # Summary: find first paragraph after H1 or introduction
    summary = ""
    for line in lines:
        if not line.startswith("#") and len(line) > 30 and not line.startswith("!"):
            summary = normalize_plain_text(line)
            break
    if not summary:
        summary = f"OWASP Security Cheat Sheet: {title}"

    content = markdown_to_text(text)

    # Extract CWE and OWASP identifiers
    cwes = [f"CWE-{m}" for m in set(re.findall(r"\bCWE-(\d+)\b", text, flags=re.IGNORECASE))]
    owasps = [f"A{m[0]}:{m[1]}" for m in set(re.findall(r"\bA(\d{1,2}):(\d{4})\b", text, flags=re.IGNORECASE))]

    # Doc ID
    slug = re.sub(r"[^a-z0-9]+", "-", path.stem.lower()).strip("-")
    doc_id = f"cheatsheet-{slug}"

    tags = ["cheatsheet", "owasp", "defense-in-depth"]
    title_slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    if title_slug:
        tags.append(title_slug)

    return KnowledgeDocument(
        doc_id=doc_id,
        doc_type="cheatsheet",
        title=f"OWASP Cheat Sheet: {title}",
        aliases=unique_casefold([title, path.stem.replace("_", " ")]),
        summary=summary,
        content=content,
        identifiers=KnowledgeIdentifiers(cwe=cwes, owasp=owasps),
        tags=tags,
        source=KnowledgeSource(
            name="OWASP Cheat Sheet Series",
            version="1.0",
            raw_path=repository_path(path),
            source_locator=path.name,
        ),
    )


def parse_cheatsheet_directory(path: Path) -> list[KnowledgeDocument]:
    """Parse all non-empty Markdown cheat sheets in a directory."""
    documents: list[KnowledgeDocument] = []
    if not path.is_dir():
        return documents
    for file_path in sorted(path.glob("*.md")):
        if file_path.stat().st_size == 0:
            continue
        try:
            documents.append(parse_cheatsheet_file(file_path))
        except SourceValidationError:
            continue
    return documents
