"""Parser for general security documentation and scanner guides in Markdown."""

import re
from pathlib import Path

from src.retrieval.exceptions import SourceValidationError
from src.retrieval.models import KnowledgeDocument, KnowledgeIdentifiers, KnowledgeSource
from src.retrieval.parsers.base import markdown_to_text, normalize_plain_text, repository_path


def parse_generic_markdown_file(
    path: Path,
    source_name: str,
    doc_type: str = "scanner_document",
    doc_id_prefix: str = "doc",
    extra_tags: list[str] | None = None,
) -> KnowledgeDocument:
    """Parse a Markdown document into a canonical KnowledgeDocument."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise SourceValidationError(f"Unable to read documentation file {path}: {error}") from error

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise SourceValidationError(f"{path}: markdown file is empty")

    title = path.stem.replace("-", " ").replace("_", " ").title()
    for line in lines:
        if line.startswith("# "):
            title = line.removeprefix("# ").strip()
            break

    # Summary: first meaningful non-heading paragraph or blockquote
    summary = ""
    for line in lines:
        if not line.startswith("#") and not line.startswith("!") and len(line) > 25:
            summary = normalize_plain_text(line.removeprefix(">").strip())
            break
    if not summary:
        summary = f"{source_name}: {title}"

    content = markdown_to_text(text)

    # Extract identifiers mentioned in document
    cwes = [f"CWE-{m}" for m in set(re.findall(r"\bCWE-(\d+)\b", text, flags=re.IGNORECASE))]
    owasps = [f"A{m[0]}:{m[1]}" for m in set(re.findall(r"\bA(\d{1,2}):(\d{4})\b", text, flags=re.IGNORECASE))]

    clean_stem = re.sub(r"[^a-z0-9]+", "-", path.stem.lower()).strip("-")
    doc_id = f"{doc_id_prefix}-{clean_stem}"

    tags = list(extra_tags or [])
    title_slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    if title_slug:
        tags.append(title_slug)

    return KnowledgeDocument(
        doc_id=doc_id,
        doc_type=doc_type,
        title=title,
        aliases=[title, path.stem.replace("-", " ").replace("_", " ")],
        summary=summary,
        content=content,
        identifiers=KnowledgeIdentifiers(
            cwe=list(dict.fromkeys(cwes)),
            owasp=list(dict.fromkeys(owasps)),
        ),
        tags=list(dict.fromkeys(tags)),
        source=KnowledgeSource(
            name=source_name,
            version="1.0",
            raw_path=repository_path(path),
            source_locator=path.name,
        ),
    )


def parse_generic_markdown_directory(
    path: Path,
    source_name: str,
    doc_type: str = "scanner_document",
    doc_id_prefix: str = "doc",
    extra_tags: list[str] | None = None,
    recursive: bool = False,
) -> list[KnowledgeDocument]:
    """Parse all Markdown files in a directory."""
    documents: list[KnowledgeDocument] = []
    if not path.is_dir():
        return documents

    files = sorted(path.rglob("*.md") if recursive else path.glob("*.md"))
    for file_path in files:
        documents.append(
            parse_generic_markdown_file(
                file_path,
                source_name=source_name,
                doc_type=doc_type,
                doc_id_prefix=doc_id_prefix,
                extra_tags=extra_tags,
            )
        )
    return documents
