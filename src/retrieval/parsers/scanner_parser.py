"""Parser for Semgrep and OWASP ZAP Markdown knowledge sources."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from src.retrieval.exceptions import DuplicateDocumentIdError, SourceValidationError
from src.retrieval.models import KnowledgeDocument, KnowledgeIdentifiers, KnowledgeSource
from src.retrieval.parsers.base import markdown_to_text, repository_path, unique_casefold


def _front_matter(text: str, path: Path) -> tuple[dict[str, Any], str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise SourceValidationError(f"{path}: scanner Markdown must start with YAML front matter")
    try:
        closing = lines.index("---", 1)
    except ValueError as error:
        raise SourceValidationError(f"{path}: scanner Markdown has unterminated YAML front matter") from error
    try:
        metadata = yaml.safe_load("\n".join(lines[1:closing]))
    except yaml.YAMLError as error:
        raise SourceValidationError(f"{path}: invalid YAML front matter: {error}") from error
    if not isinstance(metadata, dict):
        raise SourceValidationError(f"{path}: scanner front matter must be a mapping")
    return metadata, "\n".join(lines[closing + 1 :]).strip()


def _required(metadata: dict[str, Any], field: str, path: Path) -> str:
    value = metadata.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SourceValidationError(f"{path}: missing scanner metadata field {field}")
    return value.strip()


def _strings(value: Any, field: str, path: Path) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise SourceValidationError(f"{path}: {field} must be an array of non-empty strings")
    return unique_casefold(value)


def parse_scanner_file(path: Path) -> KnowledgeDocument:
    """Parse one scanner Markdown document with validated YAML front matter."""
    try:
        metadata, body = _front_matter(path.read_text(encoding="utf-8"), path)
    except OSError as error:
        raise SourceValidationError(f"Unable to read scanner source {path}: {error}") from error
    content = markdown_to_text(body)
    if not content:
        raise SourceValidationError(f"{path}: scanner Markdown body is empty")
    identifiers = metadata.get("identifiers") or {}
    if not isinstance(identifiers, dict):
        raise SourceValidationError(f"{path}: identifiers must be a mapping")
    try:
        return KnowledgeDocument(
            doc_id=_required(metadata, "id", path),
            doc_type=_required(metadata, "doc_type", path),
            title=_required(metadata, "title", path),
            aliases=_strings(metadata.get("aliases"), "aliases", path),
            summary=_required(metadata, "summary", path),
            content=content,
            identifiers=KnowledgeIdentifiers(
                cwe=_strings(identifiers.get("cwe"), "identifiers.cwe", path),
                owasp=_strings(identifiers.get("owasp"), "identifiers.owasp", path),
                semgrep=_strings(identifiers.get("semgrep"), "identifiers.semgrep", path),
                zap=_strings(identifiers.get("zap"), "identifiers.zap", path),
            ),
            tags=_strings(metadata.get("tags"), "tags", path),
            source=KnowledgeSource(
                name=_required(metadata, "source_name", path),
                version=metadata.get("source_version"),
                raw_path=repository_path(path),
                source_locator=metadata.get("source_locator"),
            ),
        )
    except ValidationError as error:
        raise SourceValidationError(f"{path}: invalid scanner knowledge document: {error}") from error


def parse_scanner_directories(paths: tuple[Path, ...] | list[Path]) -> list[KnowledgeDocument]:
    """Parse scanner Markdown recursively and reject duplicate document IDs."""
    documents: list[KnowledgeDocument] = []
    sources: dict[str, Path] = {}
    for directory in paths:
        for source_path in sorted(directory.rglob("*.md")):
            document = parse_scanner_file(source_path)
            if document.doc_id in sources:
                raise DuplicateDocumentIdError(
                    f"Duplicate ID {document.doc_id}: first source {sources[document.doc_id]}; "
                    f"conflicting source {source_path}"
                )
            sources[document.doc_id] = source_path
            documents.append(document)
    if not documents:
        raise SourceValidationError(f"No scanner Markdown found in: {', '.join(map(str, paths))}")
    return documents
