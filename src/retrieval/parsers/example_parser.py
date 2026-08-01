"""Parser for curated vulnerability example YAML files."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from src.retrieval.exceptions import DuplicateDocumentIdError, SourceValidationError
from src.retrieval.models import Detectability, KnowledgeDocument, KnowledgeIdentifiers, KnowledgeSource
from src.retrieval.parsers.base import normalize_plain_text, repository_path, unique_casefold


def _mapping(value: Any, path: Path, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise SourceValidationError(f"{path}: {field} must be a mapping")
    return value


def _required_string(data: dict[str, Any], field: str, path: Path) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SourceValidationError(f"{path}: missing required field {field}")
    return value.strip()


def _strings(value: Any, path: Path, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise SourceValidationError(f"{path}: {field} must be an array of non-empty strings")
    return unique_casefold([item.strip() for item in value])


def _section(label: str, value: Any, path: Path) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        body = value.strip()
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        body = "\n".join(f"- {item.strip()}" for item in value if item.strip())
    else:
        raise SourceValidationError(f"{path}: {label.casefold().replace(' ', '_')} must be text or a string array")
    return f"{label}\n{body}" if body else ""


def parse_example_file(path: Path) -> KnowledgeDocument:
    """Parse and validate one curated vulnerability example."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise SourceValidationError(f"{path}: invalid YAML: {error}") from error
    if not isinstance(data, dict):
        raise SourceValidationError(f"{path}: YAML root must be a mapping")
    doc_id = _required_string(data, "id", path)
    title = _required_string(data, "title", path)
    description = _required_string(data, "description", path)
    identifiers = _mapping(data.get("identifiers"), path, "identifiers")
    detectability_data = data.get("detectability")
    try:
        detectability = (
            Detectability.model_validate(_mapping(detectability_data, path, "detectability"))
            if detectability_data is not None
            else None
        )
    except ValidationError as error:
        raise SourceValidationError(f"{path}: invalid detectability: {error}") from error
    content = "\n\n".join(
        section
        for section in (
            _section("Description", description, path),
            _section("Root cause", data.get("root_cause"), path),
            _section("Vulnerable example", data.get("vulnerable_example"), path),
            _section("Safe example", data.get("safe_example"), path),
            _section("Impact", data.get("impact"), path),
            _section("Remediation", data.get("remediation"), path),
        )
        if section
    )
    try:
        return KnowledgeDocument(
            doc_id=doc_id,
            doc_type="vulnerability_example",
            title=title,
            aliases=_strings(data.get("aliases"), path, "aliases"),
            summary=normalize_plain_text(description),
            content=content,
            identifiers=KnowledgeIdentifiers(
                cwe=_strings(identifiers.get("cwe"), path, "identifiers.cwe"),
                owasp=_strings(identifiers.get("owasp"), path, "identifiers.owasp"),
                semgrep=_strings(identifiers.get("semgrep"), path, "identifiers.semgrep"),
                zap=_strings(identifiers.get("zap"), path, "identifiers.zap"),
            ),
            tags=_strings(data.get("tags"), path, "tags"),
            detectability=detectability,
            source=KnowledgeSource(
                name="Project Sentinel curated example",
                version="1.0",
                raw_path=repository_path(path),
                source_locator=doc_id,
            ),
        )
    except ValidationError as error:
        raise SourceValidationError(f"{path}: invalid knowledge document: {error}") from error


def parse_example_directory(path: Path) -> list[KnowledgeDocument]:
    """Parse all examples and reject duplicate IDs with both source paths."""
    documents: list[KnowledgeDocument] = []
    sources: dict[str, Path] = {}
    for source_path in sorted(path.glob("*.yml")):
        document = parse_example_file(source_path)
        if document.doc_id in sources:
            raise DuplicateDocumentIdError(
                f"Duplicate ID {document.doc_id}: first source {sources[document.doc_id]}; "
                f"conflicting source {source_path}"
            )
        sources[document.doc_id] = source_path
        documents.append(document)
    if not documents:
        raise SourceValidationError(f"No curated YAML examples found in {path}")
    return documents
