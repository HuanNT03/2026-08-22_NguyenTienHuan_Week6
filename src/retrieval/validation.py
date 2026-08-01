"""JSON Schema validation for canonical knowledge documents."""

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from src.retrieval.exceptions import InvalidKnowledgeDocumentError
from src.retrieval.models import KnowledgeDocument


def load_knowledge_schema(path: Path) -> dict[str, Any]:
    """Load and meta-validate the knowledge document JSON Schema."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InvalidKnowledgeDocumentError(f"Unable to load knowledge schema {path}: {error}") from error
    if not isinstance(value, dict):
        raise InvalidKnowledgeDocumentError(f"Knowledge schema must be an object: {path}")
    try:
        Draft202012Validator.check_schema(value)
    except SchemaError as error:
        raise InvalidKnowledgeDocumentError(f"Invalid knowledge schema {path}: {error.message}") from error
    return value


def build_knowledge_validator(schema: dict[str, Any]) -> Draft202012Validator:
    """Build a Draft 2020-12 validator from a checked schema."""
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as error:
        raise InvalidKnowledgeDocumentError(f"Invalid knowledge schema: {error.message}") from error
    return Draft202012Validator(schema)


def validate_document(document: KnowledgeDocument, validator: Draft202012Validator) -> None:
    """Validate a model serialization and report the first stable schema error."""
    errors = sorted(validator.iter_errors(document.to_canonical_dict()), key=lambda error: list(error.absolute_path))
    if errors:
        first = errors[0]
        location = "/".join(str(item) for item in first.absolute_path) or "<root>"
        raise InvalidKnowledgeDocumentError(f"{document.doc_id} at {location}: {first.message}")
