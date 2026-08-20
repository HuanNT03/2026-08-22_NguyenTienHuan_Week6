"""Validated data models shared by all knowledge-base sources."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.retrieval.config import SCHEMA_VERSION

NonEmptyString = Annotated[str, Field(min_length=1)]
DocumentType = Literal[
    "owasp_category",
    "cwe",
    "scanner_document",
    "scanner_rule",
    "vulnerability_example",
    "cheatsheet",
    "asvs_requirement",
    "document",
]
DetectabilityValue = Literal["high", "medium", "low", "unknown"]


def _unique(values: list[str], field_name: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must contain unique values")
    return values


class StrictModel(BaseModel):
    """Base model that rejects unknown fields and trims simple strings."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class KnowledgeIdentifiers(StrictModel):
    """Identifiers assigned by supported security knowledge sources."""

    cwe: list[NonEmptyString] = Field(default_factory=list)
    owasp: list[NonEmptyString] = Field(default_factory=list)
    semgrep: list[NonEmptyString] = Field(default_factory=list)
    zap: list[NonEmptyString] = Field(default_factory=list)

    @field_validator("cwe", "owasp", "semgrep", "zap")
    @classmethod
    def validate_unique_identifiers(cls, values: list[str], info: object) -> list[str]:
        """Reject duplicate identifiers within one namespace."""
        field_name = getattr(info, "field_name", "identifiers")
        return _unique(values, str(field_name))


class Detectability(StrictModel):
    """Optional assessment of how reliably common review modes detect an issue."""

    sast: DetectabilityValue | None = None
    dast: DetectabilityValue | None = None
    manual: DetectabilityValue | None = None

    @model_validator(mode="after")
    def require_one_value(self) -> "Detectability":
        """Reject an empty detectability object."""
        if self.sast is None and self.dast is None and self.manual is None:
            raise ValueError("detectability must define at least one method")
        return self


class KnowledgeSource(StrictModel):
    """Provenance for normalized content without embedding the raw source."""

    name: NonEmptyString
    raw_path: NonEmptyString
    version: NonEmptyString | None = None
    source_locator: NonEmptyString | None = None

    @field_validator("raw_path")
    @classmethod
    def validate_relative_raw_path(cls, value: str) -> str:
        """Require portable repository-relative provenance paths."""
        if value.startswith(("/", "\\")) or ".." in value.split("/"):
            raise ValueError("raw_path must be repository-relative")
        return value


class KnowledgeDocument(StrictModel):
    """Canonical normalized document stored in JSONL and indexed by SQLite."""

    schema_version: Literal["1.0.0"] = SCHEMA_VERSION
    doc_id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    doc_type: DocumentType
    title: NonEmptyString
    aliases: list[NonEmptyString]
    summary: NonEmptyString
    content: NonEmptyString
    identifiers: KnowledgeIdentifiers
    tags: list[NonEmptyString]
    detectability: Detectability | None = None
    source: KnowledgeSource

    @field_validator("aliases", "tags")
    @classmethod
    def validate_unique_values(cls, values: list[str], info: object) -> list[str]:
        """Keep user-facing aliases and tags deterministic and unambiguous."""
        field_name = getattr(info, "field_name", "values")
        return _unique(values, str(field_name))

    def to_canonical_dict(self) -> dict[str, object]:
        """Return a JSON-ready mapping with unused optional fields omitted."""
        return self.model_dump(mode="json", exclude_none=True)
