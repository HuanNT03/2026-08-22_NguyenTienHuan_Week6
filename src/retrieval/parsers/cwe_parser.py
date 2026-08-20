"""CSV parser and deterministic union builder for MITRE CWE views."""

import csv
import re
from dataclasses import dataclass
from pathlib import Path

from src.retrieval.exceptions import DuplicateDocumentIdError, InvalidCweCsvRowError, SourceValidationError
from src.retrieval.models import KnowledgeDocument, KnowledgeIdentifiers, KnowledgeSource
from src.retrieval.parsers.base import normalize_plain_text, normalize_structured_text, repository_path, unique_casefold

REQUIRED_COLUMNS = (
    "CWE-ID",
    "Name",
    "Weakness Abstraction",
    "Status",
    "Description",
    "Extended Description",
    "Alternate Terms",
    "Likelihood of Exploit",
    "Common Consequences",
    "Detection Methods",
    "Potential Mitigations",
    "Observed Examples",
    "Taxonomy Mappings",
    "Related Attack Patterns",
)
CONTENT_FIELDS = (
    ("Description", "Description"),
    ("Extended Description", "Extended description"),
    ("Weakness Abstraction", "Weakness abstraction"),
    ("Status", "Status"),
    ("Likelihood of Exploit", "Likelihood of exploit"),
    ("Common Consequences", "Common consequences"),
    ("Detection Methods", "Detection methods"),
    ("Potential Mitigations", "Potential mitigations"),
    ("Observed Examples", "Observed examples"),
    ("Taxonomy Mappings", "Taxonomy mappings"),
    ("Related Attack Patterns", "Related attack patterns"),
)
_TERM = re.compile(r"::TERM:(.*?):DESCRIPTION:", flags=re.IGNORECASE | re.DOTALL)
_DISPLAY_NAME = re.compile(r"\('([^']+)'\)")


@dataclass(frozen=True)
class CweCsvRecord:
    """One validated raw CWE row with provenance."""

    fields: dict[str, str]
    path: Path
    line_number: int

    @property
    def cwe_id(self) -> str:
        return self.fields["CWE-ID"]


@dataclass(frozen=True)
class CweParseResult:
    """Canonical CWE documents and deterministic ingestion statistics."""

    documents: list[KnowledgeDocument]
    input_counts: dict[str, int]
    coalesced_records: int


def read_cwe_csv(path: Path) -> list[CweCsvRecord]:
    """Read one CWE CSV without pandas and validate every row width."""
    try:
        handle = path.open(encoding="utf-8-sig", newline="")
    except OSError as error:
        raise SourceValidationError(f"Unable to read CWE source {path}: {error}") from error
    with handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration as error:
            raise SourceValidationError(f"{path}: empty CWE CSV") from error
        missing = [column for column in REQUIRED_COLUMNS if column not in header]
        if missing:
            raise SourceValidationError(f"{path}: missing required CWE columns: {', '.join(missing)}")
        records: list[CweCsvRecord] = []
        seen: dict[str, int] = {}
        for line_number, row in enumerate(reader, start=2):
            if len(row) == len(header) + 1 and row[-1] == "":
                row = row[:-1]
            if len(row) != len(header):
                raise InvalidCweCsvRowError(f"{path}:{line_number}: expected {len(header)} columns, found {len(row)}")
            fields = dict(zip(header, row, strict=True))
            cwe_id = fields["CWE-ID"].strip()
            if not cwe_id.isdigit() or int(cwe_id) < 1:
                raise InvalidCweCsvRowError(f"{path}:{line_number}: invalid CWE-ID {cwe_id!r}")
            if cwe_id in seen:
                raise DuplicateDocumentIdError(
                    f"Duplicate ID cwe-{cwe_id}: first source {path}:{seen[cwe_id]}; "
                    f"conflicting source {path}:{line_number}"
                )
            seen[cwe_id] = line_number
            records.append(CweCsvRecord(fields=fields, path=path, line_number=line_number))
        return records


def _aliases(record: CweCsvRecord, display_name: str) -> list[str]:
    terms = [normalize_plain_text(term) for term in _TERM.findall(record.fields["Alternate Terms"])]
    raw_name = normalize_plain_text(record.fields["Name"])
    values = [display_name, *terms]
    if display_name.casefold() != raw_name.casefold():
        values.append(raw_name)
    return unique_casefold(values)


def _display_name(raw_name: str) -> str:
    match = _DISPLAY_NAME.search(raw_name)
    return match.group(1) if match else raw_name


def _tags(display_name: str, in_view_1435: bool) -> list[str]:
    tags = ["cwe", *re.findall(r"[a-z0-9]+", display_name.casefold())]
    if in_view_1435:
        tags.extend(("cwe-view-1435", "cwe-top-25"))
    return unique_casefold(tags)


def _document(record: CweCsvRecord, *, in_view_1435: bool) -> KnowledgeDocument:
    cwe_identifier = f"CWE-{int(record.cwe_id)}"
    raw_name = normalize_plain_text(record.fields["Name"])
    display_name = _display_name(raw_name)
    content_parts: list[str] = []
    for field, label in CONTENT_FIELDS:
        value = (
            normalize_plain_text(record.fields[field])
            if field
            in {"Description", "Extended Description", "Weakness Abstraction", "Status", "Likelihood of Exploit"}
            else normalize_structured_text(record.fields[field])
        )
        if value:
            content_parts.append(f"{label}\n{value}")
    summary = normalize_plain_text(record.fields["Description"])
    if not summary:
        raise SourceValidationError(f"{record.path}:{record.line_number}: CWE-{record.cwe_id} has no Description")
    return KnowledgeDocument(
        doc_id=f"cwe-{int(record.cwe_id)}",
        doc_type="cwe",
        title=f"{cwe_identifier}: {display_name}",
        aliases=_aliases(record, display_name),
        summary=summary,
        content="\n\n".join(content_parts),
        identifiers=KnowledgeIdentifiers(cwe=[cwe_identifier]),
        tags=_tags(display_name, in_view_1435),
        source=KnowledgeSource(
            name="MITRE CWE",
            version=f"View {record.path.stem}",
            raw_path=repository_path(record.path),
            source_locator=cwe_identifier,
        ),
    )


def parse_cwe_views(paths: tuple[Path, ...] | list[Path]) -> CweParseResult:
    """Parse CWE views, coalescing only identical cross-view records by CWE ID."""
    if not paths:
        raise SourceValidationError("At least one CWE CSV path is required")
    records_by_path = {path: read_cwe_csv(path) for path in paths}
    primary: dict[str, CweCsvRecord] = {}
    memberships_1435: set[str] = set()
    coalesced = 0
    for path in paths:
        for record in records_by_path[path]:
            if path.stem == "1435":
                memberships_1435.add(record.cwe_id)
            existing = primary.get(record.cwe_id)
            if existing is None:
                primary[record.cwe_id] = record
                continue
            different = [key for key in existing.fields if existing.fields[key] != record.fields[key]]
            if different:
                raise SourceValidationError(
                    f"CWE-{record.cwe_id} differs between {existing.path} and {record.path}; "
                    f"conflicting fields: {', '.join(different)}"
                )
            coalesced += 1
    documents = [
        _document(record, in_view_1435=cwe_id in memberships_1435)
        for cwe_id, record in sorted(primary.items(), key=lambda item: int(item[0]))
    ]
    return CweParseResult(
        documents=documents,
        input_counts={path.stem: len(records) for path, records in records_by_path.items()},
        coalesced_records=coalesced,
    )
