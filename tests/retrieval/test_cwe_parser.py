import csv
from pathlib import Path

import pytest

from src.retrieval.config import CWE_RAW_PATHS
from src.retrieval.exceptions import DuplicateDocumentIdError, InvalidCweCsvRowError, SourceValidationError
from src.retrieval.parsers.cwe_parser import parse_cwe_views, read_cwe_csv


def _header() -> list[str]:
    with CWE_RAW_PATHS[0].open(encoding="utf-8-sig", newline="") as handle:
        return next(csv.reader(handle))


def _row(cwe_id: str, description: str = "Description") -> list[str]:
    header = _header()
    values = [""] * len(header)
    values[header.index("CWE-ID")] = cwe_id
    values[header.index("Name")] = f"Test weakness {cwe_id}"
    values[header.index("Description")] = description
    return values


def _write_csv(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(_header())
        writer.writerows(rows)


def test_parse_both_cwe_views_and_coalesce_overlap() -> None:
    result = parse_cwe_views(CWE_RAW_PATHS)
    assert result.input_counts == {"699": 399, "1435": 25}
    assert result.coalesced_records == 15
    assert len(result.documents) == 409
    assert len({document.doc_id for document in result.documents}) == 409


def test_cwe_89_aliases_and_structured_fields() -> None:
    documents = {document.doc_id: document for document in parse_cwe_views(CWE_RAW_PATHS).documents}
    document = documents["cwe-89"]
    assert document.title == "CWE-89: SQL Injection"
    assert "SQLi" in document.aliases
    assert document.identifiers.cwe == ["CWE-89"]
    assert "Detection methods" in document.content
    assert "Potential mitigations" in document.content
    assert "cwe-view-1435" in document.tags
    assert document.source.raw_path.endswith("699.csv")


@pytest.mark.parametrize(
    ("doc_id", "alias"),
    [("cwe-79", "XSS"), ("cwe-611", "XXE"), ("cwe-639", "Insecure Direct Object Reference / IDOR")],
)
def test_required_security_aliases_are_parsed(doc_id: str, alias: str) -> None:
    documents = {document.doc_id: document for document in parse_cwe_views(CWE_RAW_PATHS).documents}
    assert alias in documents[doc_id].aliases


def test_1435_only_record_uses_1435_provenance() -> None:
    documents = {document.doc_id: document for document in parse_cwe_views(CWE_RAW_PATHS).documents}
    document = documents["cwe-20"]
    assert document.source.raw_path.endswith("1435.csv")
    assert {"cwe-view-1435", "cwe-top-25"}.issubset(document.tags)


def test_trailing_empty_field_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "fixture.csv"
    _write_csv(path, [_row("89") + [""]])
    records = read_cwe_csv(path)
    assert len(records) == 1
    assert records[0].cwe_id == "89"


def test_invalid_row_reports_filename_and_line(tmp_path: Path) -> None:
    path = tmp_path / "invalid.csv"
    _write_csv(path, [_row("89")[:-2]])
    with pytest.raises(InvalidCweCsvRowError, match=r"invalid\.csv:2: expected 23 columns, found 21"):
        read_cwe_csv(path)


def test_duplicate_id_in_one_file_fails(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.csv"
    _write_csv(path, [_row("89"), _row("89")])
    with pytest.raises(DuplicateDocumentIdError, match=r"Duplicate ID cwe-89.*first source.*conflicting source"):
        read_cwe_csv(path)


def test_cross_view_difference_fails_with_fields(tmp_path: Path) -> None:
    primary = tmp_path / "699.csv"
    secondary = tmp_path / "1435.csv"
    _write_csv(primary, [_row("89", "First")])
    _write_csv(secondary, [_row("89", "Second")])
    with pytest.raises(SourceValidationError, match=r"CWE-89 differs.*Description"):
        parse_cwe_views((primary, secondary))


def test_identical_fixture_overlap_is_coalesced(tmp_path: Path) -> None:
    primary = tmp_path / "699.csv"
    secondary = tmp_path / "1435.csv"
    row = _row("89")
    _write_csv(primary, [row])
    _write_csv(secondary, [row])
    result = parse_cwe_views((primary, secondary))
    assert len(result.documents) == 1
    assert result.coalesced_records == 1
