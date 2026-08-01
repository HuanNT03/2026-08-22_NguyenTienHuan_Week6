from pathlib import Path

import pytest

from src.retrieval.config import OWASP_RAW_DIR
from src.retrieval.exceptions import SourceValidationError
from src.retrieval.parsers.owasp_parser import parse_owasp_directory, parse_owasp_file


def test_parse_a01_2025() -> None:
    path = OWASP_RAW_DIR / "A01_2025-Broken_Access_Control.md"
    document, warnings = parse_owasp_file(path)
    assert document.doc_id == "owasp-2025-a01"
    assert document.title == "A01:2025 Broken Access Control"
    assert document.identifiers.owasp == ["A01:2025"]
    assert "CWE-22" in document.identifiers.cwe
    assert "Access control enforces policy" in document.content
    assert "Prevention" in document.content
    assert "Attack scenarios" in document.content
    assert "References" in document.content
    assert "Score table" not in document.content
    assert "Max Incidence Rate" not in document.content
    assert "![icon]" not in document.title
    assert warnings == []


def test_parse_all_ten_owasp_categories() -> None:
    documents, warnings = parse_owasp_directory(OWASP_RAW_DIR)
    assert len(documents) == 10
    assert len({document.doc_id for document in documents}) == 10
    assert warnings == []


def test_missing_optional_section_warns_without_crashing(tmp_path: Path) -> None:
    path = tmp_path / "A01_2025-Test.md"
    path.write_text(
        "# A01:2025 Test Category ![icon](icon.png){: width=10}\n\n"
        "## Description.\n\nA required description.\n",
        encoding="utf-8",
    )
    document, warnings = parse_owasp_file(path)
    assert document.title == "A01:2025 Test Category"
    assert warnings
    assert all(str(path) in warning for warning in warnings)


def test_missing_required_description_fails_with_filename(tmp_path: Path) -> None:
    path = tmp_path / "A01_2025-Test.md"
    path.write_text("# A01:2025 Test Category\n\n## Background.\n\nContext.\n", encoding="utf-8")
    with pytest.raises(SourceValidationError, match=r"A01_2025-Test\.md.*Description"):
        parse_owasp_file(path)


def test_missing_title_fails_with_filename(tmp_path: Path) -> None:
    path = tmp_path / "missing-title.md"
    path.write_text("## Description.\n\nDescription.\n", encoding="utf-8")
    with pytest.raises(SourceValidationError, match=r"missing-title\.md.*H1"):
        parse_owasp_file(path)
