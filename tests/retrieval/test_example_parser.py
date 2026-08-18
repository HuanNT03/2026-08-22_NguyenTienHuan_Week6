from pathlib import Path

import pytest

from src.retrieval.config import EXAMPLES_DIR
from src.retrieval.exceptions import DuplicateDocumentIdError, SourceValidationError
from src.retrieval.parsers.example_parser import parse_example_directory, parse_example_file


def test_all_twenty_examples_are_valid_and_unique() -> None:
    documents = parse_example_directory(EXAMPLES_DIR)
    assert len(documents) == 20
    assert len({document.doc_id for document in documents}) == 20
    assert all(document.doc_type == "vulnerability_example" for document in documents)


def test_sql_injection_example_preserves_multiline_code() -> None:
    document = parse_example_file(EXAMPLES_DIR / "sql-injection-nodejs.yml")
    assert document.doc_id == "example-sql-injection-nodejs"
    assert "Node.js SQL Injection" in document.aliases
    assert document.identifiers.cwe == ["CWE-89"]
    assert "const query = `SELECT" in document.content
    assert "db.query(query);" in document.content
    assert document.detectability is not None
    assert document.detectability.sast == "high"


@pytest.mark.parametrize("missing", ["id", "title", "description"])
def test_missing_required_field_fails(tmp_path: Path, missing: str) -> None:
    values = {
        "id": "example-test",
        "title": "Test",
        "description": "Test description",
    }
    values.pop(missing)
    path = tmp_path / "invalid.yml"
    path.write_text("\n".join(f"{key}: {value}" for key, value in values.items()), encoding="utf-8")
    with pytest.raises(SourceValidationError, match=f"missing required field {missing}"):
        parse_example_file(path)


def test_invalid_detectability_fails(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yml"
    path.write_text(
        "id: example-test\ntitle: Test\ndescription: Description\n"
        "detectability:\n  sast: certain\n",
        encoding="utf-8",
    )
    with pytest.raises(SourceValidationError, match="invalid detectability"):
        parse_example_file(path)


def test_invalid_yaml_fails_with_filename(tmp_path: Path) -> None:
    path = tmp_path / "broken.yml"
    path.write_text("id: [broken\n", encoding="utf-8")
    with pytest.raises(SourceValidationError, match=r"broken\.yml: invalid YAML"):
        parse_example_file(path)


def test_duplicate_example_id_reports_both_sources(tmp_path: Path) -> None:
    content = "id: example-test\ntitle: Test\ndescription: Description\n"
    (tmp_path / "first.yml").write_text(content, encoding="utf-8")
    (tmp_path / "second.yml").write_text(content, encoding="utf-8")
    with pytest.raises(DuplicateDocumentIdError, match=r"Duplicate ID example-test.*first\.yml.*second\.yml"):
        parse_example_directory(tmp_path)


def test_optional_detectability_can_be_absent(tmp_path: Path) -> None:
    path = tmp_path / "example.yml"
    path.write_text("id: example-test\ntitle: Test\ndescription: Description\n", encoding="utf-8")
    assert parse_example_file(path).detectability is None
