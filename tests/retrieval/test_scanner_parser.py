from pathlib import Path

import pytest

from src.retrieval.config import SEMGREP_RAW_DIR, ZAP_RAW_DIR
from src.retrieval.exceptions import SourceValidationError
from src.retrieval.parsers.scanner_parser import parse_scanner_directories, parse_scanner_file


def test_scanner_inventory_parses_four_overviews_and_four_rules() -> None:
    documents = parse_scanner_directories((SEMGREP_RAW_DIR, ZAP_RAW_DIR))
    counts = {doc_type: sum(document.doc_type == doc_type for document in documents) for doc_type in {d.doc_type for d in documents}}
    assert len(documents) == 8
    assert counts == {"scanner_document": 4, "scanner_rule": 4}
    assert len({document.doc_id for document in documents}) == 8


def test_semgrep_selected_rule_uses_observed_identifier() -> None:
    path = SEMGREP_RAW_DIR / "selected-rules" / "tainted-sql-string.md"
    document = parse_scanner_file(path)
    assert document.identifiers.cwe == ["CWE-89"]
    assert document.identifiers.semgrep == [
        "javascript.express.security.injection.tainted-sql-string.tainted-sql-string"
    ]
    assert "six findings" in document.content


def test_zap_selected_alert_contains_risk_and_evidence_guidance() -> None:
    path = ZAP_RAW_DIR / "selected-alerts" / "10038-1-csp-header-not-set.md"
    document = parse_scanner_file(path)
    assert document.identifiers.zap == ["10038", "10038-1"]
    assert "Medium risk" in document.content
    assert "Evidence" in document.content


def test_missing_front_matter_fails(tmp_path: Path) -> None:
    path = tmp_path / "scanner.md"
    path.write_text("# Missing metadata\n", encoding="utf-8")
    with pytest.raises(SourceValidationError, match="must start with YAML front matter"):
        parse_scanner_file(path)


def test_empty_scanner_body_fails(tmp_path: Path) -> None:
    path = tmp_path / "scanner.md"
    path.write_text(
        "---\nid: scanner-test\ndoc_type: scanner_document\ntitle: Test\n"
        "summary: Test summary\nsource_name: Test source\n---\n",
        encoding="utf-8",
    )
    with pytest.raises(SourceValidationError, match="body is empty"):
        parse_scanner_file(path)
