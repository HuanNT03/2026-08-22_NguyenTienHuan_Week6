"""Comprehensive unit and integration tests for all knowledge source parsers."""

from src.retrieval.config import (
    ASVS_RAW_DIR,
    CHEATSHEETS_RAW_DIR,
    CODEQL_RAW_DIR,
    CWE_RAW_PATHS,
    EXAMPLES_DIR,
    OWASP_TOP_TEN_DIR,
    SEMGREP_RAW_DIR,
    ZAP_RAW_DIR,
)
from src.retrieval.parsers.asvs_parser import parse_asvs_csv
from src.retrieval.parsers.cheatsheet_parser import parse_cheatsheet_directory
from src.retrieval.parsers.cwe_parser import parse_cwe_views
from src.retrieval.parsers.example_parser import parse_example_directory
from src.retrieval.parsers.markdown_doc_parser import parse_generic_markdown_directory
from src.retrieval.parsers.owasp_parser import parse_owasp_directory
from src.retrieval.parsers.semgrep_rule_parser import parse_semgrep_rules_directory
from src.retrieval.parsers.zap_alert_parser import parse_zap_alerts_directory


def test_asvs_parser_ingests_requirements() -> None:
    csv_path = ASVS_RAW_DIR / "OWASP_Application_Security_Verification_Standard_5.0.0_en.csv"
    docs = parse_asvs_csv(csv_path)
    assert len(docs) > 300
    assert all(doc.doc_type == "asvs_requirement" for doc in docs)
    first = next(doc for doc in docs if doc.doc_id == "asvs-5-0-0-v1-1-1")
    assert "OWASP ASVS 5.0.0 V1.1.1" in first.title
    assert "level-2" in first.tags


def test_cheatsheet_parser_ingests_all_cheatsheets() -> None:
    docs = parse_cheatsheet_directory(CHEATSHEETS_RAW_DIR)
    assert len(docs) >= 60
    assert all(doc.doc_type == "cheatsheet" for doc in docs)
    ai_sheet = next((doc for doc in docs if "ai-agent" in doc.doc_id), None)
    assert ai_sheet is not None
    assert "AI Agent" in ai_sheet.title


def test_semgrep_rules_parser_ingests_all_rules() -> None:
    docs = parse_semgrep_rules_directory(SEMGREP_RAW_DIR / "rules")
    assert len(docs) > 50
    assert all(doc.doc_type == "scanner_rule" for doc in docs)
    jwt_rule = next((doc for doc in docs if "jwt-hardcode" in doc.doc_id or "hardcoded-jwt" in doc.doc_id), None)
    assert jwt_rule is not None
    assert "semgrep" in jwt_rule.tags


def test_zap_alerts_parser_ingests_all_alerts() -> None:
    docs = parse_zap_alerts_directory(ZAP_RAW_DIR / "alerts")
    assert len(docs) >= 25
    assert all(doc.doc_type == "scanner_document" for doc in docs)
    csp_alert = next((doc for doc in docs if "10038" in doc.doc_id), None)
    assert csp_alert is not None
    assert "10038-1" in csp_alert.identifiers.zap or "10038" in csp_alert.identifiers.zap


def test_markdown_doc_parser_ingests_codeql_and_semgrep_docs() -> None:
    codeql_docs = parse_generic_markdown_directory(
        CODEQL_RAW_DIR,
        source_name="CodeQL Documentation",
        doc_type="scanner_document",
        doc_id_prefix="codeql-doc",
        extra_tags=["codeql", "sast", "data-flow"],
    )
    assert len(codeql_docs) >= 5

    semgrep_vulns = parse_generic_markdown_directory(
        SEMGREP_RAW_DIR / "vulnerabilities",
        source_name="Semgrep Vulnerability Guides",
        doc_type="scanner_document",
        doc_id_prefix="semgrep-vuln",
        extra_tags=["semgrep", "vulnerability-guide"],
        recursive=True,
    )
    assert len(semgrep_vulns) >= 10


def test_owasp_parser_ingests_multi_versions() -> None:
    docs, _ = parse_owasp_directory(OWASP_TOP_TEN_DIR)
    assert len(docs) >= 30
    assert any("2025" in doc.doc_id for doc in docs)
    assert any("2021" in doc.doc_id for doc in docs)
    assert any("2017" in doc.doc_id for doc in docs)


def test_vulnerable_examples_parser() -> None:
    docs = parse_example_directory(EXAMPLES_DIR)
    assert len(docs) == 20
    assert all(doc.doc_type == "vulnerability_example" for doc in docs)


def test_cwe_parser() -> None:
    result = parse_cwe_views(CWE_RAW_PATHS)
    assert len(result.documents) == 409
