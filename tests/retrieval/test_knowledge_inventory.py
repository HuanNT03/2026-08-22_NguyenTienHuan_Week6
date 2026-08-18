from src.retrieval.config import EXAMPLES_DIR, PROJECT_ROOT, SEMGREP_RAW_DIR, ZAP_RAW_DIR
from src.retrieval.parsers.example_parser import parse_example_directory
from src.retrieval.parsers.scanner_parser import parse_scanner_directories

EXAMPLE_IDS = {
    "example-sql-injection-nodejs",
    "example-reflected-xss-express",
    "example-stored-xss",
    "example-dom-based-xss",
    "example-idor",
    "example-missing-function-level-authorization",
    "example-authentication-bypass",
    "example-csrf",
    "example-path-traversal",
    "example-os-command-injection",
    "example-ssrf",
    "example-open-redirect",
    "example-unrestricted-file-upload",
    "example-xxe",
    "example-cors-misconfiguration",
    "example-prototype-pollution",
    "example-weak-jwt-signing",
    "example-missing-rate-limiting",
    "example-sensitive-data-logging",
    "example-verbose-error-leakage",
}
SCANNER_IDS = {
    "semgrep-finding-anatomy",
    "semgrep-rule-metadata",
    "semgrep-rule-javascript-express-security-injection-tainted-sql-string-tainted-sql-string",
    "semgrep-rule-javascript-express-security-audit-express-open-redirect-express-open-redirect",
    "zap-alert-anatomy",
    "zap-risk-confidence-evidence",
    "zap-alert-10038-1",
    "zap-alert-10098",
}


def test_documented_inventory_matches_parsed_sources() -> None:
    examples = parse_example_directory(EXAMPLES_DIR)
    scanners = parse_scanner_directories((SEMGREP_RAW_DIR, ZAP_RAW_DIR))
    assert {document.doc_id for document in examples} == EXAMPLE_IDS
    assert {document.doc_id for document in scanners} == SCANNER_IDS


def test_every_curated_and_scanner_source_is_listed_in_review_document() -> None:
    review = (
        PROJECT_ROOT / "docs" / "reports" / "week2" / "week-2-knowledgebase.md"
    ).read_text(encoding="utf-8")
    documents = [
        *parse_example_directory(EXAMPLES_DIR),
        *parse_scanner_directories((SEMGREP_RAW_DIR, ZAP_RAW_DIR)),
    ]
    for document in documents:
        assert document.doc_id in review
        assert document.source.raw_path in review
