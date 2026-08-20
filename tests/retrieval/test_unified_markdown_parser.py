"""Unit and integration tests for UnifiedMarkdownParser."""

from pathlib import Path

from src.retrieval.config import KNOWLEDGE_BASE_DIR
from src.retrieval.parsers.unified_markdown_parser import UnifiedMarkdownParser, parse_all_markdown_sources


def test_unified_markdown_parser_discovers_all_md_files() -> None:
    raw_root = KNOWLEDGE_BASE_DIR / "raw"
    parser = UnifiedMarkdownParser(raw_root)
    documents, warnings = parser.parse_all()

    # Count total non-empty md files in raw
    all_md_files = [f for f in raw_root.rglob("*.md") if f.stat().st_size > 0]

    assert len(documents) == len(all_md_files)
    assert len(documents) >= 800

    # Ensure 0 duplicate doc_ids
    doc_ids = [doc.doc_id for doc in documents]
    assert len(doc_ids) == len(set(doc_ids))


def test_unified_markdown_parser_parses_owasp_2017_2021_2025() -> None:
    raw_root = KNOWLEDGE_BASE_DIR / "raw"
    documents, _ = parse_all_markdown_sources(raw_root)

    # OWASP 2017
    a1_2017 = next((d for d in documents if d.doc_id == "owasp-2017-a01"), None)
    assert a1_2017 is not None
    assert a1_2017.doc_type == "owasp_category"
    assert a1_2017.title == "A01:2017 Injection"

    # OWASP 2021
    a1_2021 = next((d for d in documents if d.doc_id == "owasp-2021-a01"), None)
    assert a1_2021 is not None
    assert a1_2021.doc_type == "owasp_category"

    # OWASP 2025
    a1_2025 = next((d for d in documents if d.doc_id == "owasp-2025-a01"), None)
    assert a1_2025 is not None
    assert a1_2025.doc_type == "owasp_category"


def test_unified_markdown_parser_fallback_handles_overview_documents() -> None:
    raw_root = KNOWLEDGE_BASE_DIR / "raw"
    documents, _ = parse_all_markdown_sources(raw_root)

    # OWASP 2021 About OWASP
    about_owasp = next((d for d in documents if "about-owasp" in d.doc_id), None)
    assert about_owasp is not None
    assert about_owasp.doc_type == "document"
    assert "About OWASP" in about_owasp.title

    # ASVS Intro
    asvs_intro = next((d for d in documents if "what-is-the-asvs" in d.doc_id), None)
    assert asvs_intro is not None
    assert asvs_intro.doc_type == "document"


def test_unified_markdown_parser_handles_cheatsheets_and_zap_alerts() -> None:
    raw_root = KNOWLEDGE_BASE_DIR / "raw"
    documents, _ = parse_all_markdown_sources(raw_root)

    # Cheatsheet
    cs = next((d for d in documents if d.doc_type == "cheatsheet"), None)
    assert cs is not None

    # ZAP Alert
    zap = next((d for d in documents if d.doc_id.startswith("zap-alert-")), None)
    assert zap is not None
