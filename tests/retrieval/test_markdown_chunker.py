"""Unit tests for Section-Aware Markdown Chunker."""

from src.retrieval.chunking.markdown_chunker import MarkdownSectionChunker
from src.retrieval.models import KnowledgeDocument, KnowledgeIdentifiers, KnowledgeSource


def create_sample_doc(
    doc_id: str,
    doc_type: str,
    title: str,
    content: str,
    summary: str = "A summary of the security document.",
) -> KnowledgeDocument:
    return KnowledgeDocument(
        schema_version="1.0.0",
        doc_id=doc_id,
        doc_type=doc_type,  # type: ignore[arg-type]
        title=title,
        aliases=[title],
        summary=summary,
        content=content,
        identifiers=KnowledgeIdentifiers(cwe=[], owasp=[], semgrep=[], zap=[]),
        tags=["test", "security"],
        source=KnowledgeSource(name="Test Source", raw_path="test/path.md"),
    )


def test_chunk_atomic_cwe_and_asvs_returns_single_chunk() -> None:
    chunker = MarkdownSectionChunker()
    cwe_doc = create_sample_doc(
        doc_id="cwe-89",
        doc_type="cwe",
        title="CWE-89: SQL Injection",
        content="Improper neutralization of special elements in SQL query.",
    )
    chunks = chunker.chunk_document(cwe_doc)
    assert len(chunks) == 1
    assert chunks[0].parent_doc_id == "cwe-89"
    assert chunks[0].section_title == "Overview"
    assert "CWE-89: SQL Injection" in chunks[0].content


def test_chunk_owasp_category_splits_by_h2_sections() -> None:
    content = (
        "## Description\n"
        "Access control enforces policy such that users cannot act outside of their permissions.\n\n"
        "## Prevention\n"
        "Enforce record-level ownership and role-based access control (RBAC).\n\n"
        "## Attack Scenarios\n"
        "Scenario 1: An attacker modifies parameter acct=admin in the URL."
    )
    doc = create_sample_doc(
        doc_id="owasp-2025-a01",
        doc_type="owasp_category",
        title="A01:2025 Broken Access Control",
        content=content,
    )
    chunker = MarkdownSectionChunker()
    chunks = chunker.chunk_document(doc)

    assert len(chunks) == 3
    section_titles = [c.section_title for c in chunks]
    assert "Description" in section_titles
    assert "Prevention" in section_titles
    assert "Attack Scenarios" in section_titles

    prev_chunk = next(c for c in chunks if c.section_title == "Prevention")
    assert "# A01:2025 Broken Access Control" in prev_chunk.content
    assert "## Prevention" in prev_chunk.content
    assert "Enforce record-level ownership" in prev_chunk.content


def test_chunk_splits_oversized_section_by_h3_and_paragraphs() -> None:
    # Build a long section with H3 sub-headings (>1500 chars)
    long_para_1 = "Paragraph 1 describing authentication controls in great detail. " * 20
    long_para_2 = "Paragraph 2 describing multi-factor authentication requirements. " * 20
    content = (
        "## General Guidance\n"
        "Short guidance text.\n\n"
        "## Deep Dive\n"
        f"### Subtopic A\n{long_para_1}\n\n"
        f"### Subtopic B\n{long_para_2}"
    )
    doc = create_sample_doc(
        doc_id="cheatsheet-auth",
        doc_type="cheatsheet",
        title="Authentication Cheat Sheet",
        content=content,
    )
    chunker = MarkdownSectionChunker(max_chunk_chars=1200, overlap_chars=150)
    chunks = chunker.chunk_document(doc)

    assert len(chunks) >= 3
    assert all(len(c.content) <= 2000 for c in chunks)
    assert any("Subtopic A" in c.content for c in chunks)
    assert any("Subtopic B" in c.content for c in chunks)


def test_chunk_document_handles_preamble_intro() -> None:
    content = (
        "This is an introductory preamble before any H2 section appears.\n\n## Specific Section\nSection details here."
    )
    doc = create_sample_doc(
        doc_id="zap-doc-intro",
        doc_type="scanner_document",
        title="ZAP Introduction Guide",
        content=content,
    )
    chunker = MarkdownSectionChunker()
    chunks = chunker.chunk_document(doc)

    assert len(chunks) == 2
    assert chunks[0].section_title in ("Overview", "Introduction")
    assert "introductory preamble" in chunks[0].content
    assert chunks[1].section_title == "Specific Section"
