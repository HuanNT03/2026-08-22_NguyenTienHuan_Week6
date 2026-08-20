"""Unified single-pass Markdown ingestion engine for Project Sentinel knowledge base."""

import re
from pathlib import Path

from src.retrieval.exceptions import SourceValidationError
from src.retrieval.models import KnowledgeDocument
from src.retrieval.parsers.base import repository_path
from src.retrieval.parsers.cheatsheet_parser import parse_cheatsheet_file
from src.retrieval.parsers.markdown_doc_parser import parse_generic_markdown_file
from src.retrieval.parsers.owasp_parser import parse_owasp_file
from src.retrieval.parsers.zap_alert_parser import parse_zap_alert_file


class UnifiedMarkdownParser:
    """Dispatches markdown files to domain-specific extractors or the general document fallback."""

    def __init__(self, raw_root: Path) -> None:
        self.raw_root = raw_root

    def _derive_fallback_metadata(self, path: Path) -> tuple[str, str, list[str]]:
        """Derive source name, doc_id_prefix, and extra tags for general documentation."""
        rel_parts = [p.lower() for p in path.relative_to(self.raw_root).parts]
        rel_str = "/".join(rel_parts)

        tags = ["documentation"]
        source_name = "Security Documentation"
        doc_id_prefix = "doc"

        if "owasp/top-ten" in rel_str:
            version = "2021"
            for v in ("2017", "2021", "2025"):
                if v in rel_str:
                    version = v
                    break
            source_name = f"OWASP Top 10 ({version})"
            doc_id_prefix = f"owasp-{version}"
            tags.extend(["owasp", "top-10", f"owasp-{version}"])
        elif "asvs" in rel_str:
            source_name = "OWASP ASVS Standard"
            doc_id_prefix = "asvs-5-0-0"
            tags.extend(["owasp", "asvs"])
        elif "semgrep" in rel_str:
            source_name = "Semgrep Documentation"
            doc_id_prefix = "semgrep-doc"
            tags.extend(["semgrep", "docs"])
        elif "zap" in rel_str:
            source_name = "OWASP ZAP Documentation"
            doc_id_prefix = "zap-doc"
            tags.extend(["zap", "dast"])
        elif "codeql" in rel_str:
            source_name = "CodeQL Documentation"
            doc_id_prefix = "codeql-doc"
            tags.extend(["codeql", "sast"])

        return source_name, doc_id_prefix, tags

    def parse_file(self, path: Path) -> tuple[KnowledgeDocument | None, list[str]]:
        """Parse one markdown file using the most appropriate domain handler."""
        if path.stat().st_size == 0:
            return None, []

        rel_path = repository_path(path).lower()
        warnings: list[str] = []

        # 1. OWASP Top 10 Category Candidates
        if "raw/owasp/top-ten" in rel_path:
            try:
                doc, doc_warnings = parse_owasp_file(path)
                return doc, doc_warnings
            except SourceValidationError:
                # If not an A01..A10 category (e.g. About OWASP or Introduction), fall through to Fallback
                pass

        # 2. OWASP ZAP Alerts
        if "raw/zap/alerts" in rel_path:
            doc = parse_zap_alert_file(path)
            return doc, warnings

        # 3. OWASP Cheat Sheets
        if "raw/cheatsheets" in rel_path:
            doc = parse_cheatsheet_file(path)
            return doc, warnings

        # 4. CodeQL Documentation
        if "raw/codeql" in rel_path:
            doc = parse_generic_markdown_file(
                path,
                source_name="CodeQL Documentation",
                doc_type="scanner_document",
                doc_id_prefix="codeql-doc",
                extra_tags=["codeql", "sast", "data-flow"],
            )
            return doc, warnings

        # 5. Semgrep Vulnerability Guides
        if "raw/semgrep/vulnerabilities" in rel_path:
            doc = parse_generic_markdown_file(
                path,
                source_name="Semgrep Vulnerability Guides",
                doc_type="scanner_document",
                doc_id_prefix="semgrep-vuln",
                extra_tags=["semgrep", "vulnerability-guide"],
            )
            return doc, warnings

        # 6. Semgrep Documentation
        if "raw/semgrep/docs" in rel_path:
            doc = parse_generic_markdown_file(
                path,
                source_name="Semgrep Documentation",
                doc_type="scanner_document",
                doc_id_prefix="semgrep-doc",
                extra_tags=["semgrep", "docs"],
            )
            return doc, warnings

        # 7. ZAP Docker Guides
        if "raw/zap/docker" in rel_path:
            doc = parse_generic_markdown_file(
                path,
                source_name="OWASP ZAP Docker Guides",
                doc_type="scanner_document",
                doc_id_prefix="zap-docker",
                extra_tags=["zap", "docker"],
            )
            return doc, warnings

        # 8. Fallback for all other Markdown files (e.g., OWASP 2021 About/Intro, ASVS Intro...)
        source_name, doc_id_prefix, extra_tags = self._derive_fallback_metadata(path)
        doc = parse_generic_markdown_file(
            path,
            source_name=source_name,
            doc_type="document",
            doc_id_prefix=doc_id_prefix,
            extra_tags=extra_tags,
        )
        return doc, warnings

    def parse_all(self) -> tuple[list[KnowledgeDocument], list[str]]:
        """Discover and parse 100% of all Markdown files in the configured raw root."""
        documents: list[KnowledgeDocument] = []
        all_warnings: list[str] = []

        if not self.raw_root.is_dir():
            return documents, all_warnings

        for file_path in sorted(self.raw_root.rglob("*.md")):
            try:
                doc, warnings = self.parse_file(file_path)
                if doc is not None:
                    documents.append(doc)
                all_warnings.extend(warnings)
            except SourceValidationError as error:
                all_warnings.append(f"{file_path}: {error}")
                continue

        return documents, all_warnings


def parse_all_markdown_sources(raw_root: Path) -> tuple[list[KnowledgeDocument], list[str]]:
    """Convenience functional interface for parsing all markdown sources in a single pass."""
    parser = UnifiedMarkdownParser(raw_root)
    return parser.parse_all()
