"""Section-aware Markdown chunker for hierarchical parent-child knowledge retrieval."""

import re
from dataclasses import dataclass

from src.retrieval.models import KnowledgeDocument

_H2_HEADING = re.compile(r"^##\s+(.+?)\s*$", flags=re.MULTILINE)
_H3_HEADING = re.compile(r"^###\s+(.+?)\s*$", flags=re.MULTILINE)


@dataclass(frozen=True)
class DocumentChunk:
    """A granular semantic chunk derived from a parent KnowledgeDocument."""

    chunk_id: str
    parent_doc_id: str
    parent_title: str
    section_title: str
    content: str
    doc_type: str


class MarkdownSectionChunker:
    """Splits knowledge documents into structured section-aware child chunks."""

    def __init__(self, max_chunk_chars: int = 1200, overlap_chars: int = 150) -> None:
        """Initialize the section chunker with maximum character thresholds.

        Args:
            max_chunk_chars: Maximum character length for a single chunk before splitting.
            overlap_chars: Number of overlapping characters between consecutive sub-chunks.
        """
        self.max_chunk_chars = max_chunk_chars
        self.overlap_chars = overlap_chars

    def _slugify(self, text: str) -> str:
        """Create a clean slug for stable chunk IDs."""
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower()).strip("-")
        return slug or "sec"

    def _split_into_paragraphs(self, text: str, max_chars: int, overlap: int) -> list[str]:
        """Split a long text block into overlapping paragraph-aligned chunks."""
        paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
        if not paragraphs:
            return [text.strip()] if text.strip() else []

        chunks: list[str] = []
        current_paras: list[str] = []
        current_len = 0

        for para in paragraphs:
            para_len = len(para)
            if current_len + para_len + 2 > max_chars and current_paras:
                chunks.append("\n\n".join(current_paras))
                # Keep last paragraph for overlap if within overlap budget
                if len(current_paras[-1]) <= overlap:
                    current_paras = [current_paras[-1], para]
                    current_len = len(current_paras[0]) + para_len + 2
                else:
                    current_paras = [para]
                    current_len = para_len
            else:
                current_paras.append(para)
                current_len += para_len + 2

        if current_paras:
            chunks.append("\n\n".join(current_paras))

        return chunks

    def _chunk_h3_subsections(
        self,
        doc: KnowledgeDocument,
        h2_title: str,
        h2_text: str,
        h2_index: int,
    ) -> list[DocumentChunk]:
        """Split an oversized H2 section by H3 subheadings or recursive paragraph chunks."""
        h3_matches = list(_H3_HEADING.finditer(h2_text))
        chunks: list[DocumentChunk] = []

        if not h3_matches:
            # Split directly by paragraphs
            sub_texts = self._split_into_paragraphs(h2_text, self.max_chunk_chars, self.overlap_chars)
            for sub_idx, sub_text in enumerate(sub_texts):
                chunk_id = f"{doc.doc_id}#{self._slugify(h2_title)}-{sub_idx}"
                content = f"# {doc.title}\n\n## {h2_title}\n\n{sub_text}"
                chunks.append(
                    DocumentChunk(
                        chunk_id=chunk_id,
                        parent_doc_id=doc.doc_id,
                        parent_title=doc.title,
                        section_title=h2_title,
                        content=content,
                        doc_type=doc.doc_type,
                    )
                )
            return chunks

        # Handle text before first H3
        if h3_matches[0].start() > 0:
            pre_h3_text = h2_text[: h3_matches[0].start()].strip()
            if pre_h3_text:
                chunks.append(
                    DocumentChunk(
                        chunk_id=f"{doc.doc_id}#{self._slugify(h2_title)}-intro",
                        parent_doc_id=doc.doc_id,
                        parent_title=doc.title,
                        section_title=h2_title,
                        content=f"# {doc.title}\n\n## {h2_title}\n\n{pre_h3_text}",
                        doc_type=doc.doc_type,
                    )
                )

        for i, match in enumerate(h3_matches):
            h3_title = match.group(1).strip()
            start = match.end()
            end = h3_matches[i + 1].start() if i + 1 < len(h3_matches) else len(h2_text)
            sub_text = h2_text[start:end].strip()

            if len(sub_text) > self.max_chunk_chars:
                para_chunks = self._split_into_paragraphs(sub_text, self.max_chunk_chars, self.overlap_chars)
                for p_idx, p_text in enumerate(para_chunks):
                    chunk_id = f"{doc.doc_id}#{self._slugify(h2_title)}-{self._slugify(h3_title)}-{p_idx}"
                    content = f"# {doc.title}\n\n## {h2_title}\n\n### {h3_title}\n\n{p_text}"
                    chunks.append(
                        DocumentChunk(
                            chunk_id=chunk_id,
                            parent_doc_id=doc.doc_id,
                            parent_title=doc.title,
                            section_title=f"{h2_title} > {h3_title}",
                            content=content,
                            doc_type=doc.doc_type,
                        )
                    )
            else:
                chunk_id = f"{doc.doc_id}#{self._slugify(h2_title)}-{self._slugify(h3_title)}"
                content = f"# {doc.title}\n\n## {h2_title}\n\n### {h3_title}\n\n{sub_text}"
                chunks.append(
                    DocumentChunk(
                        chunk_id=chunk_id,
                        parent_doc_id=doc.doc_id,
                        parent_title=doc.title,
                        section_title=f"{h2_title} > {h3_title}",
                        content=content,
                        doc_type=doc.doc_type,
                    )
                )

        return chunks

    def chunk_document(self, doc: KnowledgeDocument) -> list[DocumentChunk]:
        """Convert a parent KnowledgeDocument into a list of section-aware child chunks.

        Args:
            doc: A validated KnowledgeDocument object.

        Returns:
            A list of DocumentChunk instances with hierarchical Markdown titles.
        """
        # 1. Atomic sources (CWE, ASVS, Rules, Examples) are kept as single atomic chunks
        if doc.doc_type in ("cwe", "asvs_requirement", "vulnerability_example", "scanner_rule"):
            return [
                DocumentChunk(
                    chunk_id=f"{doc.doc_id}#main",
                    parent_doc_id=doc.doc_id,
                    parent_title=doc.title,
                    section_title="Overview",
                    content=f"# {doc.title}\n\n{doc.summary}\n\n{doc.content}",
                    doc_type=doc.doc_type,
                )
            ]

        # 2. Markdown sources: Split by H2 sections
        text = doc.content
        h2_matches = list(_H2_HEADING.finditer(text))

        if not h2_matches:
            # No H2 headings found; check if splitting by paragraphs is needed
            if len(text) <= self.max_chunk_chars:
                return [
                    DocumentChunk(
                        chunk_id=f"{doc.doc_id}#main",
                        parent_doc_id=doc.doc_id,
                        parent_title=doc.title,
                        section_title="Overview",
                        content=f"# {doc.title}\n\n## Overview\n\n{doc.summary}\n\n{text}",
                        doc_type=doc.doc_type,
                    )
                ]
            para_texts = self._split_into_paragraphs(text, self.max_chunk_chars, self.overlap_chars)
            return [
                DocumentChunk(
                    chunk_id=f"{doc.doc_id}#chunk-{idx}",
                    parent_doc_id=doc.doc_id,
                    parent_title=doc.title,
                    section_title="Overview",
                    content=f"# {doc.title}\n\n## Overview\n\n{p_text}",
                    doc_type=doc.doc_type,
                )
                for idx, p_text in enumerate(para_texts)
            ]

        chunks: list[DocumentChunk] = []

        # Handle preamble text before first H2
        if h2_matches[0].start() > 0:
            preamble = text[: h2_matches[0].start()].strip()
            if preamble:
                chunks.append(
                    DocumentChunk(
                        chunk_id=f"{doc.doc_id}#intro",
                        parent_doc_id=doc.doc_id,
                        parent_title=doc.title,
                        section_title="Overview",
                        content=f"# {doc.title}\n\n## Overview\n\n{doc.summary}\n\n{preamble}",
                        doc_type=doc.doc_type,
                    )
                )

        for index, match in enumerate(h2_matches):
            h2_title = match.group(1).strip()
            start = match.end()
            end = h2_matches[index + 1].start() if index + 1 < len(h2_matches) else len(text)
            section_body = text[start:end].strip()

            if not section_body:
                continue

            if len(section_body) > self.max_chunk_chars:
                sub_chunks = self._chunk_h3_subsections(doc, h2_title, section_body, index)
                chunks.extend(sub_chunks)
            else:
                chunk_id = f"{doc.doc_id}#{self._slugify(h2_title)}"
                content = f"# {doc.title}\n\n## {h2_title}\n\n{section_body}"
                chunks.append(
                    DocumentChunk(
                        chunk_id=chunk_id,
                        parent_doc_id=doc.doc_id,
                        parent_title=doc.title,
                        section_title=h2_title,
                        content=content,
                        doc_type=doc.doc_type,
                    )
                )

        return chunks
