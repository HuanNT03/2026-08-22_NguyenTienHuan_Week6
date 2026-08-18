"""Parser for OWASP ASVS v5.0.0 requirements CSV file."""

import csv
import re
from pathlib import Path

from src.retrieval.exceptions import SourceValidationError
from src.retrieval.models import KnowledgeDocument, KnowledgeIdentifiers, KnowledgeSource
from src.retrieval.parsers.base import normalize_plain_text, repository_path


def parse_asvs_csv(path: Path) -> list[KnowledgeDocument]:
    """Parse OWASP ASVS v5.0.0 CSV into canonical KnowledgeDocuments."""
    if not path.is_file():
        raise SourceValidationError(f"ASVS source CSV does not exist: {path}")

    documents: list[KnowledgeDocument] = []
    try:
        with open(path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                req_id = row.get("req_id", "").strip()
                if not req_id:
                    continue
                chapter_id = row.get("chapter_id", "").strip()
                chapter_name = row.get("chapter_name", "").strip()
                section_id = row.get("section_id", "").strip()
                section_name = row.get("section_name", "").strip()
                req_desc = row.get("req_description", "").strip()
                level = row.get("L", "").strip()

                slug_id = re.sub(r"[^a-z0-9]+", "-", f"asvs-5-0-0-{req_id.lower()}").strip("-")
                title = f"OWASP ASVS 5.0.0 {req_id}: {section_name}"
                summary = normalize_plain_text(req_desc)

                content = (
                    f"Chapter: {chapter_id} - {chapter_name}\n"
                    f"Section: {section_id} - {section_name}\n"
                    f"Requirement ID: {req_id}\n"
                    f"Verification Level: L{level}\n\n"
                    f"Requirement:\n{req_desc}"
                )

                # Extract any mentioned CWEs in description
                cwes = [f"CWE-{match}" for match in re.findall(r"\bCWE-(\d+)\b", req_desc, flags=re.IGNORECASE)]

                tags = ["asvs", "asvs-5.0.0", f"level-{level}"]
                if chapter_name:
                    tags.append(re.sub(r"[^a-z0-9]+", "-", chapter_name.lower()).strip("-"))

                documents.append(
                    KnowledgeDocument(
                        doc_id=slug_id,
                        doc_type="asvs_requirement",
                        title=title,
                        aliases=[f"ASVS {req_id}", req_id],
                        summary=summary,
                        content=content,
                        identifiers=KnowledgeIdentifiers(cwe=cwes),
                        tags=tags,
                        source=KnowledgeSource(
                            name="OWASP ASVS",
                            version="5.0.0",
                            raw_path=repository_path(path),
                            source_locator=req_id,
                        ),
                    )
                )
    except Exception as error:
        raise SourceValidationError(f"Error parsing ASVS CSV {path}: {error}") from error

    return documents
