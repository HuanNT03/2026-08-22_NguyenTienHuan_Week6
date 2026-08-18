"""Parser for OWASP ZAP Alert Markdown definitions."""

import re
from pathlib import Path
from typing import Any

import yaml

from src.retrieval.exceptions import SourceValidationError
from src.retrieval.models import KnowledgeDocument, KnowledgeIdentifiers, KnowledgeSource
from src.retrieval.parsers.base import markdown_to_text, normalize_plain_text, repository_path


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    try:
        closing = lines.index("---", 1)
        meta = yaml.safe_load("\n".join(lines[1:closing]))
        body = "\n".join(lines[closing + 1 :])
        return meta if isinstance(meta, dict) else {}, body
    except (yaml.YAMLError, ValueError, IndexError):
        return {}, text


def parse_zap_alert_file(path: Path) -> KnowledgeDocument:
    """Parse one OWASP ZAP alert definition Markdown file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise SourceValidationError(f"Unable to read ZAP alert {path}: {error}") from error

    meta, body = _parse_frontmatter(text)

    alert_id = str(meta.get("alertid", path.stem))
    title = str(meta.get("title", f"ZAP Alert {alert_id}"))
    risk = str(meta.get("risk", "Medium"))
    solution = str(meta.get("solution", ""))
    cwe_num = meta.get("cwe")

    cwes: list[str] = []
    if cwe_num and str(cwe_num).strip() and str(cwe_num) != "0":
        cwes.append(f"CWE-{cwe_num}")

    owasps: list[str] = []
    tags: list[str] = ["zap", "dast", f"risk-{risk.lower()}"]

    alert_tags = meta.get("alerttags", [])
    if isinstance(alert_tags, list):
        for tag in alert_tags:
            tag_str = str(tag).strip()
            if not tag_str:
                continue
            cwe_match = re.search(r"CWE-(\d+)", tag_str, flags=re.IGNORECASE)
            if cwe_match:
                cwes.append(f"CWE-{cwe_match.group(1)}")
            owasp_match = re.search(r"OWASP_(\d{4})_A(\d{1,2})", tag_str, flags=re.IGNORECASE)
            if owasp_match:
                owasps.append(f"A{int(owasp_match.group(2)):02d}:{owasp_match.group(1)}")
            tags.append(tag_str.lower().replace("_", "-"))

    content_parts = [
        f"ZAP Alert ID: {alert_id}",
        f"Title: {title}",
        f"Risk: {risk}",
    ]
    if solution:
        content_parts.append(f"Solution:\n{solution}")
    if body.strip():
        content_parts.append(f"Details:\n{markdown_to_text(body)}")

    summary = normalize_plain_text(solution) if solution else f"OWASP ZAP Alert {alert_id}: {title}"
    slug_id = re.sub(r"[^a-z0-9]+", "-", f"zap-alert-{alert_id.lower()}").strip("-")

    return KnowledgeDocument(
        doc_id=slug_id,
        doc_type="scanner_document",
        title=f"OWASP ZAP Alert {alert_id}: {title}",
        aliases=[f"ZAP {alert_id}", title],
        summary=summary,
        content="\n\n".join(content_parts),
        identifiers=KnowledgeIdentifiers(
            cwe=list(dict.fromkeys(cwes)),
            owasp=list(dict.fromkeys(owasps)),
            zap=[alert_id],
        ),
        tags=list(dict.fromkeys(tags)),
        source=KnowledgeSource(
            name="OWASP ZAP Alerts",
            version="2.15",
            raw_path=repository_path(path),
            source_locator=alert_id,
        ),
    )


def parse_zap_alerts_directory(path: Path) -> list[KnowledgeDocument]:
    """Parse all ZAP alert markdown files in a directory."""
    documents: list[KnowledgeDocument] = []
    if not path.is_dir():
        return documents
    for file_path in sorted(path.glob("*.md")):
        documents.append(parse_zap_alert_file(file_path))
    return documents
