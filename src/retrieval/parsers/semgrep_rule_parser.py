"""Parser for Semgrep Rule YAML files."""

import re
from pathlib import Path

import yaml

from src.retrieval.exceptions import SourceValidationError
from src.retrieval.models import KnowledgeDocument, KnowledgeIdentifiers, KnowledgeSource
from src.retrieval.parsers.base import normalize_plain_text, repository_path


def parse_semgrep_rule_file(path: Path) -> list[KnowledgeDocument]:
    """Parse one Semgrep rule YAML file which may contain multiple rules."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise SourceValidationError(f"Invalid YAML in Semgrep rule file {path}: {error}") from error

    if not isinstance(data, dict) or "rules" not in data or not isinstance(data["rules"], list):
        return []

    documents: list[KnowledgeDocument] = []
    for rule in data["rules"]:
        if not isinstance(rule, dict):
            continue
        rule_id = rule.get("id", "").strip()
        if not rule_id:
            continue

        message = rule.get("message", "").strip()
        metadata = rule.get("metadata", {}) or {}
        severity = rule.get("severity", "WARNING").upper()

        # Extract CWEs
        raw_cwes = metadata.get("cwe", [])
        if isinstance(raw_cwes, str):
            raw_cwes = [raw_cwes]
        cwes: list[str] = []
        for item in raw_cwes:
            match = re.search(r"CWE-(\d+)", str(item), flags=re.IGNORECASE)
            if match:
                cwes.append(f"CWE-{match.group(1)}")

        # Extract OWASP
        raw_owasp = metadata.get("owasp", [])
        if isinstance(raw_owasp, str):
            raw_owasp = [raw_owasp]
        owasps: list[str] = []
        for item in raw_owasp:
            match = re.search(r"A(\d{1,2}):(\d{4})", str(item), flags=re.IGNORECASE)
            if match:
                owasps.append(f"A{match.group(1)}:{match.group(2)}")

        # Tags
        tags = ["semgrep", "sast", f"severity-{severity.lower()}"]
        techs = metadata.get("technology", [])
        if isinstance(techs, list):
            tags.extend(str(t).lower() for t in techs)
        category = metadata.get("category")
        if category:
            tags.append(str(category).lower())

        summary = normalize_plain_text(message) if message else f"Semgrep rule {rule_id}"

        # Detailed content
        content_parts = [
            f"Rule ID: {rule_id}",
            f"Severity: {severity}",
            f"Message: {message}",
        ]
        if "languages" in rule:
            content_parts.append(f"Languages: {', '.join(rule['languages'])}")
        if "pattern" in rule:
            content_parts.append(f"Pattern:\n{rule['pattern']}")
        if "pattern-either" in rule:
            content_parts.append(f"Patterns:\n{yaml.dump(rule['pattern-either'])}")

        rel_path = path.as_posix().split("rules/")[-1]
        file_prefix = re.sub(r"[^a-z0-9]+", "-", rel_path.lower()).strip("-")
        slug_id = re.sub(r"[^a-z0-9]+", "-", f"semgrep-rule-{file_prefix}-{rule_id.lower()}").strip("-")

        documents.append(
            KnowledgeDocument(
                doc_id=slug_id,
                doc_type="scanner_rule",
                title=f"Semgrep Rule: {rule_id}",
                aliases=[rule_id, f"semgrep {rule_id}"],
                summary=summary,
                content="\n\n".join(content_parts),
                identifiers=KnowledgeIdentifiers(
                    cwe=list(dict.fromkeys(cwes)),
                    owasp=list(dict.fromkeys(owasps)),
                    semgrep=[rule_id],
                ),
                tags=list(dict.fromkeys(tags)),
                source=KnowledgeSource(
                    name="Semgrep Rules",
                    version="1.0",
                    raw_path=repository_path(path),
                    source_locator=rule_id,
                ),
            )
        )

    return documents


def parse_semgrep_rules_directory(path: Path) -> list[KnowledgeDocument]:
    """Recursively parse all YAML files in Semgrep rules directory."""
    documents: list[KnowledgeDocument] = []
    if not path.is_dir():
        return documents
    for file_path in sorted(path.rglob("*.yaml")) + sorted(path.rglob("*.yml")):
        documents.extend(parse_semgrep_rule_file(file_path))
    return documents
