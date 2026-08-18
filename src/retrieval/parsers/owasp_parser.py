"""Parser for local OWASP Top 10 Markdown sources across versions."""

import re
from pathlib import Path

from src.retrieval.exceptions import SourceValidationError
from src.retrieval.models import KnowledgeDocument, KnowledgeIdentifiers, KnowledgeSource
from src.retrieval.parsers.base import markdown_to_text, repository_path, unique_casefold

_TITLE = re.compile(r"^A(\d{2}):(\d{4})\s*[\u2013\u2014-]?\s*(.+)$", flags=re.IGNORECASE)
_HEADING = re.compile(r"^##\s+(.+?)\s*$", flags=re.MULTILINE)
_IMAGE = re.compile(r"!\[[^]]*]\([^)]*\)(?:\{[^}]*\})?")
_HTML = re.compile(r"<[^>]+>")
_CWE = re.compile(r"\bCWE-(\d+)\b", flags=re.IGNORECASE)

_SECTION_NAMES = {
    "background": "Background",
    "overview": "Overview",
    "description": "Description",
    "how to prevent": "Prevention",
    "how to prevent it": "Prevention",
    "example attack scenarios": "Attack scenarios",
    "references": "References",
    "list of mapped cwes": "Mapped CWEs",
    "factors": "Factors",
}


def _section_key(heading: str) -> str:
    return heading.strip().rstrip(".").strip().casefold()


def _split_sections(text: str) -> dict[str, str]:
    matches = list(_HEADING.finditer(text))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections[_section_key(match.group(1))] = text[start:end].strip()
    return sections


def _clean_title(raw_title: str) -> str:
    title = _IMAGE.sub("", raw_title)
    title = _HTML.sub("", title)
    title = re.sub(r"\{[^}]*\}", "", title)
    return " ".join(title.split())


def parse_owasp_file(path: Path) -> tuple[KnowledgeDocument, list[str]]:
    """Parse one OWASP category and return the document plus optional-section warnings."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise SourceValidationError(f"Unable to read OWASP source {path}: {error}") from error
    first_line = next((line for line in text.splitlines() if line.strip()), "")
    if not first_line.startswith("# "):
        raise SourceValidationError(f"{path}: missing required H1 title")
    raw_title = _clean_title(first_line.removeprefix("# ").strip())
    title_match = _TITLE.fullmatch(raw_title)
    if title_match is None:
        raise SourceValidationError(f"{path}: invalid OWASP title {raw_title!r}")
    category_number, version, category_title = title_match.groups()
    identifier = f"A{category_number}:{version}"
    title = f"{identifier} {category_title.strip()}"
    sections = _split_sections(text)

    desc_text = sections.get("description") or sections.get("overview") or sections.get("background") or ""
    description = markdown_to_text(desc_text)
    if not description:
        # Use first meaningful paragraph after title
        for line in text.splitlines():
            if not line.startswith("#") and len(line.strip()) > 30:
                description = markdown_to_text(line.strip())
                break
    if not description:
        description = f"OWASP Top 10 category: {title}"

    mapped_cwes = sorted(
        {f"CWE-{match}" for match in _CWE.findall(text)},
        key=lambda value: int(value.split("-")[1]),
    )
    content_parts: list[str] = []
    for key, label in _SECTION_NAMES.items():
        if key in sections:
            content_parts.append(f"{label}\n{markdown_to_text(sections[key])}")

    aliases = unique_casefold([category_title.strip(), f"OWASP {identifier}", identifier])
    tags = unique_casefold(["owasp", "top-10", f"owasp-{version}", *re.findall(r"[a-z0-9]+", category_title.casefold())])
    document = KnowledgeDocument(
        doc_id=f"owasp-{version}-a{category_number}",
        doc_type="owasp_category",
        title=title,
        aliases=aliases,
        summary=description.split("\n", 1)[0],
        content="\n\n".join(content_parts) if content_parts else markdown_to_text(text),
        identifiers=KnowledgeIdentifiers(owasp=[identifier], cwe=mapped_cwes),
        tags=tags,
        source=KnowledgeSource(
            name="OWASP Top 10",
            version=version,
            raw_path=repository_path(path),
            source_locator=identifier,
        ),
    )
    return document, []


def parse_owasp_directory(path: Path) -> tuple[list[KnowledgeDocument], list[str]]:
    """Parse all deterministic OWASP Top 10 category paths in a directory or subdirectories."""
    documents: list[KnowledgeDocument] = []
    warnings: list[str] = []
    if not path.is_dir():
        return documents, warnings

    files = sorted(path.rglob("A*_20*.md"))
    for source_path in files:
        try:
            document, source_warnings = parse_owasp_file(source_path)
            documents.append(document)
            warnings.extend(source_warnings)
        except SourceValidationError:
            continue

    if not documents:
        raise SourceValidationError(f"No OWASP Markdown files found in {path}")
    return documents, warnings
