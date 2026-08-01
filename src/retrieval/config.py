"""Central configuration for the knowledge-base pipeline and search index."""

from pathlib import Path

SCHEMA_VERSION = "1.0.0"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
KNOWLEDGE_BASE_DIR = PROJECT_ROOT / "knowledge-base"
OWASP_RAW_DIR = KNOWLEDGE_BASE_DIR / "raw" / "owasp"
CWE_RAW_PATHS = (
    KNOWLEDGE_BASE_DIR / "raw" / "cwe" / "699.csv",
    KNOWLEDGE_BASE_DIR / "raw" / "cwe" / "1435.csv",
)
SEMGREP_RAW_DIR = KNOWLEDGE_BASE_DIR / "raw" / "semgrep"
ZAP_RAW_DIR = KNOWLEDGE_BASE_DIR / "raw" / "zap"
EXAMPLES_DIR = KNOWLEDGE_BASE_DIR / "curated" / "examples"
PROCESSED_DIR = KNOWLEDGE_BASE_DIR / "processed"
DOCUMENTS_PATH = PROCESSED_DIR / "documents.jsonl"
MANIFEST_PATH = PROCESSED_DIR / "manifest.json"
INDEX_DIR = KNOWLEDGE_BASE_DIR / "index"
INDEX_PATH = INDEX_DIR / "knowledge.db"
INDEX_TEMP_PATH = INDEX_DIR / "knowledge.db.tmp"
SCHEMA_PATH = PROJECT_ROOT / "schemas" / "knowledge_document.schema.json"

DOCUMENT_TYPES = (
    "owasp_category",
    "cwe",
    "scanner_document",
    "scanner_rule",
    "vulnerability_example",
)
DETECTABILITY_VALUES = ("high", "medium", "low", "unknown")
IDENTIFIER_NAMES = ("cwe", "owasp", "semgrep", "zap")

FTS_COLUMNS = (
    "title",
    "aliases_text",
    "identifiers_text",
    "tags_text",
    "summary",
    "content",
)
FTS_WEIGHTS = {
    "title": 6.0,
    "aliases_text": 5.0,
    "identifiers_text": 5.0,
    "tags_text": 3.0,
    "summary": 2.0,
    "content": 1.0,
}
BM25_WEIGHTS = tuple(FTS_WEIGHTS[column] for column in FTS_COLUMNS)
SNIPPET_COLUMN_INDEX = FTS_COLUMNS.index("content")
