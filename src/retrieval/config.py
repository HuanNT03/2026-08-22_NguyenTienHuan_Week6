"""Central configuration for the knowledge-base pipeline and search index."""

from pathlib import Path

SCHEMA_VERSION = "1.0.0"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
KNOWLEDGE_BASE_DIR = PROJECT_ROOT / "knowledge-base"
OWASP_RAW_DIR = KNOWLEDGE_BASE_DIR / "raw" / "owasp"
OWASP_TOP_TEN_DIR = OWASP_RAW_DIR / "top-ten"
ASVS_RAW_DIR = OWASP_RAW_DIR / "asvs" / "5.0.0"
CHEATSHEETS_RAW_DIR = KNOWLEDGE_BASE_DIR / "raw" / "cheatsheets"
CODEQL_RAW_DIR = KNOWLEDGE_BASE_DIR / "raw" / "codeql"
CWE_RAW_PATHS = (
    KNOWLEDGE_BASE_DIR / "raw" / "cwe" / "699.csv",
    KNOWLEDGE_BASE_DIR / "raw" / "cwe" / "1435.csv",
)
SEMGREP_RAW_DIR = KNOWLEDGE_BASE_DIR / "raw" / "semgrep"
ZAP_RAW_DIR = KNOWLEDGE_BASE_DIR / "raw" / "zap"
EXAMPLES_DIR = KNOWLEDGE_BASE_DIR / "vulnerable_examples"
PROCESSED_DIR = KNOWLEDGE_BASE_DIR / "processed"
DOCUMENTS_PATH = PROCESSED_DIR / "documents.jsonl"
MANIFEST_PATH = PROCESSED_DIR / "manifest.json"
INDEX_DIR = KNOWLEDGE_BASE_DIR / "index"
INDEX_PATH = INDEX_DIR / "knowledge.db"
INDEX_TEMP_PATH = INDEX_DIR / "knowledge.db.tmp"
QDRANT_STORAGE_DIR = INDEX_DIR / "qdrant_storage"
QDRANT_COLLECTION_NAME = "sentinel_knowledge"
SCHEMA_PATH = PROJECT_ROOT / "schemas" / "knowledge_document.schema.json"

DOCUMENT_TYPES = (
    "owasp_category",
    "cwe",
    "scanner_document",
    "scanner_rule",
    "vulnerability_example",
    "cheatsheet",
    "asvs_requirement",
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
