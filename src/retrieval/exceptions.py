"""Domain exceptions raised by knowledge-base components."""


class KnowledgeBaseError(Exception):
    """Base class for expected knowledge-base errors."""


class SourceValidationError(KnowledgeBaseError):
    """Raised when a raw source is missing or malformed."""


class DuplicateDocumentIdError(SourceValidationError):
    """Raised when two source documents resolve to the same document ID."""


class InvalidCweCsvRowError(SourceValidationError):
    """Raised when a CWE CSV row does not match the declared header."""


class InvalidKnowledgeDocumentError(KnowledgeBaseError):
    """Raised when a normalized document violates its contract."""


class InvalidSearchQueryError(KnowledgeBaseError):
    """Raised when a search query has no safe searchable terms."""


class UnsupportedSQLiteError(KnowledgeBaseError):
    """Raised when the Python SQLite runtime lacks JSON or FTS5 support."""


class KnowledgeIndexNotFoundError(KnowledgeBaseError):
    """Raised when search is attempted before the index is built."""


class KnowledgeIndexBuildError(KnowledgeBaseError):
    """Raised when an atomic index build cannot be completed."""


class KnowledgeDocumentNotFoundError(KnowledgeBaseError):
    """Raised when an inspected canonical document does not exist."""


class EmbeddingConfigurationError(KnowledgeBaseError):
    """Raised when required embedding model configurations (API key, model, URL) are missing."""


class EmbeddingAPIError(KnowledgeBaseError):
    """Raised when cloud embedding API requests fail."""
