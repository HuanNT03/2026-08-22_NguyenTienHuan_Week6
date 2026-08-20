import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from src.retrieval.config import BM25_WEIGHTS, FTS_COLUMNS, FTS_WEIGHTS, SCHEMA_PATH
from src.retrieval.models import KnowledgeDocument


def document_data() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "doc_id": "cwe-89",
        "doc_type": "cwe",
        "title": "CWE-89: SQL Injection",
        "aliases": ["SQL Injection", "SQLi"],
        "summary": "Improper neutralization in an SQL command.",
        "content": "Use parameterized SQL queries.",
        "identifiers": {
            "cwe": ["CWE-89"],
            "owasp": [],
            "semgrep": [],
            "zap": [],
        },
        "tags": ["sql", "injection"],
        "detectability": {"sast": "high", "manual": "medium"},
        "source": {
            "name": "MITRE CWE",
            "raw_path": "knowledge-base/raw/cwe/699.csv",
            "source_locator": "CWE-89",
        },
    }


def test_model_and_json_schema_accept_the_same_document() -> None:
    document = KnowledgeDocument.model_validate(document_data())
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema).iter_errors(document.to_canonical_dict()))
    assert errors == []


@pytest.mark.parametrize("doc_id", ["CWE-89", "cwe 89", "cwe_89", "-cwe-89"])
def test_invalid_document_id_is_rejected(doc_id: str) -> None:
    data = document_data()
    data["doc_id"] = doc_id
    with pytest.raises(ValidationError, match="doc_id"):
        KnowledgeDocument.model_validate(data)


def test_duplicate_alias_is_rejected() -> None:
    data = document_data()
    data["aliases"] = ["SQLi", "SQLi"]
    with pytest.raises(ValidationError, match="aliases must contain unique values"):
        KnowledgeDocument.model_validate(data)


def test_invalid_detectability_is_rejected() -> None:
    data = document_data()
    data["detectability"] = {"sast": "certain"}
    with pytest.raises(ValidationError, match="detectability.sast"):
        KnowledgeDocument.model_validate(data)


def test_empty_detectability_is_rejected() -> None:
    data = document_data()
    data["detectability"] = {}
    with pytest.raises(ValidationError, match="at least one method"):
        KnowledgeDocument.model_validate(data)


def test_none_optional_values_are_omitted() -> None:
    data = document_data()
    data.pop("detectability")
    data["source"] = {**data["source"], "version": None}
    canonical = KnowledgeDocument.model_validate(data).to_canonical_dict()
    assert "detectability" not in canonical
    assert "version" not in canonical["source"]


def test_bm25_weights_follow_fts_column_order() -> None:
    assert BM25_WEIGHTS == tuple(FTS_WEIGHTS[column] for column in FTS_COLUMNS)


def test_document_type_accepts_document_enum() -> None:
    data = document_data()
    data["doc_type"] = "document"
    data["doc_id"] = "general-about-owasp"
    document = KnowledgeDocument.model_validate(data)
    assert document.doc_type == "document"
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(document.to_canonical_dict()))
    assert errors == []

