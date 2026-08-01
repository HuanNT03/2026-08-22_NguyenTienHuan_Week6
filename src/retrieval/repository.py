"""SQLite repository for ranked knowledge retrieval."""

import json
import sqlite3
from pathlib import Path
from typing import Any

from src.retrieval.config import BM25_WEIGHTS, INDEX_PATH, SNIPPET_COLUMN_INDEX
from src.retrieval.exceptions import KnowledgeIndexNotFoundError


class KnowledgeRepository:
    """Read-only search adapter over the generated SQLite index."""

    def __init__(self, index_path: Path = INDEX_PATH) -> None:
        self.index_path = index_path

    def _connect(self) -> sqlite3.Connection:
        if not self.index_path.is_file():
            raise KnowledgeIndexNotFoundError(
                f"Knowledge index not found: {self.index_path}. Run the knowledge-base build first."
            )
        connection = sqlite3.connect(self.index_path)
        connection.row_factory = sqlite3.Row
        return connection

    def search(
        self,
        *,
        normalized_query: str,
        match_expression: str,
        top_k: int,
        doc_type: str | None,
    ) -> list[dict[str, Any]]:
        """Execute exact-tier plus weighted BM25 ranking with bound user parameters."""
        weights = ", ".join(str(weight) for weight in BM25_WEIGHTS)
        sql = f"""
            SELECT
                d.doc_id,
                d.doc_type,
                d.title,
                d.aliases_json,
                d.identifiers_json,
                d.tags_json,
                d.summary,
                snippet(
                    knowledge_fts,
                    {SNIPPET_COLUMN_INDEX},
                    '<mark>',
                    '</mark>',
                    ' … ',
                    24
                ) AS snippet,
                bm25(knowledge_fts, {weights}) AS bm25_score,
                CASE
                    WHEN EXISTS (
                        SELECT 1
                        FROM json_tree(d.identifiers_json) AS identifier
                        WHERE identifier.type = 'text'
                          AND lower(identifier.atom) = lower(:normalized_query)
                    ) THEN 0
                    WHEN lower(d.title) = lower(:normalized_query) THEN 1
                    WHEN EXISTS (
                        SELECT 1
                        FROM json_each(d.aliases_json) AS alias
                        WHERE lower(alias.value) = lower(:normalized_query)
                    ) THEN 2
                    ELSE 3
                END AS exact_match_rank,
                CASE
                    WHEN :normalized_query GLOB 'CWE-[0-9]*' AND d.doc_type = 'cwe' THEN 0
                    WHEN :normalized_query GLOB 'A[0-9][0-9]:[0-9][0-9][0-9][0-9]'
                         AND d.doc_type = 'owasp_category' THEN 0
                    ELSE 1
                END AS canonical_identifier_owner_rank
            FROM knowledge_fts
            JOIN documents AS d ON d.rowid = knowledge_fts.rowid
            WHERE knowledge_fts MATCH :match_expression
              AND (:doc_type IS NULL OR d.doc_type = :doc_type)
            ORDER BY
                exact_match_rank ASC,
                canonical_identifier_owner_rank ASC,
                bm25_score ASC,
                d.doc_id ASC
            LIMIT :top_k
        """
        parameters: dict[str, str | int | None] = {
            "normalized_query": normalized_query,
            "match_expression": match_expression,
            "doc_type": doc_type,
            "top_k": top_k,
        }
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [
            {
                "doc_id": row["doc_id"],
                "doc_type": row["doc_type"],
                "title": row["title"],
                "snippet": row["snippet"] or "",
                "summary": row["summary"],
                "aliases": json.loads(row["aliases_json"]),
                "identifiers": json.loads(row["identifiers_json"]),
                "tags": json.loads(row["tags_json"]),
                "bm25_score": float(row["bm25_score"]),
                "exact_match_rank": int(row["exact_match_rank"]),
            }
            for row in rows
        ]
