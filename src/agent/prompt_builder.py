"""Prompt builder and KB retrieval integration for Security Analysis Agent."""

import json
import logging
from typing import Any

from src.agent.models import AnalysisGroup
from src.guardrails.redactor import mask_sensitive_data
from src.retrieval.service import KnowledgeSearchService, SearchResult

logger = logging.getLogger(__name__)


def compress_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Strip only pipeline/run metadata while preserving 100% of vulnerability evidence and context."""
    compressed = dict(finding)

    # Exclude pipeline-only metadata fields
    compressed.pop("schema_version", None)
    compressed.pop("normalization", None)
    compressed.pop("scan", None)

    return compressed


def fetch_kb_context_for_group(
    group: AnalysisGroup,
    kb_service: KnowledgeSearchService,
    top_k: int = 5,
) -> tuple[list[dict[str, Any]], list[SearchResult]]:
    """Perform per-CWE multi-search and deduplicate KB documents for the given analysis group."""
    search_queries: list[str] = []

    # Collect all CWE IDs in this group
    cwe_set: set[str] = set()
    if group.primary_cwe:
        cwe_set.add(group.primary_cwe)
    for f in group.findings:
        for cwe in f.get("cwe_ids") or []:
            cwe_set.add(cwe)

    # Collect title keywords
    titles: list[str] = [f.get("title") for f in group.findings if f.get("title")]

    # Build queries: 1 search per CWE, plus 1 query with primary title if available
    for cwe in sorted(cwe_set):
        search_queries.append(f"{cwe}")
    if titles:
        search_queries.append(titles[0])

    dedup_results: dict[str, SearchResult] = {}
    for query in search_queries:
        try:
            results = kb_service.search(query=query, top_k=top_k)
            for res in results:
                if res.doc_id not in dedup_results:
                    dedup_results[res.doc_id] = res
                else:
                    # Keep result with best BM25 score
                    if res.bm25_score < dedup_results[res.doc_id].bm25_score:
                        dedup_results[res.doc_id] = res
        except Exception as e:  # noqa: BLE001
            logger.debug("KB search failed for query %r: %s", query, e)
            continue

    sorted_results = sorted(dedup_results.values(), key=lambda r: r.bm25_score)[:top_k]

    formatted_snippets: list[dict[str, Any]] = [
        {
            "doc_id": r.doc_id,
            "title": r.title,
            "aliases": r.aliases,
            "tags": r.tags,
            "summary": r.summary,
        }
        for r in sorted_results
    ]

    return formatted_snippets, sorted_results


def build_user_prompt(group: AnalysisGroup, kb_snippets: list[dict[str, Any]]) -> str:
    """Build structured user prompt JSON string for single analysis group LLM call."""
    compressed_findings = [compress_finding(f) for f in group.findings]

    payload = {
        "analysis_group_id": group.group_id,
        "primary_cwe": group.primary_cwe,
        "correlation_type": group.correlation_type,
        "correlated_fingerprints": group.correlated_fingerprints,
        "findings_count": len(compressed_findings),
        "unified_findings": compressed_findings,
        "knowledge_base_snippets": kb_snippets,
        "instructions": (
            "Phân tích cụm lỗ hổng trên và tạo báo cáo chi tiết cho TỪNG finding (mỗi finding_id/fingerprint 1 entry JSON) "
            "tuân theo Pydantic schema được yêu cầu. Phải ghi rõ correlation_type, bằng chứng evidence_summary, "
            "giải thích tiếng Việt (giữ thuật ngữ tiếng Anh trong ngoặc), và proposed_test_request dưới dạng dữ liệu."
        ),
    }

    # Redact sensitive data before returning string
    redacted_payload = mask_sensitive_data(payload)
    return json.dumps(redacted_payload, indent=2, ensure_ascii=False)
