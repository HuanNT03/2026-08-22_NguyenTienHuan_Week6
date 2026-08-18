"""Reciprocal Rank Fusion (RRF) algorithm for combining sparse and dense rankings."""

from collections import defaultdict


def reciprocal_rank_fusion(
    sparse_doc_ids: list[str],
    dense_doc_ids: list[str],
    k: int = 60,
    weight_sparse: float = 1.0,
    weight_dense: float = 1.0,
) -> list[tuple[str, float]]:
    """Compute Reciprocal Rank Fusion scores across sparse (BM25) and dense (Vector) ranked lists.

    Score(d) = (weight_sparse / (k + rank_sparse)) + (weight_dense / (k + rank_dense))
    Ranks are 1-based indices in their respective result lists.
    """
    scores: dict[str, float] = defaultdict(float)

    for rank, doc_id in enumerate(sparse_doc_ids, start=1):
        scores[doc_id] += weight_sparse / (k + rank)

    for rank, doc_id in enumerate(dense_doc_ids, start=1):
        scores[doc_id] += weight_dense / (k + rank)

    sorted_results = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    return sorted_results
