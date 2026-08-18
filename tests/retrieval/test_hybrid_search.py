"""Unit tests for Two-Stage Hybrid Search (RRF + Pure MMR)."""

import numpy as np

from src.retrieval.hybrid.mmr import cosine_similarity, maximal_marginal_relevance
from src.retrieval.hybrid.rrf import reciprocal_rank_fusion


def test_reciprocal_rank_fusion_ranks_overlapping_documents_highest() -> None:
    sparse_ids = ["doc-a", "doc-b", "doc-c", "doc-d"]
    dense_ids = ["doc-b", "doc-d", "doc-e", "doc-a"]

    rrf_results = reciprocal_rank_fusion(sparse_ids, dense_ids, k=60)
    ranked_ids = [doc_id for doc_id, _ in rrf_results]

    # doc-b is rank 2 in sparse and rank 1 in dense -> should be top 1
    assert ranked_ids[0] == "doc-b"
    # doc-a is rank 1 in sparse and rank 4 in dense -> should be in top 2 or 3
    assert "doc-a" in ranked_ids[:3]


def test_cosine_similarity_computation() -> None:
    v1 = np.array([1.0, 0.0, 0.0])
    v2 = np.array([1.0, 0.0, 0.0])
    v3 = np.array([0.0, 1.0, 0.0])

    assert cosine_similarity(v1, v2) == 1.0
    assert cosine_similarity(v1, v3) == 0.0


def test_pure_mmr_diversifies_highly_redundant_candidates() -> None:
    # Query vector along X axis
    query_vec = [1.0, 0.0, 0.0]

    # Doc A: strongly aligned with query
    # Doc B: identical to Doc A (100% redundant)
    # Doc C: slightly lower query similarity, but distinct from Doc A
    candidate_ids = ["doc-a", "doc-b", "doc-c"]
    candidate_vectors = {
        "doc-a": [1.0, 0.0, 0.0],
        "doc-b": [1.0, 0.0, 0.0],
        "doc-c": [0.8, 0.6, 0.0],
    }
    candidate_scores = {
        "doc-a": 1.0,
        "doc-b": 1.0,
        "doc-c": 0.8,
    }

    # With diversity penalty (lambda = 0.3), MMR should pick Doc C before identical Doc B
    selected = maximal_marginal_relevance(
        query_vector=query_vec,
        candidate_doc_ids=candidate_ids,
        candidate_vectors=candidate_vectors,
        candidate_relevance_scores=candidate_scores,
        top_k=2,
        lambda_mult=0.3,
    )

    assert len(selected) == 2
    assert selected[0] == "doc-a"
    assert selected[1] == "doc-c"  # Doc C selected over redundant Doc B!
