"""Pure Maximal Marginal Relevance (MMR) diversity reranker."""

import numpy as np


def cosine_similarity(v1: np.ndarray, v2: np.ndarray) -> float:
    """Calculate cosine similarity between two numpy vectors."""
    norm1 = np.linalg.norm(v1)
    norm2 = np.linalg.norm(v2)
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return float(np.dot(v1, v2) / (norm1 * norm2))


def maximal_marginal_relevance(
    query_vector: list[float] | np.ndarray,
    candidate_doc_ids: list[str],
    candidate_vectors: dict[str, list[float] | np.ndarray],
    candidate_relevance_scores: dict[str, float],
    top_k: int = 5,
    lambda_mult: float = 0.7,
) -> list[str]:
    """Select top_k documents balancing relevance with diversity using Pure MMR.

    MMR(d_i) = lambda_mult * Rel(d_i) - (1 - lambda_mult) * max_{d_j in Selected} Sim(v_i, v_j)
    """
    if not candidate_doc_ids or top_k <= 0:
        return []

    # Normalize candidate relevance scores to [0, 1] range
    scores = [candidate_relevance_scores.get(doc_id, 0.0) for doc_id in candidate_doc_ids]
    min_score = min(scores) if scores else 0.0
    max_score = max(scores) if scores else 1.0
    score_range = max_score - min_score if max_score > min_score else 1.0

    normalized_rel: dict[str, float] = {
        doc_id: (candidate_relevance_scores.get(doc_id, 0.0) - min_score) / score_range
        for doc_id in candidate_doc_ids
    }

    # Convert vectors to numpy arrays
    q_vec = np.array(query_vector, dtype=float)
    doc_vectors: dict[str, np.ndarray] = {
        doc_id: np.array(vec, dtype=float)
        for doc_id, vec in candidate_vectors.items()
        if len(vec) > 0
    }

    selected: list[str] = []
    unselected = list(candidate_doc_ids)

    # 1. Select initial document with highest combined score or query similarity
    if unselected:
        initial_doc = max(
            unselected,
            key=lambda d: normalized_rel.get(d, 0.0) + (
                cosine_similarity(q_vec, doc_vectors[d]) if d in doc_vectors else 0.0
            ),
        )
        selected.append(initial_doc)
        unselected.remove(initial_doc)

    # 2. Greedily select next documents maximizing MMR
    while len(selected) < top_k and unselected:
        best_doc = None
        best_mmr_score = float("-inf")

        for doc_id in unselected:
            v_i = doc_vectors.get(doc_id)
            if v_i is not None and len(q_vec) > 0:
                rel = cosine_similarity(v_i, q_vec)
            else:
                rel = normalized_rel.get(doc_id, 0.0)

            if v_i is not None and selected:
                max_sim_to_selected = max(
                    cosine_similarity(v_i, doc_vectors[s])
                    for s in selected
                    if s in doc_vectors
                )
            else:
                max_sim_to_selected = 0.0

            mmr_score = (lambda_mult * rel) - ((1.0 - lambda_mult) * max_sim_to_selected)

            if mmr_score > best_mmr_score:
                best_mmr_score = mmr_score
                best_doc = doc_id

        if best_doc is None:
            break

        selected.append(best_doc)
        unselected.remove(best_doc)

    return selected
