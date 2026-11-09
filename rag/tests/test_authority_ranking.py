from __future__ import annotations

from typing import Any

from rag.app.retriever import (
    rerank_with_source_authority,
    retrieve_authority_ranked,
    retrieve_trusted_authorized,
)

QUERY = (
    "How many days do customers have "
    "to return a purchase?"
)

CANONICAL_DOCUMENT_ID = (
    "public:returns-policy:0"
)

LURE_PREFIX = (
    "employee:returns-analytics-retention:"
)


def make_record(
    *,
    document_id: str,
    distance: float,
    authority: str,
    authority_score: int,
) -> dict[str, Any]:
    return {
        "document_id": document_id,
        "document": "test content",
        "distance": distance,
        "metadata": {
            "source_authority": authority,
            "source_authority_score": (
                authority_score
            ),
        },
    }


def test_competitive_canonical_source_is_promoted() -> None:
    records = [
        make_record(
            document_id="supporting:0",
            distance=0.55,
            authority="supporting",
            authority_score=1,
        ),
        make_record(
            document_id="canonical:0",
            distance=0.57,
            authority="canonical",
            authority_score=3,
        ),
    ]

    result = rerank_with_source_authority(
        records,
        relevance_margin=0.10,
    )

    assert (
        result[0]["document_id"]
        == "canonical:0"
    )

    assert (
        result[0]["semantic_rank"]
        == 2
    )

    assert (
        result[0]["final_rank"]
        == 1
    )


def test_noncompetitive_canonical_source_is_not_promoted() -> None:
    records = [
        make_record(
            document_id="supporting:0",
            distance=0.40,
            authority="supporting",
            authority_score=1,
        ),
        make_record(
            document_id="canonical:0",
            distance=0.80,
            authority="canonical",
            authority_score=3,
        ),
    ]

    result = rerank_with_source_authority(
        records,
        relevance_margin=0.10,
    )

    assert (
        result[0]["document_id"]
        == "supporting:0"
    )

    assert (
        result[1]["document_id"]
        == "canonical:0"
    )


def test_negative_relevance_margin_fails_closed() -> None:
    records = [
        make_record(
            document_id="canonical:0",
            distance=0.50,
            authority="canonical",
            authority_score=3,
        )
    ]

    try:
        rerank_with_source_authority(
            records,
            relevance_margin=-0.01,
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Negative relevance margin "
            "should raise ValueError"
        )


def test_cyr_rag_004_authority_control() -> None:
    semantic_results = (
        retrieve_trusted_authorized(
            QUERY,
            role="employee",
            n_results=4,
        )
    )

    assert semantic_results

    assert semantic_results[
        0
    ]["document_id"].startswith(
        LURE_PREFIX
    )

    canonical_semantic_rank = next(
        index
        for index, record in enumerate(
            semantic_results,
            start=1,
        )
        if record["document_id"]
        == CANONICAL_DOCUMENT_ID
    )

    assert canonical_semantic_rank > 1

    hardened_results = (
        retrieve_authority_ranked(
            QUERY,
            role="employee",
            n_results=1,
            candidate_pool_size=4,
            relevance_margin=0.10,
        )
    )

    assert len(hardened_results) == 1

    result = hardened_results[0]

    assert (
        result["document_id"]
        == CANONICAL_DOCUMENT_ID
    )

    assert (
        result["semantic_rank"]
        == canonical_semantic_rank
    )

    assert result["final_rank"] == 1

    assert (
        result["metadata"][
            "source_authority"
        ]
        == "canonical"
    )