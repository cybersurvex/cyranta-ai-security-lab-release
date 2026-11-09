from __future__ import annotations

from typing import Any

import chromadb
import httpx

from rag.app.ingestion import (
    CHROMA_PATH,
    COLLECTION_NAME,
    EMBEDDING_MODEL,
    OLLAMA_URL,
)

VALID_ROLES = {
    "employee",
    "hr",
}


def _validate_role(
    role: str,
) -> str:
    normalized_role = role.strip().lower()

    if normalized_role not in VALID_ROLES:
        raise ValueError(
            f"Unsupported role: {role}"
        )

    return normalized_role


def embed_query(
    query: str,
) -> list[float]:
    cleaned_query = query.strip()

    if not cleaned_query:
        raise ValueError(
            "Query cannot be empty"
        )

    response = httpx.post(
        f"{OLLAMA_URL}/api/embed",
        json={
            "model": EMBEDDING_MODEL,
            "input": [
                cleaned_query
            ],
        },
        timeout=120.0,
    )
    response.raise_for_status()

    payload = response.json()

    embeddings = payload.get(
        "embeddings"
    )

    if (
        not isinstance(
            embeddings,
            list,
        )
        or not embeddings
    ):
        raise RuntimeError(
            "Ollama response did not "
            "contain query embeddings"
        )

    embedding = embeddings[0]

    if not isinstance(
        embedding,
        list,
    ):
        raise RuntimeError(  # noqa: TRY004
            "Unexpected query embedding "
            "format"
        )

    return embedding


def _get_collection():
    client = chromadb.PersistentClient(
        path=str(CHROMA_PATH),
    )

    return client.get_collection(
        COLLECTION_NAME
    )


def _records_from_query_result(
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    ids = (
        result.get("ids")
        or [[]]
    )[0]

    documents = (
        result.get("documents")
        or [[]]
    )[0]

    metadatas = (
        result.get("metadatas")
        or [[]]
    )[0]

    distances = (
        result.get("distances")
        or [[]]
    )[0]

    records: list[
        dict[str, Any]
    ] = []

    for (
        document_id,
        document,
        metadata,
        distance,
    ) in zip(
        ids,
        documents,
        metadatas,
        distances,
        strict=True,
    ):
        records.append(
            {
                "document_id": (
                    document_id
                ),
                "document": document,
                "metadata": (
                    metadata or {}
                ),
                "distance": float(
                    distance
                ),
            }
        )

    return records


def _query_collection(
    query: str,
    *,
    n_results: int,
    where: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if n_results <= 0:
        raise ValueError(
            "n_results must be "
            "greater than zero"
        )

    query_embedding = embed_query(
        query
    )

    collection = _get_collection()

    query_kwargs: dict[
        str,
        Any,
    ] = {
        "query_embeddings": [
            query_embedding
        ],
        "n_results": n_results,
        "include": [
            "documents",
            "metadatas",
            "distances",
        ],
    }

    if where is not None:
        query_kwargs["where"] = where

    result = collection.query(
        **query_kwargs
    )

    return _records_from_query_result(
        result
    )


def retrieve_unfiltered(
    query: str,
    role: str,
    n_results: int = 4,
) -> list[dict[str, Any]]:
    """
    Original vulnerable baseline.

    This function deliberately does not enforce
    role-based authorization.

    It remains in the lab so CYR-RAG-001 baseline
    behavior can be demonstrated historically.
    """

    _ = role

    return _query_collection(
        query,
        n_results=n_results,
    )


def retrieve_authorized(
    query: str,
    role: str,
    n_results: int = 4,
) -> list[dict[str, Any]]:
    """
    CYR-RAG-001 control.

    Restrict retrieval to documents authorized
    for the requesting role.
    """

    normalized_role = _validate_role(
        role
    )

    authorization_field = (
        f"allow_{normalized_role}"
    )

    return _query_collection(
        query,
        n_results=n_results,
        where={
            authorization_field: True,
        },
    )


def retrieve_trusted_authorized(
    query: str,
    role: str,
    n_results: int = 4,
) -> list[dict[str, Any]]:
    """
    CYR-RAG-002 / CYR-RAG-003 control.

    Restrict retrieval to documents that are
    both authorized for the requesting role
    and marked trusted by the provenance-aware
    ingestion pipeline.

    Results remain ordered by vector similarity.
    """

    normalized_role = _validate_role(
        role
    )

    authorization_field = (
        f"allow_{normalized_role}"
    )

    return _query_collection(
        query,
        n_results=n_results,
        where={
            "$and": [
                {
                    authorization_field: True,
                },
                {
                    "trust_level": "trusted",
                },
            ]
        },
    )


def rerank_with_source_authority(
    records: list[dict[str, Any]],
    *,
    relevance_margin: float = 0.10,
) -> list[dict[str, Any]]:
    """
    CYR-RAG-004 control.

    Preserve semantic relevance as the primary
    candidate-selection mechanism, then use source
    authority to resolve semantically competitive
    candidates.

    Chroma distance is lower-is-better.

    Only candidates whose distance falls within
    `relevance_margin` of the best semantic result
    are eligible for authority-based reranking.

    This prevents an unrelated canonical document
    from jumping ahead solely because it has a
    higher authority score.
    """

    if relevance_margin < 0:
        raise ValueError(
            "relevance_margin cannot "
            "be negative"
        )

    if not records:
        return []

    ranked_records: list[
        dict[str, Any]
    ] = []

    for semantic_rank, record in enumerate(
        records,
        start=1,
    ):
        enriched = dict(
            record
        )

        enriched[
            "semantic_rank"
        ] = semantic_rank

        ranked_records.append(
            enriched
        )

    best_distance = min(
        float(
            record["distance"]
        )
        for record in ranked_records
    )

    competitive: list[
        dict[str, Any]
    ] = []

    noncompetitive: list[
        dict[str, Any]
    ] = []

    for record in ranked_records:
        distance = float(
            record["distance"]
        )

        semantic_gap = (
            distance
            - best_distance
        )

        record[
            "semantic_gap"
        ] = semantic_gap

        if (
            semantic_gap
            <= relevance_margin
        ):
            competitive.append(
                record
            )
        else:
            noncompetitive.append(
                record
            )

    competitive.sort(
        key=lambda record: (
            -int(
                record[
                    "metadata"
                ].get(
                    "source_authority_score",
                    1,
                )
            ),
            float(
                record["distance"]
            ),
            int(
                record[
                    "semantic_rank"
                ]
            ),
        )
    )

    noncompetitive.sort(
        key=lambda record: (
            float(
                record["distance"]
            ),
            int(
                record[
                    "semantic_rank"
                ]
            ),
        )
    )

    final_records = (
        competitive
        + noncompetitive
    )

    for final_rank, record in enumerate(
        final_records,
        start=1,
    ):
        record[
            "final_rank"
        ] = final_rank

    return final_records


def retrieve_authority_ranked(
    query: str,
    role: str,
    n_results: int = 4,
    candidate_pool_size: int = 4,
    relevance_margin: float = 0.10,
) -> list[dict[str, Any]]:
    """
    CYR-RAG-004 hardened retrieval path.

    1. Enforce role authorization.
    2. Enforce trusted-document retrieval.
    3. Over-fetch semantic candidates.
    4. Apply authority-aware reranking to
       semantically competitive candidates.
    5. Return the requested final top-k.

    The semantic-only retrieval functions remain
    available so historical vulnerable behavior
    can still be reproduced.
    """

    if n_results <= 0:
        raise ValueError(
            "n_results must be "
            "greater than zero"
        )

    if candidate_pool_size <= 0:
        raise ValueError(
            "candidate_pool_size must be "
            "greater than zero"
        )

    if (
        candidate_pool_size
        < n_results
    ):
        raise ValueError(
            "candidate_pool_size must be "
            "greater than or equal to "
            "n_results"
        )

    candidates = (
        retrieve_trusted_authorized(
            query,
            role=role,
            n_results=(
                candidate_pool_size
            ),
        )
    )

    reranked = (
        rerank_with_source_authority(
            candidates,
            relevance_margin=(
                relevance_margin
            ),
        )
    )

    return reranked[
        :n_results
    ]


if __name__ == "__main__":
    demo_query = (
        "How many days do customers "
        "have to return a purchase?"
    )

    print(
        "Semantic-only retrieval:"
    )

    semantic_results = (
        retrieve_trusted_authorized(
            demo_query,
            role="employee",
            n_results=4,
        )
    )

    for index, record in enumerate(
        semantic_results,
        start=1,
    ):
        print(
            f"{index}. "
            f"{record['document_id']} "
            f"distance="
            f"{record['distance']} "
            f"authority="
            f"{record['metadata'].get('source_authority')}"
        )

    print()
    print(
        "Authority-aware retrieval:"
    )

    hardened_results = (
        retrieve_authority_ranked(
            demo_query,
            role="employee",
            n_results=4,
            candidate_pool_size=4,
        )
    )

    for record in hardened_results:
        print(
            f"{record['final_rank']}. "
            f"{record['document_id']} "
            f"semantic_rank="
            f"{record['semantic_rank']} "
            f"distance="
            f"{record['distance']} "
            f"authority="
            f"{record['metadata'].get('source_authority')}"
        )