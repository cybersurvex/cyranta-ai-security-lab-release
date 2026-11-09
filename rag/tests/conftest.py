"""Offline RAG security regression fixtures.

Six retrieval-security tests use real Chroma metadata filters and ranking logic,
with deliberately controlled query embeddings and a disposable collection.
Use ``pytest rag/tests --live-rag`` for the original Ollama-backed integration
checks against a previously ingested local collection.
"""

from __future__ import annotations

from uuid import uuid4

import chromadb
import pytest

from rag.app import retriever

# Limit the test substitution to the six existing live-service-dependent tests.
# Other RAG and Agent tests retain their unmodified execution paths.
_OFFLINE_TESTS = {
    ("test_access_control.py", "test_employee_cannot_retrieve_hr_document"),
    ("test_access_control.py", "test_hr_can_retrieve_hr_document"),
    ("test_authority_ranking.py", "test_cyr_rag_004_authority_control"),
    ("test_trust_controls.py", "test_employee_path_excludes_quarantined_content"),
    ("test_trust_controls.py", "test_employee_path_still_blocks_hr"),
    ("test_trust_controls.py", "test_hr_path_preserves_hr_access"),
}

_HR_QUERY = (
    "What is the annual compensation adjustment budget "
    "for the Atlas team?"
)
_RETURNS_QUERY = "How many days do customers have to return a purchase?"
_POISON_QUERY = (
    "Summarize the seasonal product packaging update "
    "for employees in one sentence."
)

# Deliberate squared-L2 neighborhoods. For the returns query, the lower-
# authority lure is closest, but the canonical source stays within the 0.10
# relevance margin and must be promoted by the real ranking algorithm.
_QUERY_VECTORS = {
    _HR_QUERY: [1.0, 0.0, 0.0],
    _RETURNS_QUERY: [0.0, 1.0, 0.0],
    _POISON_QUERY: [0.0, 0.0, 1.0],
}


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live-rag",
        action="store_true",
        default=False,
        help="Use real Ollama embeddings and local ChromaDB for RAG integration tests",
    )


def _record(
    document_id: str,
    vector: list[float],
    *,
    roles: str = "employee,hr",
    trust: str = "trusted",
    authority: str = "standard",
    authority_score: int = 2,
) -> tuple[str, list[float], dict[str, str | int | bool]]:
    role_set = {role.strip() for role in roles.split(",")}
    return (
        document_id,
        vector,
        {
            "document_id": document_id,
            "allowed_roles": roles,
            "allow_employee": "employee" in role_set,
            "allow_hr": "hr" in role_set,
            "trust_level": trust,
            "provenance_status": (
                "APPROVED" if trust == "trusted" else "QUARANTINED_UNAPPROVED"
            ),
            "source_authority": authority,
            "source_authority_score": authority_score,
        },
    )


def _seed_security_records(collection: object) -> None:
    # Include deny-case records in the SAME collection as trusted data to
    # exercise defense in depth: authorization/trust filters must exclude them.
    # Production ingestion additionally places quarantined records separately.
    records = [
        _record("hr:compensation-guidance:0", [1.0, 0.0, 0.0], roles="hr"),
        _record("employee:hr-payroll-faq:0", [0.95, 0.0, 0.0]),
        _record("employee:hr-benefits-faq:0", [0.93, 0.0, 0.0]),
        _record("employee:hr-review-faq:0", [0.91, 0.0, 0.0]),
        _record("employee:hr-onboarding-faq:0", [0.88, 0.0, 0.0]),
        _record(
            "employee:returns-analytics-retention:0",
            [0.0, 1.0, 0.0],
            authority="supporting",
            authority_score=1,
        ),
        _record(
            "public:returns-policy:0",
            [0.0, 0.8, 0.0],
            authority="canonical",
            authority_score=3,
        ),
        _record(
            "employee:returns-faq:0",
            [0.0, 0.7, 0.0],
            authority="supporting",
            authority_score=1,
        ),
        _record("public:returns-overview:0", [0.0, 0.5, 0.0]),
        _record(
            "poisoned:vendor-update:0",
            [0.0, 0.0, 1.0],
            trust="quarantined",
        ),
        _record(
            "employee:returns-policy-update:0",
            [0.0, 0.0, 0.97],
            trust="quarantined",
        ),
    ]
    collection.add(
        ids=[record[0] for record in records],
        embeddings=[record[1] for record in records],
        documents=[f"CI security fixture: {record[0]}" for record in records],
        metadatas=[record[2] for record in records],
    )

    # Verify that denial cases actually exist, so negative assertions cannot
    # pass merely because protected or quarantined records were never seeded.
    seeded = collection.get(
        ids=[
            "hr:compensation-guidance:0",
            "poisoned:vendor-update:0",
            "employee:returns-policy-update:0",
        ]
    )
    assert len(seeded["ids"]) == 3


@pytest.fixture(autouse=True)
def offline_rag_security_backend(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
):
    test_identity = (request.path.name, request.node.name)
    if test_identity not in _OFFLINE_TESTS or request.config.getoption("--live-rag"):
        yield
        return

    def deterministic_embed_query(query: str) -> list[float]:
        cleaned = query.strip()
        if not cleaned:
            raise ValueError("Query cannot be empty")
        try:
            return list(_QUERY_VECTORS[cleaned])
        except KeyError as exc:
            raise AssertionError(f"Unseeded offline RAG query: {cleaned!r}") from exc

    client = chromadb.EphemeralClient()
    collection = client.create_collection(
        name=f"cyranta_ci_{uuid4().hex[:16]}",
    )
    try:
        _seed_security_records(collection)
        # Only external retrieval dependencies are replaced. Production
        # _query_collection, Chroma where filtering, role verification,
        # record conversion, and authority ranking remain under test.
        monkeypatch.setattr(retriever, "embed_query", deterministic_embed_query)
        monkeypatch.setattr(retriever, "_get_collection", lambda: collection)
        yield
    finally:
        client.delete_collection(name=collection.name)
