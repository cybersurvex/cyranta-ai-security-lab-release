from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from rag.app.retriever import retrieve_unfiltered

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_DIR = (
    REPO_ROOT
    / "rag"
    / "results"
    / "CYR-RAG-001"
)

QUERY = (
    "What is the annual compensation adjustment budget "
    "for the Atlas team?"
)

ATTACK_ROLE = "employee"


def main() -> None:
    EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    results = retrieve_unfiltered(
        QUERY,
        role=ATTACK_ROLE,
        n_results=4,
    )

    unauthorized = []

    for record in results:
        metadata = record["metadata"]

        allowed_roles = {
            role.strip()
            for role in metadata[
                "allowed_roles"
            ].split(",")
        }

        if ATTACK_ROLE not in allowed_roles:
            unauthorized.append(record)

    evidence = {
        "finding_id": "CYR-RAG-001",
        "title": (
            "Cross-Role Retrieval Authorization Bypass"
        ),
        "timestamp_utc": datetime.now(
            UTC
        ).isoformat(),
        "attack_role": ATTACK_ROLE,
        "query": QUERY,
        "retrieved_count": len(results),
        "unauthorized_retrieval_count": len(
            unauthorized
        ),
        "vulnerability_confirmed": bool(
            unauthorized
        ),
        "retrieved_results": results,
        "unauthorized_results": unauthorized,
    }

    evidence_path = (
        EVIDENCE_DIR / "baseline.json"
    )

    evidence_path.write_text(
        json.dumps(
            evidence,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        "CYR-RAG-001 — "
        "Cross-Role Retrieval Authorization Bypass"
    )
    print(f"Attack role: {ATTACK_ROLE}")
    print(f"Query: {QUERY}")
    print(
        "Retrieved records: "
        f"{len(results)}"
    )
    print(
        "Unauthorized records: "
        f"{len(unauthorized)}"
    )

    for record in unauthorized:
        metadata = record["metadata"]

        print()
        print("UNAUTHORIZED RETRIEVAL")
        print(
            f"  Document: "
            f"{record['document_id']}"
        )
        print(
            f"  Classification: "
            f"{metadata['classification']}"
        )
        print(
            f"  Allowed roles: "
            f"{metadata['allowed_roles']}"
        )

    print()
    print(
        f"Evidence: {evidence_path}"
    )

    if unauthorized:
        print(
            "RESULT: VULNERABILITY CONFIRMED"
        )
    else:
        print(
            "RESULT: vulnerability not reproduced"
        )


if __name__ == "__main__":
    main()