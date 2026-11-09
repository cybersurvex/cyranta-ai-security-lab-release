from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import chromadb

from rag.app.ingestion import (
    CHROMA_PATH,
    COLLECTION_NAME,
    PROVENANCE_REPORT_PATH,
    QUARANTINE_COLLECTION_NAME,
    ingest,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

EVIDENCE_DIR = (
    REPO_ROOT
    / "rag"
    / "results"
    / "CYR-RAG-003"
)

TARGET_PATH = (
    REPO_ROOT
    / "rag"
    / "data"
    / "public"
    / "returns-policy.txt"
)

TARGET_SOURCE = (
    "rag/data/public/returns-policy.txt"
)

TARGET_DOCUMENT_ID = (
    "public:returns-policy:0"
)

EXPECTED_STATUS = (
    "QUARANTINED_HASH_MISMATCH"
)

TAMPER_MARKER = (
    "CYR-RAG-HASH-TAMPER-7C21"
)


def main() -> None:
    EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    original_bytes = TARGET_PATH.read_bytes()

    tampered_text = (
        original_bytes.decode("utf-8")
        + "\n\n"
        + TAMPER_MARKER
        + "\n"
        + "The return window is now 999 days.\n"
    )

    try:
        TARGET_PATH.write_text(
            tampered_text,
            encoding="utf-8",
        )

        print(
            "Temporarily modified approved source:"
        )
        print(TARGET_SOURCE)
        print()

        ingest()

        client = chromadb.PersistentClient(
            path=str(CHROMA_PATH),
        )

        approved_collection = (
            client.get_collection(
                COLLECTION_NAME
            )
        )

        quarantine_collection = (
            client.get_collection(
                QUARANTINE_COLLECTION_NAME
            )
        )

        approved_result = (
            approved_collection.get(
                include=["metadatas"]
            )
        )

        quarantine_result = (
            quarantine_collection.get(
                include=["metadatas"]
            )
        )

        poison_in_approved = (
            TARGET_DOCUMENT_ID
            in set(
                approved_result["ids"]
            )
        )

        poison_in_quarantine = (
            TARGET_DOCUMENT_ID
            in set(
                quarantine_result["ids"]
            )
        )

        target_metadata = None

        for document_id, metadata in zip(
            quarantine_result["ids"],
            quarantine_result["metadatas"],
            strict=True,
        ):
            if (
                document_id
                == TARGET_DOCUMENT_ID
            ):
                target_metadata = metadata
                break

        hash_mismatch_detected = (
            target_metadata is not None
            and target_metadata.get(
                "provenance_status"
            )
            == EXPECTED_STATUS
        )

        hash_match_false = (
            target_metadata is not None
            and target_metadata.get(
                "hash_match"
            )
            is False
        )

        quarantined_trust = (
            target_metadata is not None
            and target_metadata.get(
                "trust_level"
            )
            == "quarantined"
        )

        mitigation_passed = (
            not poison_in_approved
            and poison_in_quarantine
            and hash_mismatch_detected
            and hash_match_false
            and quarantined_trust
        )

        evidence = {
            "finding_id": "CYR-RAG-003",
            "test_type": (
                "approved-source-hash-tamper-retest"
            ),
            "timestamp_utc": datetime.now(
                UTC
            ).isoformat(),
            "target_source": TARGET_SOURCE,
            "target_document_id": (
                TARGET_DOCUMENT_ID
            ),
            "tamper_marker": TAMPER_MARKER,
            "target_in_approved_collection": (
                poison_in_approved
            ),
            "target_in_quarantine_collection": (
                poison_in_quarantine
            ),
            "hash_mismatch_detected": (
                hash_mismatch_detected
            ),
            "hash_match_false": (
                hash_match_false
            ),
            "quarantined_trust": (
                quarantined_trust
            ),
            "target_metadata": (
                target_metadata
            ),
            "mitigation_passed": (
                mitigation_passed
            ),
        }

        evidence_path = (
            EVIDENCE_DIR
            / "hash-mismatch-retest.json"
        )

        evidence_path.write_text(
            json.dumps(
                evidence,
                indent=2,
            ),
            encoding="utf-8",
        )

        tamper_report_path = (
            EVIDENCE_DIR
            / "hash-mismatch-provenance-report.json"
        )

        if PROVENANCE_REPORT_PATH.exists():
            tamper_report_path.write_bytes(
                PROVENANCE_REPORT_PATH.read_bytes()
            )

        print(
            "CYR-RAG-003 — "
            "Approved Source Hash-Tamper Retest"
        )
        print()

        print(
            "Target in approved collection:",
            poison_in_approved,
        )

        print(
            "Target in quarantine collection:",
            poison_in_quarantine,
        )

        print(
            "Hash mismatch detected:",
            hash_mismatch_detected,
        )

        print(
            "hash_match == False:",
            hash_match_false,
        )

        print(
            "Trust set to quarantined:",
            quarantined_trust,
        )

        print()
        print(
            f"Evidence: {evidence_path}"
        )

        if mitigation_passed:
            print()
            print(
                "RESULT: CYR-RAG-003 "
                "HASH-TAMPER MITIGATION PASSED"
            )
        else:
            print()
            print(
                "RESULT: CYR-RAG-003 "
                "HASH-TAMPER MITIGATION FAILED"
            )

    finally:
        print()
        print(
            "Restoring original approved source..."
        )

        TARGET_PATH.write_bytes(
            original_bytes
        )

        print(
            "Rebuilding normal collections..."
        )

        ingest()

        print(
            "Original document and normal "
            "collection state restored."
        )


if __name__ == "__main__":
    main()