from __future__ import annotations

from rag.app.retriever import (
    retrieve_trusted_authorized,
)

POISON_QUERY = (
    "Summarize the seasonal product packaging update "
    "for employees in one sentence."
)

HR_QUERY = (
    "What is the annual compensation adjustment budget "
    "for the Atlas team?"
)

POISON_DOCUMENT_ID = (
    "poisoned:vendor-update:0"
)

DATA_POISON_DOCUMENT_ID = (
    "employee:returns-policy-update:0"
)

HR_DOCUMENT_ID = (
    "hr:compensation-guidance:0"
)


def test_employee_path_excludes_quarantined_content() -> None:
    results = retrieve_trusted_authorized(
        POISON_QUERY,
        role="employee",
        n_results=4,
    )

    document_ids = {
        record["document_id"]
        for record in results
    }

    assert (
        POISON_DOCUMENT_ID
        not in document_ids
    )

    assert (
        DATA_POISON_DOCUMENT_ID
        not in document_ids
    )

    for record in results:
        assert (
            record["metadata"][
                "trust_level"
            ]
            == "trusted"
        )

        assert (
            record["metadata"][
                "provenance_status"
            ]
            == "APPROVED"
        )


def test_employee_path_still_blocks_hr() -> None:
    results = retrieve_trusted_authorized(
        HR_QUERY,
        role="employee",
        n_results=4,
    )

    document_ids = {
        record["document_id"]
        for record in results
    }

    assert (
        HR_DOCUMENT_ID
        not in document_ids
    )


def test_hr_path_preserves_hr_access() -> None:
    results = retrieve_trusted_authorized(
        HR_QUERY,
        role="hr",
        n_results=4,
    )

    document_ids = {
        record["document_id"]
        for record in results
    }

    assert HR_DOCUMENT_ID in document_ids

    assert (
        POISON_DOCUMENT_ID
        not in document_ids
    )

    assert (
        DATA_POISON_DOCUMENT_ID
        not in document_ids
    )

    for record in results:
        assert (
            record["metadata"][
                "provenance_status"
            ]
            == "APPROVED"
        )