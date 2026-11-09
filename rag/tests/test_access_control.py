from __future__ import annotations

import pytest

from rag.app.retriever import retrieve_authorized

QUERY = (
    "What is the annual compensation adjustment budget "
    "for the Atlas team?"
)

HR_DOCUMENT_ID = "hr:compensation-guidance:0"


def test_employee_cannot_retrieve_hr_document() -> None:
    results = retrieve_authorized(
        QUERY,
        role="employee",
        n_results=4,
    )

    document_ids = {
        record["document_id"]
        for record in results
    }

    assert HR_DOCUMENT_ID not in document_ids

    for record in results:
        allowed_roles = {
            role.strip()
            for role in record["metadata"][
                "allowed_roles"
            ].split(",")
        }

        assert "employee" in allowed_roles


def test_hr_can_retrieve_hr_document() -> None:
    results = retrieve_authorized(
        QUERY,
        role="hr",
        n_results=4,
    )

    document_ids = {
        record["document_id"]
        for record in results
    }

    assert HR_DOCUMENT_ID in document_ids


def test_unknown_role_fails_closed() -> None:
    with pytest.raises(
        ValueError,
        match="Unsupported role",
    ):
        retrieve_authorized(
            "test",
            role="admin",
        )