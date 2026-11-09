from __future__ import annotations

from pathlib import Path

from rag.app.ingestion import (
    APPROVED,
    QUARANTINED_HASH_MISMATCH,
    QUARANTINED_UNAPPROVED,
    calculate_sha256,
    determine_provenance,
)


def make_manifest(
    *,
    source: str,
    path: Path,
) -> dict:
    return {
        "schema_version": 1,
        "approved_sources": {
            source: {
                "sha256": calculate_sha256(path),
                "classification": "internal",
                "allowed_roles": [
                    "employee",
                    "hr",
                ],
            }
        },
    }


def test_matching_approved_source_is_trusted(
    tmp_path: Path,
) -> None:
    path = tmp_path / "approved.txt"
    path.write_text(
        "Approved Cyranta content.",
        encoding="utf-8",
    )

    source = (
        "rag/data/employee/approved.txt"
    )

    manifest = make_manifest(
        source=source,
        path=path,
    )

    result = determine_provenance(
        source=source,
        path=path,
        folder_name="employee",
        manifest=manifest,
    )

    assert (
        result["provenance_status"]
        == APPROVED
    )
    assert result["trust_level"] == "trusted"
    assert result["source_approved"] is True
    assert result["hash_match"] is True


def test_unapproved_source_is_quarantined(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unapproved.txt"
    path.write_text(
        "Unapproved Cyranta content.",
        encoding="utf-8",
    )

    result = determine_provenance(
        source=(
            "rag/data/employee/"
            "unapproved.txt"
        ),
        path=path,
        folder_name="employee",
        manifest={
            "schema_version": 1,
            "approved_sources": {},
        },
    )

    assert (
        result["provenance_status"]
        == QUARANTINED_UNAPPROVED
    )
    assert (
        result["trust_level"]
        == "quarantined"
    )
    assert result["source_approved"] is False
    assert result["hash_match"] is False


def test_modified_approved_source_is_quarantined(
    tmp_path: Path,
) -> None:
    path = tmp_path / "approved.txt"
    path.write_text(
        "Original approved content.",
        encoding="utf-8",
    )

    source = (
        "rag/data/employee/approved.txt"
    )

    manifest = make_manifest(
        source=source,
        path=path,
    )

    path.write_text(
        "Tampered approved content.",
        encoding="utf-8",
    )

    result = determine_provenance(
        source=source,
        path=path,
        folder_name="employee",
        manifest=manifest,
    )

    assert (
        result["provenance_status"]
        == QUARANTINED_HASH_MISMATCH
    )
    assert (
        result["trust_level"]
        == "quarantined"
    )
    assert result["source_approved"] is True
    assert result["hash_match"] is False

    assert (
        result["sha256"]
        != result["approved_sha256"]
    )