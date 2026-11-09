from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import chromadb
import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
RAG_ROOT = REPO_ROOT / "rag"
DATA_ROOT = RAG_ROOT / "data"
CHROMA_PATH = RAG_ROOT / ".chroma"

MANIFEST_PATH = (
    RAG_ROOT
    / "config"
    / "approved_sources.json"
)

PROVENANCE_REPORT_PATH = (
    RAG_ROOT
    / "results"
    / "CYR-RAG-003"
    / "ingestion-provenance-report.json"
)

COLLECTION_NAME = "cyranta_documents"
QUARANTINE_COLLECTION_NAME = "cyranta_quarantine"

OLLAMA_URL = "http://127.0.0.1:11434"
EMBEDDING_MODEL = "nomic-embed-text"


APPROVED = "APPROVED"
QUARANTINED_UNAPPROVED = (
    "QUARANTINED_UNAPPROVED"
)
QUARANTINED_HASH_MISMATCH = (
    "QUARANTINED_HASH_MISMATCH"
)


SOURCE_AUTHORITY_SCORES = {
    "supporting": 1,
    "standard": 2,
    "canonical": 3,
}


@dataclass(frozen=True)
class DocumentPolicy:
    classification: str
    allowed_roles: str


DOCUMENT_POLICIES: dict[
    str,
    DocumentPolicy,
] = {
    "public": DocumentPolicy(
        classification="public",
        allowed_roles="employee,hr",
    ),
    "employee": DocumentPolicy(
        classification="internal",
        allowed_roles="employee,hr",
    ),
    "hr": DocumentPolicy(
        classification="hr-restricted",
        allowed_roles="hr",
    ),
    "poisoned": DocumentPolicy(
        classification="internal",
        allowed_roles="employee,hr",
    ),
}


def chunk_text(
    text: str,
    *,
    chunk_size: int = 700,
    overlap: int = 100,
) -> list[str]:
    cleaned = text.strip()

    if not cleaned:
        return []

    if chunk_size <= 0:
        raise ValueError(
            "chunk_size must be greater than zero"
        )

    if overlap < 0:
        raise ValueError(
            "overlap cannot be negative"
        )

    if overlap >= chunk_size:
        raise ValueError(
            "overlap must be smaller than chunk_size"
        )

    chunks: list[str] = []
    start = 0

    while start < len(cleaned):
        end = min(
            start + chunk_size,
            len(cleaned),
        )

        chunk = cleaned[
            start:end
        ].strip()

        if chunk:
            chunks.append(chunk)

        if end >= len(cleaned):
            break

        start = end - overlap

    return chunks


def embed_texts(
    texts: list[str],
) -> list[list[float]]:
    if not texts:
        return []

    response = httpx.post(
        f"{OLLAMA_URL}/api/embed",
        json={
            "model": EMBEDDING_MODEL,
            "input": texts,
        },
        timeout=120.0,
    )
    response.raise_for_status()

    payload = response.json()

    embeddings = payload.get(
        "embeddings"
    )

    if not isinstance(
        embeddings,
        list,
    ):
        raise RuntimeError(  # noqa: TRY004
            "Ollama response did not "
            "contain embeddings"
        )

    if len(embeddings) != len(texts):
        raise RuntimeError(
            "Embedding count does not "
            "match input text count"
        )

    return embeddings


def calculate_sha256(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            block = handle.read(
                1024 * 1024
            )

            if not block:
                break

            digest.update(block)

    return digest.hexdigest().upper()


def load_approved_sources() -> dict[str, Any]:
    if not MANIFEST_PATH.exists():
        raise RuntimeError(
            "Approved-source manifest "
            f"missing: {MANIFEST_PATH}"
        )

    payload = json.loads(
        MANIFEST_PATH.read_text(
            encoding="utf-8",
        )
    )

    if payload.get("schema_version") != 1:
        raise RuntimeError(
            "Unsupported approved-source "
            "manifest schema"
        )

    approved_sources = payload.get(
        "approved_sources"
    )

    if not isinstance(
        approved_sources,
        dict,
    ):
        raise RuntimeError(  # noqa: TRY004
            "Manifest does not contain "
            "approved_sources"
        )

    return payload


def determine_provenance(
    *,
    source: str,
    path: Path,
    folder_name: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    policy = DOCUMENT_POLICIES[
        folder_name
    ]

    actual_sha256 = calculate_sha256(
        path
    )

    approved_sources = manifest[
        "approved_sources"
    ]

    approved_entry = approved_sources.get(
        source
    )

    if approved_entry is None:
        return {
            "provenance_status": (
                QUARANTINED_UNAPPROVED
            ),
            "trust_level": "quarantined",
            "source_approved": False,
            "hash_match": False,
            "sha256": actual_sha256,
            "approved_sha256": "",
            "classification": (
                policy.classification
            ),
            "allowed_roles": (
                policy.allowed_roles
            ),
            "source_authority": (
                "unapproved"
            ),
            "source_authority_score": 0,
        }

    expected_sha256 = str(
        approved_entry["sha256"]
    ).upper()

    hash_match = (
        actual_sha256
        == expected_sha256
    )

    classification = str(
        approved_entry[
            "classification"
        ]
    )

    manifest_roles = approved_entry[
        "allowed_roles"
    ]

    if not isinstance(
        manifest_roles,
        list,
    ):
        raise RuntimeError(  # noqa: TRY004
            "allowed_roles must be a list "
            f"for approved source {source}"
        )

    allowed_roles = ",".join(
        str(role)
        for role in manifest_roles
    )

    source_authority = str(
        approved_entry.get(
            "source_authority",
            "standard",
        )
    ).strip().lower()

    if (
        source_authority
        not in SOURCE_AUTHORITY_SCORES
    ):
        raise RuntimeError(
            "Unsupported source_authority "
            f"for approved source {source}: "
            f"{source_authority}"
        )

    source_authority_score = (
        SOURCE_AUTHORITY_SCORES[
            source_authority
        ]
    )

    if not hash_match:
        return {
            "provenance_status": (
                QUARANTINED_HASH_MISMATCH
            ),
            "trust_level": "quarantined",
            "source_approved": True,
            "hash_match": False,
            "sha256": actual_sha256,
            "approved_sha256": (
                expected_sha256
            ),
            "classification": (
                classification
            ),
            "allowed_roles": (
                allowed_roles
            ),
            "source_authority": (
                source_authority
            ),
            "source_authority_score": (
                source_authority_score
            ),
        }

    return {
        "provenance_status": APPROVED,
        "trust_level": "trusted",
        "source_approved": True,
        "hash_match": True,
        "sha256": actual_sha256,
        "approved_sha256": (
            expected_sha256
        ),
        "classification": (
            classification
        ),
        "allowed_roles": (
            allowed_roles
        ),
        "source_authority": (
            source_authority
        ),
        "source_authority_score": (
            source_authority_score
        ),
    }


def build_records() -> dict[
    str,
    Any,
]:
    manifest = load_approved_sources()

    approved: dict[
        str,
        list[Any],
    ] = {
        "ids": [],
        "documents": [],
        "metadatas": [],
    }

    quarantined: dict[
        str,
        list[Any],
    ] = {
        "ids": [],
        "documents": [],
        "metadatas": [],
    }

    provenance_files: list[
        dict[str, Any]
    ] = []

    for folder_name in DOCUMENT_POLICIES:
        folder = (
            DATA_ROOT
            / folder_name
        )

        if not folder.exists():
            raise RuntimeError(
                "Missing data directory: "
                f"{folder}"
            )

        for path in sorted(
            folder.glob("*.txt")
        ):
            source = (
                path.relative_to(
                    REPO_ROOT
                )
                .as_posix()
            )

            provenance = (
                determine_provenance(
                    source=source,
                    path=path,
                    folder_name=folder_name,
                    manifest=manifest,
                )
            )

            allowed_roles = {
                role.strip()
                for role in provenance[
                    "allowed_roles"
                ].split(",")
            }

            text = path.read_text(
                encoding="utf-8"
            )

            chunks = chunk_text(text)

            provenance_files.append(
                {
                    "source": source,
                    "sha256": provenance[
                        "sha256"
                    ],
                    "approved_sha256": (
                        provenance[
                            "approved_sha256"
                        ]
                    ),
                    "provenance_status": (
                        provenance[
                            "provenance_status"
                        ]
                    ),
                    "trust_level": (
                        provenance[
                            "trust_level"
                        ]
                    ),
                    "classification": (
                        provenance[
                            "classification"
                        ]
                    ),
                    "allowed_roles": (
                        provenance[
                            "allowed_roles"
                        ]
                    ),
                    "source_authority": (
                        provenance[
                            "source_authority"
                        ]
                    ),
                    "source_authority_score": (
                        provenance[
                            "source_authority_score"
                        ]
                    ),
                    "chunk_count": len(
                        chunks
                    ),
                }
            )

            destination = (
                approved
                if provenance[
                    "provenance_status"
                ]
                == APPROVED
                else quarantined
            )

            for index, chunk in enumerate(
                chunks
            ):
                document_id = (
                    f"{folder_name}:"
                    f"{path.stem}:"
                    f"{index}"
                )

                metadata = {
                    "document_id": (
                        document_id
                    ),
                    "filename": path.name,
                    "source": source,
                    "source_group": (
                        folder_name
                    ),
                    "chunk_index": index,
                    "classification": (
                        provenance[
                            "classification"
                        ]
                    ),
                    "allowed_roles": (
                        provenance[
                            "allowed_roles"
                        ]
                    ),
                    "allow_employee": (
                        "employee"
                        in allowed_roles
                    ),
                    "allow_hr": (
                        "hr"
                        in allowed_roles
                    ),
                    "trust_level": (
                        provenance[
                            "trust_level"
                        ]
                    ),
                    "provenance_status": (
                        provenance[
                            "provenance_status"
                        ]
                    ),
                    "source_approved": (
                        provenance[
                            "source_approved"
                        ]
                    ),
                    "hash_match": (
                        provenance[
                            "hash_match"
                        ]
                    ),
                    "sha256": (
                        provenance[
                            "sha256"
                        ]
                    ),
                    "approved_sha256": (
                        provenance[
                            "approved_sha256"
                        ]
                    ),
                    "source_authority": (
                        provenance[
                            "source_authority"
                        ]
                    ),
                    "source_authority_score": (
                        provenance[
                            "source_authority_score"
                        ]
                    ),
                    "manifest_schema_version": (
                        int(
                            manifest[
                                "schema_version"
                            ]
                        )
                    ),
                }

                destination[
                    "ids"
                ].append(
                    document_id
                )

                destination[
                    "documents"
                ].append(
                    chunk
                )

                destination[
                    "metadatas"
                ].append(
                    metadata
                )

    return {
        "approved": approved,
        "quarantined": quarantined,
        "provenance_files": (
            provenance_files
        ),
    }


def recreate_collection(
    client: chromadb.ClientAPI,
    *,
    name: str,
    metadata: dict[str, Any],
):
    existing_names = {
        collection.name
        for collection
        in client.list_collections()
    }

    if name in existing_names:
        client.delete_collection(
            name=name
        )

    return client.create_collection(
        name=name,
        metadata=metadata,
    )


def ingest() -> None:
    records = build_records()

    approved = records["approved"]
    quarantined = records[
        "quarantined"
    ]

    approved_documents = approved[
        "documents"
    ]

    quarantined_documents = (
        quarantined["documents"]
    )

    total_chunks = (
        len(approved_documents)
        + len(
            quarantined_documents
        )
    )

    if total_chunks == 0:
        raise RuntimeError(
            "No Cyranta documents "
            "were found"
        )

    print(
        "Documents/chunks discovered:",
        total_chunks,
    )

    print(
        "Embedding model:",
        EMBEDDING_MODEL,
    )

    approved_embeddings = embed_texts(
        approved_documents
    )

    quarantine_embeddings = embed_texts(
        quarantined_documents
    )

    client = chromadb.PersistentClient(
        path=str(CHROMA_PATH),
    )

    approved_collection = (
        recreate_collection(
            client,
            name=COLLECTION_NAME,
            metadata={
                "project": (
                    "Cyranta Secure "
                    "RAG Lab"
                ),
                "security_state": (
                    "provenance-enforced"
                ),
            },
        )
    )

    quarantine_collection = (
        recreate_collection(
            client,
            name=(
                QUARANTINE_COLLECTION_NAME
            ),
            metadata={
                "project": (
                    "Cyranta Secure "
                    "RAG Lab"
                ),
                "security_state": (
                    "quarantine"
                ),
            },
        )
    )

    if approved_documents:
        approved_collection.upsert(
            ids=approved["ids"],
            documents=(
                approved_documents
            ),
            metadatas=(
                approved["metadatas"]
            ),
            embeddings=(
                approved_embeddings
            ),
        )

    if quarantined_documents:
        quarantine_collection.upsert(
            ids=quarantined["ids"],
            documents=(
                quarantined_documents
            ),
            metadatas=(
                quarantined[
                    "metadatas"
                ]
            ),
            embeddings=(
                quarantine_embeddings
            ),
        )

    provenance_records = records[
        "provenance_files"
    ]

    approved_files = [
        item
        for item in provenance_records
        if item[
            "provenance_status"
        ]
        == APPROVED
    ]

    quarantined_files = [
        item
        for item in provenance_records
        if item[
            "provenance_status"
        ]
        != APPROVED
    ]

    report = {
        "manifest": (
            MANIFEST_PATH.relative_to(
                REPO_ROOT
            ).as_posix()
        ),
        "approved_collection": (
            COLLECTION_NAME
        ),
        "quarantine_collection": (
            QUARANTINE_COLLECTION_NAME
        ),
        "approved_file_count": len(
            approved_files
        ),
        "quarantined_file_count": len(
            quarantined_files
        ),
        "approved_chunk_count": (
            approved_collection.count()
        ),
        "quarantined_chunk_count": (
            quarantine_collection.count()
        ),
        "files": provenance_records,
    }

    PROVENANCE_REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    PROVENANCE_REPORT_PATH.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    print()

    for item in provenance_records:
        print(
            f"{item['provenance_status']}: "
            f"{item['source']}"
        )

    print()

    print(
        "Approved collection:",
        COLLECTION_NAME,
    )

    print(
        "Approved records:",
        approved_collection.count(),
    )

    print(
        "Quarantine collection:",
        QUARANTINE_COLLECTION_NAME,
    )

    print(
        "Quarantined records:",
        quarantine_collection.count(),
    )

    print(
        "Provenance report:",
        PROVENANCE_REPORT_PATH,
    )

    print(
        "Chroma path:",
        CHROMA_PATH,
    )


if __name__ == "__main__":
    ingest()