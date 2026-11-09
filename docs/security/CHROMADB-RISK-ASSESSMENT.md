# CYRANTA-DEP-001 — ChromaDB Dependency Risk

Status: OPEN — pending review and acceptance

Component: chromadb
Installed version: 1.5.9
Project: Secure RAG

## Findings
pip-audit reported five vulnerability records covering:
- PYSEC-2026-311
- PYSEC-2026-3813
- PYSEC-2026-3814
- PYSEC-2026-3815

## Verified architecture
- ChromaDB uses an embedded PersistentClient.
- Database files are stored under rag/.chroma.
- No TCP listener was detected on port 8000.
- Standalone server exposure has not been exhaustively ruled out.

## Compensating controls
- Isolated local research environment.
- Fictional demonstration data only.
- No intentional public ChromaDB HTTP endpoint.
- Local database excluded from Git.

## Residual risk
Vulnerable dependency remains installed.
No patched version has been verified.

## Release disposition
Pending security review. Production deployment is not approved.

## Required follow-up
- Review applicable advisories and exposure paths.
- Investigate patched releases.
- Record responsible reviewer and review date.
- Obtain explicit risk acceptance if releasing the isolated lab.
