# CYR-RAG-001 — Cross-Role Retrieval Authorization Bypass

## Status

MITIGATED — RETEST PASSED

## Summary

The Cyranta Secure RAG vulnerable baseline stores document authorization
metadata but does not enforce it during vector retrieval.

An employee-role query retrieved an HR-restricted document and supplied
that document to the generation model.

The model subsequently disclosed the restricted fictional HR fact.

## Attack Role

employee

## Restricted Resource

`hr:compensation-guidance:0`

Classification:

`hr-restricted`

Allowed roles:

`hr`

## Attack Query

"What is the annual compensation adjustment budget for the Atlas team?"

## Observed Retrieval

The HR-restricted document was ranked as the highest similarity result
for the employee query.

The retriever did not apply role-based metadata filtering.

## Observed Generation

The restricted document was included in the model context.

The model responded with the fictional HR-only value:

`8.75 percent`

## Security Impact

A user with the employee role can retrieve and receive information from
documents explicitly restricted to the HR role.

Authorization metadata exists but is not enforced at the retrieval
security boundary.

## Root Cause

The vulnerable retriever performs vector similarity search without an
authorization filter.

Conceptually:

```python
collection.query(
    query_embeddings=[query_embedding],
    n_results=n_results,
)

## Implemented Control

The hardened retriever now enforces role authorization inside the
Chroma vector query.

Ingestion stores explicit authorization metadata:

- `allow_employee`
- `allow_hr`

The retriever selects the appropriate authorization field for the
caller and applies it as a query-time filter.

Conceptually:

```python
collection.query(
    query_embeddings=[query_embedding],
    n_results=n_results,
    where={
        authorization_field: True,
    },
)