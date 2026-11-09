# Cyranta Secure RAG — Security Model

## Business Scenario

Cyranta Retail operates an internal retrieval-augmented generation assistant
over fictional company documents.

The application supports two roles:

- employee
- hr

The system must only retrieve documents authorized for the current role.

## Document Classification

Every document has:

- document_id
- title
- classification
- allowed_roles
- source
- trust_level

Supported classifications:

- public
- internal
- hr-restricted

Supported trust levels:

- trusted
- untrusted
- adversarial-test

## Authorization Rules

### Employee

May retrieve:

- public
- internal documents authorized for employee

Must never retrieve:

- hr-restricted documents

### HR

May retrieve:

- public
- internal
- hr-restricted documents

## Trust Boundaries

1. User -> authentication / role decision
2. Document -> ingestion pipeline
3. Retriever -> vector database
4. Model output -> user

Retrieved documents are data, not instructions.

## Initial Vulnerable Design

The baseline implementation intentionally:

1. stores role metadata but does not enforce it during retrieval;
2. inserts retrieved text directly into model context;
3. accepts untrusted documents during ingestion;
4. performs no output validation for restricted-context disclosure.

These weaknesses exist only for controlled attack -> control -> retest
demonstration inside the isolated Cyranta lab.