# CYR-IR-001 — AI Security Alert Investigation Playbook

**Scope:** fictional Cyranta lab. This is an analyst exercise, not a production containment runbook.

## 1. Intake and evidence hygiene

Verify the source is an approved sanitized detector output (`CYR-DET-001`, `006`, or `007`). Record the alert ID, request ID, UTC timestamp, source environment and rule. Keep synthetic exercise files separately from operational lab alerts. Do not paste prompts, customer notes, JWTs, capability bearer values or approval tokens into tickets.

## 2. Validate the signal

- **CYR-DET-001:** a chatbot request was blocked. It does not by itself prove successful prompt injection or unauthorized disclosure.
- **CYR-DET-006:** the tool gateway rejected identity, role, resource or capability scope. Check whether any operation was actually authorized or executed.
- **CYR-DET-007:** a capability or approval was rejected, or emergency revocation was active. `APPROVAL_INVALID_OR_EXPIRED` combines several causes and does **not** establish replay on its own.
- **ALLOWED:** a benign control should produce no security alert; investigate any surprising match.

Correlate trusted request IDs and inspect only the minimum approved supporting evidence. Mark missing or invalid evidence as an investigation gap rather than assuming compromise.

## 3. Classify and respond

Use the dashboard's statuses (`new`, `investigating`, `false_positive`, `confirmed`, `resolved`) only after analyst review. A detection alert and an incident confirmation are distinct decisions. Where justified in a real environment, follow the organization's approval and escalation processes; do not let this educational script revoke real credentials, block users or alter production systems.

## 4. Preserve and close

Generate the case report and `evidence-manifest.json`; verify SHA-256 hashes before review. Restrict access to reports because request identifiers can still be operational metadata. The SHA-256 manifest is unsigned and **does not** establish authenticity, trusted time or complete chain of custody. Record analyst disposition and evidence gaps in the organization's authorized case system.
