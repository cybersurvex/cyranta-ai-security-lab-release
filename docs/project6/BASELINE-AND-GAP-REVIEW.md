# Cyranta Project 6.0–6.1 — Baseline and Scope Review

**Scope:** fictional, isolated local security lab. This note is based on the owner's reported terminal checks and the existing Project 5 registry declarations. It is **not** a live vulnerability scan or independently validated audit.

## Reported Git baseline

- Last confirmed `main` merge commit before Project 6: `90245aa` (Project 5.4).
- Full regression baseline: **338 passing tests**, verified by owner from synchronized, clean `main` before creating `project6-scenario-catalogue`.
- Project 5.3 selected assurance suites: five passing, 191 recorded test cases at the same clean `main` commit.
- Project 5.4 offline dashboard reported 5 assets, 7 internal controls, 20 located evidence paths and 1 open registered risk.
- The GitHub CLI observation for run `39634725772` was reported successful for that main revision. **Unsigned; not independent attestation.**

## Unresolved security and governance risks — carry forward without edits

- `CYRANTA-DEP-001`: ChromaDB `1.5.9` dependency risk; status **open**, decision **pending_review**, owner **null**. Historical dependency audit recorded five findings across `PYSEC-2026-311`, `PYSEC-2026-3813`, `PYSEC-2026-3814`, `PYSEC-2026-3815`. No verified remediation or authorized acceptance is claimed.
- `CYR-AST-001` through `005`: five unassigned asset owners.
- `CYR-CTL-001` through `007`: seven unassigned control owners, all requiring human review and declaring known gaps.
- `CYR-CTL-006` (dependency risk): **no passing scenario** or CI green status can close or verify it. The RAG dependency audit remains outside the passing core/agent CI gates.
- No compliance certification, independently verified control effectiveness or security-assured production release authorization.

## Existing findings and adapter interfaces require local inspection

Project 6.1 does not claim that scenario identifiers are real exploit findings. The six JSON records contain `finding_id: null`, `registered_risk_ids: []`, `execution_status: not_run` and metadata-only fixtures. These fields cannot be changed by this validator; a future reviewed schema migration is necessary for linked evidence.

Before Project 6.2 execution, **inspect actual local repository contents** rather than assume that historical examples are complete evidence:

```powershell
Get-ChildItem findings,agent\findings,results,docs\security -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object FullName,Length

Select-String -Path app\security.py,agent\security\tool_gateway.py,monitoring\detector.py,monitoring\gateway_detection.py -Pattern '^def |^class '

Get-ChildItem rag\app -Recurse -File -Filter '*.py' |
    Select-String -Pattern '^def |^class '

& '.\.venv-agent\Scripts\python.exe' -m validation.project6.schema validate
```

**Do not open, copy or commit local `.env` or raw telemetry**, and do not automatically import old findings as verified. Confirm source IDs and artifacts manually before adding traceability links.

## Threat boundaries

- Untrusted or malicious source material is inert **metadata** in 6.1, not an instruction to the assistant, CLI or agent.
- Six exact allowlisted scenarios; no arbitrary files, paths, network calls, tool invocations or local attack subprocesses.
- Each control is cross-referenced to at least one declared Project 5 asset and must exist in the registry.
- No current-principal, credential, real prompt, real restricted document, command, live token, or customer record in the fixture files.
- Any genuine execution in Project 6.2 requires specific tested adapters, safety oracle assertions and new review.
