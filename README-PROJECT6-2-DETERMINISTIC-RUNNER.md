# Cyranta Project 6.2 — Deterministic AI Security Validation Runner

**Scope:** isolated, fictional Cyranta research lab. **No live attacks, no Ollama calls, no real database queries, no independent verification, no compliance claims, no risk acceptance, no release approval.**

## What this milestone builds

Three new, version-controlled files:

- `validation/project6/runner.py` — fixed six-scenario offline security adapter runner and local report CLI.
- `validation/project6/tests/test_runner.py` — 72 deterministic tests for valid and invalid outcomes, source changes, path safety, malicious metadata and stale revision state.
- This README.

Expand the existing `scripts/security_gate.sh` Bandit target to include `validation/project6/runner.py` **after successful local tests**. Existing Project 6.1 manifests, fixtures, registry records and Projects 1–5 remain unchanged.

## Security control adapters and limits

| Scenario | Calls into existing Cyranta security code | What the result actually establishes |
|---|---|---|
| `CYR-P6-SCN-001` | `app.security.assess_input`, `redact_output` | Hardened direct-injection signal and planted-fake-marker redaction behave as expected on a fixed input |
| `CYR-P6-SCN-002` | `app.security.assess_input` | A fixed Base64-encoded sensitive-access request is detected and blocked |
| `CYR-P6-SCN-003` | `rag.app.retriever.retrieve_authorized` | A fixed `allow_employee` filter is requested; an **in-memory fake query selector**, not Chroma, filters a restricted fixture |
| `CYR-P6-SCN-004` | `retrieve_trusted_authorized`, `rag.app.generation.build_trusted_context` | `allow_employee` + `trust_level=trusted` are requested; untrusted fixture is absent from the simulated context |
| `CYR-P6-SCN-005` | `agent.security.tool_gateway.ToolGateway.execute` with `MockRetailTools` | Fictional unapproved refund is denied and mock tool state is not mutated |
| `CYR-P6-SCN-006` | `monitoring.detector.detect_blocked_request`, `gateway_detection.normalize_gateway_audit`/`detect_gateway_decision`, `ToolGateway.execute` | Two fixed synthetic blocked events produce sanitized alerts retaining their respective request IDs |

**Important:** RAG checks do **not** exercise the actual ChromaDB filtering implementation, embeddings, ingestion, Ollama, generated answers, or live prompt-injection resistance. The monitoring check does not establish cross-event incident correlation or retest traces (planned in Project 6.3). `expected_decision` and `observed_decision` describe narrow fixture assertions, not broad security policy conclusions. Failure or import errors always produce `not_established` instead of a passing observation.

## Evidence separation

The Project 6.1 JSON scenario definitions remain `execution_status: not_run`, with `finding_id: null`, empty registered risk links and `contains_live_payload: false`. Project 6.2 produces **separate local, unsigned** evidence under the existing ignored telemetry/governance tree:

- `telemetry/governance/project6-2/execution-evidence.json`
- `telemetry/governance/project6-2/execution-report.md`

The JSON records the current Git HEAD, clean-worktree flag, hashes of fixed code and catalogue files, six status/decision enums and aggregate totals. It intentionally stores **no** raw prompts, retrieved documents, bearer tokens, tool arguments, raw telemetry, model responses, exceptions or stack traces.

Source hashes detect some accidental source changes but **do not authenticate execution or prevent a local attacker from forging evidence**. A `clean_committed_local_record: true` is an integrity-context observation, not independent attestation. The report rejects unexpected fields, altered references, changed source hashes, contradicted totals, added release approvals and unsafe paths.

## Windows PowerShell — local feature branch

Run from `C:\AI-Security\cyranta-ai-security-lab` on branch `project6-deterministic-runner`:

```powershell
$py = '.\.venv-agent\Scripts\python.exe'

& $py -m validation.project6.runner plan
if ($LASTEXITCODE -ne 0) { throw 'STOP: Plan failed' }

& $py -m validation.project6.runner run
if ($LASTEXITCODE -ne 0) { throw 'STOP: One or more offline control checks failed' }

& $py -m validation.project6.runner report
if ($LASTEXITCODE -ne 0) { throw 'STOP: Local report rejected' }

Get-Content telemetry\governance\project6-2\execution-report.md -Encoding UTF8

& $py -m pytest validation/project6/tests -q
if ($LASTEXITCODE -ne 0) { throw 'STOP: Project 6 tests failed' }

& $py -m pytest -q
if ($LASTEXITCODE -ne 0) { throw 'STOP: Full regression failed' }

& $py -m ruff check .
if ($LASTEXITCODE -ne 0) { throw 'STOP: Ruff failed' }

& $py -m compileall -q validation
if ($LASTEXITCODE -ne 0) { throw 'STOP: Python compilation failed' }

& $py -m bandit -q validation/project6/schema.py validation/project6/runner.py
if ($LASTEXITCODE -ne 0) { throw 'STOP: Bandit needs investigation' }
```

Expected on the unchanged baseline: six checks passing; 66 Project 6.1 tests plus **72 new Project 6.2 tests**, 138 Project 6 tests total. If all 404 baseline regression tests remain, full pytest should collect **476 tests**; check actual output. Fresh untracked/modified files mean `worktree_clean_at_run: false`, which is expected. Re-run on clean committed merge commit for a current clean snapshot.

The RAG Python dependencies must be available to import the existing retriever/generation modules. Do not run a live Chroma or Ollama service for this milestone. The CI job's existing core/agent dependency audit deliberately does not resolve the ChromaDB Project 5 registered risk.

## CI integration

After Windows validation, append `validation/project6/runner.py` to the Bandit scan target in `scripts/security_gate.sh`; the script already compiles `validation` and scans `pytest -q`, so no recursive test execution should be added. The `run` CLI is **not** part of the core CI gate in Project 6.2 because the installed RAG dependency environment can vary; its fixed regression tests provide offline CI coverage. Validate the modified security gate with `git diff --check` and the normal PR/merge process.

## Governance boundaries

- `CYRANTA-DEP-001` for `chromadb==1.5.9`: open/pending review; **not accepted or fixed**.
- All seven control owners and five asset owners remain unassigned. Risk owner unassigned.
- Controls continue to require human review. A passing local check does not prove operational control effectiveness.
- `live_attacks_executed`, `independently_attested`, `control_effectiveness_verified`, `compliance_certified` and `security_assured_release_approved` are **always false**.
- Do not upload local execution evidence or sensitive workspace data to the public repository.
