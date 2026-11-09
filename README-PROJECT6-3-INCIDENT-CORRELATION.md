# Cyranta Project 6.3 — Synthetic Detection and Incident Correlation

## What this does

An **additive offline exercise** for `project6-incident-correlation` based on Project 4's existing `scan_jsonl()`, `load_alerts()`, `generate()`, `detect_blocked_request()` and `detect_gateway_decision()` interfaces. It creates **fixed fictional events**, produces the normal Project 4 sanitized alerts and offline HTML dashboard, groups alerts using only a validated request UUID and a 300-second time window, writes an analyst-response checklist and verifies unsigned local evidence.

The Project 4.4 incident simulator and the six Project 6.1 scenario manifests are **unchanged**. This package does not call an LLM, ChromaDB, a live gateway, a service or a network endpoint. The shared request ID is deliberately assigned to two fictional records to **test correlation logic**; it is not proof that unrelated real system events occurred in one transaction.

## Expected exercise results

- **5 synthetic event rows:** blocked chatbot, denied tool, expired-approval tool, one duplicate blocked row, one benign allowed decision.
- **3 sanitized alerts:** `CYR-DET-001`, `CYR-DET-006`, `CYR-DET-007`.
- **2 incident candidates:** one pair with a shared UUID within 60 seconds; one independent authorization-expiry alert with a distinct UUID.
- **1 duplicate and 1 benign row ignored**, and no confirmed incidents or analyst triage.
- **55 new tests** added. Prior baseline was 476; expect approximately **531** repository tests after install, subject to the actual test collection.

## Files supplied

```text
README-PROJECT6-3-INCIDENT-CORRELATION.md
validation/project6/correlation.py
validation/project6/tests/test_correlation.py
```

All previous Project 1–5 and Project 6.1–6.2 source remains untouched. To integrate the new module with CI, add `validation/project6/correlation.py` to the existing Bandit file list in `scripts/security_gate.sh` after local checks pass; syntax validation already recursively checks `validation` and pytest already discovers its tests.

## Windows PowerShell commands (run from the repository)

```powershell
cd C:\AI-Security\cyranta-ai-security-lab
$py = ".\.venv-agent\Scripts\python.exe"
if ((git branch --show-current) -ne 'project6-incident-correlation') { throw 'STOP: Wrong branch' }
& $py -m validation.project6.schema validate
if ($LASTEXITCODE -ne 0) { throw 'STOP: Scenario catalogue invalid' }
& $py -m validation.project6.correlation run
if ($LASTEXITCODE -ne 0) { throw 'STOP: Correlation exercise failed' }
& $py -m validation.project6.correlation verify
if ($LASTEXITCODE -ne 0) { throw 'STOP: Evidence verification failed' }
& $py -m pytest validation/project6/tests/test_correlation.py -q
if ($LASTEXITCODE -ne 0) { throw 'STOP: Project 6.3 tests failed' }
& $py -m pytest -q
if ($LASTEXITCODE -ne 0) { throw 'STOP: Full regression failed' }
& $py -m ruff check .
if ($LASTEXITCODE -ne 0) { throw 'STOP: Ruff failed' }
& $py -m compileall -q validation
if ($LASTEXITCODE -ne 0) { throw 'STOP: Python syntax validation failed' }
& $py -m bandit -q validation/project6/correlation.py
if ($LASTEXITCODE -ne 0) { throw 'STOP: Bandit failed' }
```

The default output is `telemetry/governance/project6-3`. The runner **refuses to overwrite** a prior exercise. For a second run choose an entirely new path below the ignored governance tree, e.g. `--output-dir telemetry/governance/project6-3-retest-01` (the same path must be used for the subsequent `verify`). Do not commit generated files or paste raw telemetry into a pull request.

Generated files:

```text
telemetry/governance/project6-3/
  events.jsonl
  alerts.jsonl
  dashboard.html
  incident-cases.json
  incident-report.md
  response-playbook.md
  evidence-manifest.json
```

Evidence has SHA-256 file and source checks, exact synthetic-event and sanitized-alert allowlists, a Git revision, and a clean-worktree flag. It is **unsigned** and proves neither source authenticity nor forensic chain of custody. While the branch is uncommitted, `clean_committed_local_record` is expected `false`; after merge, recapture into a fresh folder on clean `main`. The Project 6.1 manifests remain `execution_status: not_run`, and `project6_2_evidence_link_verified` is **false**—Project 6.4 will consider traceability without inventing links.

## Required security boundary and governance limits

- No prompts, model replies, secrets, bearer tokens, tool arguments, user IDs, or real customer data are copied into evidence.
- No production containment, automatic triage, incident confirmation, approval, compliance certification or risk acceptance occurs.
- Project 5 dependency risk `CYRANTA-DEP-001` remains open and governance owners remain unassigned.
- `control_effectiveness_verified=false`, `independently_attested=false`, `compliance_certified=false`, and `security_assured_release_approved=false` continue to hold.
- CI success will validate these *offline local contracts*, not live prompt-injection resistance or production readiness.
