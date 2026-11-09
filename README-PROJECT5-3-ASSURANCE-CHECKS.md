# Cyranta Project 5.3 — Automated AI Security Assurance Checks

**Scope:** isolated fictional research lab. **Never treat this package as a security-assured release, independently verified control effectiveness, compliance certification, or a formal risk decision.**

## Baseline / prerequisites

The installed Project 5.1–5.2 files must already exist at `governance/project5/`: `registry.py`, `control_mapping.py`, `assets.json`, `risks.json`, `controls.json`. Run from the repository root on the `project5-assurance-checks` Git branch using `.venv-agent\Scripts\python.exe`. The existing `telemetry/governance/` `.gitignore` rule hides generated evidence reports; **do not add those generated reports to Git**.

This package adds only three version-controlled files:

- `governance/project5/assurance_checks.py` — fixed-group, offline pytest capture; sanitized execution metadata and integrity checks; optional *explicit* live GitHub CLI metadata query; local report.
- `governance/project5/tests/test_assurance_checks.py` — 45 deterministic test cases, including real execution against isolated synthetic test files, test failures, skipped tests, modified source files, unsafe paths, stale Git/CI status, and tampered metadata.
- This README.

## Five fixed test groups

| Group | Fixed test modules | Associated internal controls |
|---|---|---|
| `chatbot` | `tests/test_security.py`; `monitoring/tests/test_detector.py` | CYR-CTL-001 |
| `rag` | `rag/tests/test_access_control.py`; `rag/tests/test_provenance.py` | CYR-CTL-002 |
| `agent` | `agent/tests/test_tool_gateway.py` | CYR-CTL-003 |
| `monitoring` | `monitoring/tests/test_gateway_detection.py`; `monitoring/tests/test_incident_simulation.py` | CYR-CTL-004, 005 |
| `governance` | `governance/project5/tests/test_registry.py`; `governance/project5/tests/test_control_mapping.py` | CYR-CTL-007 |

**CYR-CTL-006 is not marked passed.** ChromaDB 1.5.9 `CYRANTA-DEP-001` remains **open**, with five historical pip-audit records across four advisory IDs, no verified remediation or authorized acceptance. Core/agent CI dependency checks do not close RAG dependency risk. No risk or control owner is assigned.

`collect` launches the fixed test modules in five subprocesses using the current Python interpreter and `python -m pytest`. It **does not** permit arbitrary commands or test paths supplied by the caller. Per-suite subprocess timeout defaults to 180 seconds. It parses temporary, bounded JUnit XML and stores **only** sanitized counts, suite state, Git HEAD, clean-worktree flag, and SHA-256 source/test-file hashes. It does **not** persist pytest stdout/stderr, raw JUnit XML, credential files, local telemetry or prompt contents. Failed, skipped, empty, timed-out or missing test suites are **not** counted as passed.

## PowerShell steps (local feature branch)

```powershell
$py = '.\.venv-agent\Scripts\python.exe'
& $py -m governance.project5.assurance_checks plan
if ($LASTEXITCODE -ne 0) { throw 'Plan failed' }

& $py -m governance.project5.assurance_checks collect --output-dir telemetry\governance\project5-3
if ($LASTEXITCODE -ne 0) { throw 'Collection failed; inspect sanitized test-evidence.json' }

& $py -m governance.project5.assurance_checks report --output-dir telemetry\governance\project5-3
if ($LASTEXITCODE -ne 0) { throw 'Assurance report failed' }

Get-Content telemetry\governance\project5-3\assurance-summary.json -Encoding UTF8
Get-Content telemetry\governance\project5-3\assurance-report.md -Encoding UTF8

& $py -m ruff check .
& $py -m pytest governance/project5/tests -q
& $py -m pytest -q
& $py -m compileall -q governance
& $py -m bandit -q governance/project5/assurance_checks.py
```

**Expected in the unmodified repo:** 5 planned suites, all 5 locally passing, 7 control records, 1 open dependency risk, no release approval. The isolated authoring fixture passed 45 Project 5.3 tests and 130 combined governance tests. If baseline remains 256 tests, a full suite of **301 collected tests** is expected (a symlink-restriction test may skip on some Windows environments). These counts must be confirmed on your computer.

When the new files are untracked or staged, Git is **dirty**. Therefore initial `worktree_clean_at_capture` and `clean_committed_snapshot` will normally be **false**; this is correct. After committing the files and validating CI, rerun `collect` and `report` on the clean branch to get a snapshot associated with a committed Git HEAD. After merging, rerun on the updated clean `main` because the merge commit is a different revision.

The report is a **record**, not proof that the tests genuinely ran: unsigned local JSON, hashes, time and terminal logs can all be forged. Even when a clean commit and locally recorded passing tests match, **control effectiveness remains false** pending independent review.

## Optional GitHub Actions verification

Only on explicit user command, `ci-check` invokes `gh run view <numeric-id> --json status,conclusion,headSha,event,workflowName` using the authenticated GitHub CLI configured on the user's computer. It stores a small metadata observation, not untrusted workflow logs. The observation is considered relevant to the *current clean repository* only when the GitHub-reported completed successful **push** run for workflow `security-gate` exactly matches current `git HEAD` **and** the working tree is clean. Pull-request runs, historical successful runs, and dirty branches do **not** satisfy this check. This is an API-reported observation, **not a cryptographic attestation**.

For illustration only, the known historical successful Project 5.2 `main` run is **39299690492** at commit `706cf6eee82d7eeb1bf28049f925482f4ae3e2a4`. This **does not verify Project 5.3 changes**. Do not reuse it to claim Project 5.3 passed CI.

After merging Project 5.3 and confirming the **new** `main` push workflow ID:

```powershell
& $py -m governance.project5.assurance_checks ci-check --run-id <NEW_MAIN_PUSH_RUN_ID> --output-dir telemetry\governance\project5-3
& $py -m governance.project5.assurance_checks report --output-dir telemetry\governance\project5-3
```

Use the numeric ID without angle brackets. The `ci-check` command needs working `gh` authentication and network access. `plan`, `collect` and `report` do not contact GitHub or other remote services (note: installed test files themselves control their own external behavior).

## Integrate into existing CI gate

After *local* Ruff, Bandit and full pytest validation pass, append `governance/project5/assurance_checks.py` to the existing `bandit -q -r ... governance/project5/registry.py governance/project5/control_mapping.py` command in `scripts/security_gate.sh`. The script already compiles `governance`, while Ruff and pytest scan the whole repository. Do not add an automatically generated `collect` run inside its own `pytest` phase: it would recursively start pytest inside pytest if called from a test, and could create undesirable CI overhead.

## Limitations and final release decision

- The `assurance-summary.json` contains `recorded_test_pass` and `clean_committed_snapshot`; these are **not** independent test-origin attestations.
- The actual pytest environment, installed dependency versions and runtime configuration are not fully captured or attested.
- Framework references remain broad, unofficial NIST AI RMF and ISO/IEC 42001 management themes from Project 5.2—not audited normative clauses.
- `controls_needing_human_review` remains seven; `control_effectiveness_verified`, `compliance_certified` and `security_assured_release_approved` are always **false**.
- The RAG ChromaDB advisory set and unassigned owners remain unresolved.

**Project 5.3 cannot approve release or accept risk.**
