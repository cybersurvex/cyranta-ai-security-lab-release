# Cyranta Project 6.4 — Finding-to-Governance Traceability

## Scope and provenance

Additive, read-only inspection of **three checked-in historical finding narratives** and **one registered open dependency risk**. The script uses existing Project 5 `registry.py`, `control_mapping.py` and Project 6.1 `schema.validate()` validators, hashes the reviewed source files, and writes **unsigned** local crosswalk metadata. It does not copy finding text, raw logs, prompts, credentials or model responses into reports.

The supplied review archive was validated against SHA-256 `83523035A8282F9092C7D3750BEBEF2FFE91B2827E8079F8D1AD9817836D7297` and contained all 15 requested files. The design uses those inspected files, not an assumed new registry schema.

| Record | Classification | Link basis | Mapped controls |
|---|---|---|---|
| `CYR-LLM-002` | checked-in historical finding | proposed, human-review-only | `CYR-CTL-001` |
| `CYR-DET-003` | checked-in historical finding | proposed, human-review-only | `CYR-CTL-001`, `CYR-CTL-004` |
| `CYR-AGENT-001` | checked-in historical finding, including retest and control-validation narratives | proposed, human-review-only | `CYR-CTL-003`, `CYR-CTL-004` |
| `CYRANTA-DEP-001` | registered open dependency risk | **explicit** `risk_ids` in Project 5 controls registry | `CYR-CTL-006`, `CYR-CTL-007` |

These proposed finding mappings **are not** previously approved governance declarations. The historical documents report tested local remediation, but the module **does not independently inspect the original attack corpus, omitted/ignored raw artifacts, or the source of any retrospective claims**. For example, `CYR-DET-003` references a Garak retest in its narrative but has no separate retest artifact among the 15 reviewed files. The two Project 6.3 incident candidates are explicitly synthetic: **zero** finding/incident links are asserted, and Project 6.1 scenario manifests remain `not_run` with `finding_id: null`.

### What it produces

Three new files are created only in a previously nonexistent ignored directory, default `telemetry/governance/project6-4/`:

```text
telemetry/governance/project6-4/
  traceability-index.json
  traceability-report.md
  evidence-manifest.json
```

The manifest binds 13 reviewed repository source files (three JSON registries, six documentation files, three previous Project 6 Python modules and this module) to SHA-256 values and hashes the two reports. `verify` checks the source hashes, schema, risk-to-control registry links, and a deterministic re-generated index/report. It rejects extra/modified fields, forged assurance approvals, swapped IDs and output manipulation, including when an attacker has edited unsigned hashes to match a modified report.

**This is still unsigned evidence:** hashes do not establish a trusted author, forensic custody or an independently attested source. No control effectiveness, legal/compliance certification, risk acceptance, incident confirmation, production readiness or release approval is concluded. The 5 asset owners, 7 control owners and the `CYRANTA-DEP-001` risk owner remain unassigned, the risk remains `open/pending_review`, and all 7 controls require human review. No registry, Project 6.1 manifest, monitoring code or historical finding file is changed.

## Installation — Windows PowerShell

Run from `C:\AI-Security\cyranta-ai-security-lab` on the existing clean `project6-governance-traceability` branch. Download `cyranta-project6-4-governance-traceability.zip` to Downloads first. **Verify the ZIP SHA-256 printed in the ChatGPT response; do not use a hash copied from an untrusted page.** The ZIP contains only:

```text
README-PROJECT6-4-GOVERNANCE-TRACEABILITY.md
validation/project6/traceability.py
validation/project6/tests/test_traceability.py
```

Extract to a new `$env:TEMP` directory; fail if any destination already exists; copy the files into the repository while preserving relative paths and verifying the copied hashes. Do not replace anything in Project 5 or the earlier Project 6 milestones.

## Run and test

```powershell
$py = ".\.venv-agent\Scripts\python.exe"
& $py -m validation.project6.schema validate
if ($LASTEXITCODE -ne 0) { throw 'STOP: Scenario catalogue invalid' }
& $py -m validation.project6.traceability plan
if ($LASTEXITCODE -ne 0) { throw 'STOP: Traceability planning failed' }
& $py -m validation.project6.traceability build
if ($LASTEXITCODE -ne 0) { throw 'STOP: Traceability build failed' }
& $py -m validation.project6.traceability verify
if ($LASTEXITCODE -ne 0) { throw 'STOP: Traceability verification failed' }
& $py -m pytest validation/project6/tests/test_traceability.py -q
if ($LASTEXITCODE -ne 0) { throw 'STOP: Project 6.4 regression failed' }
& $py -m pytest validation/project6/tests -q
if ($LASTEXITCODE -ne 0) { throw 'STOP: Project 6 regression failed' }
& $py -m pytest -q
if ($LASTEXITCODE -ne 0) { throw 'STOP: Full regression failed' }
& $py -m ruff check .
if ($LASTEXITCODE -ne 0) { throw 'STOP: Ruff failed' }
& $py -m compileall -q validation
if ($LASTEXITCODE -ne 0) { throw 'STOP: Python compilation failed' }
& $py -m bandit -q validation/project6/traceability.py
if ($LASTEXITCODE -ne 0) { throw 'STOP: Bandit failed' }
git check-ignore -q -- telemetry/governance/project6-4/evidence-manifest.json
if ($LASTEXITCODE -ne 0) { throw 'STOP: Evidence is not Git-ignored' }
```

In the reconstructed review fixture, **58** new Project 6.4 tests and **124** Project 6.1+6.4 tests passed. The previous full baseline reported **531** tests; expect about **589** after adding 58 tests, but this **has not** been run on your Windows repository. No local Ruff/Bandit binaries were available in the fixture; run both on Windows before commit. While source files are uncommitted, `worktree_clean_at_capture` and `clean_committed_local_record` should be `false`; `revision_matches` should remain `true` immediately after building.

`build` **refuses to overwrite** an existing evidence directory. For repeat runs, choose another new output path, for example `--output-dir telemetry/governance/project6-4-retest-01`, and pass the same argument to `verify`. After merge, recapture on the new clean `main` SHA in another new directory, e.g. `telemetry/governance/project6-4-postmerge`. Never delete or commit historical evidence to force a rerun.

## CI integration (only after all checks pass)

Append `validation/project6/traceability.py` **once** to the existing Bandit command in `scripts/security_gate.sh`, directly after `validation/project6/correlation.py`. The pytest discovery and Ruff checks already cover the new tests/module. Do not expand the RAG dependency audit gate without reviewing `CYRANTA-DEP-001`; do not modify the Project 5 registries or risk decisions.

Before committing, verify exactly four intended changes: the README, `traceability.py`, `test_traceability.py` and `scripts/security_gate.sh`. Do not commit the `telemetry/` output. After code review and GitHub PR CI, merge normally; then rerun full tests and verify the **post-merge `main` CI run** against its exact new SHA. Rebuild the evidence on that same clean revision.
