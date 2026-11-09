# Cyranta Project 5.4 — Offline AI Governance Dashboard and Audit Report

**Scope:** isolated, fictional research lab. **Not** a security-assured release, risk acceptance, independent audit, compliance certification, or production deployment approval.

## Design

Project 5.4 builds a *self-contained, offline* governance dashboard and matching Markdown and JSON audit views. It reads only:

- **Project 5.1:** declared `assets.json` and `risks.json`, using the existing registry validation.
- **Project 5.2:** declared `controls.json`, evidence *path presence* and explicit known gaps.
- **Project 5.3:** `telemetry/governance/project5-3/test-evidence.json` and `ci-observation.json` if present. It uses Project 5.3's validated test manifest, Git SHA and clean-worktree checks. CI information remains an *unsigned GitHub CLI observation*, not a trusted attestation.

It never reads raw test stdout/stderr or JUnit XML, LLM prompts/responses, `.env`, ChromaDB data, or `telemetry/events.jsonl`. No network connections, subprocesses, JavaScript, remote scripts, or external assets are added by Project 5.4. The output HTML has a restrictive Content Security Policy and HTML-escaped declaration fields. Browser printing is supported; no PDF library required.

## Files to add to the existing Project 5.1–5.3 repository

- `governance/project5/governance_dashboard.py` — offline validation, rendering and exports.
- `governance/project5/tests/test_governance_dashboard.py` — 37 deterministic tests, including invalid/stale CI and test manifests, HTML escaping and path confinement.
- `README-PROJECT5-4-GOVERNANCE-DASHBOARD.md` — this guide.

**Generated output is local only**, under the already ignored `telemetry/governance/` tree:

- `telemetry/governance/project5-4/governance-dashboard.html`
- `telemetry/governance/project5-4/audit-summary.json`
- `telemetry/governance/project5-4/audit-report.md`

Never commit generated snapshots. Avoid uploading audit reports without human review, even though they contain allowlisted metadata.

## Commands (PowerShell from repository root)

```powershell
$py = '.\.venv-agent\Scripts\python.exe'
& $py -m governance.project5.governance_dashboard validate
if ($LASTEXITCODE -ne 0) { throw 'Project 5.4 registry validation failed' }

& $py -m governance.project5.governance_dashboard build `
  --evidence-dir telemetry\governance\project5-3 `
  --output-dir telemetry\governance\project5-4
if ($LASTEXITCODE -ne 0) { throw 'Project 5.4 report generation failed' }

Start-Process (Resolve-Path 'telemetry\governance\project5-4\governance-dashboard.html').Path

& $py -m pytest governance/project5/tests -q
& $py -m pytest -q
& $py -m ruff check .
& $py -m compileall -q governance
& $py -m bandit -q governance/project5/governance_dashboard.py
```

Expected baseline with Project 5.1–5.3: five assets, seven controls, 20 declared evidence-path references, one open risk, seven unassigned control owners. There are **37 new Project 5.4 tests**, giving **167 Project 5 governance tests** and **338 full-repository tests** if the previous 301-test baseline is unchanged. Run and confirm these values locally; do not assume them from the package.

## Evidence semantics

- **Located** means that an expected local file/directory exists; it is *not* proof the control is effective or even that the related test executed.
- **Recorded pass** means an unsigned Project 5.3 local pytest manifest reports a pass.
- **Clean committed test snapshot** requires the manifest's recorded Git SHA to match current HEAD, an originally clean capture, unchanged declared/test-file hashes, and a currently clean Git worktree.
- **GitHub CI reported success** requires the Project 5.3 unsigned GitHub CLI observation to match a completed successful `security-gate` *push* workflow for the current clean HEAD. It is **not a cryptographic CI attestation**.
- **Dirty/stale state:** after adding Project 5.4's source files on a feature branch, the original Project 5.3 recorded results may still appear, but the dashboard must mark the current snapshot as *unverified*. After merging Project 5.4, recollect tests and record the new **post-merge `main`** CI run if you want matched results for the new commit.
- **Missing evidence:** a dashboard can be built showing `not_collected`. Malformed/tampered manifests or incorrectly structured CI observations **stop report generation** rather than silently assert success.

### Risk and approval invariants

`CYRANTA-DEP-001` (embedded ChromaDB 1.5.9) remains **open/pending review**, with historical pip-audit findings not remedied or accepted. The core/agent CI dependency audit does not establish a passing RAG dependency audit. All control owners are **unassigned**. Project 5.4 never computes a compliance percentage or sets `control_effectiveness_verified`, `compliance_certified`, or `security_assured_release_approved` to `true`. The NIST AI RMF and ISO/IEC 42001 text is a proposed *function/theme-level association*, not an audited clause mapping.

## GitHub CI integration

After local pytest, Ruff, compile and Bandit checks pass, add `governance/project5/governance_dashboard.py` to the existing Bandit target list in `scripts/security_gate.sh`. The existing syntax, Ruff and pytest stages already include it. Don't place a `collect` invocation inside the CI `pytest` phase, and don't claim full RAG dependency security while `CYRANTA-DEP-001` remains unresolved. Review all modifications before commit, open a **draft** PR, verify checks, review, then merge and verify the post-merge gate.
