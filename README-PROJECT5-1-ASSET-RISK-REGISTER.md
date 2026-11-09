# Project 5.1 — Offline AI Asset Inventory and Risk Register

**Scope:** isolated, fictional Cyranta research lab. This is **not** a production security assurance or a compliance certification.

## Purpose

Project 5.1 creates a version-controlled, machine-validated *declaration* of five known Cyranta components and the outstanding `CYRANTA-DEP-001` risk. It does not perform network discovery, live vulnerability scans, risk scoring, audit certification, or risk acceptance. It does not read `.env`, raw prompts, chat responses, local telemetry, or ChromaDB records.

## Files

- `governance/project5/assets.json` — baseline inventory of 5 components, with **owner `null`** until explicitly reviewed.
- `governance/project5/risks.json` — the **open**, **pending-review** ChromaDB risk, 5 audit records / 4 distinct advisory IDs.
- `governance/project5/registry.py` — standard-library-only validation and offline reporting CLI.
- `governance/project5/tests/test_registry.py` — deterministic tests (including deliberate failures).
- `governance/project5/__init__.py` — Python package marker.

The source-reference paths in the JSON files come from prior lab work; they are references, **not attestations that files are deployed**. Run the CLI from the repository root.

## Commands

```powershell
$py = ".\.venv-agent\Scripts\python.exe"
& $py -m governance.project5.registry validate
& $py -m governance.project5.registry report --output-dir telemetry\governance\project5-1
& $py -m pytest governance/project5/tests -q
& $py -m pytest -q
& $py -m ruff check .
```

Expected validator output (format may differ in key order):

```json
{"assets":5,"open_risks":1,"pending_risk_reviews":1,"security_assured_release_approved":false,"unassigned_asset_owners":5}
```

Generated **local-only** files are `telemetry/governance/project5-1/summary.json` and `telemetry/governance/project5-1/risk-register.md`. Add `telemetry/governance/` to `.gitignore`; do **not** commit generated copies. These reports include input SHA-256 hashes (unsigned and not provenance proof) and deliberately mark release as **NOT APPROVED**.

The JSON deliberately rejects `accepted`, assigned risk owners, ratings, and arbitrary unreviewed fields. Proper owner assignment, risk scoring, acceptance evidence and ISO/NIST control mapping are planned **subsequent governed changes**, not automatic transitions performed in Project 5.1.

## Source of truth and important limitations

The prior risk document is `docs/security/CHROMADB-RISK-ASSESSMENT.md` and closure assessment is `docs/security/PROJECT4-SECURITY-CLOSURE.md`. ChromaDB 1.5.9 still has five pip-audit vulnerability entries under four advisory IDs. This baseline must be reviewed against the actual Git tree and refreshed when versions or architecture change.

`data_profile` is a declared intended profile, not a technical prevention guarantee: especially for Project 1, configuration such as `LOG_RAW_CONTENT` may permit local raw logging. Do not import raw telemetry into governance reports.

Risk status is **open/pending_review**, owner and impact/likelihood **null**, and security-assured production release **not approved**. Do not add fictional sign-offs or fabricate compliance evidence.
