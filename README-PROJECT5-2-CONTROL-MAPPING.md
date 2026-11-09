# Project 5.2 — Offline AI Security Control Mapping

**Status: research-lab evidence index only. Not a compliance assessment, certification, signed attestation, risk acceptance, or production release authorization.**

## Purpose

Index seven *proposed internal* Cyranta security controls, each associated with Project 5.1 registered assets, code/test/documentation evidence paths, broad governance-framework themes, and explicit review gaps. The module neither imports live telemetry nor executes referenced tests. A file marked `located` means only that a local filesystem entry of the expected type is present; it **does not mean the control is implemented effectively or that a test passed**.

Inputs from the merged Project 5.1 implementation are `governance/project5/assets.json` and `governance/project5/risks.json`. The new catalogue is `governance/project5/controls.json`. The module `governance/project5/control_mapping.py` is Python standard-library only, relying on the existing Project 5.1 registry validation. See `governance/project5/tests/test_control_mapping.py` for 52 targeted offline tests.

## Controls

- `CYR-CTL-001` Chatbot input controls and blocked-event detection.
- `CYR-CTL-002` RAG access and provenance controls.
- `CYR-CTL-003` Agent tool authorization and approval.
- `CYR-CTL-004` Security telemetry and gateway audit.
- `CYR-CTL-005` Detection, incident triage and exercise.
- `CYR-CTL-006` Dependency auditing and residual risk (`CYRANTA-DEP-001` remains **open**).
- `CYR-CTL-007` AI asset ownership and risk oversight (owners **unassigned**).

There are 20 local evidence path references in the baseline catalogue; some paths represent directories. All seven controls require human review and contain known gaps. No automatic approvals or scores are emitted.

## Framework reference boundaries

- **NIST AI RMF 1.0:** only four *function-level* terms — `GOVERN`, `MAP`, `MEASURE`, and `MANAGE`. Source: https://airc.nist.gov/airmf-resources/airmf/5-sec-core/
- **ISO/IEC 42001:2023:** non-normative, **broad management-system themes** only, not requirements, audited clause mappings, or claims of conformity. Source: https://www.iso.org/standard/42001

Framework associations are proposed interpretation for later independent review. They do not reproduce normative ISO clauses and are not an official crosswalk. The NIST AI RMF 1.0 is undergoing revision, so mappings need a version review before any future claim.

## Commands (PowerShell, from repository root)

```powershell
$py = ".\.venv-agent\Scripts\python.exe"
& $py -m governance.project5.control_mapping validate
& $py -m governance.project5.control_mapping report --output-dir telemetry\governance\project5-2
& $py -m pytest governance/project5/tests -q
& $py -m pytest -q
& $py -m ruff check .
& $py -m bandit -q governance/project5/control_mapping.py
```

The `validate` command validates registry and control schema, identifiers, and cross-references; it does **not** examine evidence availability. The `report` command performs local presence/type checks and emits `telemetry/governance/project5-2/control-summary.json` and `control-mapping.md`. Files within `telemetry/governance/` are already ignored from Git by Project 5.1. Only sanitized, allowlisted metadata, evidence paths, open-risk references, and unsigned input SHA-256 hashes are included. The report does not read evidence file contents.

Expected in a complete working tree: 7 controls, 20 path references, 7 needing human review, 7 with known gaps, 7 unassigned owners, one open registered risk, and `security_assured_release_approved: false`. `evidence_located` may be lower than 20 if referenced files or folders are absent. This is a *gap*, not proof of a failed security test.

## Integration

Before opening a Project 5.2 PR, extend **Bandit** in `scripts/security_gate.sh` to include `governance/project5/control_mapping.py` alongside `registry.py`. Syntax coverage already includes the entire `governance` directory; pytest and Ruff already run across the repository. Do not expand existing CI audit claims to include `requirements-rag.txt`: its ChromaDB dependency findings are still open and separately documented under `CYRANTA-DEP-001`.

Do not assign asset owners, change risk decisions, or mark controls as certified without authorized review and separate evidence. No release tag is recommended by this package.
