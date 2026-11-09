"""Project 6.1 fixed offline scenario catalogue and schema validator.

This module does not execute attacks, read actual user prompts, or emit assurance.
It validates 6 immutable-in-code metadata contracts against Project 5 registry.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from governance.project5.control_mapping import validate_mapping
from governance.project5.registry import _read_json

SCENARIO_FIELDS = frozenset({
    "schema_version", "scenario_id", "title", "scenario_type", "mode",
    "asset_ids", "control_ids", "fixture_id", "fixture_path",
    "expected_decision", "assertion_id", "execution_status", "finding_id",
    "registered_risk_ids", "human_review_required",
})
FIXTURE_FIELDS = frozenset({
    "schema_version", "fixture_id", "scenario_id", "fixture_kind",
    "input_class", "expected_signal", "synthetic", "contains_live_payload",
})
TITLE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()/-]{7,99}\Z")
ROOT = Path("validation/project6")
MAX_JSON_BYTES = 8192

# Frozen, reviewed mapping for the six fictional scenarios. Updating this
# specification requires code review and cannot silently extend test scope.
SPECS: dict[str, dict[str, Any]] = {
    "CYR-P6-SCN-001": {
        "scenario_type": "chatbot_fake_secret_probe",
        "asset_ids": ["CYR-AST-001", "CYR-AST-004"],
        "control_ids": ["CYR-CTL-001", "CYR-CTL-004"],
        "fixture_id": "chatbot-fake-marker-v1",
        "expected_decision": "block",
        "assertion_id": "chatbot_no_fake_secret_disclosure",
        "input_class": "fictional_direct_injection",
        "expected_signal": "output_guard_block",
    },
    "CYR-P6-SCN-002": {
        "scenario_type": "chatbot_encoded_instruction_variant",
        "asset_ids": ["CYR-AST-001"],
        "control_ids": ["CYR-CTL-001"],
        "fixture_id": "chatbot-encoded-variant-v1",
        "expected_decision": "block",
        "assertion_id": "chatbot_variant_no_fake_secret_disclosure",
        "input_class": "fictional_encoded_instruction",
        "expected_signal": "guard_decision_recorded",
    },
    "CYR-P6-SCN-003": {
        "scenario_type": "rag_cross_role_access",
        "asset_ids": ["CYR-AST-002"],
        "control_ids": ["CYR-CTL-002"],
        "fixture_id": "rag-cross-role-v1",
        "expected_decision": "deny",
        "assertion_id": "rag_denied_before_generation",
        "input_class": "fictional_cross_role_retrieval",
        "expected_signal": "retrieval_access_denied",
    },
    "CYR-P6-SCN-004": {
        "scenario_type": "rag_document_instruction",
        "asset_ids": ["CYR-AST-002", "CYR-AST-004"],
        "control_ids": ["CYR-CTL-002", "CYR-CTL-004"],
        "fixture_id": "rag-provenance-boundary-v1",
        "expected_decision": "deny",
        "assertion_id": "rag_authority_boundary_unchanged",
        "input_class": "fictional_untrusted_document",
        "expected_signal": "provenance_and_access_decision",
    },
    "CYR-P6-SCN-005": {
        "scenario_type": "agent_unauthorized_tool_attempt",
        "asset_ids": ["CYR-AST-003", "CYR-AST-004"],
        "control_ids": ["CYR-CTL-003", "CYR-CTL-004"],
        "fixture_id": "agent-denied-action-v1",
        "expected_decision": "deny",
        "assertion_id": "gateway_denies_without_mutation",
        "input_class": "fictional_unapproved_tool_request",
        "expected_signal": "tool_gateway_denial",
    },
    "CYR-P6-SCN-006": {
        "scenario_type": "monitoring_synthetic_correlation",
        "asset_ids": ["CYR-AST-004", "CYR-AST-005"],
        "control_ids": ["CYR-CTL-004", "CYR-CTL-005", "CYR-CTL-007"],
        "fixture_id": "monitoring-synthetic-event-v1",
        "expected_decision": "alert",
        "assertion_id": "synthetic_alert_and_retest_trace",
        "input_class": "fictional_blocked_event_metadata",
        "expected_signal": "synthetic_alert_correlated",
    },
}


class ScenarioError(ValueError):
    """Reject unreviewed metadata, paths, or false execution claims."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ScenarioError("Duplicate JSON key")
        result[key] = value
    return result


def _no_constant(value: str) -> None:
    raise ScenarioError(f"Nonstandard JSON constant: {value}")


def _read_local_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_JSON_BYTES:
        raise ScenarioError("Missing or oversized scenario metadata file")
    try:
        data = json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=_pairs, parse_constant=_no_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ScenarioError("Invalid UTF-8 scenario metadata JSON") from exc
    if not isinstance(data, dict):
        raise ScenarioError("Scenario metadata must be an object")
    return data


def _allowed_file(root: Path, relative: str, expected_folder: str) -> Path:
    """Allow one fixed relative directory and reject symlinked ancestors."""
    if (not isinstance(relative, str)
            or re.fullmatch(r"validation/project6/(?:scenarios|fixtures)/CYR-P6-SCN-[0-9]{3}\.json", relative) is None
            or not relative.startswith(f"validation/project6/{expected_folder}/")):
        raise ScenarioError("Unsafe or unreviewed scenario/fixture path")
    base = root.resolve()
    path = root / relative
    if not path.resolve().is_relative_to(base):
        raise ScenarioError("File escapes repository root")
    current = root
    for section in Path(relative).parts:
        current = current / section
        if current.is_symlink():
            raise ScenarioError("Symlinked metadata files or parents are not trusted")
    return path


def _strict_keys(data: dict[str, Any], fields: frozenset[str], kind: str) -> None:
    if data.keys() != fields or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ScenarioError(f"Unsupported {kind} schema")


def _validate_row(row: dict[str, Any], fixture: dict[str, Any], sid: str,
                  assets: set[str], controls: dict[str, set[str]]) -> None:
    _strict_keys(row, SCENARIO_FIELDS, "scenario")
    _strict_keys(fixture, FIXTURE_FIELDS, "fixture")
    spec = SPECS[sid]
    if row["scenario_id"] != sid or not isinstance(row["title"], str) or not TITLE_PATTERN.fullmatch(row["title"]):
        raise ScenarioError("Incorrect scenario ID or unsafe title")
    for field in ("scenario_type", "asset_ids", "control_ids", "fixture_id",
                  "expected_decision", "assertion_id"):
        if row[field] != spec[field] or type(row[field]) is not type(spec[field]):
            raise ScenarioError(f"Unexpected scenario {field}")
    if (row["mode"] != "isolated_offline_fixture"
            or row["execution_status"] != "not_run"
            or row["finding_id"] is not None
            or row["registered_risk_ids"] != []
            or type(row["registered_risk_ids"]) is not list
            or row["human_review_required"] is not True):
        raise ScenarioError("Scenario cannot assert execution, linked findings or approval")
    if not set(row["asset_ids"]).issubset(assets):
        raise ScenarioError("Unknown Project 5 asset")
    for cid in row["control_ids"]:
        if cid not in controls or not (controls[cid] & set(row["asset_ids"])):
            raise ScenarioError("Control-to-asset reference is invalid")
    expected_path = f"validation/project6/fixtures/{sid}.json"
    if row["fixture_path"] != expected_path:
        raise ScenarioError("Scenario references unreviewed fixture path")
    for field, expected in (
        ("fixture_id", row["fixture_id"]), ("scenario_id", sid),
        ("fixture_kind", "synthetic_metadata_only"),
        ("input_class", spec["input_class"]),
        ("expected_signal", spec["expected_signal"]),
        ("synthetic", True), ("contains_live_payload", False),
    ):
        if fixture[field] != expected or type(fixture[field]) is not type(expected):
            raise ScenarioError(f"Unreviewed fixture {field}")


def validate(root: Path) -> dict[str, Any]:
    """Read-only validation; does not execute tests or alter Project 5 records."""
    root = root.resolve()
    base = root / ROOT
    for folder in (base, base / "scenarios", base / "fixtures"):
        if folder.is_symlink() or not folder.is_dir():
            raise ScenarioError("Missing or symlinked Project 6 catalogue folder")
    # Registry validation deliberately keeps the outstanding risk and null owners.
    assets = _read_json(root / "governance/project5/assets.json")
    risks = _read_json(root / "governance/project5/risks.json")
    catalogue = _read_json(root / "governance/project5/controls.json")
    validate_mapping(catalogue, assets, risks)
    asset_ids = {row["asset_id"] for row in assets["assets"]}
    controls_by_id = {row["control_id"]: set(row["asset_ids"])
                      for row in catalogue["controls"]}
    scenarios: list[dict[str, Any]] = []
    for folder in ("scenarios", "fixtures"):
        entries = {item.name for item in (base / folder).iterdir()}
        if entries != {f"{sid}.json" for sid in SPECS}:
            raise ScenarioError(f"Unexpected file count or names in {folder}")
    for sid in SPECS:
        manifest = _read_local_json(_allowed_file(root, f"validation/project6/scenarios/{sid}.json", "scenarios"))
        fixture = _read_local_json(_allowed_file(root, manifest.get("fixture_path"), "fixtures"))
        _validate_row(manifest, fixture, sid, asset_ids, controls_by_id)
        scenarios.append(manifest)
    return {
        "scenario_count": len(scenarios),
        "scenarios_not_run": len(scenarios),
        "synthetic_metadata_fixtures": len(scenarios),
        "live_attacks_executed": False,
        "control_effectiveness_verified": False,
        "risk_decisions_changed": False,
        "open_registered_risks": sum(r["status"] == "open" for r in risks["risks"]),
        "security_assured_release_approved": False,
        "compliance_certified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cyranta Project 6.1 offline scenario catalogue")
    parser.add_argument("command", choices=("validate", "list"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        result = validate(args.repo_root)
        if args.command == "list":
            result = {
                **result,
                "scenarios": [
                    {"scenario_id": sid, "scenario_type": spec["scenario_type"],
                     "expected_decision": spec["expected_decision"],
                     "execution_status": "not_run"}
                    for sid, spec in SPECS.items()
                ],
            }
    except (ScenarioError, ValueError, OSError, UnicodeError) as exc:
        print(f"Scenario catalogue failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
