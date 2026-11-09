"""Offline, read-only Cyranta AI asset inventory and risk register.

Project 5.1 intentionally cannot approve/accept risks or certify compliance.
Records are declarations requiring human verification, not runtime discovery.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 128 * 1024
ASSET_FIELDS = frozenset(
    {
        "asset_id", "name", "component_path", "environment",
        "data_profile", "status", "owner",
    }
)
RISK_FIELDS = frozenset(
    {
        "risk_id", "asset_ids", "category", "component", "observed_version",
        "status", "decision", "risk_owner", "likelihood", "impact",
        "finding_records", "advisories", "source_document",
    }
)
ASSET_ID_RE = re.compile(r"CYR-AST-[0-9]{3}\Z")
RISK_ID_RE = re.compile(r"CYRANTA-(?:DEP|SEC|POL)-[0-9]{3}\Z")
ADVISORY_RE = re.compile(r"PYSEC-[0-9]{4}-[0-9]+\Z")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()/+\-]{1,79}\Z")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}\Z")
COMPONENT_RE = re.compile(r"[a-z][a-z0-9_-]{0,39}\Z")
VALID_PROFILES = frozenset(
    {
        "fictional_lab_data", "sanitized_security_telemetry",
        "configuration_and_test_metadata",
    }
)


class RegistryError(ValueError):
    """Invalid local inventory/risk input."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError("Duplicate JSON key")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise RegistryError("Registry file exceeds size limit")
        data = json.loads(
            path.read_text(encoding="utf-8-sig"),
            object_pairs_hook=_unique_pairs,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RegistryError("Cannot read valid UTF-8 registry JSON") from exc
    if not isinstance(data, dict):
        raise RegistryError("Registry root must be an object")
    return data


def _fields(value: Any, expected: frozenset[str], kind: str) -> dict[str, Any]:
    if not isinstance(value, dict) or value.keys() != expected:
        raise RegistryError(f"Invalid {kind} fields")
    return value


def _matches(value: Any, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _safe_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 160:
        return False
    if "\\" in value or ":" in value or not re.fullmatch(r"[A-Za-z0-9._/-]+", value):
        return False
    parts = value.split("/")
    return not any(part in {"", ".", ".."} for part in parts)


def _validate_root(data: dict[str, Any], field: str) -> list[Any]:
    if (
        data.keys() != {"schema_version", field}
        or type(data["schema_version"]) is not int
    ):
        raise RegistryError("Invalid registry schema")
    if data["schema_version"] != 1 or not isinstance(data[field], list):
        raise RegistryError("Unsupported schema version or registry list")
    if len(data[field]) > 100 or not data[field]:
        raise RegistryError("Registry must contain 1 to 100 entries")
    return data[field]


def validate(assets: dict[str, Any], risks: dict[str, Any]) -> dict[str, int | bool]:
    """Validate declared data, cross-references, and non-acceptance policy.

    No compliance assertions, advisory lookups, or risk scoring occur here.
    """
    asset_rows = _validate_root(assets, "assets")
    risk_rows = _validate_root(risks, "risks")
    asset_ids: set[str] = set()
    for row in asset_rows:
        item = _fields(row, ASSET_FIELDS, "asset")
        asset_id = item["asset_id"]
        if not _matches(asset_id, ASSET_ID_RE) or asset_id in asset_ids:
            raise RegistryError("Invalid or duplicated asset identifier")
        asset_ids.add(asset_id)
        if not _matches(item["name"], NAME_RE):
            raise RegistryError("Invalid asset name")
        if not _safe_path(item["component_path"]):
            raise RegistryError("Invalid component path")
        if item["environment"] != "isolated_local_research":
            raise RegistryError("Unexpected environment")
        if (
            not isinstance(item["data_profile"], str)
            or item["data_profile"] not in VALID_PROFILES
        ):
            raise RegistryError("Invalid declared data profile")
        if item["status"] != "implemented" or item["owner"] is not None:
            raise RegistryError("Asset ownership/status needs explicit schema review")

    risk_ids: set[str] = set()
    for row in risk_rows:
        item = _fields(row, RISK_FIELDS, "risk")
        risk_id = item["risk_id"]
        if not _matches(risk_id, RISK_ID_RE) or risk_id in risk_ids:
            raise RegistryError("Invalid or duplicated risk identifier")
        risk_ids.add(risk_id)
        refs = item["asset_ids"]
        if (
            not isinstance(refs, list)
            or not refs
            or len(refs) != len({ref for ref in refs if isinstance(ref, str)})
            or any(not isinstance(ref, str) or ref not in asset_ids for ref in refs)
        ):
            raise RegistryError("Invalid risk-to-asset references")
        if item["category"] != "vulnerable_dependency":
            raise RegistryError("Unrecognized risk category")
        if not _matches(item["component"], COMPONENT_RE):
            raise RegistryError("Invalid dependency component")
        if not _matches(item["observed_version"], VERSION_RE):
            raise RegistryError("Invalid observed version")
        if (
            item["status"] != "open"
            or item["decision"] != "pending_review"
            or item["risk_owner"] is not None
            or item["likelihood"] is not None
            or item["impact"] is not None
        ):
            raise RegistryError(
                "Risk resolution, scoring and acceptance are not supported in 5.1"
            )
        adv = item["advisories"]
        if (
            not isinstance(adv, list)
            or not adv
            or len(adv) > 20
            or not all(_matches(a, ADVISORY_RE) for a in adv)
            or len(adv) != len(set(adv))
        ):
            raise RegistryError("Invalid or duplicated advisories")
        count = item["finding_records"]
        if type(count) is not int or not len(adv) <= count <= 100:
            raise RegistryError("Invalid finding record count")
        if not _safe_path(item["source_document"]):
            raise RegistryError("Invalid risk source document path")

    return {
        "assets": len(asset_rows),
        "open_risks": len(risk_rows),
        "unassigned_asset_owners": len(asset_rows),
        "pending_risk_reviews": len(risk_rows),
        "security_assured_release_approved": False,
    }


def _source_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    staged: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=".cyranta-", suffix=".tmp", delete=False,
        ) as handle:
            staged = Path(handle.name)
            handle.write(data)
        os.replace(staged, path)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def generate_report(
    asset_data: dict[str, Any], risk_data: dict[str, Any],
    assets_path: Path, risks_path: Path, output_dir: Path,
) -> dict[str, int | bool]:
    summary = validate(asset_data, risk_data)
    outputs = (output_dir / "summary.json", output_dir / "risk-register.md")
    inputs = {assets_path.resolve(), risks_path.resolve()}
    if any(path.resolve() in inputs for path in outputs):
        raise RegistryError("Output would overwrite registry source")
    payload = {
        "schema_version": 1,
        "scope": "isolated_local_research",
        "summary": summary,
        "assets": sorted(asset_data["assets"], key=lambda row: row["asset_id"]),
        "risks": sorted(risk_data["risks"], key=lambda row: row["risk_id"]),
        "source_sha256": {
            "assets": _source_hash(assets_path),
            "risks": _source_hash(risks_path),
        },
        "limitations": [
            "Declared records are not automatic discovery or verified asset ownership.",
            ("This report is not an authorization, compliance certification, "
            "or risk acceptance."),
            "Input SHA-256 hashes are unsigned and do not prove provenance.",
        ],
    }
    lines = [
        "# Cyranta AI Asset and Risk Register — Project 5.1",
        "", "**LOCAL RESEARCH LAB — NO RELEASE AUTHORIZATION**", "",
        (f"Assets: {summary['assets']} | Open risks: {summary['open_risks']} | "
        f"Pending reviews: {summary['pending_risk_reviews']}"),
        "", "## Declared assets", "",
        "| ID | Asset | Component | Owner |", "|---|---|---|---|",
    ]
    for asset in payload["assets"]:
        lines.append(
            f"| {asset['asset_id']} | {asset['name']} | "
            f"{asset['component_path']} | Unassigned |"
        )
    lines.extend(
        [
            "", "## Open risks", "",
            "| ID | Asset IDs | Component | Decision | Source |",
            "|---|---|---|---|---|",
        ]
    )
    for risk in payload["risks"]:
        lines.append(
            f"| {risk['risk_id']} | {', '.join(risk['asset_ids'])} | "
            f"{risk['component']} {risk['observed_version']} | "
            f"Pending review | {risk['source_document']} |"
        )
    lines.extend(
        ["", "## Assurance limitations", "",
         ("- Registry is a reviewed declaration, not automatic discovery "
         "or live vulnerability verification."),
         "- Unassigned owners, no risk scoring, no signed risk-acceptance record.",
         "- No NIST AI RMF or ISO/IEC 42001 compliance certification is asserted.",
         "- Security-assured production release remains NOT APPROVED.", ""]
    )
    _atomic_write(outputs[0], json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    _atomic_write(outputs[1], "\n".join(lines))
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline Cyranta AI asset and risk register"
    )
    parser.add_argument("command", choices=("validate", "report"))
    parser.add_argument(
        "--assets", type=Path, default=Path("governance/project5/assets.json")
    )
    parser.add_argument(
        "--risks", type=Path, default=Path("governance/project5/risks.json")
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("telemetry/governance/project5-1")
    )
    args = parser.parse_args(argv)
    try:
        asset_data = _read_json(args.assets)
        risk_data = _read_json(args.risks)
        if args.command == "report":
            result = generate_report(
                asset_data, risk_data, args.assets, args.risks, args.output_dir
            )
        else:
            result = validate(asset_data, risk_data)
    except (RegistryError, OSError) as exc:
        print(f"Registry validation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
