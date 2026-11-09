"""Offline Project 5.1 registry regression tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from governance.project5.registry import (
    MAX_INPUT_BYTES,
    RegistryError,
    _read_json,
    generate_report,
    main,
    validate,
)

DATA_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture
def sample() -> tuple[dict, dict]:
    assets = json.loads((DATA_DIR / "assets.json").read_text(encoding="utf-8"))
    risks = json.loads((DATA_DIR / "risks.json").read_text(encoding="utf-8"))
    return assets, risks


def test_checked_in_registry_is_valid(sample):
    assets, risks = sample
    assert validate(assets, risks) == {
        "assets": 5,
        "open_risks": 1,
        "unassigned_asset_owners": 5,
        "pending_risk_reviews": 1,
        "security_assured_release_approved": False,
    }


def test_risk_baseline_and_unassigned_owners(sample):
    assets, risks = sample
    risk = risks["risks"][0]
    assert risk["risk_id"] == "CYRANTA-DEP-001"
    assert risk["asset_ids"] == ["CYR-AST-002"]
    assert risk["finding_records"] == 5
    assert len(risk["advisories"]) == 4
    assert risk["risk_owner"] is None
    assert risk["decision"] == "pending_review"
    assert all(asset["owner"] is None for asset in assets["assets"])


def test_report_writes_allowlisted_offline_fields(sample, tmp_path):
    assets, risks = sample
    asset_src = tmp_path / "assets.json"
    risk_src = tmp_path / "risks.json"
    asset_src.write_text(json.dumps(assets), encoding="utf-8")
    risk_src.write_text(json.dumps(risks), encoding="utf-8")
    output = tmp_path / "reports"
    summary = generate_report(assets, risks, asset_src, risk_src, output)
    doc = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    markdown = (output / "risk-register.md").read_text(encoding="utf-8")
    assert doc["summary"] == summary
    assert set(doc) == {
        "schema_version", "scope", "summary", "assets",
        "risks", "source_sha256", "limitations",
    }
    assert len(doc["source_sha256"]["assets"]) == 64
    assert len(doc["source_sha256"]["risks"]) == 64
    assert "NOT APPROVED" in markdown
    assert "CYRANTA-DEP-001" in markdown
    assert "Pending review" in markdown
    assert "approved" not in markdown.lower().replace("not approved", "")


def test_report_is_deterministic(sample, tmp_path):
    assets, risks = sample
    asset_src = tmp_path / "assets.json"
    risk_src = tmp_path / "risks.json"
    asset_src.write_text(json.dumps(assets), encoding="utf-8")
    risk_src.write_text(json.dumps(risks), encoding="utf-8")
    out = tmp_path / "out"
    generate_report(assets, risks, asset_src, risk_src, out)
    before = (
        (out / "summary.json").read_bytes(),
        (out / "risk-register.md").read_bytes(),
    )
    generate_report(assets, risks, asset_src, risk_src, out)
    after = (out / "summary.json").read_bytes(), (out / "risk-register.md").read_bytes()
    assert before == after


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("owner", "invented-owner"),
        ("status", "production"),
        ("environment", "public_cloud"),
        ("component_path", "../.env"),
        ("component_path", "C:\\secrets.txt"),
        ("component_path", "rag//app"),
        ("name", "Sensitive | Secret"),
        ("data_profile", "production_pii"),
        ("data_profile", ["fictional_lab_data"]),
    ],
)
def test_rejects_invalid_asset_fields(sample, field, value):
    assets, risks = copy.deepcopy(sample)
    assets["assets"][0][field] = value
    with pytest.raises(RegistryError):
        validate(assets, risks)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("decision", "accepted"),
        ("status", "resolved"),
        ("risk_owner", "made-up-reviewer"),
        ("likelihood", "low"),
        ("impact", "high"),
        ("asset_ids", ["CYR-AST-999"]),
        ("asset_ids", ["CYR-AST-002", "CYR-AST-002"]),
        ("advisories", ["PYSEC-2026-311", "PYSEC-2026-311"]),
        ("source_document", "../../.env"),
        ("finding_records", 2),
    ],
)
def test_rejects_unsupported_risk_mutations(sample, field, value):
    assets, risks = copy.deepcopy(sample)
    risks["risks"][0][field] = value
    with pytest.raises(RegistryError):
        validate(assets, risks)


def test_rejects_extra_fields(sample):
    assets, risks = copy.deepcopy(sample)
    assets["assets"][0]["raw_prompt"] = "secret"
    with pytest.raises(RegistryError):
        validate(assets, risks)


def test_rejects_duplicate_asset_identifiers(sample):
    assets, risks = copy.deepcopy(sample)
    assets["assets"].append(copy.deepcopy(assets["assets"][0]))
    with pytest.raises(RegistryError):
        validate(assets, risks)


def test_rejects_duplicate_risk_identifiers(sample):
    assets, risks = copy.deepcopy(sample)
    risks["risks"].append(copy.deepcopy(risks["risks"][0]))
    with pytest.raises(RegistryError):
        validate(assets, risks)


def test_rejects_unsupported_schema(sample):
    assets, risks = copy.deepcopy(sample)
    assets["schema_version"] = 2
    with pytest.raises(RegistryError):
        validate(assets, risks)


def test_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"schema_version":1,"schema_version":1,"assets":[]}',
        encoding="utf-8",
    )
    with pytest.raises(RegistryError, match="Duplicate JSON key"):
        _read_json(path)


def test_rejects_oversized_file(tmp_path):
    path = tmp_path / "big.json"
    path.write_bytes(b"x" * (MAX_INPUT_BYTES + 1))
    with pytest.raises(RegistryError, match="size limit"):
        _read_json(path)


def test_cli_validate_from_explicit_files(sample, tmp_path, capsys):
    assets, risks = sample
    asset_src = tmp_path / "assets.json"
    risk_src = tmp_path / "risks.json"
    asset_src.write_text(json.dumps(assets), encoding="utf-8")
    risk_src.write_text(json.dumps(risks), encoding="utf-8")
    code = main(["validate", "--assets", str(asset_src), "--risks", str(risk_src)])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["open_risks"] == 1


def test_cli_invalid_status_exits_without_traceback(sample, tmp_path, capsys):
    assets, risks = copy.deepcopy(sample)
    risks["risks"][0]["decision"] = "accepted"
    asset_src = tmp_path / "assets.json"
    risk_src = tmp_path / "risks.json"
    asset_src.write_text(json.dumps(assets), encoding="utf-8")
    risk_src.write_text(json.dumps(risks), encoding="utf-8")
    code = main(["validate", "--assets", str(asset_src), "--risks", str(risk_src)])
    out = capsys.readouterr()
    assert code == 2
    assert "validation failed" in out.err.lower()
    assert "Traceback" not in out.err
    assert out.out == ""


def test_report_cannot_overwrite_input_file(sample, tmp_path):
    assets, risks = sample
    asset_src = tmp_path / "summary.json"
    risk_src = tmp_path / "risks.json"
    asset_src.write_text(json.dumps(assets), encoding="utf-8")
    risk_src.write_text(json.dumps(risks), encoding="utf-8")
    with pytest.raises(RegistryError, match="overwrite"):
        generate_report(assets, risks, asset_src, risk_src, tmp_path)
    assert json.loads(asset_src.read_text(encoding="utf-8")) == assets


def test_no_network_or_raw_telemetry_access_in_registry_module():
    source = (DATA_DIR / "registry.py").read_text(encoding="utf-8")
    assert "requests" not in source
    assert "urllib" not in source
    assert "telemetry/events.jsonl" not in source
    assert "LOG_RAW_CONTENT" not in source
