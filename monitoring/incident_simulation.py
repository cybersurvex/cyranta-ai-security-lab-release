"""Project 4.4: offline, fictional SOC scenario replay and evidence verification.

Uses real in-process ToolGateway decisions and the existing detection/dashboard
modules. This module does not invoke an LLM, network endpoint, or live tools.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from agent.security.tool_gateway import SERVICE_ID, Principal, ToolGateway
from agent.tools.mock_tools import MockRetailTools
from monitoring.dashboard import generate, load_alerts
from monitoring.detector import scan_jsonl
from monitoring.gateway_detection import normalize_gateway_audit

EVIDENCE_NAMES = (
    "events.jsonl",
    "alerts.jsonl",
    "dashboard.html",
    "case-report.json",
    "incident-report.md",
)
FIXTURE_EPOCH = 1791916800.0


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    origin: str
    expected_rule: str | None
    request_id: str
    event: dict[str, Any]


def _principal(role: str) -> Principal:
    return Principal(
        user_id="CYR-LAB-OPERATOR",
        role=role,
        agent_id=SERVICE_ID,
        order_ids=frozenset({"CYR-ORDER-1007"}),
        skus=frozenset({"CYR-HEADSET-01"}),
    )


def build_scenarios() -> list[Scenario]:
    """Create four disconnected, in-memory lab scenarios without raw secrets."""
    blocked_id = str(uuid4())
    blocked = Scenario(
        scenario_id="SIM-LLM-001",
        origin="synthetic_chatbot_event",
        expected_rule="CYR-DET-001",
        request_id=blocked_id,
        event={
            "event_type": "llm_request",
            "ts": datetime.fromtimestamp(FIXTURE_EPOCH, tz=UTC).isoformat(),
            "request_id": blocked_id,
            "status": "blocked",
            "blocked": True,
        },
    )

    readonly = _principal("support_readonly")
    readonly_gateway = ToolGateway(MockRetailTools(), now=lambda: FIXTURE_EPOCH)
    denied = readonly_gateway.execute(
        readonly,
        "issue_refund",
        {"order_id": "CYR-ORDER-1007", "amount": "10"},
    )
    if denied.code != "ROLE_TOOL_DENIED" or denied.allowed:
        raise RuntimeError("Lab fixture failed authorization precondition")
    denied_event = normalize_gateway_audit(readonly_gateway.audit[-1])
    if denied_event is None:
        raise RuntimeError("Gateway audit normalization failed")

    clock = [FIXTURE_EPOCH]
    specialist = _principal("refund_specialist")
    specialist_tools = MockRetailTools()
    specialist_gateway = ToolGateway(specialist_tools, now=lambda: clock[0])
    capability = specialist_gateway.issue_capability(
        specialist, "issue_refund", "CYR-ORDER-1007", ttl_seconds=120
    )
    approval = specialist_gateway.approve_refund(
        specialist,
        order_id="CYR-ORDER-1007",
        amount="10",
        approved_by="CYR-SUP-01",
        ttl_seconds=5,
    )
    clock[0] += 5  # Exactly at expiry; this is NOT evidence of approval replay.
    expired = specialist_gateway.execute(
        specialist,
        "issue_refund",
        {"order_id": "CYR-ORDER-1007", "amount": "10"},
        capability=capability,
        approval=approval,
    )
    if expired.code != "APPROVAL_INVALID_OR_EXPIRED" or expired.allowed:
        raise RuntimeError("Lab fixture failed approval-expiry precondition")
    expired_event = normalize_gateway_audit(specialist_gateway.audit[-1])
    if expired_event is None or specialist_tools.refunds:
        raise RuntimeError("Unexpected mock refund or invalid gateway audit")

    benign_gateway = ToolGateway(MockRetailTools(), now=lambda: FIXTURE_EPOCH)
    benign_capability = benign_gateway.issue_capability(
        readonly, "lookup_order", "CYR-ORDER-1007"
    )
    allowed = benign_gateway.execute(
        readonly,
        "lookup_order",
        {"order_id": "CYR-ORDER-1007"},
        capability=benign_capability,
    )
    if allowed.code != "ALLOWED" or not allowed.allowed:
        raise RuntimeError("Lab fixture failed benign-control precondition")
    allowed_event = normalize_gateway_audit(benign_gateway.audit[-1])
    if allowed_event is None:
        raise RuntimeError("Gateway audit normalization failed")

    return [
        blocked,
        Scenario("SIM-GATE-006", "real_mock_gateway_decision", "CYR-DET-006", denied.request_id, denied_event),
        Scenario("SIM-GATE-007", "real_mock_gateway_decision", "CYR-DET-007", expired.request_id, expired_event),
        Scenario("SIM-CTRL-000", "real_mock_gateway_decision", None, allowed.request_id, allowed_event),
    ]


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def run_simulation(output_dir: Path) -> dict[str, Any]:
    """Create a new, self-contained simulation directory; never overwrite data."""
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise ValueError("The output directory already exists; choose a new path")
    scenarios = build_scenarios()
    output_dir.mkdir(parents=True, exist_ok=False)
    events_path = output_dir / "events.jsonl"
    alerts_path = output_dir / "alerts.jsonl"
    with events_path.open("w", encoding="utf-8", newline="\n") as handle:
        for scenario in scenarios:
            handle.write(json.dumps(scenario.event, sort_keys=True) + "\n")

    scan = scan_jsonl(events_path, alerts_path)
    if scan.to_dict() != {
        "lines": 4, "alerts": 3, "ignored": 1, "malformed": 0, "duplicates": 0
    }:
        raise RuntimeError("Detector validation failed; inspect isolated simulation")
    validated = load_alerts(alerts_path)
    if validated.invalid or validated.duplicates or len(validated.alerts) != 3:
        raise RuntimeError("Dashboard alert validation failed")
    by_request: dict[str, list[str]] = {}
    for alert in validated.alerts:
        by_request.setdefault(alert.request_id, []).append(alert.rule_id)

    cases: list[dict[str, Any]] = []
    for scenario in scenarios:
        observed = sorted(by_request.get(scenario.request_id, []))
        expected = [] if scenario.expected_rule is None else [scenario.expected_rule]
        if observed != expected:
            raise RuntimeError("Scenario-to-detection correlation mismatch")
        cases.append({
            "scenario_id": scenario.scenario_id,
            "origin": scenario.origin,
            "request_id": scenario.request_id,
            "expected_rules": expected,
            "observed_rules": observed,
            "event_ts": scenario.event["ts"],
            "decision_code": scenario.event.get("decision_code", "not_applicable"),
            "result": "pass",
            "analyst_disposition": "not_triaged",
        })

    generate(alerts_path, output_dir / "triage.json", output_dir / "dashboard.html")
    report: dict[str, Any] = {
        "schema_version": 1,
        "scope": "OFFLINE_FICTIONAL_SIMULATION_ONLY",
        "not_a_confirmed_incident": True,
        "created_utc": datetime.now(UTC).isoformat(),
        "summary": {
            "scenarios": 4,
            "alerts": 3,
            "benign_controls": 1,
            "all_expected_detections_matched": True,
        },
        "cases": cases,
        "assessment": (
            "Detection correlation passed for controlled synthetic chatbot input "
            "and real in-memory mock ToolGateway decisions. No live attack or "
            "production incident is established."
        ),
        "limitations": (
            "SHA-256 hashes detect subsequent file changes but do not prove "
            "authenticity, original collection time, or chain of custody."
        ),
    }
    _write_json(output_dir / "case-report.json", report)
    timeline = "\n".join(
        f"| {case['scenario_id']} | {case['event_ts']} | "
        f"{case['decision_code']} | {','.join(case['observed_rules']) or 'none'} |"
        for case in cases
    )
    markdown = (
        "# CYR-IR-001 — SOC Investigation Exercise\n\n"
        "**SIMULATED / FICTIONAL LAB ONLY — NOT A CONFIRMED INCIDENT.**\n\n"
        "## Scope and evidence\n\n"
        "Offline chatbot fixture plus real in-memory MockRetailTools gateway decisions. "
        "The generator writes only sanitized telemetry and correlation identifiers.\n\n"
        "## UTC timeline\n\n"
        "| Scenario | Time (UTC) | Gateway decision | Detection |\n"
        "|---|---|---|---|\n"
        f"{timeline}\n\n"
        "## Assessment\n\n"
        "One synthetic blocked request and two real mock-gateway denials "
        "produced the three expected detections; "
        "one authorized benign control produced no alert. The blocked chatbot "
        "event is synthetic, not a test of a live prompt-injection endpoint. "
        "The expired approval is not evidence of approval replay.\n\n"
        "## Triage and recommended response\n\n"
        "Analyst state: **not triaged**. For real alerts, confirm request and "
        "scope, assess whether an unauthorized operation executed, preserve "
        "evidence under access control, and escalate only after validation. "
        "Do not perform a production containment action based on this fixture.\n\n"
        "## Evidence limitations\n\n"
        "evidence-manifest.json contains unsigned SHA-256 checksums, not a "
        "cryptographic signature or forensic chain of custody.\n"
    )
    (output_dir / "incident-report.md").write_text(markdown, encoding="utf-8")
    _write_json(output_dir / "evidence-manifest.json", {
        "schema_version": 1,
        "purpose": "offline_fictional_soc_simulation",
        "hash_algorithm": "sha256",
        "files": {name: _digest_file(output_dir / name) for name in EVIDENCE_NAMES},
        "signed": False,
    })
    return report["summary"]


def verify_evidence(output_dir: Path) -> bool:
    """Validate exact expected file hashes; no digital signature is claimed."""
    root = Path(output_dir)
    manifest_path = root / "evidence-manifest.json"
    try:
        if manifest_path.stat().st_size > 8192:
            return False
    except OSError:
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(manifest, dict):
        return False
    if manifest.get("schema_version") != 1 or manifest.get("hash_algorithm") != "sha256":
        return False
    actual_files = manifest.get("files")
    if not isinstance(actual_files, dict) or set(actual_files) != set(EVIDENCE_NAMES):
        return False
    for name in EVIDENCE_NAMES:
        expected_hash = actual_files[name]
        if (
            not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(char not in "0123456789abcdef" for char in expected_hash)
        ):
            return False
        try:
            if _digest_file(root / name) != expected_hash:
                return False
        except OSError:
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Cyranta Project 4.4: fictional SOC incident simulation"
    )
    options = parser.add_subparsers(dest="action", required=True)
    simulate = options.add_parser("run", help="Generate new, isolated simulation evidence")
    simulate.add_argument("--output-dir", type=Path, required=True)
    verify = options.add_parser("verify", help="Verify SHA-256 evidence checksums")
    verify.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "run":
            summary = run_simulation(args.output_dir)
            print(json.dumps(summary, sort_keys=True))
        else:
            if not verify_evidence(args.output_dir):
                parser.exit(2, "Evidence verification failed.\n")
            print("Evidence verification passed (SHA-256 only; unsigned).")
    except (OSError, ValueError, RuntimeError):
        parser.exit(2, "Simulation failed; inspect the isolated output directory.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
