"""Project 6.3: strictly local, fictional detection and incident correlation.

Reuses Project 4 detectors and dashboard. No external telemetry, production
containment, model calls, authorization changes, or incident confirmation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from governance.project5 import assurance_checks as ac
from governance.project5 import governance_dashboard as gd
from governance.project5.registry import _read_json
from monitoring.dashboard import Alert, _parse_alert, generate, load_alerts
from monitoring.detector import detect_blocked_request, scan_jsonl
from monitoring.gateway_detection import detect_gateway_decision
from validation.project6 import schema

DEFAULT_OUTPUT = Path("telemetry/governance/project6-3")
CORRELATION_WINDOW_SECONDS = 300
MAX_MANIFEST_BYTES = 16 * 1024
MAX_CASE_BYTES = 64 * 1024
FIXTURE_REQUEST_A = "11111111-1111-4111-8111-111111111111"
FIXTURE_REQUEST_B = "22222222-2222-4222-8222-222222222222"
FIXTURE_REQUEST_C = "33333333-3333-4333-8333-333333333333"
EVIDENCE_FILES = (
    "events.jsonl", "alerts.jsonl", "dashboard.html", "incident-cases.json",
    "incident-report.md", "response-playbook.md",
)
SOURCES = (
    "validation/project6/correlation.py",
    "validation/project6/schema.py",
    "validation/project6/runner.py",
    "monitoring/detector.py",
    "monitoring/gateway_detection.py",
    "monitoring/dashboard.py",
)
RULES = frozenset({"CYR-DET-001", "CYR-DET-006", "CYR-DET-007"})


class CorrelationError(ValueError):
    """Missing, modified, unsafely placed, or unsupported local evidence."""


def fixture_events() -> list[dict[str, Any]]:
    """Frozen, explicitly fictional events; the repeated row tests deduplication."""
    blocked = {
        "event_type": "llm_request", "blocked": True,
        "request_id": FIXTURE_REQUEST_A, "ts": "2026-11-02T12:00:00+00:00",
    }
    denied = {
        "event_type": "tool_decision", "allowed": False,
        "decision_code": "ROLE_TOOL_DENIED", "request_id": FIXTURE_REQUEST_A,
        "ts": "2026-11-02T12:01:00+00:00",
    }
    expired = {
        "event_type": "tool_decision", "allowed": False,
        "decision_code": "APPROVAL_INVALID_OR_EXPIRED", "request_id": FIXTURE_REQUEST_B,
        "ts": "2026-11-02T12:04:00+00:00",
    }
    benign = {
        "event_type": "tool_decision", "allowed": True,
        "decision_code": "ALLOWED", "request_id": FIXTURE_REQUEST_C,
        "ts": "2026-11-02T12:05:00+00:00",
    }
    return [blocked, denied, expired, blocked.copy(), benign]


def _case_id(request_id: str, first_ts: str) -> str:
    return hashlib.sha256(f"synthetic_case_v1:{request_id}:{first_ts}".encode()).hexdigest()[:24]


def correlate(alerts: list[Alert], *, window_seconds: int = CORRELATION_WINDOW_SECONDS) -> list[dict[str, Any]]:
    """Group validated alerts ONLY by equal UUID and bounded UTC time span.

    Multiple alerts with matching titles, severity, or rules are never enough.
    A reused request ID beyond the window forms an independent case.
    """
    if type(window_seconds) is not int or not 1 <= window_seconds <= 3600:
        raise CorrelationError("Invalid correlation window")
    grouped: dict[str, list[Alert]] = defaultdict(list)
    seen: set[str] = set()
    for alert in alerts:
        if not isinstance(alert, Alert) or alert.rule_id not in RULES:
            raise CorrelationError("Unvalidated alert")
        reconstructed = _parse_alert({
            "alert_id": alert.alert_id, "rule_id": alert.rule_id,
            "severity": alert.severity, "event_type": alert.event_type,
            "request_id": alert.request_id, "event_ts": alert.event_ts,
            "decision_code": alert.decision_code,
        })
        if reconstructed != alert:
            raise CorrelationError("Alert failed Project 4 validation")
        if alert.alert_id in seen:
            raise CorrelationError("Duplicate alert supplied to correlator")
        seen.add(alert.alert_id)
        grouped[alert.request_id].append(alert)

    cases: list[dict[str, Any]] = []
    for request_id in sorted(grouped):
        # P4 alert IDs are keyed on (rule,request ID), so a repeated rule with
        # a different event timestamp is rejected by the duplicate check.
        ordered = sorted(grouped[request_id], key=lambda a: (a.event_ts, a.alert_id))
        buckets: list[list[Alert]] = []
        for alert in ordered:
            if not buckets or (
                datetime.fromisoformat(alert.event_ts) -
                datetime.fromisoformat(buckets[-1][0].event_ts)
            ).total_seconds() > window_seconds:
                buckets.append([alert])
            else:
                buckets[-1].append(alert)
        for bucket in buckets:
            first = bucket[0].event_ts
            rules = sorted(alert.rule_id for alert in bucket)
            cases.append({
                "case_id": _case_id(request_id, first),
                "request_id": request_id,
                "first_event_utc": first,
                "last_event_utc": bucket[-1].event_ts,
                "alert_ids": sorted(alert.alert_id for alert in bucket),
                "rule_ids": rules,
                "alert_count": len(bucket),
                "severity": "high" if any(a.severity == "high" for a in bucket) else "medium",
                "triage_state": "not_triaged",
                "confirmed_incident": False,
                "relationship": "shared_validated_request_id_within_300_seconds"
                if len(bucket) > 1 and window_seconds == CORRELATION_WINDOW_SECONDS
                else "separate_synthetic_case",
            })
    return sorted(cases, key=lambda c: (c["first_event_utc"], c["case_id"]))


def _output(root: Path, path: Path) -> Path:
    return gd._local_folder(root, path)


def _hash(path: Path) -> str:
    return ac._hash(path)


def _source_hashes(root: Path) -> dict[str, str]:
    return {path: _hash(ac._in_repo(root, path)) for path in SOURCES}


def _safe_read_json(path: Path, max_bytes: int) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= max_bytes:
        raise CorrelationError("Missing, symlinked or oversized evidence")
    value = _read_json(path)
    if not isinstance(value, dict):
        raise CorrelationError("Invalid evidence object")
    return value


def _expected_alert_rows() -> list[dict[str, str]]:
    """Project 4 allowlisted output for the frozen fixture, preserving scan order."""
    seen: set[str] = set()
    rows: list[dict[str, str]] = []
    for event in fixture_events():
        alert = detect_blocked_request(event)
        if alert is None:
            alert = detect_gateway_decision(event)
        if alert is not None and alert["alert_id"] not in seen:
            seen.add(alert["alert_id"])
            rows.append(alert)
    return rows


def _require_expected_alert_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise CorrelationError("Missing, symlinked, oversized alert list")
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CorrelationError("Invalid alert file") from exc
    if rows != _expected_alert_rows():
        raise CorrelationError("Alert output differs from allowlisted synthetic detections")


def _check_cases(cases: list[dict[str, Any]]) -> None:
    if len(cases) != 2 or sorted(c["alert_count"] for c in cases) != [1, 2]:
        raise CorrelationError("Expected exactly two synthetic cases")
    expected = {
        FIXTURE_REQUEST_A: ("CYR-DET-001", "CYR-DET-006"),
        FIXTURE_REQUEST_B: ("CYR-DET-007",),
    }
    if {c["request_id"]: tuple(c["rule_ids"]) for c in cases} != expected:
        raise CorrelationError("Rules or request correlation mismatch")
    if any(c["confirmed_incident"] is not False or c["triage_state"] != "not_triaged" for c in cases):
        raise CorrelationError("Synthetic cases cannot claim confirmation or triage")


def run(root: Path, destination: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Generate never-overwritten synthetic evidence inside ignored governance tree."""
    root = root.resolve()
    schema.validate(root)
    folder = _output(root, destination)
    if folder.exists():
        raise CorrelationError("Output already exists; use another run directory")
    folder.mkdir(parents=True, exist_ok=False)
    events_path = folder / "events.jsonl"
    events_path.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in fixture_events()),
        encoding="utf-8", newline="\n",
    )
    alerts_path = folder / "alerts.jsonl"
    scan = scan_jsonl(events_path, alerts_path).to_dict()
    expected_scan = {"lines": 5, "alerts": 3, "ignored": 1, "malformed": 0, "duplicates": 1}
    if scan != expected_scan:
        raise CorrelationError("Project 4 detector behavior changed")
    _require_expected_alert_file(alerts_path)
    validated = load_alerts(alerts_path)
    if validated.invalid or validated.duplicates or len(validated.alerts) != 3:
        raise CorrelationError("Untrusted or incomplete Project 4 alerts")
    cases = correlate(validated.alerts)
    _check_cases(cases)
    rebuilt = generate(alerts_path, folder / "triage.json", folder / "dashboard.html")
    if rebuilt.invalid or rebuilt.duplicates or len(rebuilt.alerts) != 3:
        raise CorrelationError("Project 4 dashboard validation failed")

    head, clean = ac._revision(root)
    source_hashes = _source_hashes(root)
    risk_count = schema.validate(root)["open_registered_risks"]
    case_report: dict[str, Any] = {
        "schema_version": 1,
        "kind": "unsigned_fictional_project6_incident_exercise",
        "source_commit": head,
        "worktree_clean_at_capture": clean,
        "scenario_context": "CYR-P6-SCN-006",
        "project6_2_evidence_link_verified": False,
        "event_scope": "fixed_synthetic_events_not_actual_gateway_or_live_chatbot_traffic",
        "scan": scan,
        "case_count": len(cases),
        "cases": cases,
        "open_registered_risks": risk_count,
        "live_attacks_executed": False,
        "incident_confirmed": False,
        "independently_attested": False,
        "control_effectiveness_verified": False,
        "compliance_certified": False,
        "security_assured_release_approved": False,
    }
    (folder / "incident-cases.json").write_text(json.dumps(case_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    case_rows = "".join(
        f"| {c['case_id']} | {c['first_event_utc']} | {c['alert_count']} | {', '.join(c['rule_ids'])} | not triaged |\n"
        for c in cases
    )
    (folder / "incident-report.md").write_text(
        "# Project 6.3 — Synthetic SOC correlation exercise\n\n"
        "**NOT A CONFIRMED INCIDENT. UNSIGNED LOCAL LAB EVIDENCE.**\n\n"
        f"Recorded revision: `{head}`; clean worktree at capture: `{clean}`.\n\n"
        "Fixed fictional input: 5 rows, 3 sanitized alerts, 1 ignored benign row, "
        "1 duplicate alert ignored. No live systems, LLM or real gateway operation.\n\n"
        "## Incident candidates (UTC)\n\n"
        "| Case ID | First event UTC | Alerts | Rules | Analyst state |\n|---|---|---:|---|---|\n"
        + case_rows + "\n"
        "Two alerts were intentionally assigned the same synthetic request ID, 60 seconds apart. "
        "This is a **fixture-defined** linkage, not evidence that real systems shared a transaction. "
        "The separate high-severity authorization alert has a different request ID and remains independent.\n\n"
        "## Response\n\nSee `response-playbook.md` for human-led investigation steps. "
        "No containment, escalation, triage confirmation, risk acceptance or release approval was executed.\n\n"
        "## Integrity and limitations\n\nLocal SHA-256 hashes detect changes, not authorship, "
        "a trusted collection process or forensic chain of custody. "
        "Linkage to the Project 6.2 runner is conceptual only and not independently verified.\n",
        encoding="utf-8",
    )
    (folder / "response-playbook.md").write_text(
        "# CYR-P6-IR-001 — Synthetic alert response playbook\n\n"
        "**Exercise only. No production action or incident confirmation.**\n\n"
        "1. Validate alert IDs, request UUIDs, rule IDs and timestamps against trusted telemetry.\n"
        "2. Verify whether the apparently linked events share a genuine trusted transaction; "
        "synthetic request-ID equality alone is insufficient in a real incident.\n"
        "3. Check any actual tool execution and material side effects in trusted server-side audit records.\n"
        "4. Determine false-positive possibility, scope and exposure through human analyst review.\n"
        "5. Preserve original evidence under access control, documenting time source and custody.\n"
        "6. Escalate only confirmed findings through approved SOC response procedures.\n"
        "7. Require explicit authorization before containment or governance risk decisions.\n\n"
        "Current analyst state: **not triaged**. No automatic closure or approval.\n",
        encoding="utf-8",
    )
    manifest = {
        "schema_version": 1,
        "kind": "unsigned_synthetic_correlation_hash_manifest",
        "source_commit": head,
        "source_sha256": source_hashes,
        "files_sha256": {name: _hash(folder / name) for name in EVIDENCE_FILES},
        "signed": False,
    }
    (folder / "evidence-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "events": scan["lines"], "alerts": scan["alerts"],
        "duplicates_ignored": scan["duplicates"], "benign_ignored": scan["ignored"],
        "cases": len(cases), "multi_alert_cases": sum(c["alert_count"] > 1 for c in cases),
        "source_commit": head, "worktree_clean_at_capture": clean,
        "incident_confirmed": False, "security_assured_release_approved": False,
    }


def verify(root: Path, destination: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Fail closed on local evidence changes; hashes do NOT authenticate evidence."""
    root = root.resolve()
    schema.validate(root)
    folder = _output(root, destination)
    manifest = _safe_read_json(folder / "evidence-manifest.json", MAX_MANIFEST_BYTES)
    if (manifest.keys() != {"schema_version", "kind", "source_commit", "source_sha256", "files_sha256", "signed"}
            or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
            or manifest["kind"] != "unsigned_synthetic_correlation_hash_manifest"
            or manifest["signed"] is not False
            or not isinstance(manifest["source_commit"], str)
            or ac.FULL_SHA.fullmatch(manifest["source_commit"]) is None
            or manifest["source_sha256"] != _source_hashes(root)):
        raise CorrelationError("Invalid or stale synthetic evidence manifest")
    if not isinstance(manifest["files_sha256"], dict) or set(manifest["files_sha256"]) != set(EVIDENCE_FILES):
        raise CorrelationError("Unexpected evidence file list")
    for name in EVIDENCE_FILES:
        expected_hash = manifest["files_sha256"][name]
        file = folder / name
        if (not isinstance(expected_hash, str) or len(expected_hash) != 64
                or any(ch not in "0123456789abcdef" for ch in expected_hash)
                or file.is_symlink() or not file.is_file() or file.stat().st_size > 2 * 1024 * 1024
                or _hash(file) != expected_hash):
            raise CorrelationError("Missing or modified synthetic evidence file")
    cases_doc = _safe_read_json(folder / "incident-cases.json", MAX_CASE_BYTES)
    required = {"schema_version", "kind", "source_commit", "worktree_clean_at_capture", "scenario_context",
                "project6_2_evidence_link_verified", "event_scope", "scan", "case_count", "cases",
                "open_registered_risks", "live_attacks_executed", "incident_confirmed", "independently_attested",
                "control_effectiveness_verified", "compliance_certified", "security_assured_release_approved"}
    if (cases_doc.keys() != required or type(cases_doc["schema_version"]) is not int
            or cases_doc["schema_version"] != 1
            or cases_doc["kind"] != "unsigned_fictional_project6_incident_exercise"
            or cases_doc["source_commit"] != manifest["source_commit"]
            or type(cases_doc["worktree_clean_at_capture"]) is not bool
            or cases_doc["scenario_context"] != "CYR-P6-SCN-006"
            or cases_doc["event_scope"] != "fixed_synthetic_events_not_actual_gateway_or_live_chatbot_traffic"
            or any(cases_doc[k] is not False for k in (
                "project6_2_evidence_link_verified", "live_attacks_executed", "incident_confirmed",
                "independently_attested", "control_effectiveness_verified", "compliance_certified",
                "security_assured_release_approved"))
            or type(cases_doc["open_registered_risks"]) is not int
            or cases_doc["open_registered_risks"] != schema.validate(root)["open_registered_risks"]):
        raise CorrelationError("Invalid or falsely approved incident exercise")
    raw_lines = (folder / "events.jsonl").read_text(encoding="utf-8").splitlines()
    if len(raw_lines) != 5 or [json.loads(line) for line in raw_lines] != fixture_events():
        raise CorrelationError("Synthetic event input changed")
    expected_scan = {"lines": 5, "alerts": 3, "ignored": 1, "malformed": 0, "duplicates": 1}
    if cases_doc["scan"] != expected_scan or cases_doc["case_count"] != 2:
        raise CorrelationError("Synthetic event counts changed")
    _require_expected_alert_file(folder / "alerts.jsonl")
    alerts = load_alerts(folder / "alerts.jsonl")
    if alerts.invalid or alerts.duplicates or len(alerts.alerts) != 3:
        raise CorrelationError("Alert input failed validation")
    rebuilt = correlate(alerts.alerts)
    _check_cases(rebuilt)
    if cases_doc["cases"] != rebuilt:
        raise CorrelationError("Cases do not match validated sanitized alerts")
    head, clean = ac._revision(root)
    return {
        "events": 5, "alerts": 3, "cases": 2, "duplicates_ignored": 1,
        "revision_matches": head == manifest["source_commit"],
        "clean_committed_local_record": head == manifest["source_commit"] and clean and cases_doc["worktree_clean_at_capture"],
        "synthetic_only": True,
        "independently_attested": False, "incident_confirmed": False,
        "control_effectiveness_verified": False, "security_assured_release_approved": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Project 6.3 offline synthetic incident correlation")
    parser.add_argument("command", choices=("run", "verify"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            result = run(args.repo_root, args.output_dir)
        else:
            result = verify(args.repo_root, args.output_dir)
    except (CorrelationError, schema.ScenarioError, gd.DashboardError, ac.AssuranceError,
            OSError, ValueError, UnicodeError, TypeError, KeyError) as exc:
        print(f"Project 6.3 correlation failed ({type(exc).__name__})", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
