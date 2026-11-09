"""Project 5.3: local test execution records and narrowly scoped CI observation.

The report is NOT proof of execution provenance, control effectiveness, risk
acceptance, ISO conformity, or production-release authorization. No raw test
stdout/stderr, JUnit XML, telemetry, credentials, or prompt data is persisted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess  # nosec B404
import sys
import tempfile
import xml.etree.ElementTree as ET  # nosec B405
from pathlib import Path
from typing import Any

from governance.project5.control_mapping import MappingError, assess, validate_mapping
from governance.project5.registry import RegistryError, _atomic_write, _read_json

MAX_JUNIT_BYTES = 2 * 1024 * 1024
FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,17}\Z")
MAX_MANIFEST_BYTES = 128 * 1024
SOURCES = ("governance/project5/assets.json", "governance/project5/risks.json",
           "governance/project5/controls.json")
SUITES: dict[str, tuple[str, ...]] = {
    "chatbot": ("tests/test_security.py", "monitoring/tests/test_detector.py"),
    "rag": ("rag/tests/test_access_control.py", "rag/tests/test_provenance.py"),
    "agent": ("agent/tests/test_tool_gateway.py",),
    "monitoring": ("monitoring/tests/test_gateway_detection.py",
                   "monitoring/tests/test_incident_simulation.py"),
    "governance": ("governance/project5/tests/test_registry.py",
                   "governance/project5/tests/test_control_mapping.py"),
}
CONTROL_SUITES = {
    "CYR-CTL-001": ("chatbot",),
    "CYR-CTL-002": ("rag",),
    "CYR-CTL-003": ("agent",),
    "CYR-CTL-004": ("monitoring",),
    "CYR-CTL-005": ("monitoring",),
    "CYR-CTL-006": (),  # Deliberately NOT considered covered by a green core CI audit.
    "CYR-CTL-007": ("governance",),
}


class AssuranceError(ValueError):
    """Unsafe or inconsistent local assurance input."""


def _in_repo(repo: Path, path: str) -> Path:
    if not isinstance(path, str) or not re.fullmatch(r"[A-Za-z0-9._/-]{2,180}", path):
        raise AssuranceError("Invalid evidence path")
    if any(part in ("", ".", "..") or part.startswith(".") for part in path.split("/")):
        raise AssuranceError("Unsafe evidence path")
    target = repo / path
    if not target.resolve().is_relative_to(repo):
        raise AssuranceError("Evidence path escapes repository")
    if target.is_symlink():
        raise AssuranceError("Symlink evidence is not accepted")
    return target


def _destination(root: Path, output: Path) -> Path:
    allowed = (root / "telemetry" / "governance").resolve()
    dest = (output if output.is_absolute() else root / output).resolve()
    if dest == allowed or not dest.is_relative_to(allowed):
        raise AssuranceError("Output must be under telemetry/governance/<run-name>")
    return dest


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(  # nosec B603 B607
            ["git", *args], cwd=root, capture_output=True, text=True, timeout=12,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssuranceError("Git query unavailable") from exc
    if result.returncode != 0:
        raise AssuranceError("Git query failed")
    return result.stdout.strip()


def _revision(root: Path) -> tuple[str, bool]:
    sha = _git(root, "rev-parse", "--verify", "HEAD")
    if not FULL_SHA.fullmatch(sha):
        raise AssuranceError("Invalid Git revision")
    clean = not bool(_git(root, "status", "--porcelain", "--untracked-files=normal"))
    return sha, clean


def _registry(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    data = [_read_json(_in_repo(root, item)) for item in SOURCES]
    assets, risks, catalogue = data
    validate_mapping(catalogue, assets, risks)
    if {row["control_id"] for row in catalogue["controls"]} != set(CONTROL_SUITES):
        raise AssuranceError("Control catalogue differs from reviewed Project 5.2 baseline")
    return assets, risks, catalogue


def _source_hashes(root: Path) -> dict[str, str]:
    return {path: _hash(_in_repo(root, path)) for path in SOURCES}


def _suite_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for paths in SUITES.values():
        for path in paths:
            file = _in_repo(root, path)
            if file.is_file():
                hashes[path] = _hash(file)
    return hashes


def _junit_counts(file: Path) -> dict[str, int]:
    if not file.is_file() or not 0 < file.stat().st_size <= MAX_JUNIT_BYTES:
        raise AssuranceError("Missing or oversized test result XML")
    raw = file.read_bytes()
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise AssuranceError("Unsafe JUnit XML")
    try:
        root = ET.fromstring(raw)  # nosec B314
    except ET.ParseError as exc:
        raise AssuranceError("Malformed JUnit XML") from exc
    if root.tag not in ("testsuites", "testsuite"):
        raise AssuranceError("Unexpected JUnit XML root")
    cases = list(root.iter("testcase"))
    if not cases:
        raise AssuranceError("Empty JUnit result")
    failures = sum(any(x.tag == "failure" for x in case) for case in cases)
    errors = sum(any(x.tag == "error" for x in case) for case in cases)
    skipped = sum(any(x.tag == "skipped" for x in case) for case in cases)
    return {"tests": len(cases), "failures": failures, "errors": errors,
            "skipped": skipped}


def _execute_suite(root: Path, name: str, timeout: int) -> dict[str, Any]:
    paths = SUITES[name]
    if any(not _in_repo(root, path).is_file() for path in paths):
        return {"status": "missing", "tests": 0, "failures": 0, "errors": 0,
                "skipped": 0, "exit_code": None}
    with tempfile.TemporaryDirectory(prefix="cyranta-p53-") as folder:
        xml = Path(folder) / "junit.xml"
        cmd = [sys.executable, "-m", "pytest", *paths, "-q", f"--junitxml={xml}"]
        try:
            completed = subprocess.run(  # nosec B603
                cmd, cwd=root, capture_output=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return {"status": "error", "tests": 0, "failures": 0,
                    "errors": 0, "skipped": 0, "exit_code": None}
        except OSError:
            return {"status": "error", "tests": 0, "failures": 0,
                    "errors": 0, "skipped": 0, "exit_code": None}
        try:
            counts = _junit_counts(xml)
        except (AssuranceError, OSError):
            return {"status": "error", "tests": 0, "failures": 0,
                    "errors": 0, "skipped": 0, "exit_code": completed.returncode}
    success = (completed.returncode == 0 and counts["failures"] == 0
               and counts["errors"] == 0 and counts["skipped"] == 0)
    return {"status": "passed" if success else "failed", **counts,
            "exit_code": completed.returncode}


def collect(root: Path, output: Path, *, timeout: int = 180) -> dict[str, Any]:
    """Execute only fixed, checked-in test file groups; persist sanitized counts."""
    if type(timeout) is not int or not 10 <= timeout <= 900:
        raise AssuranceError("Timeout must be between 10 and 900 seconds")
    _registry(root)
    dest = _destination(root, output)
    sha, clean = _revision(root)
    results = {name: {"paths": list(paths), **_execute_suite(root, name, timeout)}
               for name, paths in SUITES.items()}
    artifact = {
        "schema_version": 1,
        "kind": "unsigned_local_pytest_execution_record",
        "head_sha": sha,
        "worktree_clean_at_capture": clean,
        "source_sha256": _source_hashes(root),
        "test_file_sha256": _suite_hashes(root),
        "suites": results,
        "limitations": "No authenticated provenance, dependency assurance, or control certification",
    }
    _atomic_write(dest / "test-evidence.json", json.dumps(artifact, indent=2) + "\n")
    return {"suites": len(results), "passed_suites": sum(
        item["status"] == "passed" for item in results.values()),
        "recorded_tests": sum(item["tests"] for item in results.values()),
        "head_sha": sha, "worktree_clean_at_capture": clean,
        "assurance_approved": False}


def _evidence(root: Path, dest: Path) -> dict[str, Any]:
    path = dest / "test-evidence.json"
    if not path.is_file() or path.stat().st_size > MAX_MANIFEST_BYTES:
        raise AssuranceError("Missing or oversized test-evidence.json; run collect first")
    record = _read_json(path)
    if (record.keys() != {"schema_version", "kind", "head_sha",
                          "worktree_clean_at_capture", "source_sha256",
                          "test_file_sha256", "suites", "limitations"}
            or type(record["schema_version"]) is not int
            or record["schema_version"] != 1
            or record["kind"] != "unsigned_local_pytest_execution_record"
            or not isinstance(record["worktree_clean_at_capture"], bool)
            or not isinstance(record["head_sha"], str)
            or FULL_SHA.fullmatch(record["head_sha"]) is None):
        raise AssuranceError("Unsupported local test evidence")
    if record["source_sha256"] != _source_hashes(root):
        raise AssuranceError("Registry sources changed; collect new evidence")
    if record["test_file_sha256"] != _suite_hashes(root):
        raise AssuranceError("Test files changed; collect new evidence")
    suites = record["suites"]
    if not isinstance(suites, dict) or suites.keys() != SUITES.keys():
        raise AssuranceError("Unexpected suite identifiers")
    for name, row in suites.items():
        if (not isinstance(row, dict)
                or row.keys() != {"paths", "status", "tests", "failures",
                                  "errors", "skipped", "exit_code"}
                or row["paths"] != list(SUITES[name])
                or row["status"] not in {"passed", "failed", "missing", "error"}
                or any(type(row[key]) is not int or row[key] < 0
                       for key in ("tests", "failures", "errors", "skipped"))
                or (row["exit_code"] is not None
                    and (type(row["exit_code"]) is not int
                         or not 0 <= row["exit_code"] <= 255))):
            raise AssuranceError("Invalid suite metadata")
        if row["status"] == "passed" and (row["exit_code"] != 0
                or row["tests"] == 0 or row["failures"] or row["errors"]
                or row["skipped"]):
            raise AssuranceError("Contradictory passing suite metadata")
    return record


def ci_check(root: Path, output: Path, *, run_id: str) -> dict[str, Any]:
    """Query GitHub CLI explicitly; a successful report is not a signed attestation."""
    if not isinstance(run_id, str) or RUN_ID.fullmatch(run_id) is None:
        raise AssuranceError("Invalid numeric GitHub Actions run ID")
    dest = _destination(root, output)
    sha, clean = _revision(root)
    try:
        response = subprocess.run(  # nosec B603 B607
            ["gh", "run", "view", run_id, "--json",
             "status,conclusion,headSha,event,workflowName"],
            cwd=root, capture_output=True, text=True, timeout=45, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssuranceError("GitHub CLI unavailable or timed out") from exc
    if response.returncode != 0 or len(response.stdout) > 8192:
        raise AssuranceError("GitHub CLI could not fetch run metadata")
    try:
        data = json.loads(response.stdout)
    except json.JSONDecodeError as exc:
        raise AssuranceError("Invalid GitHub CLI response") from exc
    if not isinstance(data, dict) or data.keys() != {
        "status", "conclusion", "headSha", "event", "workflowName"
    } or not isinstance(data["headSha"], str) or FULL_SHA.fullmatch(data["headSha"]) is None:
        raise AssuranceError("Unexpected GitHub Actions metadata")
    matching = data["headSha"] == sha
    reported_pass = (data["status"] == "completed"
                     and data["conclusion"] == "success"
                     and data["event"] == "push"
                     and data["workflowName"] == "security-gate")
    artifact = {
        "schema_version": 1, "source": "github_cli_live_query_unsigned",
        "run_id": run_id, "status": data["status"], "conclusion": data["conclusion"],
        "event": data["event"], "workflow_name": data["workflowName"],
        "head_sha": data["headSha"], "expected_head_sha": sha,
        "revision_matches": matching, "worktree_clean_at_query": clean,
        "reported_success_for_current_clean_head": reported_pass and matching and clean,
        "independently_attested": False,
    }
    _atomic_write(dest / "ci-observation.json", json.dumps(artifact, indent=2) + "\n")
    return {"run_id": run_id, "revision_matches": matching,
            "reported_success_for_current_clean_head": artifact[
                "reported_success_for_current_clean_head"],
            "independently_attested": False}


def report(root: Path, output: Path) -> dict[str, Any]:
    assets, risks, catalogue = _registry(root)
    dest = _destination(root, output)
    record = _evidence(root, dest)
    sha, clean = _revision(root)
    revision_matches = record["head_sha"] == sha
    committed_snapshot = (revision_matches and clean
                          and record["worktree_clean_at_capture"])
    groups = record["suites"]
    controls = []
    for item in sorted(catalogue["controls"], key=lambda row: row["control_id"]):
        cid = item["control_id"]
        required = CONTROL_SUITES[cid]
        passed = bool(required) and all(groups[suite]["status"] == "passed"
                                        for suite in required)
        controls.append({"control_id": cid, "test_suites": list(required),
                         "recorded_test_pass": passed,
                         "source_snapshot_matched": committed_snapshot,
                         "effectiveness_verified": False,
                         "review_status": "needs_human_review",
                         "known_gap_count": len(item["known_gaps"]),
                         "open_linked_risks": sorted(
                             set(item["risk_ids"]) & {
                                 risk["risk_id"] for risk in risks["risks"]
                                 if risk["status"] == "open"}),
                         })
    ci_path = dest / "ci-observation.json"
    ci_observation = None
    if ci_path.is_file():
        ci = _read_json(ci_path)
        if (ci.get("schema_version") == 1
                and ci.get("source") == "github_cli_live_query_unsigned"
                and ci.get("expected_head_sha") == sha
                and ci.get("head_sha") == sha
                and ci.get("reported_success_for_current_clean_head") is True
                and ci.get("worktree_clean_at_query") is True
                and clean):
            ci_observation = "github_cli_reported_success_for_current_clean_head"
        else:
            ci_observation = "missing_stale_or_mismatched"
    summary = {
        "controls": len(controls),
        "recorded_passed_suites": sum(x["status"] == "passed" for x in groups.values()),
        "planned_suites": len(SUITES),
        "recorded_tests": sum(x["tests"] for x in groups.values()),
        "clean_committed_snapshot": committed_snapshot,
        "ci_observation": ci_observation or "not_collected",
        "open_registered_risks": len(risks["risks"]),
        "controls_needing_human_review": len(controls),
        "control_effectiveness_verified": False,
        "compliance_certified": False,
        "security_assured_release_approved": False,
    }
    payload = {"schema_version": 1, "summary": summary,
               "source_head_sha": sha, "control_checks": controls,
               "suite_results": groups,
               "mapping_evidence_presence": assess(catalogue, assets, risks, root)["summary"],
               "limitations": [
                   "Unsigned local execution records can be altered or forged.",
                   "A GitHub CLI response is not a cryptographic CI attestation.",
                   "A passing test is not independent verification of a security control.",
                   "Core/agent CI excludes the open RAG dependency audit risk.",
                   "No human control approval or security-assured release authorization.",
               ]}
    lines = [
        "# Cyranta Project 5.3 — Offline AI Security Assurance Checks", "",
        "**RESEARCH LAB ONLY — NO ASSURANCE OR RELEASE APPROVAL**", "",
        f"Git HEAD: `{sha}`", "",
        f"Recorded test suites passed: {summary['recorded_passed_suites']}/{len(SUITES)}",
        f"Recorded test cases: {summary['recorded_tests']}",
        f"Clean committed snapshot: {committed_snapshot}",
        f"CI status: {summary['ci_observation']}",
        f"Open registered risks: {len(risks['risks'])}", "",
        "| Control | Local test record | Snapshot | Human review |", "|---|---|---|---|",
    ]
    for item in controls:
        state = "recorded pass" if item["recorded_test_pass"] else "not established"
        lines.append(f"| {item['control_id']} | {state} | "
                     f"{'matched' if committed_snapshot else 'unverified'} | Required |")
    lines.extend(["", "## Unresolved gaps", "",
                  "- CYRANTA-DEP-001 / ChromaDB 1.5.9 remains open and unaccepted.",
                  "- RAG dependency audit is not part of the passing CI gate.",
                  "- All seven control owners require explicit assignment and review.",
                  "- Locally recorded outcomes do not provide cryptographic provenance.",
                  "- No security control is independently certified or approved.", ""])
    _atomic_write(dest / "assurance-summary.json", json.dumps(payload, indent=2) + "\n")
    _atomic_write(dest / "assurance-report.md", "\n".join(lines))
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cyranta 5.3 local assurance evidence")
    parser.add_argument("command", choices=("plan", "collect", "ci-check", "report"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path,
                        default=Path("telemetry/governance/project5-3"))
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--run-id", type=str)
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    try:
        if args.command == "plan":
            _registry(root)
            result = {"suite_groups": {k: list(v) for k, v in SUITES.items()},
                      "control_test_mapping": {k: list(v) for k, v in CONTROL_SUITES.items()},
                      "note": "Test execution is local and not an assurance decision"}
        elif args.command == "collect":
            result = collect(root, args.output_dir, timeout=args.timeout)
        elif args.command == "ci-check":
            result = ci_check(root, args.output_dir, run_id=args.run_id or "")
        else:
            result = report(root, args.output_dir)
    except (AssuranceError, MappingError, RegistryError, OSError, UnicodeError) as exc:
        print(f"Assurance check failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    if args.command == "collect" and result["passed_suites"] != result["suites"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
