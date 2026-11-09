"""Project 5.4: offline governance dashboard and audit exports.

Read declared registries and narrowly validated Project 5.3 metadata only.
Never claim compliance, independently verified controls, or release authorization.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import sys
from pathlib import Path
from typing import Any

from governance.project5 import assurance_checks as ac
from governance.project5.control_mapping import MappingError, assess
from governance.project5.registry import RegistryError, _atomic_write, _read_json

MAX_CI_BYTES = 8192
CI_FIELDS = frozenset({
    "schema_version", "source", "run_id", "status", "conclusion", "event",
    "workflow_name", "head_sha", "expected_head_sha", "revision_matches",
    "worktree_clean_at_query", "reported_success_for_current_clean_head",
    "independently_attested",
})


class DashboardError(ValueError):
    """Invalid local input or unsafe governance export path."""


def _local_folder(repo_root: Path, candidate: Path) -> Path:
    """Return a run folder within the repository's ignored governance tree."""
    root = repo_root.resolve()
    base = root / "telemetry" / "governance"
    target = candidate if candidate.is_absolute() else root / candidate
    resolved = target.resolve()
    if not resolved.is_relative_to(base) or resolved == base:
        raise DashboardError("Folder must be under telemetry/governance/<run-name>")
    if target.is_symlink() or base.is_symlink():
        raise DashboardError("Symlinked governance folders are not permitted")
    for parent in (root / "telemetry", base):
        if parent.is_symlink():
            raise DashboardError("Symlinked governance folder ancestors are not permitted")
    relative = resolved.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise DashboardError("Symlinked governance paths are not permitted")
    return resolved


def _ci_status(folder: Path, *, sha: str, clean: bool) -> dict[str, Any]:
    path = folder / "ci-observation.json"
    if not path.exists():
        return {"state": "not_collected", "run_id": None, "independently_attested": False}
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_CI_BYTES:
        raise DashboardError("Unsafe or oversized CI observation")
    data = _read_json(path)
    if (
        data.keys() != CI_FIELDS
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or data["source"] != "github_cli_live_query_unsigned"
        or not isinstance(data["run_id"], str)
        or ac.RUN_ID.fullmatch(data["run_id"]) is None
        or not all(isinstance(data[key], str) for key in (
            "status", "conclusion", "event", "workflow_name", "head_sha",
            "expected_head_sha",
        ))
        or not all(type(data[key]) is bool for key in (
            "revision_matches", "worktree_clean_at_query",
            "reported_success_for_current_clean_head", "independently_attested",
        ))
        or data["independently_attested"] is not False
        or ac.FULL_SHA.fullmatch(data["head_sha"]) is None
        or ac.FULL_SHA.fullmatch(data["expected_head_sha"]) is None
    ):
        raise DashboardError("Unsupported CI observation schema")
    valid = (
        data["status"] == "completed"
        and data["conclusion"] == "success"
        and data["event"] == "push"
        and data["workflow_name"] == "security-gate"
        and data["head_sha"] == sha
        and data["expected_head_sha"] == sha
        and data["revision_matches"] is True
        and data["worktree_clean_at_query"] is True
        and data["reported_success_for_current_clean_head"] is True
        and clean
    )
    return {
        "state": "github_cli_reported_success_for_current_clean_head" if valid else "stale_or_unverified",
        "run_id": data["run_id"],
        "independently_attested": False,
    }


def snapshot(root: Path, evidence_folder: Path) -> dict[str, Any]:
    """Construct a fail-closed metadata snapshot; never open evidence content."""
    root = root.resolve()
    assets, risks, catalogue = ac._registry(root)
    presence = assess(catalogue, assets, risks, root)
    head, worktree_clean = ac._revision(root)
    evidence_path = evidence_folder / "test-evidence.json"
    record: dict[str, Any] | None = None
    if evidence_path.exists():
        if evidence_path.is_symlink():
            raise DashboardError("Symlinked test manifest is not permitted")
        record = ac._evidence(root, evidence_folder)
    committed = bool(
        record
        and record["head_sha"] == head
        and record["worktree_clean_at_capture"] is True
        and worktree_clean
    )
    suites: dict[str, Any] = {}
    for name in ac.SUITES:
        item = record["suites"][name] if record else None
        suites[name] = {
            "status": item["status"] if item else "not_collected",
            "recorded_tests": item["tests"] if item else 0,
            "linked_to_clean_commit": committed,
        }
    control_rows = []
    presence_by_id = {item["control_id"]: item for item in presence["controls"]}
    for row in sorted(catalogue["controls"], key=lambda item: item["control_id"]):
        cid = row["control_id"]
        required = list(ac.CONTROL_SUITES[cid])
        local_pass = bool(record and required) and all(
            suites[name]["status"] == "passed" for name in required
        )
        mapped = presence_by_id[cid]
        control_rows.append({
            "control_id": cid,
            "title": row["title"],
            "asset_ids": list(row["asset_ids"]),
            "nist_ai_rmf_functions": list(row["nist_ai_rmf_functions"]),
            "iso_42001_theme": row["iso_42001_theme"],
            "test_suites": required,
            "recorded_test_pass": local_pass,
            "commit_bound_local_test_record": bool(local_pass and committed),
            "evidence": [
                {"path": ref["path"], "kind": ref["kind"], "presence": ref["presence"]}
                for ref in mapped["evidence"]
            ],
            "known_gaps": list(row["known_gaps"]),
            "open_linked_risks": mapped["open_linked_risk_ids"],
            "owner": None,
            "review_status": "needs_human_review",
            "control_effectiveness_verified": False,
        })
    risk_rows = [{
        "risk_id": row["risk_id"], "asset_ids": row["asset_ids"],
        "component": row["component"], "observed_version": row["observed_version"],
        "status": row["status"], "decision": row["decision"],
        "risk_owner": None, "source_document": row["source_document"],
    } for row in risks["risks"]]
    ci = _ci_status(evidence_folder, sha=head, clean=worktree_clean)
    return {
        "schema_version": 1,
        "scope": "isolated_local_research",
        "head_sha": head,
        "snapshot": {
            "worktree_clean": worktree_clean,
            "clean_committed_test_snapshot": committed,
            "test_record_provenance": "unsigned_local_pytest_record" if record else "not_collected",
            "ci_observation": ci,
        },
        "totals": {
            "assets": len(assets["assets"]),
            "controls": len(control_rows),
            "control_owners_unassigned": len(control_rows),
            "controls_needing_human_review": len(control_rows),
            "controls_with_declared_gaps": len(control_rows),
            "evidence_references": presence["summary"]["evidence_references"],
            "evidence_located": presence["summary"]["evidence_located"],
            "evidence_missing": presence["summary"]["evidence_missing"],
            "evidence_untrusted": presence["summary"]["evidence_untrusted"],
            "open_risks": sum(item["status"] == "open" for item in risks["risks"]),
            "recorded_passed_suites": sum(x["status"] == "passed" for x in suites.values()),
            "planned_suites": len(ac.SUITES),
            "recorded_tests": sum(x["recorded_tests"] for x in suites.values()),
        },
        "assets": [{
            "asset_id": row["asset_id"], "name": row["name"],
            "component_path": row["component_path"], "owner": None,
        } for row in assets["assets"]],
        "risks": risk_rows,
        "suites": suites,
        "controls": control_rows,
        "review_requirements": [
            "Assign and authorize asset, risk, and control owners.",
            "Resolve or formally review CYRANTA-DEP-001; do not imply acceptance.",
            "Review test and CI provenance independently before assurance decisions.",
            "Assess operational effectiveness beyond located files and recorded tests.",
        ],
        "limitations": [
            "Offline declarations are not automatic discovery.",
            "Evidence file presence is not proof of execution or effectiveness.",
            "Locally recorded tests and GitHub CLI observations are unsigned and can be forged.",
            "NIST and ISO associations are broad, unreviewed themes, not certification.",
            "RAG dependency audit remains outside the passing core/agent CI gate.",
        ],
        "control_effectiveness_verified": False,
        "compliance_certified": False,
        "security_assured_release_approved": False,
    }


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


_STYLE = """
:root{color-scheme:light;--ink:#17243b;--navy:#112b49;--muted:#65758b;--line:#dbe3ec;--bg:#f3f6fa;--card:#fff;--accent:#286a9f;--amber:#a2681d}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,'Segoe UI',sans-serif}
.container{max-width:1180px;margin:auto;padding:28px 24px 52px}
.top{background:linear-gradient(110deg,#102d4d,#234d70);color:#fff;padding:34px 0}
.top .container{padding-top:0;padding-bottom:0}.eyebrow{letter-spacing:.15em;text-transform:uppercase;font-size:11px;opacity:.85;font-weight:700}
h1{font-size:30px;line-height:1.2;margin:8px 0}h2{font-size:20px;margin:0 0 14px}h3{font-size:17px;margin:0 0 6px}.subhead{margin-top:24px}p{margin:7px 0 14px}
.top p{color:#d8e4ef}.banner{margin-top:20px;border:1px solid #ffc987;background:#fff4e6;color:#713f09;padding:13px 16px;border-radius:10px;font-weight:700}
.cards{display:grid;grid-template-columns:repeat(5,minmax(135px,1fr));gap:12px;margin:22px 0}.stat,.panel{background:#fff;border:1px solid var(--line);border-radius:12px;box-shadow:0 2px 10px #19345208}
.stat{padding:16px}.stat .number{display:block;font-size:28px;line-height:1.1;font-weight:800;color:var(--navy)}.stat .label{display:block;margin-top:9px;font-size:12px;color:var(--muted)}
.panel{padding:21px;margin:16px 0}.muted{color:var(--muted)}.small{font-size:12px}.facts{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.fact{padding:12px 14px;background:#f7f9fc;border-radius:8px}.fact strong{display:block;font-size:13px;margin-bottom:4px}
.tag{display:inline-block;font-size:12px;font-weight:650;padding:3px 9px;border-radius:999px;background:#edf3fa;color:#345778}.tag.open{background:#fff0e0;color:#86460c}.tag.danger{background:#feecec;color:#9c3434}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--muted);font-size:11px;letter-spacing:.06em;text-transform:uppercase;background:#f7f9fc}td,th{padding:10px 9px;border-bottom:1px solid var(--line);vertical-align:top}
.scroll{overflow:auto}details{border:1px solid var(--line);border-radius:9px;margin-top:10px;padding:12px 14px;background:#fff}summary{cursor:pointer;font-weight:700}details p{font-size:13px}.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}
code{font-family:ui-monospace,Consolas,monospace;font-size:12px;overflow-wrap:anywhere}.foot{color:var(--muted);font-size:12px;padding:20px 0 0}
ul{margin:6px 0 12px;padding-left:20px}li{margin:4px 0}a{color:var(--accent)}.visually-hidden{position:absolute;left:-9999px}
@media(max-width:850px){.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.cols,.facts{grid-template-columns:1fr}.container{padding-left:16px;padding-right:16px}}
@media print{body{background:white}.top{background:white;color:#111;border-bottom:2px solid #444}.top p{color:#444}.cards{grid-template-columns:repeat(5,1fr)}.panel,.stat{box-shadow:none;break-inside:avoid}details{break-inside:avoid}details:not([open])>*:not(summary){display:block}}
""".strip()


def render_html(data: dict[str, Any]) -> str:
    """Produce inert HTML: no JS, external resources, requests, or unescaped input."""
    totals = data["totals"]
    snap = data["snapshot"]
    ci = snap["ci_observation"]
    metrics = (
        ("Registered assets", totals["assets"]),
        ("Mapped controls", totals["controls"]),
        ("Open risks", totals["open_risks"]),
        ("Evidence located", f"{totals['evidence_located']}/{totals['evidence_references']}"),
        ("Recorded passing suites", f"{totals['recorded_passed_suites']}/{totals['planned_suites']}"),
    )
    cards = "".join(
        f'<div class="stat"><span class="number">{_esc(val)}</span><span class="label">{_esc(label)}</span></div>'
        for label, val in metrics
    )
    control_table = "".join(
        "<tr>" + "".join(f"<td>{_esc(value)}</td>" for value in (
            row["control_id"], row["title"],
            ", ".join(row["test_suites"]) or "No covered suite",
            "Recorded pass (unsigned)" if row["recorded_test_pass"] else "Not established",
            "Matched clean commit" if row["commit_bound_local_test_record"] else "Unverified",
            "Human review required",
        )) + "</tr>"
        for row in data["controls"]
    )
    risk_table = "".join(
        f'<tr><td>{_esc(row["risk_id"])}</td><td>{_esc(row["component"])} {_esc(row["observed_version"])}</td>'
        f'<td><span class="tag open">{_esc(row["status"])}</span></td>'
        f'<td>{_esc(row["decision"])}</td><td>Unassigned</td></tr>'
        for row in data["risks"]
    )
    details = []
    for row in data["controls"]:
        refs = "".join(
            f'<li><code>{_esc(ev["path"])}</code> — {_esc(ev["kind"])}: {_esc(ev["presence"])}</li>'
            for ev in row["evidence"]
        )
        gaps = "".join(f"<li>{_esc(gap)}</li>" for gap in row["known_gaps"])
        details.append(
            f'<details><summary>{_esc(row["control_id"])} · {_esc(row["title"])}</summary>'
            f'<p class="muted">Assets: {_esc(", ".join(row["asset_ids"]))} · '
            f'NIST functions: {_esc(", ".join(row["nist_ai_rmf_functions"]))} · '
            f'ISO management theme: {_esc(row["iso_42001_theme"])}</p>'
            f'<h3>Declared evidence</h3><ul>{refs}</ul><h3>Known gaps</h3><ul>{gaps}</ul>'
            f'<p>Linked open risks: {_esc(", ".join(row["open_linked_risks"]) or "None recorded")}</p></details>'
        )
    suite_rows = "".join(
        f'<tr><td>{_esc(name)}</td><td>{_esc(suite["status"])}</td>'
        f'<td>{_esc(suite["recorded_tests"])}</td></tr>'
        for name, suite in data["suites"].items()
    )
    assets_rows = "".join(
        f'<tr><td>{_esc(row["asset_id"])}</td><td>{_esc(row["name"])}</td>'
        f'<td><code>{_esc(row["component_path"])}</code></td><td>Unassigned</td></tr>'
        for row in data["assets"]
    )
    limitations = "".join(f"<li>{_esc(item)}</li>" for item in data["limitations"])
    checks = "".join(f"<li>{_esc(item)}</li>" for item in data["review_requirements"])
    digest = base64.b64encode(hashlib.sha256(_STYLE.encode("utf-8")).digest()).decode("ascii")
    csp = f"default-src 'none'; style-src 'sha256-{digest}'; img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'"
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{_esc(csp)}">
<title>Cyranta | Offline AI Governance</title><style>{_STYLE}</style></head>
<body><header class="top"><div class="container"><div class="eyebrow">Cyranta · AI Security Lab · Project 5.4</div>
<h1>AI Governance &amp; Assurance Dashboard</h1><p>Offline research-lab audit overview · self-contained, no network requests</p>
<code>Git HEAD: {_esc(data["head_sha"])}</code></div></header>
<main class="container"><div class="banner" role="status">LOCAL RESEARCH ONLY — NO CERTIFICATION, RISK ACCEPTANCE OR RELEASE AUTHORIZATION</div>
<section class="cards" aria-label="Governance metrics">{cards}</section>
<section class="panel"><h2>Evidence context</h2><div class="facts">
<div class="fact"><strong>Source snapshot</strong>{'Clean committed local test record' if snap['clean_committed_test_snapshot'] else 'Unverified or uncommitted local test record'}</div>
<div class="fact"><strong>GitHub CI observation</strong>{_esc(ci['state'])} (unsigned){f' · Run {_esc(ci["run_id"])}' if ci['run_id'] else ''}</div>
<div class="fact"><strong>Control effectiveness</strong>Not independently verified · All {_esc(totals['controls'])} controls require human review</div>
<div class="fact"><strong>Evidence availability</strong>{_esc(totals['evidence_missing'])} missing · {_esc(totals['evidence_untrusted'])} untrusted paths</div>
</div></section>
<div class="cols"><section class="panel"><h2>Known open risks</h2><div class="scroll"><table><thead><tr><th>ID</th><th>Component</th><th>Status</th><th>Decision</th><th>Owner</th></tr></thead><tbody>{risk_table}</tbody></table></div></section>
<section class="panel"><h2>Recorded test groups</h2><div class="scroll"><table><thead><tr><th>Suite</th><th>Local status</th><th>Tests</th></tr></thead><tbody>{suite_rows}</tbody></table></div>
<p class="muted small">Passing a selected test does not certify a control; the RAG dependency risk remains open.</p></section></div>
<section class="panel"><h2>Security control review</h2><div class="scroll"><table><thead><tr><th>ID</th><th>Control</th><th>Test groups</th><th>Local record</th><th>Snapshot</th><th>Review</th></tr></thead><tbody>{control_table}</tbody></table></div>
<h3 class="subhead">Control details and outstanding gaps</h3>{''.join(details)}</section>
<section class="panel"><h2>Registered AI assets</h2><div class="scroll"><table><thead><tr><th>Asset ID</th><th>Asset</th><th>Path reference</th><th>Owner</th></tr></thead><tbody>{assets_rows}</tbody></table></div></section>
<div class="cols"><section class="panel"><h2>Required human actions</h2><ul>{checks}</ul></section>
<section class="panel"><h2>Assurance limitations</h2><ul>{limitations}</ul></section></div>
<footer class="foot">Cyranta research-lab output · NIST AI RMF function-level and ISO/IEC 42001 management-theme associations are not certified mappings. Evidence records and hashes are unsigned. Production release is NOT APPROVED.</footer>
</main></body></html>'''


def render_markdown(data: dict[str, Any]) -> str:
    totals = data["totals"]
    snapshot_data = data["snapshot"]
    lines = [
        "# Cyranta — Project 5.4 Governance Audit Report", "",
        "**RESEARCH LAB ONLY — NO CERTIFICATION OR RELEASE AUTHORIZATION**", "",
        f"Git HEAD: `{data['head_sha']}`", "",
        "## Governance summary", "",
        f"- Assets: {totals['assets']}; controls: {totals['controls']}; open risks: {totals['open_risks']}",
        f"- Evidence paths located: {totals['evidence_located']}/{totals['evidence_references']}",
        f"- Missing: {totals['evidence_missing']}; untrusted: {totals['evidence_untrusted']}",
        f"- Recorded passing test suites: {totals['recorded_passed_suites']}/{totals['planned_suites']}",
        f"- Local recorded tests: {totals['recorded_tests']}",
        f"- Clean committed test snapshot: {snapshot_data['clean_committed_test_snapshot']}",
        f"- GitHub CI (unsigned observation): {snapshot_data['ci_observation']['state']}",
        "- Independent effectiveness verification: False", "- Compliance certification: False",
        "- Security-assured release approved: False", "",
        "## Open risks", "",
        "| Risk | Component | Decision | Owner |", "|---|---|---|---|",
    ]
    for row in data["risks"]:
        lines.append(
            f"| {row['risk_id']} | {row['component']} {row['observed_version']} | "
            f"{row['decision']} | Unassigned |"
        )
    lines += ["", "## Control evidence and review gaps", ""]
    for row in data["controls"]:
        local = "recorded pass" if row["recorded_test_pass"] else "not established"
        lines += [f"### {row['control_id']} — {row['title']}", "",
                  f"- Test record: {local}; linked to current clean commit: {row['commit_bound_local_test_record']}",
                  "- Review: needs_human_review; control effectiveness verified: False",
                  f"- Open linked risks: {', '.join(row['open_linked_risks']) or 'none recorded'}",
                  "- Declared evidence paths:"]
        lines += [f"  - `{ev['path']}` ({ev['kind']}; {ev['presence']})" for ev in row["evidence"]]
        lines.append("- Known gaps:")
        lines += [f"  - {gap}" for gap in row["known_gaps"]]
        lines.append("")
    lines += ["## Required human actions", ""]
    lines += [f"- {item}" for item in data["review_requirements"]]
    lines += ["", "## Limitations", ""]
    lines += [f"- {item}" for item in data["limitations"]]
    lines += ["", "**No risk acceptance, independent certification, or production release approval is asserted.**", ""]
    return "\n".join(lines)


def build(root: Path, evidence_dir: Path, output_dir: Path) -> dict[str, Any]:
    root = root.resolve()
    evidence = _local_folder(root, evidence_dir)
    output = _local_folder(root, output_dir)
    if output == evidence or output.is_relative_to(evidence) or evidence.is_relative_to(output):
        raise DashboardError("Audit output and evidence folders must not overlap")
    data = snapshot(root, evidence)
    _atomic_write(output / "audit-summary.json", json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    _atomic_write(output / "audit-report.md", render_markdown(data))
    _atomic_write(output / "governance-dashboard.html", render_html(data))
    return {
        **data["totals"],
        "clean_committed_test_snapshot": data["snapshot"]["clean_committed_test_snapshot"],
        "ci_observation": data["snapshot"]["ci_observation"]["state"],
        "control_effectiveness_verified": False,
        "compliance_certified": False,
        "security_assured_release_approved": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cyranta Project 5.4 offline governance dashboard")
    parser.add_argument("command", choices=("validate", "build"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--evidence-dir", type=Path, default=Path("telemetry/governance/project5-3"))
    parser.add_argument("--output-dir", type=Path, default=Path("telemetry/governance/project5-4"))
    args = parser.parse_args(argv)
    try:
        repo = args.repo_root.resolve()
        evidence = _local_folder(repo, args.evidence_dir)
        output = _local_folder(repo, args.output_dir)
        if output == evidence or output.is_relative_to(evidence) or evidence.is_relative_to(output):
            raise DashboardError("Audit output and evidence folders must not overlap")
        if args.command == "build":
            result = build(repo, evidence, output)
        else:
            view = snapshot(repo, evidence)
            result = {
                **view["totals"],
                "clean_committed_test_snapshot": view["snapshot"]["clean_committed_test_snapshot"],
                "ci_observation": view["snapshot"]["ci_observation"]["state"],
                "control_effectiveness_verified": False,
                "compliance_certified": False,
                "security_assured_release_approved": False,
            }
    except (DashboardError, ac.AssuranceError, MappingError, RegistryError, OSError, UnicodeError, ValueError) as exc:
        print(f"Governance dashboard failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
