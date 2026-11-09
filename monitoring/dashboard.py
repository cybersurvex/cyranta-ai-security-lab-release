"""Offline Cyranta alert dashboard and local triage status tracking.

Reads sanitized CYR-DET-001/006/007 alert files (not raw model telemetry).
No network service, JavaScript dependency, or external assets are required.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from monitoring.gateway_detection import AUTHORIZATION_CODES, UNAUTHORIZED_CODES

RULES: dict[str, tuple[str, str]] = {
    "CYR-DET-001": ("medium", "llm_request"),
    "CYR-DET-006": ("medium", "tool_decision"),
    "CYR-DET-007": ("high", "tool_decision"),
}
STATUSES = frozenset({"new", "investigating", "false_positive", "confirmed", "resolved"})
ALERT_ID_RE = re.compile(r"[a-f0-9]{24}\Z")
MAX_ALERT_BYTES = 25 * 1024 * 1024
MAX_TRIAGE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class Alert:
    alert_id: str
    rule_id: str
    severity: str
    event_type: str
    request_id: str
    event_ts: str  # Canonical UTC ISO-8601
    decision_code: str

    def to_view(self, status: str) -> dict[str, str]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "event_type": self.event_type,
            "request_id": self.request_id,
            "event_ts": self.event_ts,
            "decision_code": self.decision_code,
            "triage_status": status,
        }


@dataclass
class AlertLoad:
    alerts: list[Alert]
    lines: int = 0
    invalid: int = 0
    duplicates: int = 0


def _parse_alert(record: Any) -> Alert | None:
    if not isinstance(record, dict):
        return None
    rule_id = record.get("rule_id")
    if not isinstance(rule_id, str) or rule_id not in RULES:
        return None
    severity, event_type = RULES[rule_id]
    if record.get("severity") != severity or record.get("event_type") != event_type:
        return None
    alert_id = record.get("alert_id")
    raw_id = record.get("request_id")
    raw_ts = record.get("event_ts")
    if (
        not isinstance(alert_id, str)
        or ALERT_ID_RE.fullmatch(alert_id) is None
        or not isinstance(raw_id, str)
        or not isinstance(raw_ts, str)
    ):
        return None
    try:
        request_id = str(UUID(raw_id))
        event_time = datetime.fromisoformat(raw_ts)
    except ValueError:
        return None
    if event_time.tzinfo is None or event_time.utcoffset() is None:
        return None
    expected_id = hashlib.sha256(f"{rule_id}:{request_id}".encode()).hexdigest()[:24]
    if alert_id != expected_id:
        return None
    decision_code = record.get("decision_code")
    if rule_id == "CYR-DET-001":
        # Ignore any extra fields; never propagate raw data into the report.
        decision = ""
    elif rule_id == "CYR-DET-006" and isinstance(decision_code, str) and decision_code in UNAUTHORIZED_CODES or rule_id == "CYR-DET-007" and isinstance(decision_code, str) and decision_code in AUTHORIZATION_CODES:
        decision = decision_code
    else:
        return None
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        severity=severity,
        event_type=event_type,
        request_id=request_id,
        event_ts=event_time.astimezone(UTC).isoformat(),
        decision_code=decision,
    )


def load_alerts(path: Path) -> AlertLoad:
    """Read a bounded sanitized JSONL file; reject unrecognized/forged records."""
    if path.stat().st_size > MAX_ALERT_BYTES:
        raise ValueError("Alert file is over the size limit")
    result = AlertLoad([])
    seen: set[str] = set()
    with path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            result.lines += 1
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, UnicodeError):
                result.invalid += 1
                continue
            alert = _parse_alert(record)
            if alert is None:
                result.invalid += 1
            elif alert.alert_id in seen:
                result.duplicates += 1
            else:
                seen.add(alert.alert_id)
                result.alerts.append(alert)
    result.alerts.sort(
        key=lambda item: (datetime.fromisoformat(item.event_ts), item.alert_id),
        reverse=True,
    )
    return result


def load_triage(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    if path.stat().st_size > MAX_TRIAGE_BYTES:
        raise ValueError("Triage file is over the size limit")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid triage file") from exc
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("version"), int)
        or isinstance(data.get("version"), bool)
        or data["version"] != 1
    ):
        raise ValueError("Unsupported triage format")
    decisions = data.get("decisions")
    if not isinstance(decisions, dict):
        raise TypeError("Invalid triage decisions")
    for key, value in decisions.items():
        if (
            not isinstance(key, str)
            or ALERT_ID_RE.fullmatch(key) is None
            or not isinstance(value, str)
            or value not in STATUSES
        ):
            raise ValueError("Invalid triage entry")
    return decisions


def _atomic_write(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=".cyranta-dashboard-", suffix=".tmp", delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(contents)
        Path(temporary_name).replace(path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def update_triage(
    alerts_path: Path, triage_path: Path, alert_id: str, status: str
) -> None:
    if alerts_path.resolve() == triage_path.resolve():
        raise ValueError("Alert and triage files must differ")
    if ALERT_ID_RE.fullmatch(alert_id) is None or status not in STATUSES:
        raise ValueError("Invalid alert ID or triage status")
    alerts = load_alerts(alerts_path)
    if alert_id not in {alert.alert_id for alert in alerts.alerts}:
        raise ValueError("Alert ID is not present in the validated source")
    decisions = load_triage(triage_path)
    decisions[alert_id] = status
    _atomic_write(
        triage_path,
        json.dumps({"version": 1, "decisions": decisions}, sort_keys=True, indent=2) + "\n",
    )


_STYLE = r"""
:root{color-scheme:dark;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#0b1220;color:#e6edf7}
*{box-sizing:border-box}body{margin:0;padding:32px;max-width:1340px;margin-inline:auto}
a{color:#9ac4ff}h1{margin:0;font-size:clamp(24px,3vw,35px)}h2{font-size:18px;margin:0 0 16px}
.muted{color:#9aabc2}.small{font-size:12px}.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.14em;color:#7ec6e7}
header{display:flex;flex-wrap:wrap;justify-content:space-between;gap:20px;align-items:end;margin-bottom:24px}
.pill{border:1px solid #36536b;border-radius:20px;padding:9px 13px;font-size:12px;color:#c7d8ed}
.stats{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:24px}
.card,.panel{background:#131f31;border:1px solid #29405b;border-radius:15px;padding:20px;min-width:0}
.card .k{color:#afc0d3;font-size:12px}.card .v{font-size:29px;font-weight:750;margin-top:9px;font-variant-numeric:tabular-nums}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.track{background:#253750;height:14px;border-radius:8px;overflow:hidden;flex:1}
.fill{background:#53b6d4;height:100%;border-radius:8px}
.barrow{display:flex;align-items:center;gap:14px;margin:12px 0}.barrow span:first-child{width:115px;font-size:12px}.barrow b{width:40px;text-align:right;font-size:12px}
.controls{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 14px}select,input{background:#0b1729;color:#e6edf7;border:1px solid #3a5876;border-radius:8px;padding:11px;min-width:130px}
input{flex:1;min-width:200px}.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;border-bottom:1px solid #29405b;padding:12px;white-space:nowrap}th{color:#a8bfd5;font-size:12px}
code{font-family:ui-monospace,Consolas,monospace;color:#c0d9ff;font-size:12px}
sev-high{color:#fb9c9c} .high{color:#fb9c9c;font-weight:700}.medium{color:#ffd78f;font-weight:700}
.status{display:inline-block;border:1px solid #3e5c7d;border-radius:12px;padding:3px 9px;font-size:11px}
footer{padding-top:20px;color:#a5b5cb;font-size:12px;line-height:1.7}
@media(max-width:930px){.stats{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}body{padding:16px}}
"""

_SCRIPT = r"""
'use strict';
const alerts=JSON.parse(document.getElementById('alert-data').textContent);
const counts=JSON.parse(document.getElementById('summary-data').textContent);
const $=(id)=>document.getElementById(id);
for(const [id,key] of [['total','total'],['high','high'],['medium','medium'],['open','open'],['confirmed','confirmed']]){$(id).textContent=String(counts[key]);}
$('integrity').textContent=`${counts.invalid} invalid records, ${counts.duplicates} duplicates ignored`;
const days=counts.by_day;
function bar(container,data){container.replaceChildren();const max=Math.max(1,...data.map(x=>x[1]));for(const [label,n] of data){const r=document.createElement('div');r.className='barrow';const a=document.createElement('span');a.textContent=label;const t=document.createElement('div');t.className='track';const f=document.createElement('div');f.className='fill';f.style.width=`${100*n/max}%`;t.append(f);const c=document.createElement('b');c.textContent=String(n);r.append(a,t,c);container.append(r);}}
bar($('rules'),Object.entries(counts.by_rule).sort());bar($('timeline'),days);
function cell(row,value,isCode=false){const td=document.createElement('td');if(isCode){const el=document.createElement('code');el.textContent=value;td.append(el);}else{td.textContent=value;}row.append(td);}
function update(){const rule=$('rule').value,sev=$('severity').value,triage=$('triage').value,q=$('search').value.toLowerCase().trim();const rows=alerts.filter(a=>(!rule||a.rule_id===rule)&&(!sev||a.severity===sev)&&(!triage||a.triage_status===triage)&&(!q||`${a.alert_id} ${a.request_id} ${a.decision_code}`.toLowerCase().includes(q)));$('shown').textContent=`Showing ${rows.length} of ${alerts.length} alerts`;const body=$('tbody');body.replaceChildren();for(const a of rows.slice(0,1000)){const tr=document.createElement('tr');cell(tr,a.event_ts);cell(tr,a.rule_id);const s=document.createElement('td');s.className=a.severity;s.textContent=a.severity;tr.append(s);cell(tr,a.decision_code||'—');cell(tr,a.triage_status);cell(tr,a.request_id,true);cell(tr,a.alert_id,true);body.append(tr);}if(rows.length>1000){$('shown').textContent+=' (first 1,000 displayed)';}}
for(const id of ['rule','severity','triage','search']){$(id).addEventListener('input',update);}update();
"""

_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src __SCRIPT_HASH__; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; form-action 'none'">
<title>Cyranta | Offline Security Monitoring</title><style>__STYLE__</style></head><body>
<header><div><div class="eyebrow">Cyranta / Security operations</div><h1>AI Security Monitoring</h1><p class="muted">Local, offline alert analytics · CYR-DET-001 / 006 / 007</p></div><div class="pill">OFFLINE REPORT · NO NETWORK REQUESTS</div></header>
<section class="stats" aria-label="Alert totals"><div class="card"><div class="k">Validated alerts</div><div class="v" id="total">—</div></div><div class="card"><div class="k">High severity</div><div class="v high" id="high">—</div></div><div class="card"><div class="k">Medium severity</div><div class="v medium" id="medium">—</div></div><div class="card"><div class="k">Open triage</div><div class="v" id="open">—</div></div><div class="card"><div class="k">Confirmed by analyst</div><div class="v" id="confirmed">—</div></div></section>
<section class="grid"><div class="panel"><h2>Detection rules</h2><div id="rules"></div></div><div class="panel"><h2>Daily volume (UTC · most recent 14 active days)</h2><div id="timeline"></div></div></section>
<section class="panel"><h2>Alert triage queue</h2><div class="controls"><select id="rule" aria-label="Rule"><option value="">All rules</option><option>CYR-DET-001</option><option>CYR-DET-006</option><option>CYR-DET-007</option></select><select id="severity" aria-label="Severity"><option value="">All severities</option><option>high</option><option>medium</option></select><select id="triage" aria-label="Triage status"><option value="">All triage statuses</option><option>new</option><option>investigating</option><option>false_positive</option><option>confirmed</option><option>resolved</option></select><input id="search" aria-label="Search request ID, alert ID or decision code" placeholder="Search request ID, alert ID or decision code"></div><p class="muted small" id="shown"></p><div class="tablewrap"><table><thead><tr><th>Time (UTC)</th><th>Rule</th><th>Severity</th><th>Decision code</th><th>Triage</th><th>Request ID</th><th>Alert ID</th></tr></thead><tbody id="tbody"></tbody></table></div></section>
<footer><div id="integrity"></div><div>Rule matches are not confirmed incidents. Set status with <code>python -m monitoring.dashboard triage</code> and regenerate this report.</div><div>Only validated, allowlisted alert fields are included. Raw prompts, responses, user IDs, resource IDs and bearer tokens are excluded.</div></footer>
<script type="application/json" id="alert-data">__ALERT_DATA__</script><script type="application/json" id="summary-data">__SUMMARY_DATA__</script><script>__SCRIPT__</script></body></html>
"""


def _json_for_html(value: Any) -> str:
    """Escape markup-breaking bytes before embedding JSON in a script element."""
    return (
        json.dumps(value, separators=(",", ":"), ensure_ascii=True)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def render_dashboard(load: AlertLoad, triage: dict[str, str]) -> str:
    sanitized = [alert.to_view(triage.get(alert.alert_id, "new")) for alert in load.alerts]
    by_rule = Counter(alert.rule_id for alert in load.alerts)
    by_day = Counter(alert.event_ts[:10] for alert in load.alerts)
    statuses = Counter(row["triage_status"] for row in sanitized)
    stats = {
        "total": len(sanitized),
        "high": sum(a.severity == "high" for a in load.alerts),
        "medium": sum(a.severity == "medium" for a in load.alerts),
        "open": statuses["new"] + statuses["investigating"],
        "confirmed": statuses["confirmed"],
        "invalid": load.invalid,
        "duplicates": load.duplicates,
        "by_rule": dict(by_rule),
        "by_day": sorted(by_day.items())[-14:],
    }
    script_digest = base64.b64encode(hashlib.sha256(_SCRIPT.encode()).digest()).decode()
    return (
        _TEMPLATE.replace("__SCRIPT_HASH__", f"'sha256-{script_digest}'")
        .replace("__STYLE__", _STYLE)
        .replace("__ALERT_DATA__", _json_for_html(sanitized))
        .replace("__SUMMARY_DATA__", _json_for_html(stats))
        .replace("__SCRIPT__", _SCRIPT)
    )


def generate(alerts_path: Path, triage_path: Path, output_path: Path) -> AlertLoad:
    resolved = [alerts_path.resolve(), triage_path.resolve(), output_path.resolve()]
    if len(set(resolved)) != 3:
        raise ValueError("Alert, triage and report paths must all differ")
    alerts = load_alerts(alerts_path)
    triage = load_triage(triage_path)
    _atomic_write(output_path, render_dashboard(alerts, triage))
    return alerts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Cyranta alert dashboard and triage")
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("generate", help="Generate self-contained offline HTML dashboard")
    build.add_argument("--alerts", type=Path, required=True)
    build.add_argument("--triage-file", type=Path, default=Path("telemetry/triage.json"))
    build.add_argument("--output", type=Path, required=True)
    triage = sub.add_parser("triage", help="Set analyst triage status for a validated alert ID")
    triage.add_argument("--alerts", type=Path, required=True)
    triage.add_argument("--triage-file", type=Path, default=Path("telemetry/triage.json"))
    triage.add_argument("--alert-id", required=True)
    triage.add_argument("--status", choices=sorted(STATUSES), required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            load = generate(args.alerts, args.triage_file, args.output)
            print(json.dumps({"alerts": len(load.alerts), "invalid": load.invalid,
                              "duplicates": load.duplicates}, sort_keys=True))
        else:
            update_triage(args.alerts, args.triage_file, args.alert_id, args.status)
            print("Triage status updated locally; regenerate the dashboard to view it.")
    except (OSError, TypeError, ValueError):
        # Never echo untrusted file content or path from an exception.
        parser.exit(2, "Dashboard operation failed; check file paths and validated inputs.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
