# Cyranta Project 4.2 — Agent Gateway Security Detection

## Scope

An **additive** detection layer over the already validated ToolGateway audit records.
No changes to the Agent gateway's authorization or business logic.

- CYR-DET-006: explicitly denied tool requests based on identity, role, resource or capability scope.
- CYR-DET-007: rejected/expired capability or approval and emergency revocation. These codes do **not** distinguish a replay attempt from expiration or forgery; report the observed code, never assert an attack's intent.

The adapter `normalize_gateway_audit` takes actual dictionaries from `ToolGateway.audit` (which contain `time_epoch`, `allowed`, `decision_code`, `request_id`). It **does not copy** user IDs, tool names, resource IDs, arguments, approval tokens, or free-form text. It returns a sanitized `tool_decision` event with an ISO 8601 timestamp. The existing `monitoring.detector` CLI now detects both `llm_request` and gateway `tool_decision` JSONL events; it can also normalize raw gateway audit fixture lines for local testing.

The CLI remains a **one-shot** scan. Nothing runs continuously or automatically modifies the gateway.

## Run checks on PowerShell

```powershell
$py = ".\.venv-agent\Scripts\python.exe"
& $py -m ruff check .
& $py -m pytest monitoring/tests -q
& $py -m pytest -q
```

## Demo: entirely fictional denial events

```powershell
New-Item -ItemType Directory telemetry -Force | Out-Null
$sample = @'
{"request_id":"9e04bcb5-9acc-46ab-a320-dd697a580619","time_epoch":1791916800,"allowed":false,"decision_code":"ROLE_TOOL_DENIED"}
{"request_id":"37ea0284-a8ae-4feb-bd06-0b9001f136cf","time_epoch":1791916810,"allowed":false,"decision_code":"APPROVAL_INVALID_OR_EXPIRED"}
{"request_id":"35e177a6-45ee-4b61-aac5-900258ebf475","time_epoch":1791916820,"allowed":true,"decision_code":"ALLOWED"}
'@
$sample | Set-Content telemetry\project4-gateway-demo.jsonl -Encoding UTF8
& $py -m monitoring.detector --input telemetry\project4-gateway-demo.jsonl --output telemetry\project4-gateway-alerts.jsonl
```

Expected `alerts: 2`, `ignored: 1`, `malformed: 0`, `duplicates: 0`.

## Export actual trusted in-memory audit without writing raw records

Call from **trusted, local application/harness code** *after* the gateway has made decisions. For example:

```python
from app.telemetry import write_event
from monitoring.gateway_detection import emit_gateway_audit

# gateway is an existing ToolGateway that has already made decisions.
# Export only previously unexported audit entries to avoid duplicate telemetry.
emitted = emit_gateway_audit(gateway.audit, write_event)
```

Use an index/cursor (e.g. `gateway.audit[last_exported_index:]`) if exporting multiple times. Do **not** put a raw `gateway.audit` JSON dump into production logs, or expose trusted capability/approval issuance methods through an LLM or public API. The exporter does not remove previously written raw logs, should any exist.

## Privacy and limitations

The events and alerts contain only known code enums, `request_id`, event time, and rule metadata. The detector does not infer replay vs expiration or verify an attacker exists. Existing Project 4.1 tests remain intact. The ChromaDB dependency risk from Project 2 is not addressed by this addition.
