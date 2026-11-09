"""Deterministic, privacy-preserving detector for Cyranta chatbot JSONL events.

This first milestone deliberately uses only proven Project 1 telemetry fields.
It does not classify prompt injection or infer a gateway decision from chatbot logs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from monitoring.gateway_detection import (
    DETECTABLE_CODES,
    detect_gateway_decision,
    normalize_gateway_audit,
)

RULE_ID = "CYR-DET-001"


@dataclass
class ScanSummary:
    lines: int = 0
    alerts: int = 0
    ignored: int = 0
    malformed: int = 0
    duplicates: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "lines": self.lines,
            "alerts": self.alerts,
            "ignored": self.ignored,
            "malformed": self.malformed,
            "duplicates": self.duplicates,
        }


def detect_blocked_request(event: Mapping[str, Any]) -> dict[str, str] | None:
    """Return a safe alert for one validated, explicitly blocked LLM request.

    Alert fields are an allowlist. Untrusted event fields, including prompt,
    response, flags, model, user identifiers and token-bearing values, are
    never copied into output.
    """
    if event.get("event_type") != "llm_request" or event.get("blocked") is not True:
        return None

    supplied_id = event.get("request_id")
    supplied_ts = event.get("ts")
    if not isinstance(supplied_id, str) or not isinstance(supplied_ts, str):
        return None
    try:
        request_id = str(UUID(supplied_id))
        event_time = datetime.fromisoformat(supplied_ts)
    except ValueError:
        return None
    if event_time.tzinfo is None or event_time.utcoffset() is None:
        return None

    alert_id = hashlib.sha256(f"{RULE_ID}:{request_id}".encode()).hexdigest()[:24]
    return {
        "alert_id": alert_id,
        "rule_id": RULE_ID,
        "severity": "medium",
        "event_type": "llm_request",
        "request_id": request_id,
        "event_ts": event_time.isoformat(),
        "reason": "AI request blocked by application security controls",
    }


def scan_jsonl(input_path: Path, output_path: Path) -> ScanSummary:
    """Scan input one line at a time and atomically replace a sanitized alerts file.

    Repeated runs produce the same output without appending duplicate alerts.
    Invalid JSON and malformed blocked events are counted, never echoed.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output paths must be different")

    summary = ScanSummary()
    seen: set[str] = set()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None

    try:
        with input_path.open("r", encoding="utf-8-sig") as source, tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output_path.parent,
            prefix=".cyranta-alerts-",
            suffix=".tmp",
            delete=False,
        ) as sink:
            temporary_name = sink.name
            for raw_line in source:
                summary.lines += 1
                try:
                    event = json.loads(raw_line)
                except (json.JSONDecodeError, UnicodeError):
                    summary.malformed += 1
                    continue
                if not isinstance(event, dict):
                    summary.malformed += 1
                    continue

                # Project 3's in-memory audit has no event_type/ISO timestamp.
                # Normalize it through an explicit allowlist before detection.
                if "event_type" not in event and (
                    "decision_code" in event or "time_epoch" in event
                ):
                    normalized = normalize_gateway_audit(event)
                    if normalized is None:
                        summary.malformed += 1
                        continue
                    event = normalized

                alert = detect_blocked_request(event)
                if alert is None:
                    alert = detect_gateway_decision(event)
                if alert is None:
                    if event.get("event_type") == "llm_request" and event.get("blocked") is True or (
                        event.get("event_type") == "tool_decision"
                        and event.get("allowed") is False
                        and isinstance(event.get("decision_code"), str)
                        and event["decision_code"] in DETECTABLE_CODES
                    ):
                        summary.malformed += 1
                    else:
                        summary.ignored += 1
                    continue
                if alert["alert_id"] in seen:
                    summary.duplicates += 1
                    continue
                seen.add(alert["alert_id"])
                sink.write(json.dumps(alert, sort_keys=True) + "\n")
                summary.alerts += 1

        Path(temporary_name).replace(output_path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)

    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CYR-DET-001: detect blocked Cyranta LLM requests without logging raw content"
    )
    parser.add_argument("--input", type=Path, required=True, help="Source JSONL telemetry")
    parser.add_argument("--output", type=Path, required=True, help="Sanitized alerts JSONL")
    args = parser.parse_args(argv)
    try:
        summary = scan_jsonl(args.input, args.output)
    except (OSError, ValueError):
        # Never echo the exception message: input paths or file bytes could be sensitive.
        parser.exit(2, "Detection failed; check input/output paths and filesystem permissions.\n")
        return 2  # pragma: no cover
    print(json.dumps(summary.to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
