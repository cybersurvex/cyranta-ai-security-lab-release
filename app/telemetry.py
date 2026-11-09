from __future__ import annotations

import json
import os
from pathlib import Path
from threading import Lock

_lock = Lock()
LOG_PATH = Path(os.getenv("TELEMETRY_PATH", "telemetry/events.jsonl"))


def write_event(event: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _lock, LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
