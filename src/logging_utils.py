"""Append-only JSONL event log. Stores a hash of the question, not its text."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def log_event(path: Path, event: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), **event}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def question_fingerprint(question: str) -> str:
    return hashlib.sha256(question.encode()).hexdigest()[:16]


def read_events(path: Path, limit: int = 100) -> list[dict]:
    """Newest first. A damaged line is skipped rather than breaking the dashboard."""
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events[::-1]
