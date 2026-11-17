"""Append-only, tamper-evident JSONL event log. Stores a hash of the question, not its text.

Every entry is sealed: `chain_mac` is an HMAC-SHA256, under a secret key, over the
entry plus the previous entry's seal. Editing, deleting, reordering or inserting
an entry breaks the chain from that point. A plain hash chain would not be
enough, because whoever edits the file could recompute every hash; without the
key they can't recompute the seals.

A separate head file records the last seal, so cutting entries off the end is
caught too. Limits: someone holding the key can rewrite the whole log, and
restoring an old copy of both the log and its head file is not detectable
without sending the head somewhere outside this machine.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from config.settings import PROJECT_ROOT

KEY_ENV = "RAG_SHIELD_LOG_KEY"
GENESIS = "genesis"
RESTART = "restart"   # the head was missing or forged when this entry was written
SEAL_FIELDS = ("chain_seq", "chain_prev", "chain_mac")


def log_key_path() -> Path:
    return Path(os.environ.get(KEY_ENV) or PROJECT_ROOT / "keys" / "log_hmac.key")


def _key(create: bool) -> bytes | None:
    path = log_key_path()
    if path.exists():
        return bytes.fromhex(path.read_text(encoding="ascii").strip())
    if not create:
        return None
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    key = secrets.token_bytes(32)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(key.hex())
    return key


def _seal(key: bytes, record: dict) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def head_path(path: Path) -> Path:
    return path.with_name(path.name + ".head")


def _read_head(path: Path, key: bytes) -> dict | None:
    """The last seal, or None if the head file is missing or was not written with this key."""
    try:
        head = json.loads(head_path(path).read_text(encoding="utf-8"))
        expected = _seal(key, {"seq": head["seq"], "mac": head["mac"]})
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return head if hmac.compare_digest(expected, str(head.get("head_mac", ""))) else None


def _has_sealed_entries(path: Path) -> bool:
    if not path.exists():
        return False
    with path.open(encoding="utf-8") as handle:
        return any('"chain_mac"' in line for line in handle)


def log_event(path: Path, event: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": datetime.now(timezone.utc).isoformat(),
              **{k: v for k, v in event.items() if k not in SEAL_FIELDS}}
    with path.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)  # one writer at a time, so the chain stays linear
        try:
            key = _key(create=True)
            head = _read_head(path, key)
            if head:
                record["chain_seq"], record["chain_prev"] = head["seq"] + 1, head["mac"]
            else:
                record["chain_seq"] = 0
                record["chain_prev"] = RESTART if _has_sealed_entries(path) else GENESIS
            record["chain_mac"] = _seal(key, record)
            handle.write(json.dumps(record) + "\n")
            handle.flush()
            head = {"seq": record["chain_seq"], "mac": record["chain_mac"]}
            head["head_mac"] = _seal(key, head)
            tmp = head_path(path).with_suffix(".tmp")
            tmp.write_text(json.dumps(head), encoding="utf-8")
            os.replace(tmp, head_path(path))
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def verify_log(path: Path, max_problems: int = 50) -> dict:
    """Check every seal. Entries written before sealing existed are counted, not trusted."""
    report = {"path": str(path), "entries": 0, "sealed": 0, "unsealed_before_sealing": 0,
              "problems": [], "ok": True}
    problems = report["problems"]
    key = _key(create=False)
    if not path.exists():
        return report
    if key is None:
        if _has_sealed_entries(path):
            problems.append("the log's sealing key is missing, so no seal can be checked")
        report["ok"] = not problems
        return report

    last_mac, last_seq, started = None, None, False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        report["entries"] += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f"line {number}: damaged, not valid JSON")
            continue
        mac = record.pop("chain_mac", None)
        if mac is None:
            if started:
                problems.append(f"line {number}: unsealed entry added after sealing began")
            else:
                report["unsealed_before_sealing"] += 1
            continue
        report["sealed"] += 1
        if not hmac.compare_digest(_seal(key, record), str(mac)):
            problems.append(f"line {number}: contents changed, or the entry was forged")
        prev = record.get("chain_prev")
        if started and prev == RESTART:
            problems.append(f"line {number}: chain restarted because the head file was missing "
                            "or forged")
        elif started and prev != last_mac:
            problems.append(f"line {number}: does not follow the entry before it (entries "
                            "deleted, reordered or inserted)")
        elif not started and prev != GENESIS:
            problems.append(f"line {number}: first sealed entry follows earlier sealed entries "
                            "that are gone (start of the log removed)")
        started, last_mac, last_seq = True, str(mac), record.get("chain_seq")

    if started:
        head = _read_head(path, key)
        if head is None:
            problems.append("head file is missing or forged, so removal of the newest entries "
                            "can't be ruled out")
        elif head["mac"] != last_mac:
            problems.append(f"log ends at entry {last_seq}, but the head says entry "
                            f"{head['seq']} was written (newest entries removed)")
    report["ok"] = not problems
    if len(problems) > max_problems:
        report["problems"] = problems[:max_problems] + [f"... and {len(problems) - max_problems} more"]
    return report


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
