"""Incident response helper (OWASP RAG cheat sheet, section 12).

Who received answers drawn from a document? Use it after a document is found to be
poisoned, to contact everyone who may have acted on it. Reads the sealed audit log
and checks its seals first, so the list can be trusted.

    python -m src.incident affected DOC-102 --log storage/portal/audit.jsonl
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.logging_utils import verify_log
from src.monitoring import all_events


def affected(log_path: Path, doc_id: str) -> dict:
    integrity = verify_log(log_path)
    rows = []
    for e in all_events(log_path):
        if e.get("event") != "policy_decision":
            continue
        used = [s for s in e.get("sources", []) if s.get("doc_id") == doc_id
                and s.get("status") == "used"]
        if used:
            rows.append({"time": e.get("timestamp"), "request_id": e.get("request_id"),
                         "user_id": e.get("user_id"), "role": e.get("role"),
                         "shield": e.get("shield"), "decision": e.get("decision"),
                         "unchecked": not e.get("shield")})
    return {"doc_id": doc_id, "log_verified": bool(integrity.get("ok")),
            "log_problems": integrity.get("problems", [])[:5],
            "requests": rows, "users": sorted({r["user_id"] for r in rows})}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("affected", help="list requests and users that received a document")
    p.add_argument("doc_id")
    p.add_argument("--log", type=Path, default=Path("storage/portal/audit.jsonl"))
    args = parser.parse_args()
    print(json.dumps(affected(args.log, args.doc_id), indent=2))


if __name__ == "__main__":
    main()
