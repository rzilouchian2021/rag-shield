"""The Shield's Watch stage: alerts, integrity scans, purge-and-retest, and metrics.

- Retrieval concentration: alert when one document suddenly shows up in most answers.
  Each document is measured only over questions asked while it was in the index.
- Integrity scan: re-hash every registered file and screen every unapproved file,
  without waiting for a question to retrieve it. Findings are quarantined.
- Purge and retest: contain, wipe and rebuild the index, then re-ask the legitimate
  questions before the assistant goes back into use.
- Governance metrics: share of procedures with a verified owner and approval, mean
  time to detect an unauthorized change, and mean time to quarantine.

Everything here reads and writes the same append-only event log as the pipeline.
Thresholds are fixed and readable, like the Shield's detection rules. File change
times come from the file system, which an attacker with write access can falsify.

Run:  python -m src.monitoring --scan | --metrics | --purge-retest
"""
from __future__ import annotations

import argparse
import json
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median

from config.settings import Settings, load_settings
from src.ingestion import (TRUST_APPROVED, TRUST_MODIFIED, load_corpus, load_registry,
                           sha256_bytes)
from src.logging_utils import log_event
from src.shield import detect_injection

# Retrieval concentration rule. A document's exposures are the shielded queries
# asked while it was in the index. In its last WINDOW exposures (at least
# MIN_QUERIES), an unapproved document retrieved for SHARE_THRESHOLD or more
# raises an alert. An approved one alerts if its share also rose by
# RISE_THRESHOLD against its WINDOW exposures before that.
# Revised 2026-11-16 after the first drill: the original counted every recent
# query, which diluted new documents and treated quarantined time as zero
# retrievals. Thresholds are unchanged.
WINDOW = 20
MIN_QUERIES = 5
SHARE_THRESHOLD = 0.5
RISE_THRESHOLD = 0.3


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


def all_events(path: Path) -> list[dict]:
    """Oldest first. Damaged lines are skipped."""
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def alerts(path: Path) -> list[dict]:
    return [e for e in all_events(path) if e.get("event") == "alert"]


def raise_alert(path: Path, kind: str, key: str, detail: str, **fields) -> dict | None:
    """Log an alert once per key, so a standing problem doesn't repeat on every query."""
    if any(a.get("key") == key for a in alerts(path)):
        return None
    record = {"event": "alert", "kind": kind, "key": key, "detail": detail, **fields}
    log_event(path, record)
    return record


def changed_at(path: Path) -> str | None:
    """When the file last changed on disk, as the best available upload or edit time."""
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
    except OSError:
        return None


# --- Retrieval concentration -------------------------------------------------

def _shielded_queries(events: list[dict]) -> list[dict]:
    return [e for e in events if e.get("shield_mode") == "shielded" and "query_id" in e]


def exposures(events: list[dict]) -> dict[str, list[bool]]:
    """For each document, whether it was retrieved in each shielded query asked while indexed.

    Presence comes from index_change events. A document whose first logged change
    is not an addition (including logs written before index changes were logged)
    is assumed to have been indexed from the start. Being retrieved proves presence.
    """
    first_change: dict[str, str] = {}
    for event in events:
        if event.get("event") == "index_change":
            for kind in ("added", "removed"):
                for doc_id in event.get(kind, []):
                    first_change.setdefault(doc_id, kind)
    seen = {d for e in _shielded_queries(events) for d in e.get("retrieved_doc_ids") or []}
    present = {d for d in seen | set(first_change) if first_change.get(d) != "added"}
    history: dict[str, list[bool]] = defaultdict(list)
    for event in events:
        if event.get("event") == "index_change":
            present |= set(event.get("added", []))
            present -= set(event.get("removed", []))
        elif event.get("shield_mode") == "shielded" and "query_id" in event:
            retrieved = set(event.get("retrieved_doc_ids") or [])
            present |= retrieved
            for doc_id in present:
                history[doc_id].append(doc_id in retrieved)
    return history


def retrieval_concentration(events: list[dict], window: int = WINDOW) -> list[dict]:
    """How often each document was retrieved while indexed, with alerts."""
    trust: dict[str, str] = {}
    for event in _shielded_queries(events):
        trust.update(event.get("trust_classifications") or {})
    rows = []
    for doc_id, history in exposures(events).items():
        recent, previous = history[-window:], history[-2 * window:-window]
        count = sum(recent)
        if len(recent) < MIN_QUERIES or not count:
            continue
        share = count / len(recent)
        prior = sum(previous) / len(previous) if len(previous) >= MIN_QUERIES else None
        reason = ""
        if share >= SHARE_THRESHOLD:
            if trust.get(doc_id) != TRUST_APPROVED:
                reason = (f"{trust.get(doc_id, 'unknown')} document retrieved in {count} of the "
                          f"last {len(recent)} queries since it was indexed")
            elif prior is not None and share - prior >= RISE_THRESHOLD:
                reason = f"retrieval share rose from {prior:.0%} to {share:.0%}"
        rows.append({"doc_id": doc_id, "trust": trust.get(doc_id, "unknown"), "queries": count,
                     "window": len(recent), "share": round(share, 3),
                     "previous_share": None if prior is None else round(prior, 3),
                     "indexed_queries": len(history), "alert": bool(reason), "reason": reason})
    return sorted(rows, key=lambda r: -r["share"])


def check_retrieval(path: Path) -> list[dict]:
    """Raise concentration alerts. At most one per document per WINDOW queries."""
    raised = []
    for row in retrieval_concentration(all_events(path)):
        if row["alert"]:
            bucket = row["indexed_queries"] // WINDOW
            record = raise_alert(path, "retrieval_concentration",
                                 f"concentration:{row['doc_id']}:{bucket}", row["reason"],
                                 doc_id=row["doc_id"], share=row["share"])
            if record:
                raised.append(record)
    return raised


# --- Tampering and quarantine alerts ----------------------------------------

def alert_tampered(settings: Settings, filename: str, detected_by: str) -> dict | None:
    path = settings.data_dir / filename
    if not path.is_file():
        return None
    digest = sha256_bytes(path.read_bytes())
    return raise_alert(settings.log_path, "document_tampered", f"tampered:{filename}:{digest}",
                       f"{filename} does not match its signed-off hash", filename=filename,
                       sha256=digest, changed_at=changed_at(path), detected_by=detected_by)


def change_times(settings: Settings, filenames) -> dict[str, str | None]:
    """Capture change times before quarantine moves the files."""
    return {name: changed_at(settings.data_dir / name) for name in filenames}


def alert_quarantined(settings: Settings, records: list[dict], changed: dict,
                      detected_by: str) -> list[dict]:
    raised = []
    for record in records:
        alert = raise_alert(
            settings.log_path, "document_quarantined", f"quarantined:{record['stored_name']}",
            f"{record['original_path']} quarantined: {record['reason']}",
            filename=record["original_path"], reason=record["reason"],
            changed_at=changed.get(record["original_path"]),
            quarantined_at=record["quarantined_at"], detected_by=detected_by)
        if alert:
            raised.append(alert)
    return raised


# --- Integrity scan ----------------------------------------------------------

@dataclass
class ScanReport:
    scanned_at: str
    documents_scanned: int
    tampered: list[dict] = field(default_factory=list)
    flagged_uploads: list[dict] = field(default_factory=list)
    quarantined: list[dict] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    seconds: float = 0.0


def integrity_scan(pipeline, quarantine: bool = True) -> ScanReport:
    """Check every indexed file now, rather than when a question happens to retrieve it.

    Registered files are re-hashed. Unapproved files get the same injection and
    conflict screening the Shield applies at query time. Approved files are not
    screened for content: approval is trusted, which is the known weak point.
    """
    settings, shield = pipeline.settings, pipeline.shield
    start = time.perf_counter()
    documents, errors = load_corpus(settings)
    report = ScanReport(_now(), len(documents), errors=errors)
    candidates: dict[str, str] = {}

    for doc in documents:
        if doc.trust_classification == TRUST_MODIFIED:
            report.tampered.append({"doc_id": doc.doc_id, "filename": doc.filename})
            candidates[doc.filename] = "hash mismatch"
            alert = alert_tampered(settings, doc.filename, "integrity_scan")
            if alert:
                report.alerts.append(alert)
        elif doc.trust_classification != TRUST_APPROVED:
            reasons = []
            detection = detect_injection(doc.text)
            if detection["flagged"]:
                rules = ", ".join(m["rule"] for m in detection["matched_rules"])
                reasons.append(f"prompt injection: {rules}")
            reasons += [f"conflict: {c['fact_id']}" for c in shield.checker.check(doc.text)]
            if reasons:
                report.flagged_uploads.append({"doc_id": doc.doc_id, "filename": doc.filename,
                                               "reasons": reasons})
                candidates[doc.filename] = reasons[0]

    if quarantine and candidates:
        changed = change_times(settings, candidates)
        records = [shield.quarantine.add(name, reason) for name, reason in candidates.items()]
        report.quarantined = [r for r in records if r]
        report.alerts += alert_quarantined(settings, report.quarantined, changed, "integrity_scan")
        pipeline.sync()

    report.seconds = round(time.perf_counter() - start, 3)
    log_event(settings.log_path, {
        "event": "integrity_scan", "documents_scanned": report.documents_scanned,
        "tampered": [t["filename"] for t in report.tampered],
        "flagged_uploads": [f["filename"] for f in report.flagged_uploads],
        "quarantined": [q["original_path"] for q in report.quarantined],
        "seconds": report.seconds})
    return report


# --- Governance metrics ------------------------------------------------------

def _durations(pairs) -> dict:
    seconds = [(_parse(end) - _parse(start)).total_seconds()
               for start, end in pairs if start and end]
    if not seconds:
        return {"count": 0, "mean_seconds": None, "median_seconds": None, "max_seconds": None}
    return {"count": len(seconds), "mean_seconds": round(mean(seconds), 3),
            "median_seconds": round(median(seconds), 3), "max_seconds": round(max(seconds), 3)}


def procedure_status(settings: Settings) -> list[dict]:
    """Each registered document: is its owner named, approved, and unchanged on disk?"""
    rows = []
    for filename, entry in load_registry(settings.registry_path).items():
        path = settings.data_dir / filename
        problems = []
        if not str(entry.get("owner", "")).strip():
            problems.append("no named owner")
        if entry.get("approval_status") != "approved":
            problems.append("not approved")
        if not path.is_file():
            problems.append("file missing or quarantined")
        elif sha256_bytes(path.read_bytes()) != entry.get("sha256"):
            problems.append("changed since sign-off")
        rows.append({"doc_id": entry.get("doc_id", ""), "filename": filename,
                     "owner": entry.get("owner", ""), "verified": not problems,
                     "problems": problems})
    return rows


def governance_metrics(settings: Settings) -> dict:
    status = procedure_status(settings)
    verified = sum(r["verified"] for r in status)
    found = alerts(settings.log_path)
    tampered = [a for a in found if a["kind"] == "document_tampered"]
    quarantined = [a for a in found if a["kind"] == "document_quarantined"]
    return {
        "computed_at": _now(),
        "verified_procedures": {"verified": verified, "registered": len(status),
                                "share": round(verified / len(status), 3) if status else None,
                                "unverified": [r for r in status if not r["verified"]]},
        "time_to_detect_unauthorized_change": _durations(
            (a.get("changed_at"), a["timestamp"]) for a in tampered),
        "time_to_quarantine": _durations(
            (a.get("changed_at"), a.get("quarantined_at")) for a in quarantined),
        "alerts_by_kind": dict(Counter(a["kind"] for a in found)),
        "caveat": "Times start at the file's modification time on disk, which a copy can "
                  "preserve and an attacker can falsify. Detection only happens when a scan "
                  "or a question runs, so in practice scan frequency dominates these times.",
    }


# --- Purge and retest --------------------------------------------------------

def purge_and_retest(pipeline, cases: list[dict] | None = None) -> dict:
    """Contain, purge the index, rebuild it from current files, then retest.

    The prototype keeps no answer cache, so the index is the only cache to purge.
    It passes only if every registered procedure is verified and every legitimate
    question is answered correctly from approved sources with the Shield on.
    """
    from evaluation.harness import load_cases  # evaluation depends on src, not the reverse
    from evaluation.scoring import score_legitimate
    from src.shield import ShieldConfig

    cases = cases if cases is not None else [c for c in load_cases()
                                             if c["attack_category"] == "legitimate"]
    start = time.perf_counter()
    scan = integrity_scan(pipeline)
    sync = pipeline.sync(rebuild=True)[0]
    indexed = Counter(d.trust_classification for d in load_corpus(pipeline.settings)[0])

    results = []
    for case in cases:
        answer = pipeline.answer(case["question"], "shielded", ShieldConfig())
        # Same definition as the evaluation's legitimate accuracy.
        correct = (answer.status == "answered"
                   and score_legitimate(case, answer.answer)["outcome"] == "correct")
        results.append({"test_id": case["test_id"], "question": case["question"],
                        "status": answer.status, "correct": correct,
                        "cited": answer.cited_doc_ids, "answer": answer.answer})

    procedures = procedure_status(pipeline.settings)
    unverified = [r for r in procedures if not r["verified"]]
    correct = sum(r["correct"] for r in results)
    passed = not unverified and correct == len(results)
    report = {
        "event": "purge_retest", "passed": passed,
        "scan": asdict(scan),
        "index_rebuilt": asdict(sync),
        "indexed_by_trust": dict(indexed),
        "unverified_procedures": unverified,
        "legitimate_correct": correct, "legitimate_total": len(results),
        "results": results,
        "seconds": round(time.perf_counter() - start, 2),
    }
    log_event(pipeline.settings.log_path, {
        k: report[k] for k in ("event", "passed", "indexed_by_trust", "legitimate_correct",
                               "legitimate_total", "seconds")}
        | {"unverified_procedures": [r["filename"] for r in unverified]})
    return report


def main() -> None:
    from src.rag_pipeline import RAGPipeline

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scan", action="store_true", help="run an integrity scan now")
    group.add_argument("--metrics", action="store_true", help="print governance metrics")
    group.add_argument("--purge-retest", action="store_true", help="purge, rebuild, retest")
    args = parser.parse_args()
    settings = load_settings()
    if args.metrics:
        print(json.dumps(governance_metrics(settings), indent=2))
        return
    pipeline = RAGPipeline(settings)
    pipeline.sync()
    if args.scan:
        print(json.dumps(asdict(integrity_scan(pipeline)), indent=2))
    else:
        report = purge_and_retest(pipeline)
        print(json.dumps({k: v for k, v in report.items() if k != "results"}, indent=2))
        print(f"\nRetest {'PASSED' if report['passed'] else 'FAILED'}: "
              f"{report['legitimate_correct']} of {report['legitimate_total']} legitimate answers correct")


if __name__ == "__main__":
    main()
