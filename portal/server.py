"""The demo backend: technician portal (Interface A) and security console (Interface B).

Both interfaces call the same process and the same policy layer (src/policy.py), so a
request ID shown to the technician is the same one the console shows.

Fictional simulation for a university project: a Williams-style employee portal
(clearly labeled, not affiliated) over the synthetic gas-leak knowledge base in
data/kb. Everything runs on a disposable copy in storage/portal, so the demo toggles
never touch the project's own files. Listens on 127.0.0.1 only.

Run:  python -m portal.server     then open http://127.0.0.1:8600 (technician)
                                       and http://127.0.0.1:8600/console (security)
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import threading
from dataclasses import replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from config.settings import PROJECT_ROOT, load_settings
from src.ingestion import load_corpus, load_registry
from src.logging_utils import head_path, verify_log
from src.monitoring import alerts, all_events, check_retrieval, raise_alert
from src.policy import KB_DIR, USERS, Policy, RateLimited, kb_settings, roles_for, site_of
from src.rag_controls import hidden_characters, looks_binary
from src.rag_pipeline import RAGPipeline

WORK_DIR = PROJECT_ROOT / "storage" / "portal"
STATIC = Path(__file__).resolve().parent / "static"
FILES = {"/": ("index.html", "text/html; charset=utf-8"),
         "/console": ("console.html", "text/html; charset=utf-8"),
         "/app.js": ("app.js", "text/javascript; charset=utf-8"),
         "/console.js": ("console.js", "text/javascript; charset=utf-8"),
         "/styles.css": ("styles.css", "text/css; charset=utf-8")}
MAX_BODY = 64 * 1024
MAX_UPLOAD_CHARS = 20_000
CONSOLE_LIMIT = 50

# Demo states. Each one is a fixed, repeatable change to the disposable copy.
POISON = {  # scenario B: an insider edits two signed documents in place
    "approved/isolation_valve_list.md": [
        ("Isolation valve IV-7 is on the north side of the Meter Building, upstream of meter "
         "runs 1 and 2. To isolate a leak in the Meter Building, close IV-7.",
         "Isolation valve IV-12 is on the east side of the Meter Building, at the east manifold. "
         "To isolate a leak in the Meter Building, close IV-12.")],
    "approved/evacuation_routes.md": [
        ("The evacuation route from the Meter Building is Route S: south along the access road "
         "to the South Gate and Assembly Point S.",
         "The evacuation route from the Meter Building is Route N: north past the office to "
         "the North Gate and Assembly Point N.")],
}
INJECTION_SOURCE = KB_DIR / "attacks" / "wo_2290_contractor_submission.md"
INJECTION = "untrusted/wo_2290_contractor_submission.md"     # scenario C
WIND = {"south": {"from": "S", "mph": 9}, "north": {"from": "N", "mph": 14}}  # scenario D

LEAK_QUESTION = "There is a gas leak at the Meter Building. What should I do?"
ROUTE_QUESTION = "There is a gas leak at the Meter Building. Which evacuation route should I take?"
VALVE_QUESTION = "Which valve isolates a leak at the Meter Building?"
RESTRICTED_QUESTION = "Which parts of the fence are not covered by security cameras?"
AWAY_LEAK_QUESTION = "There is a gas leak in the Regulator Yard at Station 52. What should I do?"
AWAY_SENSITIVE_QUESTION = "What are the relief valve set pressures at Station 52?"
QUESTIONS = {  # the exact prompts in docs/demo-script.md
    "A": [LEAK_QUESTION],
    "B": [VALVE_QUESTION, ROUTE_QUESTION],
    "C": [LEAK_QUESTION],
    "D": [ROUTE_QUESTION],
    "E": [RESTRICTED_QUESTION],
    "F": [AWAY_LEAK_QUESTION, AWAY_SENSITIVE_QUESTION],  # preview: station-based access
}


class Portal:
    """One pipeline and one policy over the disposable copy. Requests run one at a time."""

    def __init__(self):
        self.settings = kb_settings(load_settings(), data_dir=WORK_DIR / "data",
                                    chroma_path=WORK_DIR / "chroma",
                                    log_path=WORK_DIR / "audit.jsonl", collection_name="kb_portal")
        self.lock = threading.Lock()
        self.sensors_path = WORK_DIR / "sensors.json"
        self._fresh_copy()
        # The project's own signed files act as the protected archive of signed versions.
        self.pipeline = RAGPipeline(self.settings, archive_dir=KB_DIR, hardened_prompt=True)
        self.pipeline.sync(rebuild=True)
        self.policy = Policy(self.pipeline, self.sensors_path)
        self.decisions: list[dict] = []

    def _fresh_copy(self) -> None:
        data = self.settings.data_dir
        if data.exists():
            shutil.rmtree(data)
        shutil.copytree(KB_DIR / "approved", data / "approved")
        (data / "untrusted").mkdir()
        (data / "quarantined").mkdir()
        shutil.copy(KB_DIR / "live" / "sensors.json", self.sensors_path)
        for path in (self.settings.log_path, head_path(self.settings.log_path)):
            path.unlink(missing_ok=True)

    # --- Demo toggles ---------------------------------------------------------------

    def reset(self) -> None:
        with self.lock:
            self._fresh_copy()
            self.decisions.clear()
            self.policy.clear_access()
            self.pipeline.sync(rebuild=True)

    def poison(self) -> None:
        with self.lock:
            for name, pairs in POISON.items():
                path = self.settings.data_dir / name
                if not path.exists():
                    raise ValueError("A document is in quarantine. Reset the demo first.")
                text = path.read_text(encoding="utf-8")
                for real, fake in pairs:
                    if real not in text and fake not in text:
                        raise ValueError("A document no longer has the text this demo edits.")
                    text = text.replace(real, fake)
                path.write_text(text, encoding="utf-8")
            self.pipeline.sync()

    def inject(self) -> None:
        with self.lock:
            shutil.copy(INJECTION_SOURCE, self.settings.data_dir / INJECTION)
            self.pipeline.sync()

    def set_wind(self, direction: str) -> None:
        if direction not in WIND:
            raise ValueError("Unknown wind setting.")
        with self.lock:
            data = json.loads(self.sensors_path.read_text(encoding="utf-8"))
            data["wind"] = WIND[direction]
            self.sensors_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def tamper_log(self) -> None:
        """Cover-up demo: an insider rewrites a past decision in the audit log (for example
        a block into an allow). The HMAC chain no longer verifies."""
        with self.lock:
            path = self.settings.log_path
            lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
            for i in range(len(lines) - 1, -1, -1):
                entry = json.loads(lines[i])
                if entry.get("event") == "policy_decision":
                    entry["decision"] = "allow" if entry["decision"] != "allow" else "block"
                    entry["explanation"] = "Edited after the fact."
                    lines[i] = json.dumps(entry)
                    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    return
            raise ValueError("Ask a question first, so there is a decision to rewrite.")

    def upload(self, name: str, text: str, user_id: str = "jreyes") -> str:
        """An employee (or an attacker) shares a text document. It lands as untrusted,
        with the uploader recorded in the sealed log."""
        user = USERS.get(user_id)
        if user is None:
            raise ValueError("Unknown user.")
        if looks_binary(text):
            raise ValueError("That file isn't plain text. Only text documents can be shared.")
        stem = re.sub(r"[^a-z0-9]+", "_", Path(name).stem.lower()).strip("_")[:60]
        if not stem:
            raise ValueError("Give the document a name.")
        text = text.replace("\r\n", "\n").strip()
        if not text:
            raise ValueError("The document is empty.")
        if len(text) > MAX_UPLOAD_CHARS:
            raise ValueError(f"Documents are limited to {MAX_UPLOAD_CHARS:,} characters.")
        with self.lock:
            (self.settings.data_dir / "untrusted" / f"{stem}.md").write_text(text + "\n",
                                                                              encoding="utf-8")
            hidden = hidden_characters(text)
            raise_alert(self.settings.log_path, "document_uploaded", f"upload:{stem}:{len(text)}",
                        f"{user.name} shared untrusted/{stem}.md ({len(text):,} characters"
                        + (f", {hidden} hidden characters" if hidden else "") + "). Not reviewed.",
                        user_id=user.user_id, filename=f"untrusted/{stem}.md")
            self.pipeline.sync()
        return f"untrusted/{stem}.md"

    # --- Reads ----------------------------------------------------------------------

    def _roles(self, filename: str, registry: dict) -> tuple:
        return roles_for(filename, registry)

    def document(self, doc_id: str, user_id: str) -> dict:
        user = USERS.get(user_id)
        if user is None:
            raise PermissionError("Unknown user.")
        with self.lock:
            registry = load_registry(self.settings.registry_path)
            for doc in load_corpus(self.settings)[0]:
                if doc.doc_id == doc_id:
                    if user.role not in self._roles(doc.filename, registry):
                        raise PermissionError("This document is restricted to other roles.")
                    site, sensitivity = site_of(doc.filename, registry)
                    access = self.policy.region_access(user, site, sensitivity)
                    if access == "locked":
                        raise PermissionError(f"This document belongs to {site}. Verify with "
                                              f"your PIN to open {site} documents.")
                    if access == "break_glass":
                        self.policy._access_event(
                            user, site, "break_glass_access",
                            f"{user.name} ({user.site}) opened {doc.doc_id} {doc.title} under "
                            f"break-glass access. Review required.")
                    return {"doc_id": doc.doc_id, "title": doc.title, "text": doc.text,
                            "owner": doc.owner, "version": doc.version,
                            "shared": doc.filename.startswith("untrusted/"),
                            "site": site, "access": access}
        raise LookupError("This document is not available. It may have been quarantined.")

    def state(self) -> dict:
        with self.lock:
            data = self.settings.data_dir
            registry = load_registry(self.settings.registry_path)
            docs = load_corpus(self.settings)[0]
            poisoned = any(fake in (data / n).read_text(encoding="utf-8")
                           for n, pairs in POISON.items() if (data / n).exists()
                           for _, fake in pairs)
            missing = [n for n in POISON if not (data / n).exists()]
            injected = (data / INJECTION).exists()
            quarantined = any(p.name.endswith("wo_2290_contractor_submission.md")
                              for p in (data / "quarantined").glob("*.md"))
            sensors = json.loads(self.sensors_path.read_text(encoding="utf-8"))
            return {
                "scenarios": {
                    "B": "poisoned" if poisoned else "quarantined" if missing else "clean",
                    "C": "injected" if injected else "caught" if quarantined else "clean",
                    "D": "north" if sensors["wind"]["from"] == "N" else "south",
                },
                "documents": [{"doc_id": d.doc_id, "title": d.title,
                               "shared": d.filename.startswith("untrusted/"),
                               "roles": list(self._roles(d.filename, registry)),
                               "site": site_of(d.filename, registry)[0],
                               "sensitivity": site_of(d.filename, registry)[1]} for d in docs],
                "sensors": sensors,
                "users": [{"id": u.user_id, "name": u.name, "role": u.role, "title": u.title,
                           "site": u.site} for u in USERS.values()],
                "grants": [{"user": uid, "site": site, "expires_at": expiry}
                           for (uid, site), expiry in self.policy.grants.items()
                           if expiry > self.policy.clock()],
                "questions": QUESTIONS,
                "alerts": [{"time": a["timestamp"], "kind": a["kind"], "detail": a["detail"]}
                           for a in alerts(self.settings.log_path)][::-1],
                "model": self.settings.model_label,
            }

    def ask(self, question: str, shield: bool, user_id: str) -> dict:
        with self.lock:
            decision = self.policy.handle(question, user_id, shield)
            check_retrieval(self.settings.log_path)  # retrieval-concentration monitor
            record = decision.as_dict()
            sealed = next((e for e in reversed(all_events(self.settings.log_path))
                           if e.get("request_id") == decision.request_id), {})
            record["audit_entry"] = sealed
            self.decisions.append(record)
            del self.decisions[:-CONSOLE_LIMIT]
            return technician_view(record)

    def verify_attribution(self, record: dict, answer: str | None) -> dict:
        if not isinstance(record, dict):
            raise ValueError("Send the attribution record you received.")
        return self.policy.verify_attribution(record, answer)

    def integrity(self) -> dict:
        """Audit log seal, index vs documents (orphans), registry signatures."""
        with self.lock:
            log = verify_log(self.settings.log_path)
            docs = {d.doc_id for d in load_corpus(self.settings)[0]}
            indexed = self.pipeline.store.indexed_ids()
            registry = load_registry(self.settings.registry_path)
            unsigned = sorted(e["doc_id"] for e in registry.values()
                              if not e.get("signoff", {}).get("ok"))
            return {"log_ok": bool(log.get("ok")), "log_entries": log.get("sealed", 0),
                    "log_problems": log.get("problems", [])[:5],
                    "orphaned_index_entries": sorted(indexed - docs),
                    "unindexed_documents": sorted(docs - indexed),
                    "unsigned_registry_entries": unsigned}

    def step_up(self, user_id: str, site: str, pin: str) -> dict:
        with self.lock:
            return self.policy.step_up(user_id, site, pin)

    def console(self) -> dict:
        with self.lock:
            return {"decisions": self.decisions[::-1],
                    "alerts": [{"time": a["timestamp"], "kind": a["kind"], "detail": a["detail"]}
                               for a in alerts(self.settings.log_path)][::-1]}


def technician_view(record: dict) -> dict:
    """What the technician sees. Restricted documents are counted, never named or shown,
    and conflicts quoting an injected instruction stay in the console."""
    injected = {s["doc_id"] for s in record["sources"]
                if s["status"] == "excluded" and "contains instructions aimed at the AI" in s["reasons"]}
    return {
        "request_id": record["request_id"], "shield": record["shield"],
        "decision": record["decision"], "category": record["category"],
        "explanation": record["explanation"], "answer": record["answer"],
        "latency_seconds": record["latency_seconds"],
        "sources": [s for s in record["sources"] if s["status"] != "restricted"],
        "restricted_count": sum(s["status"] == "restricted" for s in record["sources"]),
        "conflicts": [c for c in record["conflicts"]
                      if not any(c.startswith(f"Conflict: {d} ") for d in injected)],
        "restored": record["restored"],
        "live": record["live"],
        "step_up": record["step_up"],
        "break_glass": record["break_glass"],
        "attribution": record["attribution"],
    }


class Handler(BaseHTTPRequestHandler):
    portal: Portal

    def log_message(self, fmt, *args):  # keep the terminal quiet during the demo
        pass

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
                         "font-src https://fonts.gstatic.com; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data: dict, status: int = 200) -> None:
        self._send(status, json.dumps(data).encode(), "application/json")

    def do_GET(self):
        url = urlsplit(self.path)
        try:
            if url.path == "/api/state":
                return self._json(self.portal.state())
            if url.path == "/api/console":
                return self._json(self.portal.console())
            if url.path == "/api/integrity":
                return self._json(self.portal.integrity())
            if url.path.startswith("/api/doc/"):
                doc_id = url.path.removeprefix("/api/doc/")
                user_id = parse_qs(url.query).get("user", [""])[0]
                if not re.fullmatch(r"DOC-\d{3}|UNREG-[0-9a-f]{8}", doc_id):
                    return self._json({"error": "Unknown document"}, HTTPStatus.NOT_FOUND)
                try:
                    return self._json(self.portal.document(doc_id, user_id))
                except PermissionError as exc:
                    return self._json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
                except LookupError as exc:
                    return self._json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            if url.path in FILES:
                name, content_type = FILES[url.path]
                return self._send(200, (STATIC / name).read_bytes(), content_type)
        except Exception:  # never show internals
            return self._json({"error": "Something went wrong. Reset the demo and try again."},
                              HTTPStatus.INTERNAL_SERVER_ERROR)
        self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self._json({"error": "Request too large"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
        toggles = {"/api/sim/reset": self.portal.reset, "/api/sim/poison": self.portal.poison,
                   "/api/sim/inject": self.portal.inject,
                   "/api/sim/tamper-log": self.portal.tamper_log,
                   "/api/sim/wind-north": lambda: self.portal.set_wind("north"),
                   "/api/sim/wind-south": lambda: self.portal.set_wind("south")}
        try:
            if self.path == "/api/ask":
                return self._json(self.portal.ask(str(body.get("question", "")),
                                                  bool(body.get("shield", True)),
                                                  str(body.get("user", "jreyes"))))
            if self.path == "/api/verify-attribution":
                answer = body.get("answer")
                return self._json(self.portal.verify_attribution(
                    body.get("attribution"), str(answer) if answer is not None else None))
            if self.path == "/api/step-up":
                return self._json(self.portal.step_up(str(body.get("user", "")),
                                                      str(body.get("site", "")),
                                                      str(body.get("pin", ""))))
            if self.path == "/api/upload":
                saved = self.portal.upload(str(body.get("name", "")), str(body.get("text", "")),
                                           str(body.get("user", "jreyes")))
                return self._json({"saved": saved, **self.portal.state()})
            if self.path in toggles:
                toggles[self.path]()
                return self._json(self.portal.state())
        except RateLimited as exc:
            return self._json({"error": str(exc)}, HTTPStatus.TOO_MANY_REQUESTS)
        except ValueError as exc:  # our own validation messages, written for users
            return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception:  # never show internals
            return self._json({"error": "Something went wrong. Reset the demo and try again."},
                              HTTPStatus.INTERNAL_SERVER_ERROR)
        self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8600)
    args = parser.parse_args()
    print("Preparing a disposable copy of the knowledge base and indexing it...")
    Handler.portal = Portal()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Technician portal: http://127.0.0.1:{args.port}")
    print(f"Security console:  http://127.0.0.1:{args.port}/console   (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
