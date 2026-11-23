"""Deterministic policy layer for the gas-leak demo: one decision per request.

    technician question
      -> user and role identified (server-side user list, never from a document)
      -> retrieved documents filtered by role (registry allowed_roles) and by station:
         another station's emergency procedures open under break-glass access (flagged),
         its other documents need a verified PIN (step-up), granted for 15 minutes
      -> RAG Shield inspects what remains (provenance, signatures, injection, facts)
      -> the model sees only permitted, inspected context
      -> the answer is inspected (injected instructions, restricted text, live data)
      -> decision: allow / warn / redact / block, with a plain-English explanation
      -> the decision is written to the sealed audit log

Every rule here is a fixed comparison: no model output decides a policy outcome.
The frozen inspection rules in src/shield.py are reused unchanged.

Critical checks fail closed: if anything in the protected path raises, the request
is blocked and the technician gets fixed safe guidance and no internal details.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

from config.settings import PROJECT_ROOT, Settings
from src.ingestion import load_corpus, load_registry
from src.logging_utils import log_event, question_fingerprint
from src.monitoring import raise_alert
from src import rag_controls as rc
from src.rag_pipeline import MAX_QUESTION_CHARS
from src.shield import ShieldConfig, detect_injection

KB_DIR = PROJECT_ROOT / "data" / "kb"
KB_REGISTRY = PROJECT_ROOT / "config" / "kb_registry.json"
KB_FACTS = PROJECT_ROOT / "config" / "kb_facts.json"

CONTACT = "Gas Control on radio channel 1 or 555-0142"
SAFE_GUIDANCE = (f"Follow the Gas Leak Emergency Procedure (DOC-101): stop work, move upwind, "
                 f"and call {CONTACT}.")

DECISIONS = ("allow", "warn", "redact", "block")
CATEGORIES = ("clean", "poisoning", "prompt_injection", "data_conflict", "authorization",
              "step_up", "break_glass", "sensitive_data", "unverified", "system", "unprotected")

# Stations (fictional). A question names a station through these words; otherwise it is
# about the user's home station. Station tags on documents come from the signed registry.
SITES = {
    "Station 41": ("station 41", "meter building", "compressor building"),
    "Station 52": ("station 52", "regulator yard", "launcher road", "hillside"),
}
STEP_UP_MINUTES = 15
MAX_PIN_ATTEMPTS = 3
LOCKOUT_MINUTES = 5
PIN_ENV = "RAG_SHIELD_DEMO_PIN"
RATE_LIMIT = (12, 60)            # questions per user per 60 seconds
ALERT_WINDOW = 10 * 60           # "repeated X" alerts count events over 10 minutes
REPEAT_THRESHOLD = 3
MIN_SIMILARITY = 0.2             # candidates less similar than this are not used at all
# Safety first on a near tie: if another station's emergency procedure (open under
# break-glass) is within this similarity of the locked sensitive best match, the question
# is treated as an emergency question. Chosen after the 2026-11-22 evaluation, where the one
# false positive was a 0.031 tie and every cross-station attack was 0.126 or more apart.
EMERGENCY_TIE_MARGIN = 0.05


class RateLimited(ValueError):
    pass


@dataclass(frozen=True)
class User:
    user_id: str
    name: str
    role: str
    title: str
    site: str = "Station 41"


USERS = {
    "jreyes": User("jreyes", "Jordan Reyes", "field_technician", "Field Technician", "Station 41"),
    "sokafor": User("sokafor", "Sam Okafor", "security_officer", "Security Officer", "Station 41"),
}
ALL_ROLES = ("field_technician", "shift_supervisor", "security_officer")


def roles_for(filename: str, registry: dict[str, dict]) -> tuple[str, ...]:
    """Who may read a document. Fails closed: a registered document without an access
    list is readable by no one. Unregistered uploads carry no access list; they are
    open to all roles but stay untrusted, so RAG Shield excludes them on safety
    questions."""
    entry = registry.get(filename)
    if entry is None:
        return ALL_ROLES
    if entry.get("signoff", {}).get("ok") is False:  # access list edited or unsigned
        return ()
    roles = entry.get("allowed_roles")
    return tuple(roles) if isinstance(roles, list) else ()


def site_of(filename: str, registry: dict[str, dict]) -> tuple[str | None, str]:
    """(station, sensitivity) from the signed registry. Unregistered uploads have no
    station. A registered document without a station tag matches no station."""
    entry = registry.get(filename)
    if entry is None:
        return None, "untrusted"
    return entry.get("site") or "unknown", entry.get("sensitivity") or "restricted"


def sites_in(question: str) -> set[str]:
    q = question.lower()
    return {site for site, names in SITES.items() if any(n in q for n in names)}


def _pin_digest(pin: str, salt: bytes) -> bytes:
    return hashlib.scrypt(pin.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

# Evacuation routes and the compass direction each one heads, for the live-data check.
ROUTES = {
    "Route S": {"heads": "S", "names": ("route s", "south gate", "assembly point s")},
    "Route N": {"heads": "N", "names": ("route n", "north gate", "assembly point n")},
    "Route W": {"heads": "W", "names": ("route w", "west gate", "assembly point w")},
    "Route E": {"heads": "E", "names": ("route e", "east gate", "assembly point e")},
}
OPPOSITE = {"N": "S", "S": "N", "E": "W", "W": "E"}
COMPASS = {"N": "north", "S": "south", "E": "east", "W": "west"}


def kb_settings(base: Settings, data_dir: Path = KB_DIR, **overrides) -> Settings:
    """Settings for the gas-leak knowledge base. The evaluation corpus is untouched."""
    return replace(base, data_dir=data_dir, registry_path=KB_REGISTRY, facts_path=KB_FACTS,
                   **overrides)


@dataclass
class Source:
    doc_id: str
    title: str
    status: str                 # used | excluded | restricted
    reasons: list[str] = field(default_factory=list)
    shared: bool = False


@dataclass
class Decision:
    request_id: str
    timestamp: str
    user_id: str
    user_name: str
    role: str
    shield: bool
    decision: str
    category: str
    categories: list[str]
    explanation: str
    answer: str
    sources: list[Source] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    restored: list[str] = field(default_factory=list)
    live: dict = field(default_factory=dict)
    step_up: dict = field(default_factory=dict)
    break_glass: list[str] = field(default_factory=list)
    attribution: dict = field(default_factory=dict)
    query_flags: list[str] = field(default_factory=list)
    latency_seconds: float = 0.0
    audit: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


# --- Deterministic checks --------------------------------------------------------

def classify(reasons: list[str], trust: str) -> str:
    """Category for one excluded document, from the Shield's recorded reasons."""
    if any(r.startswith("possible prompt injection") for r in reasons):
        return "prompt_injection"
    if trust == "hash_mismatch" or any(r.startswith(("file does not match", "conflicts with"))
                                       for r in reasons):
        return "poisoning"
    return "unverified"


def friendly(reason: str) -> str:
    if reason.startswith("file does not match"):
        return "changed after two approvers signed it (fingerprint mismatch)"
    if reason.startswith("conflicts with"):
        return "contradicts an approved key fact (" + reason.split("(")[-1].rstrip(")") + ")"
    if reason.startswith("unapproved source"):
        return "not an approved document, on a safety question"
    if reason.startswith("possible prompt injection"):
        return "contains instructions aimed at the AI"
    return reason


def shingles(text: str, n: int = 8) -> set[tuple[str, ...]]:
    words = [w.strip(".,;:()\"'").lower() for w in text.split()]
    return {tuple(words[i:i + n]) for i in range(len(words) - n + 1)}


def leaks(answer: str, protected_texts: list[str]) -> bool:
    """True if the answer repeats 8 or more consecutive words of a protected document."""
    answer_shingles = shingles(answer)
    return any(answer_shingles & shingles(text) for text in protected_texts)


def read_sensors(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    wind = data["wind"]
    if wind["from"] not in OPPOSITE:
        raise ValueError("wind direction not recognised")
    return data


def live_route_check(answer: str, sensors: dict) -> dict:
    """Compare evacuation routes named in the answer with the live wind."""
    wind_from = sensors["wind"]["from"]
    downwind = OPPOSITE[wind_from]
    text = answer.lower()
    named = [r for r, spec in ROUTES.items() if any(n in text for n in spec["names"])]
    unsafe = [r for r in named if ROUTES[r]["heads"] == downwind]
    upwind = [r for r, spec in ROUTES.items() if spec["heads"] == wind_from]
    return {"wind_from": wind_from, "wind_mph": sensors["wind"].get("mph"),
            "routes_named": named, "downwind_routes_named": unsafe, "upwind_routes": upwind,
            "conflict": bool(unsafe)}


# --- The policy -----------------------------------------------------------------------

class Policy:
    def __init__(self, pipeline, sensors_path: Path, users: dict[str, User] = USERS):
        self.pipeline = pipeline
        self.settings = pipeline.settings
        self.sensors_path = sensors_path
        self.users = users
        self.clock = time.time
        self.grants: dict[tuple[str, str], float] = {}     # (user_id, site) -> expiry
        self.failures: dict[str, int] = {}
        self.locked_until: dict[str, float] = {}
        self._pin_salt = secrets.token_bytes(16)
        self._pin_hash: bytes | None = None
        self.set_pin(os.environ.get(PIN_ENV))
        self.limiter = rc.RateLimiter(*RATE_LIMIT, clock=lambda: self.clock())
        self.counter = rc.EventCounter(ALERT_WINDOW, clock=lambda: self.clock())
        self.stage = "starting"

    # --- Step-up verification for out-of-region documents --------------------------------

    def set_pin(self, pin: str | None) -> None:
        """Keep only a salted scrypt hash of the demo PIN. No PIN set: step-up is
        unavailable and out-of-region sensitive documents stay locked."""
        self._pin_hash = _pin_digest(pin, self._pin_salt) if pin else None

    def clear_access(self) -> None:
        self.grants.clear(); self.failures.clear(); self.locked_until.clear()
        self.limiter.clear(); self.counter.clear()

    def granted(self, user: User, site: str) -> float | None:
        expiry = self.grants.get((user.user_id, site))
        return expiry if expiry and expiry > self.clock() else None

    def region_access(self, user: User, site: str | None, sensitivity: str) -> str:
        """home | granted | break_glass | locked"""
        if site is None or site == user.site:
            return "home"
        if self.granted(user, site):
            return "granted"
        return "break_glass" if sensitivity == "emergency" else "locked"

    def step_up(self, user_id: str, site: str, pin: str) -> dict:
        user = self.users.get(user_id)
        if user is None:
            raise ValueError("Unknown user.")
        if site not in SITES or site == user.site:
            raise ValueError("No verification is needed for that station.")
        pin = (pin or "").strip()
        if not (pin.isdigit() and 4 <= len(pin) <= 8):
            raise ValueError("Enter your 4 to 8 digit PIN.")
        now = self.clock()
        if self.locked_until.get(user_id, 0) > now:
            minutes = max(1, round((self.locked_until[user_id] - now) / 60))
            self._access_event(user, site, "step_up_locked",
                               f"{user.name} tried to verify for {site} while locked out.")
            return {"granted": False, "locked": True,
                    "message": f"Too many wrong PINs. Try again in {minutes} minute(s), or "
                               f"ask your supervisor. For anything urgent, call {CONTACT}."}
        if self._pin_hash is None:
            self._access_event(user, site, "step_up_unavailable",
                               f"{user.name} asked to verify for {site}, but no PIN is set up.")
            return {"granted": False, "message": "Verification isn't set up on this server, "
                                                 f"so {site} sensitive documents stay locked."}
        if hmac.compare_digest(_pin_digest(pin, self._pin_salt), self._pin_hash):
            expiry = now + STEP_UP_MINUTES * 60
            self.grants[(user_id, site)] = expiry
            self.failures.pop(user_id, None)
            until = datetime.fromtimestamp(expiry, timezone.utc).isoformat(timespec="seconds")
            self._access_event(user, site, "step_up_granted",
                               f"{user.name} ({user.site}) verified with a PIN for {site} "
                               f"documents for {STEP_UP_MINUTES} minutes.")
            return {"granted": True, "site": site, "expires_at": until,
                    "minutes": STEP_UP_MINUTES}
        self.failures[user_id] = self.failures.get(user_id, 0) + 1
        left = MAX_PIN_ATTEMPTS - self.failures[user_id]
        if left <= 0:
            self.failures.pop(user_id, None)
            self.locked_until[user_id] = now + LOCKOUT_MINUTES * 60
            self._access_event(user, site, "step_up_locked",
                               f"{user.name} entered {MAX_PIN_ATTEMPTS} wrong PINs for {site}; "
                               f"verification locked for {LOCKOUT_MINUTES} minutes.")
            return {"granted": False, "locked": True, "attempts_left": 0,
                    "message": f"Wrong PIN. Verification is locked for {LOCKOUT_MINUTES} "
                               f"minutes. For anything urgent, call {CONTACT}."}
        self._access_event(user, site, "step_up_failed",
                           f"{user.name} entered a wrong PIN for {site}.")
        return {"granted": False, "attempts_left": left,
                "message": f"Wrong PIN. {left} attempt(s) left."}

    def _access_event(self, user: User, site: str, kind: str, detail: str,
                      request_id: str | None = None) -> None:
        """Sealed alert for the console. Never contains the PIN."""
        raise_alert(self.settings.log_path, kind, f"{kind}:{uuid.uuid4().hex}", detail,
                    user_id=user.user_id, home_site=user.site, site=site,
                    **({"request_id": request_id} if request_id else {}))

    def handle(self, question: str, user_id: str, shield: bool = True) -> Decision:
        user = self.users.get(user_id)
        if user is None:
            raise ValueError("Unknown user.")
        question, flags = rc.normalize_query(question or "")
        if not question:
            raise ValueError("Enter a question.")
        if len(question) > MAX_QUESTION_CHARS:
            raise ValueError(f"Questions are limited to {MAX_QUESTION_CHARS} characters.")
        if not self.limiter.allow(user.user_id):
            raise_alert(self.settings.log_path, "rate_limited",
                        f"rate:{user.user_id}:{int(self.clock() // RATE_LIMIT[1])}",
                        f"{user.name} sent more than {RATE_LIMIT[0]} questions in "
                        f"{RATE_LIMIT[1]} seconds; extra questions were refused.",
                        user_id=user.user_id)
            raise RateLimited("Too many questions in a short time. Wait a minute and ask again. "
                              f"For anything urgent, call {CONTACT}.")
        if detect_injection(question)["flagged"]:
            flags.append("injection_pattern")
        request_id = "REQ-" + uuid.uuid4().hex[:8].upper()
        start = time.perf_counter()
        self.stage = "starting"
        try:
            decision = (self._protected if shield else self._unprotected)(question, user, request_id)
            if shield and decision.category != "system":
                self.stage = "attribution"
                self._attribute(decision)
        except Exception as exc:  # fail closed on anything, without internal details
            decision = self._failed(question, user, request_id, shield, type(exc).__name__)
        decision.query_flags = flags
        decision.latency_seconds = round(time.perf_counter() - start, 3)
        decision.audit = self._audit(question, decision)
        log_event(self.settings.log_path, decision.audit)
        self._watch_patterns(user, decision)
        return decision

    def _attribute(self, d: Decision) -> None:
        """Seal which sources (and which exact file versions) produced this answer."""
        hashes = {doc.doc_id: doc.sha256 for doc in load_corpus(self.settings)[0]}
        used = [(s.doc_id, hashes.get(s.doc_id, "unavailable")) for s in d.sources
                if s.status == "used"]
        record = rc.attribution(d.request_id, d.answer, used, d.timestamp)
        d.attribution = rc.seal_attribution(record, rc.attribution_key())

    def verify_attribution(self, record: dict, answer: str | None = None) -> dict:
        return rc.verify_attribution(record, rc.attribution_key(), answer)

    def _watch_patterns(self, user: User, d: Decision) -> None:
        """Alerts on patterns over time (OWASP RAG cheat sheet, sections 8, 12, 14)."""
        log = self.settings.log_path
        if "injection_pattern" in d.query_flags:
            n = self.counter.add(f"inject:{user.user_id}")
            raise_alert(log, "query_injection_attempt", f"qi:{d.request_id}",
                        f"{user.name}'s question contained instructions aimed at the assistant "
                        f"({d.request_id}). Access control applied as usual.",
                        user_id=user.user_id, request_id=d.request_id)
            if n >= 2:
                raise_alert(log, "repeated_injection_attempts", f"rqi:{user.user_id}:{n}",
                            f"{user.name} sent {n} questions with injection patterns in 10 "
                            f"minutes.", user_id=user.user_id)
        if d.category in ("authorization", "step_up"):
            n = self.counter.add(f"restricted:{user.user_id}")
            if n >= REPEAT_THRESHOLD:
                raise_alert(log, "possible_reconnaissance", f"recon:{user.user_id}:{n}",
                            f"{user.name} hit {n} restricted or verification-required documents "
                            f"in 10 minutes. Check whether someone is mapping restricted content.",
                            user_id=user.user_id)
        if d.category == "system":
            n = self.counter.add("failures")
            if n >= REPEAT_THRESHOLD:
                raise_alert(log, "repeated_failures", f"fail:{n}:{int(self.clock() // ALERT_WINDOW)}",
                            f"{n} requests failed a safety stage in 10 minutes. Repeated failures "
                            f"can mean someone is trying to force unchecked answers.")

    # Shield off: an ordinary assistant, recorded so the console can show the contrast.
    def _unprotected(self, question: str, user: User, request_id: str) -> Decision:
        result = self.pipeline.answer(question, "baseline")
        titles = self._titles()
        sources = self._used(result, titles)
        return Decision(request_id, _now(), user.user_id, user.name, user.role, False, "none",
                        "unprotected", ["unprotected"],
                        "RAG Shield is off: no provenance, injection, live-data or access checks "
                        "ran. The answer is whatever the retrieved documents say.",
                        result.answer, sources, audit={"query_ids": [result.query_id]})

    def _protected(self, question: str, user: User, request_id: str) -> Decision:
        self.stage = "access check"
        registry = load_registry(self.settings.registry_path)
        titles = self._titles()

        targets = sites_in(question) or {user.site}  # which station the question is about

        # Every rule reads the signed registry; nothing inside a document can change it.
        def in_scope(chunk) -> bool:
            site, _ = site_of(chunk.metadata["filename"], registry)
            return site is None or site in targets

        def role_ok(chunk) -> bool:
            return user.role in roles_for(chunk.metadata["filename"], registry)

        def region_ok(chunk) -> bool:
            return self.region_access(user, *site_of(chunk.metadata["filename"], registry)) != "locked"

        # Index integrity and hidden characters, checked per chunk before the model sees it.
        flagged: dict[str, tuple[str, str]] = {}   # doc_id -> (reason, category)
        expected: dict[str, str] = {}

        def intact(chunk) -> bool:
            if chunk.chunk_id not in expected:
                docs = load_corpus(self.settings)[0]
                expected.update(rc.expected_chunks(docs, self.settings.chunk_size_words,
                                                   self.settings.chunk_overlap_words))
            if not rc.chunk_matches(chunk.chunk_id, chunk.text, expected):
                flagged.setdefault(chunk.doc_id, (
                    "search index entry doesn't match the verified file (index tampering)",
                    "poisoning"))
                raise_alert(self.settings.log_path, "index_tampered", f"index:{chunk.chunk_id}",
                            f"Index entry {chunk.chunk_id} differs from its source file; it was "
                            f"not used. Rebuild the index from signed documents.",
                            request_id=request_id)
                return False
            if rc.hidden_characters(chunk.text):
                flagged.setdefault(chunk.doc_id, ("contains hidden (invisible) characters",
                                                  "prompt_injection"))
                raise_alert(self.settings.log_path, "hidden_characters", f"hidden:{chunk.chunk_id}",
                            f"{chunk.doc_id} contains invisible characters that can hide "
                            f"instructions; it was not used.", request_id=request_id)
                return False
            return True

        def relevant(chunk) -> bool:
            return chunk.similarity >= MIN_SIMILARITY

        def allowed(chunk) -> bool:
            return (in_scope(chunk) and role_ok(chunk) and region_ok(chunk) and relevant(chunk)
                    and intact(chunk))

        # Station scoping happens inside the search: other stations' chunks are never returned.
        self.stage = "document search"
        by_doc = {e.get("doc_id"): e for e in registry.values()}
        scope = sorted(d for d in self.pipeline.store.indexed_ids()
                       if d not in by_doc or (by_doc[d].get("site") or "unknown") in targets)
        candidates = self.pipeline.retriever.retrieve(question, self.settings.top_k * 3, scope)
        scoped = [c for c in candidates if in_scope(c) and relevant(c)]  # defense in depth
        role_ids = list(dict.fromkeys(c.doc_id for c in scoped if not role_ok(c)))
        region_ids = list(dict.fromkeys(c.doc_id for c in scoped
                                        if role_ok(c) and not region_ok(c)))
        restricted = ([Source(d, titles.get(d, d), "restricted",
                              ["your role is not on this document's access list"])
                       for d in role_ids]
                      + [Source(d, titles.get(d, d), "restricted",
                                ["belongs to another station; needs verified access"])
                         for d in region_ids])
        protected_texts = [self._text(d) for d in role_ids + region_ids]

        offer: dict = {}
        if scoped and role_ok(scoped[0]) and not region_ok(scoped[0]):
            site, _ = site_of(scoped[0].metadata["filename"], registry)
            title = titles.get(scoped[0].doc_id, scoped[0].doc_id)
            emergency = [c for c in scoped if role_ok(c) and region_ok(c) and self.region_access(
                user, *site_of(c.metadata["filename"], registry)) == "break_glass"]
            if emergency and scoped[0].similarity - emergency[0].similarity < EMERGENCY_TIE_MARGIN:
                # Too close to call: answer from the emergency procedure now, keep the
                # sensitive document out, and offer the PIN for the rest.
                offer = {"site": site, "offered": True}
        if scoped and role_ok(scoped[0]) and not region_ok(scoped[0]) and not offer:
            site, _ = site_of(scoped[0].metadata["filename"], registry)
            title = titles.get(scoped[0].doc_id, scoped[0].doc_id)
            return Decision(
                request_id, _now(), user.user_id, user.name, user.role, True, "block",
                "step_up", ["step_up"],
                f"The best match is a sensitive {site} document ({title}). {user.name}'s home "
                f"station is {user.site}, so documents from other stations need a verified PIN "
                f"first. Nothing from it was sent to the model or shown.",
                f"{title} belongs to {site}. Verify with your PIN to unlock {site} documents for "
                f"{STEP_UP_MINUTES} minutes. For anything urgent, call {CONTACT}.",
                restricted, step_up={"site": site})

        if scoped and not role_ok(scoped[0]):
            return Decision(
                request_id, _now(), user.user_id, user.name, user.role, True, "block",
                "authorization", ["authorization"],
                f"The best match for this question is a restricted document, and the "
                f"{user.title} role is not on its access list, so it was never retrieved for "
                f"the model and nothing from it is shown.",
                "You don't have access to the document that answers this question. If you "
                f"need it, ask document control for access. For anything urgent, call {CONTACT}.",
                restricted)

        self.stage = "source inspection"
        result = self.pipeline.answer(question, "shielded", ShieldConfig(), candidate_filter=allowed,
                                      doc_scope=scope)
        self.stage = "answer checks"
        attempts = [r for r in (result.first_attempt, result) if r is not None]
        for attempt in attempts:
            titles.update({c.doc_id: c.metadata.get("title", c.doc_id) for c in attempt.chunks})

        excluded: dict[str, Source] = {}
        found: list[str] = []
        for attempt in attempts:
            for d in attempt.decisions:
                reasons = [r for r in d.get("reasons", []) if r != "below top-k after filtering"]
                if d["included"] or not reasons or d["doc_id"] in excluded:
                    continue
                found.append(classify(reasons, d["trust"]))
                if d["trust"] == "hash_mismatch":  # "not approved" just restates the mismatch
                    reasons = [r for r in reasons if not r.startswith("unapproved source")]
                excluded[d["doc_id"]] = Source(d["doc_id"], titles.get(d["doc_id"], d["doc_id"]),
                                               "excluded", [friendly(r) for r in reasons],
                                               shared=d["doc_id"].startswith("UNREG-"))
        for doc_id, (reason, cat) in flagged.items():  # index tampering, hidden characters
            if doc_id not in excluded:
                found.append(cat)
                excluded[doc_id] = Source(doc_id, titles.get(doc_id, doc_id), "excluded", [reason],
                                          shared=doc_id.startswith("UNREG-"))
        conflicts = list(dict.fromkeys(w for a in attempts for w in a.warnings
                                       if w.startswith("Conflict:")))
        restored = [r["doc_id"] for r in result.restored]
        used = self._used(result, titles)
        for s in used:  # a restored document is used in its signed version
            if s.doc_id in excluded:
                s.reasons = ["altered copy excluded; signed version restored and used"]
        used_ids = {s.doc_id for s in used}
        for doc_id in restored:
            if doc_id in excluded and doc_id not in used_ids:
                excluded[doc_id].reasons.append("signed version restored")
        sources = (used + [s for d, s in excluded.items() if d not in used_ids] + restricted)

        # Inspect the answer before release.
        answer = result.answer
        if result.status == "answered" and detect_injection(answer)["flagged"]:
            return self._blocked(request_id, user, "prompt_injection", sources,
                                 "The draft answer itself contained instructions aimed at the "
                                 "assistant or reader, so it was not released.")
        if result.status == "answered" and protected_texts and leaks(answer, protected_texts):
            return self._blocked(request_id, user, "authorization", sources,
                                 "The draft answer repeated text from a document this role may "
                                 "not see, so it was not released.")
        if result.status == "answered":
            # Every citation must name a real document this user may read. A made-up ID is
            # a sign the model invented the answer; a restricted one, that it leaked.
            known = {d.doc_id: d.filename for d in load_corpus(self.settings)[0]}
            bad = [d for d in result.invalid_citations
                   if d not in known or user.role not in roles_for(known[d], registry)
                   or self.region_access(user, *site_of(known[d], registry)) == "locked"]
            if bad:
                return self._blocked(request_id, user, "unverified", sources,
                                     f"The draft answer cited {', '.join(bad)}, which is not a "
                                     f"document available to this user, so the answer may be "
                                     f"invented and was not released.")

        removed: list[str] = []
        if result.status == "answered":  # secrets and regulated identifiers never leave
            answer, removed = rc.redact_sensitive(answer)

        self.stage = "live data"
        try:
            live = live_route_check(answer, read_sensors(self.sensors_path)) \
                if result.status == "answered" else {}
        except Exception:  # live data unavailable: warn rather than pass silently
            live = {"unavailable": True, "conflict": True}

        categories = list(dict.fromkeys(found + (["data_conflict"] if live.get("conflict") else [])
                                        + (["sensitive_data"] if removed else [])))
        category = next((c for c in ("prompt_injection", "poisoning", "authorization",
                                     "data_conflict", "sensitive_data", "unverified")
                         if c in categories), "clean")
        notes = self._explain(excluded, restored, live)
        if removed:
            notes.append(f"Sensitive data was removed from the answer before release: "
                         f"{', '.join(removed)}.")

        if result.status == "withheld":
            return Decision(request_id, _now(), user.user_id, user.name, user.role, True, "block",
                            category if category != "clean" else "unverified",
                            categories or ["unverified"],
                            " ".join(notes + ["No approved, verified source could answer this "
                                              "safely, so no answer was released."]),
                            f"RAG Shield could not verify an answer from approved procedures. "
                            f"{SAFE_GUIDANCE}", sources, conflicts, restored, live,
                            audit={"query_ids": [a.query_id for a in attempts]})
        if live.get("conflict"):
            decision = "warn"
            answer = f"{self._live_warning(live)}\n\n{answer}"
        elif excluded or removed:
            decision = "redact"
        else:
            decision = "allow"
            notes.append(f"All {len(used)} sources are approved, signed by two approvers and "
                         "unchanged, and the answer passed the release checks.")

        # Other stations' documents that reached the answer: emergency ones under
        # break-glass (answered, flagged for review), others under a PIN grant.
        by_id = {e.get("doc_id"): e for e in registry.values()}
        away = {s.doc_id: self.region_access(user, by_id[s.doc_id].get("site"),
                                             by_id[s.doc_id].get("sensitivity", "restricted"))
                for s in used if s.doc_id in by_id}
        glass = sorted(d for d, a in away.items() if a == "break_glass")
        verified = sorted(d for d, a in away.items() if a == "granted")
        if verified:
            notes.append(f"{', '.join(verified)} came from another station, opened with "
                         f"{user.name}'s verified PIN.")
        if glass:
            sites = sorted({by_id[d]["site"] for d in glass})
            categories = list(dict.fromkeys(categories + ["break_glass"]))
            if category == "clean":
                category = "break_glass"
            if decision in ("allow", "redact"):
                decision = "warn"
            answer = (f"Warning: out-of-region emergency access. You are assigned to "
                      f"{user.site}; this answer uses {', '.join(sites)} emergency procedures "
                      f"under break-glass access, and the access is flagged for review. "
                      f"Follow Gas Control's directions on site (radio channel 1 or "
                      f"555-0142).\n\n{answer}")
            notes.append(f"Break-glass access: {user.name} ({user.site}) received "
                         f"{', '.join(sites)} emergency procedures ({', '.join(glass)}) without "
                         f"waiting for verification, because safety information must not be "
                         f"delayed. The security team reviews every break-glass use.")
            self._access_event(user, sites[0], "break_glass_access",
                               f"{user.name} ({user.site}) used break-glass access to "
                               f"{', '.join(sites)} emergency procedures ({', '.join(glass)}), "
                               f"{request_id}. Review required.", request_id)
        if offer:
            notes.append(f"A sensitive {offer['site']} document matched about as closely as the "
                         f"emergency procedure. Safety came first: the answer uses the emergency "
                         f"procedure, the sensitive document was kept out, and a PIN can add it.")
        return Decision(request_id, _now(), user.user_id, user.name, user.role, True, decision,
                        category, categories or ["clean"], " ".join(notes), answer, sources,
                        conflicts, restored, live, break_glass=glass, step_up=offer,
                        audit={"query_ids": [a.query_id for a in attempts]})

    # --- Helpers ------------------------------------------------------------------------

    def _blocked(self, request_id: str, user: User, category: str, sources: list[Source],
                 explanation: str) -> Decision:
        return Decision(request_id, _now(), user.user_id, user.name, user.role, True, "block",
                        category, [category], explanation,
                        f"RAG Shield withheld this answer. {SAFE_GUIDANCE}", sources)

    def _failed(self, question: str, user: User, request_id: str, shield: bool,
                error: str) -> Decision:
        stage = self.stage
        message = (f"The assistant is unavailable right now. {SAFE_GUIDANCE}" if not shield else
                   f"A safety check ({stage}) could not finish, so no answer is shown. "
                   f"{SAFE_GUIDANCE}")
        d = Decision(request_id, _now(), user.user_id, user.name, user.role, shield,
                     "block" if shield else "none", "system", ["system"],
                     f"The {stage} stage failed, so the system refused rather than pass on "
                     "unchecked content.", message)
        d.audit = {"error_type": error, "failed_stage": stage}
        return d

    def _live_warning(self, live: dict) -> str:
        if live.get("unavailable"):
            return (f"Warning: live sensor readings are unavailable. Confirm the evacuation route "
                    f"with {CONTACT} before moving.")
        wind = COMPASS[live["wind_from"]]
        bad = ", ".join(live["downwind_routes_named"])
        good = ", ".join(live["upwind_routes"]) or "an upwind route"
        return (f"Warning: live wind is from the {wind} at {live['wind_mph']} mph, so {bad} now "
                f"leads downwind of the leak. Do not use {bad}. Confirm the route with "
                f"{CONTACT} before moving; the upwind route is {good}.")

    def _explain(self, excluded, restored, live) -> list[str]:
        notes = []
        for s in excluded.values():
            notes.append(f"{s.doc_id} {s.title} was excluded: {'; '.join(s.reasons)}.")
        if restored:
            notes.append(f"The signed versions of {', '.join(restored)} were restored from the "
                         "protected archive and used instead.")
        if live.get("unavailable"):
            notes.append("Live sensor data was unavailable, so the route could not be checked.")
        elif live.get("conflict"):
            notes.append(f"The answer named {', '.join(live['downwind_routes_named'])}, which is "
                         f"downwind given the live wind from the {COMPASS[live['wind_from']]}.")
        return notes

    def _titles(self) -> dict[str, str]:
        return {d.doc_id: d.title for d in load_corpus(self.settings)[0]}

    def _text(self, doc_id: str) -> str:
        return next((d.text for d in load_corpus(self.settings)[0] if d.doc_id == doc_id), "")

    @staticmethod
    def _used(result, titles) -> list[Source]:
        seen, used = set(), []
        for chunk in result.chunks:
            if chunk.doc_id not in seen:
                seen.add(chunk.doc_id)
                used.append(Source(chunk.doc_id, titles.get(chunk.doc_id, chunk.doc_id), "used",
                                   shared=chunk.doc_id.startswith("UNREG-")))
        return used

    def _audit(self, question: str, d: Decision) -> dict:
        """What the audit log keeps: no question or answer text, no document content."""
        return {"event": "policy_decision", "request_id": d.request_id, "user_id": d.user_id,
                "role": d.role, "shield": d.shield, "decision": d.decision,
                "category": d.category, "categories": d.categories,
                "question_sha256_16": question_fingerprint(question),
                "sources": [{"doc_id": s.doc_id, "status": s.status, "reasons": s.reasons}
                            for s in d.sources],
                "restored": d.restored, "live_conflict": bool(d.live.get("conflict")),
                "step_up_site": d.step_up.get("site"), "break_glass": d.break_glass,
                "model": self.settings.model_label,
                "home_site": self.users[d.user_id].site if d.user_id in self.users else None,
                "query_flags": d.query_flags,
                "attribution_mac": d.attribution.get("mac"),
                "explanation": d.explanation, "latency_seconds": d.latency_seconds,
                **d.audit}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
