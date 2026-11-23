"""Extra RAG controls from the OWASP RAG Security Cheat Sheet, used by src/policy.py.

Each control is a small deterministic check. Section numbers refer to the cheat sheet;
docs/owasp-rag-coverage.md maps every recommendation to the code and tests.

- Hidden characters (sec. 1, 8): zero-width, bidirectional-override and other invisible
  characters can carry instructions a reader can't see. Questions are normalized; documents
  that contain them are excluded.
- Index integrity (sec. 7): each retrieved chunk must equal the chunk re-derived from the
  verified file on disk, so editing the vector database directly is caught.
- Rate limiting and reconnaissance (sec. 8, 12): per-user question limits and alerts on
  repeated restricted or injection attempts.
- Sensitive-data redaction (sec. 9): secrets and regulated identifiers are removed from
  answers before release.
- Signed attribution (sec. 5): every protected answer carries its sources, their SHA-256
  hashes and an answer hash, sealed with an HMAC the server can verify later.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import unicodedata
from collections import deque

from src.ingestion import Document, chunk_document

# --- Hidden characters ---------------------------------------------------------------

# Zero-width, joiners, bidi controls, word joiner, invisible math operators, BOM, tag chars.
_INVISIBLE = re.compile(
    "[­͏؜ᅟᅠ឴឵᠎​-‏‪-‮"
    "⁠-⁯ㅤ︀-️﻿ﾠ\U000e0000-\U000e007f]")


def hidden_characters(text: str) -> int:
    return len(_INVISIBLE.findall(text))


def normalize_query(text: str) -> tuple[str, list[str]]:
    """NFKC-normalize and strip invisible characters. Returns (clean text, flags)."""
    flags = []
    if hidden_characters(text):
        flags.append("hidden_characters")
    clean = unicodedata.normalize("NFKC", _INVISIBLE.sub("", text))
    clean = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", clean)
    if clean != text and "hidden_characters" not in flags:
        flags.append("normalized")
    return clean.strip(), flags


def looks_binary(text: str) -> bool:
    """Uploads are text documents; control characters mean it isn't one, whatever its name."""
    return bool(re.search(r"[\x00-\x08\x0e-\x1f]", text))


# --- Index integrity ------------------------------------------------------------------

def expected_chunks(documents: list[Document], size: int, overlap: int) -> dict[str, str]:
    """chunk_id -> text, re-derived from the files on disk."""
    return {c.chunk_id: c.text for doc in documents for c in chunk_document(doc, size, overlap)}


def chunk_matches(chunk_id: str, text: str, expected: dict[str, str]) -> bool:
    return expected.get(chunk_id) == text


# --- Sensitive data in answers --------------------------------------------------------

def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    "access key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "API token": re.compile(r"\b(?:sk|pk|ghp|xox[bpa])[-_][A-Za-z0-9_-]{16,}\b"),
    "password": re.compile(r"(?i)\b(?:password|passphrase|passwd|pwd)\s*[:=]\s*\S+"),
    "social security number": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def redact_sensitive(text: str) -> tuple[str, list[str]]:
    """Remove secrets and regulated identifiers. Phone numbers, valve tags and pressures
    are operational data and stay."""
    found = []
    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            found.append(label)
            text = pattern.sub(f"[removed: {label}]", text)

    def card(match: re.Match) -> str:
        digits = re.sub(r"\D", "", match.group())
        if 13 <= len(digits) <= 19 and _luhn(digits):
            found.append("payment card number")
            return "[removed: payment card number]"
        return match.group()
    text = CARD.sub(card, text)
    return text, list(dict.fromkeys(found))


# --- Rate limiting and patterns over time --------------------------------------------

class RateLimiter:
    def __init__(self, limit: int, window_seconds: float, clock=time.time):
        self.limit, self.window, self.clock = limit, window_seconds, clock
        self.hits: dict[str, deque] = {}

    def allow(self, key: str) -> bool:
        now = self.clock()
        q = self.hits.setdefault(key, deque())
        while q and q[0] <= now - self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True

    def clear(self) -> None:
        self.hits.clear()


class EventCounter:
    """Counts events per key inside a sliding window, for "repeated X" alerts."""

    def __init__(self, window_seconds: float, clock=time.time):
        self.window, self.clock = window_seconds, clock
        self.events: dict[str, deque] = {}

    def add(self, key: str) -> int:
        now = self.clock()
        q = self.events.setdefault(key, deque())
        q.append(now)
        while q and q[0] <= now - self.window:
            q.popleft()
        return len(q)

    def clear(self) -> None:
        self.events.clear()


# --- Signed attribution ---------------------------------------------------------------

ATTRIBUTION_PURPOSE = "rag-shield-attribution-v1"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def attribution(request_id: str, answer: str, sources: list[tuple[str, str]],
                timestamp: str) -> dict:
    """sources: (doc_id, sha256 of the file the answer was drawn from)."""
    return {"purpose": ATTRIBUTION_PURPOSE, "request_id": request_id, "timestamp": timestamp,
            "answer_sha256": _sha256(answer.encode()),
            "sources": [{"doc_id": d, "sha256": h} for d, h in sources]}


def _payload(record: dict) -> bytes:
    body = {k: record[k] for k in ("purpose", "request_id", "timestamp", "answer_sha256", "sources")}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def seal_attribution(record: dict, key: bytes) -> dict:
    return {**record, "mac": hmac.new(key, _payload(record), hashlib.sha256).hexdigest()}


def verify_attribution(record: dict, key: bytes, answer: str | None = None) -> dict:
    """Checks the seal, and (if given) that the answer text is the one that was sealed."""
    try:
        expected = hmac.new(key, _payload(record), hashlib.sha256).hexdigest()
    except (KeyError, TypeError):
        return {"ok": False, "problem": "attribution record is incomplete"}
    if not hmac.compare_digest(expected, str(record.get("mac", ""))):
        return {"ok": False, "problem": "attribution was changed after it was issued"}
    if answer is not None and _sha256(answer.encode()) != record["answer_sha256"]:
        return {"ok": False, "problem": "the answer text differs from the one that was issued"}
    return {"ok": True}


def attribution_key() -> bytes:
    """A key for attribution seals, derived from the audit-log key for a separate purpose."""
    from src.logging_utils import _key
    return hmac.new(_key(create=True), ATTRIBUTION_PURPOSE.encode(), hashlib.sha256).digest()
