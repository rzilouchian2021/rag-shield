"""Load documents from disk, attach metadata, and split them into chunks.

Trust is decided only by the registry entry plus a matching SHA-256 hash.
A file's name, folder, or claims in its text never make it trusted.

Run:  python -m src.ingestion               list the corpus
      python -m src.ingestion --approve approved/file.md
                                            record reviewer sign-off of a file's hash
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pypdf import PdfReader

from config.settings import Settings, load_settings
from src import signoff

ALLOWED_EXTENSIONS = {".txt", ".md", ".pdf"}
MAX_FILE_BYTES = 10 * 1024 * 1024
SIMULATION_LABEL = "Fictional training document."

TRUST_APPROVED = "approved"          # registered, approved, hash matches
TRUST_MODIFIED = "hash_mismatch"     # registered, but bytes differ from sign-off
TRUST_UNAPPROVED = "unapproved"      # registered, not (yet) approved
TRUST_UNTRUSTED = "untrusted"        # not in the registry


class IngestionError(Exception):
    """A single file could not be ingested."""


@dataclass
class Document:
    doc_id: str
    filename: str          # path relative to data_dir, e.g. approved/x.md
    title: str
    text: str
    source: str
    owner: str
    approval_status: str
    version: str
    upload_timestamp: str
    trust_classification: str
    sha256: str
    expected_sha256: str = ""

    def metadata(self) -> dict[str, str]:
        """Metadata stored with every chunk. Chroma requires scalar values."""
        return {
            "doc_id": self.doc_id,
            "filename": self.filename,
            "title": self.title,
            "source": self.source,
            "owner": self.owner,
            "approval_status": self.approval_status,
            "version": self.version,
            "upload_timestamp": self.upload_timestamp,
            "trust_classification": self.trust_classification,
            "sha256": self.sha256,
        }


@dataclass
class Chunk:
    chunk_id: str
    text: str
    chunk_index: int
    metadata: dict = field(default_factory=dict)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_registry(path: Path) -> dict[str, dict]:
    """The effective registry. Where sign-off is enforced (src/signoff.py), an entry
    counts as approved only with valid signatures, and its hash is the signed one."""
    if not path.exists():
        return {}
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))["documents"]
    except (json.JSONDecodeError, KeyError) as exc:
        raise ValueError(f"Invalid document registry at {path}: {exc}") from exc
    return signoff.apply(path, {entry["filename"]: entry for entry in entries})


def safe_path(data_dir: Path, path: Path) -> Path:
    """Reject symlinks, unsupported types, oversized files, and paths outside data_dir."""
    if path.is_symlink():
        raise IngestionError(f"{path.name}: symlinks are not ingested")
    resolved = path.resolve()
    if not resolved.is_relative_to(data_dir.resolve()):
        raise IngestionError(f"{path.name}: outside the data directory")
    if resolved.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise IngestionError(f"{path.name}: unsupported file type")
    if resolved.stat().st_size > MAX_FILE_BYTES:
        raise IngestionError(f"{path.name}: larger than {MAX_FILE_BYTES} bytes")
    return resolved


def extract_text(path: Path, raw: bytes) -> str:
    if path.suffix.lower() == ".pdf":
        try:
            pages = [page.extract_text() or "" for page in PdfReader(path).pages]
        except Exception as exc:  # pypdf raises many types on malformed files
            raise IngestionError(f"{path.name}: unreadable PDF ({exc})") from exc
        text = "\n\n".join(pages)
    else:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise IngestionError(f"{path.name}: not valid UTF-8") from exc
    text = text.replace("\r\n", "\n")
    # The simulation label stays in the file but is hidden from the model, which
    # otherwise used it as a reason to dismiss approved documents.
    text = "\n".join(line for line in text.split("\n")
                     if not line.startswith(SIMULATION_LABEL)).strip()
    if not text:
        raise IngestionError(f"{path.name}: no extractable text")
    return text


def title_from(text: str, path: Path) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip().lstrip("#").strip()[:120]
    return path.stem


def classify_trust(entry: dict | None, sha256: str) -> str:
    if entry is None:
        return TRUST_UNTRUSTED
    if entry.get("sha256") != sha256:
        return TRUST_MODIFIED
    if entry.get("approval_status") != "approved":
        return TRUST_UNAPPROVED
    return TRUST_APPROVED


def load_document(path: Path, data_dir: Path, registry: dict[str, dict]) -> Document:
    resolved = safe_path(data_dir, path)
    raw = resolved.read_bytes()
    text = extract_text(resolved, raw)
    digest = sha256_bytes(raw)
    filename = resolved.relative_to(data_dir.resolve()).as_posix()
    entry = registry.get(filename)
    uploaded = datetime.fromtimestamp(resolved.stat().st_mtime, tz=timezone.utc).isoformat()
    if entry is None:
        return Document(
            # Includes the path so identical copies in two places stay distinct.
            doc_id=f"UNREG-{sha256_bytes(f'{filename}:{digest}'.encode())[:8]}", filename=filename, title=title_from(text, resolved),
            text=text, source="shared-repository-upload", owner="unknown",
            approval_status="none", version="unknown", upload_timestamp=uploaded,
            trust_classification=TRUST_UNTRUSTED, sha256=digest,
        )
    return Document(
        doc_id=entry["doc_id"], filename=filename, title=title_from(text, resolved), text=text,
        source=entry["source"], owner=entry["owner"],
        approval_status=entry["approval_status"], version=entry["version"],
        upload_timestamp=entry["upload_timestamp"],
        trust_classification=classify_trust(entry, digest), sha256=digest,
        expected_sha256=entry.get("sha256", ""),
    )


def load_corpus(settings: Settings) -> tuple[list[Document], list[str]]:
    """Return (documents, per-file errors). One bad file never stops the rest."""
    registry = load_registry(settings.registry_path)
    documents, errors = [], []
    for folder in settings.indexed_folders:
        root = settings.data_dir / folder
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if path.name.startswith(".") or path.is_dir():
                continue
            try:
                documents.append(load_document(path, settings.data_dir, registry))
            except IngestionError as exc:
                errors.append(str(exc))
    return documents, errors


def chunk_text(text: str, size: int, overlap: int) -> list[str]:
    """Split on paragraphs, then pack into windows of about `size` words.

    The most recent markdown heading is repeated at the top of each chunk so a
    chunk still makes sense (and embeds well) when read on its own.
    """
    chunks: list[str] = []
    current: list[str] = []
    heading = ""

    def flush() -> None:
        nonlocal current
        if not current:
            return
        chunks.append(" ".join(heading.split() + current))
        current = current[-overlap:] if overlap else []

    for paragraph in re.split(r"\n\s*\n", text):
        paragraph = paragraph.strip()
        if not paragraph:
            continue
        if paragraph.startswith("#"):
            flush()
            current = []
            heading = paragraph.lstrip("#").strip()
            continue
        words = paragraph.split()
        while words:
            room = size - len(current)
            if room <= 0:
                flush()
                continue
            # Keep a paragraph whole when it fits in a fresh chunk.
            if len(words) > room and len(words) <= size and len(current) > overlap:
                flush()
                continue
            current.extend(words[:room])
            words = words[room:]
    flush()
    return chunks


def chunk_document(doc: Document, size: int, overlap: int) -> list[Chunk]:
    return [
        Chunk(
            chunk_id=f"{doc.doc_id}::{doc.sha256[:8]}::{index}",
            text=text, chunk_index=index,
            metadata={**doc.metadata(), "chunk_index": index},
        )
        for index, text in enumerate(chunk_text(doc.text, size, overlap))
    ]


def approve_file(settings: Settings, filename: str) -> str:
    """Record the file's current hash in the registry for review.

    Where sign-off is enforced this is not approval on its own: two approvers must
    then sign it (python -m src.signoff sign FILE --as ID). A hash only proves the
    bytes match what was reviewed, not that the reviewed content was accurate.
    """
    path = (settings.data_dir / filename).resolve()
    safe_path(settings.data_dir, path)
    data = json.loads(settings.registry_path.read_text(encoding="utf-8"))
    for entry in data["documents"]:
        if entry["filename"] == filename:
            entry["sha256"] = sha256_bytes(path.read_bytes())
            entry["approval_status"] = "approved"
            break
    else:
        raise IngestionError(f"{filename}: not in the registry; add an entry for it first")
    settings.registry_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return entry["sha256"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approve", action="append", default=[], metavar="FILE")
    args = parser.parse_args()
    settings = load_settings()
    for filename in args.approve:
        print(f"recorded {filename}: {approve_file(settings, filename)[:12]}")
        if signoff.policy_for(settings.registry_path):
            print("  not approved until two approvers sign it: "
                  f"python -m src.signoff sign {filename} --as APPROVER")
    documents, errors = load_corpus(settings)
    for doc in documents:
        count = len(chunk_document(doc, settings.chunk_size_words, settings.chunk_overlap_words))
        print(f"{doc.doc_id:16} {doc.trust_classification:14} {count:3} chunks  {doc.filename}")
    for error in errors:
        print(f"SKIPPED: {error}")


if __name__ == "__main__":
    main()
