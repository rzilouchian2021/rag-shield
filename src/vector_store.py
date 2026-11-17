"""ChromaDB index with hash-based incremental re-indexing."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

import chromadb
from chromadb.config import Settings as ChromaSettings

from config.settings import Settings
from src.embeddings import Embedder
from src.ingestion import Document, chunk_document


@dataclass
class SyncReport:
    added: int = 0
    updated: int = 0
    removed: int = 0
    unchanged: int = 0


class VectorStore:
    def __init__(self, settings: Settings, embedder: Embedder):
        self.settings = settings
        self.embedder = embedder
        settings.chroma_path.mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(
            path=str(settings.chroma_path),
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        self.collection = self._open()

    def _open(self):
        return self.client.get_or_create_collection(
            self.settings.collection_name, metadata={"hnsw:space": "cosine"}
        )

    def _fingerprint(self, doc: Document) -> str:
        """Changes when the file, extracted text, metadata, or chunking/embedding config changes."""
        s = self.settings
        parts = [doc.sha256, hashlib.sha256(doc.text.encode()).hexdigest(), doc.trust_classification, doc.approval_status, doc.version,
                 doc.filename, str(s.chunk_size_words), str(s.chunk_overlap_words), s.embedding_model]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()

    def _indexed(self) -> dict[str, str]:
        """Map doc_id -> stored fingerprint."""
        metadatas = self.collection.get(include=["metadatas"])["metadatas"] or []
        return {m["doc_id"]: m["fingerprint"] for m in metadatas}

    def indexed_ids(self) -> set[str]:
        return set(self._indexed())

    def sync(self, documents: list[Document]) -> SyncReport:
        """Make the index match `documents`, re-embedding only what changed."""
        report = SyncReport()
        indexed = self._indexed()
        current_ids = {doc.doc_id for doc in documents}

        for doc_id in set(indexed) - current_ids:
            self.collection.delete(where={"doc_id": doc_id})
            report.removed += 1

        for doc in documents:
            fingerprint = self._fingerprint(doc)
            previous = indexed.get(doc.doc_id)
            if previous == fingerprint:
                report.unchanged += 1
                continue
            if previous is not None:
                self.collection.delete(where={"doc_id": doc.doc_id})
                report.updated += 1
            else:
                report.added += 1
            chunks = chunk_document(doc, self.settings.chunk_size_words,
                                    self.settings.chunk_overlap_words)
            self.collection.add(
                ids=[c.chunk_id for c in chunks],
                documents=[c.text for c in chunks],
                embeddings=self.embedder.embed([c.text for c in chunks]),
                metadatas=[{**c.metadata, "fingerprint": fingerprint} for c in chunks],
            )
        return report

    def rebuild(self, documents: list[Document]) -> SyncReport:
        self.client.delete_collection(self.settings.collection_name)
        self.collection = self._open()
        return self.sync(documents)

    def query(self, text: str, top_k: int) -> dict:
        count = self.collection.count()
        if count == 0:
            return {"documents": [[]], "metadatas": [[]], "distances": [[]], "ids": [[]]}
        return self.collection.query(
            query_embeddings=self.embedder.embed([text]),
            n_results=min(top_k, count),
            include=["documents", "metadatas", "distances"],
        )
