"""Semantic retrieval returning inspectable results."""
from __future__ import annotations

from dataclasses import dataclass

from src.vector_store import VectorStore


@dataclass
class RetrievedChunk:
    rank: int
    chunk_id: str
    text: str
    similarity: float   # cosine similarity, higher is closer
    metadata: dict

    @property
    def doc_id(self) -> str:
        return self.metadata["doc_id"]

    @property
    def trust(self) -> str:
        return self.metadata["trust_classification"]


class Retriever:
    def __init__(self, store: VectorStore, top_k: int):
        self.store = store
        self.top_k = top_k

    def retrieve(self, question: str, top_k: int | None = None) -> list[RetrievedChunk]:
        raw = self.store.query(question, top_k or self.top_k)
        rows = zip(raw["ids"][0], raw["documents"][0], raw["metadatas"][0], raw["distances"][0])
        return [
            RetrievedChunk(rank, chunk_id, text, round(1 - distance, 4), metadata)
            for rank, (chunk_id, text, metadata, distance) in enumerate(rows, start=1)
        ]
