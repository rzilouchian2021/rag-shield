"""Sentence Transformers wrapper. Runs on CPU; no GPU required."""
from __future__ import annotations

from functools import lru_cache

from sentence_transformers import SentenceTransformer


@lru_cache(maxsize=2)
def _load(model_name: str) -> SentenceTransformer:
    return SentenceTransformer(model_name, device="cpu")


class Embedder:
    def __init__(self, model_name: str):
        self.model_name = model_name

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        vectors = _load(self.model_name).encode(
            texts, normalize_embeddings=True, show_progress_bar=False
        )
        return vectors.tolist()
