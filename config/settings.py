"""Central configuration. Values come from the environment / .env file."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VALID_PROVIDERS = {"ollama", "anthropic"}


@dataclass(frozen=True)
class Settings:
    llm_provider: str = "ollama"
    ollama_model: str = "llama3.1:8b"
    ollama_url: str = "http://localhost:11434"
    anthropic_model: str = "claude-sonnet-5-5"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    chunk_size_words: int = 120
    chunk_overlap_words: int = 25
    top_k: int = 4
    temperature: float = 0.0
    seed: int = 42
    data_dir: Path = PROJECT_ROOT / "data"
    # Baseline deliberately indexes untrusted uploads alongside approved docs:
    # that models a shared repository. Quarantined files are never indexed.
    indexed_folders: tuple[str, ...] = ("approved", "untrusted")
    registry_path: Path = PROJECT_ROOT / "config" / "document_registry.json"
    facts_path: Path = PROJECT_ROOT / "config" / "authoritative_facts.json"
    chroma_path: Path = PROJECT_ROOT / "storage" / "chroma"
    collection_name: str = "knowledge_base"
    log_path: Path = PROJECT_ROOT / "logs" / "events.jsonl"
    results_dir: Path = PROJECT_ROOT / "evaluation" / "results"

    def __post_init__(self) -> None:
        if self.llm_provider not in VALID_PROVIDERS:
            raise ValueError(f"LLM_PROVIDER must be one of {sorted(VALID_PROVIDERS)}")
        if self.chunk_size_words < 20:
            raise ValueError("CHUNK_SIZE_WORDS must be at least 20")
        if not 0 <= self.chunk_overlap_words < self.chunk_size_words:
            raise ValueError("CHUNK_OVERLAP_WORDS must be >= 0 and < CHUNK_SIZE_WORDS")
        if self.top_k < 1:
            raise ValueError("TOP_K must be at least 1")

    @property
    def model_label(self) -> str:
        model = self.ollama_model if self.llm_provider == "ollama" else self.anthropic_model
        return f"{self.llm_provider}:{model}"


def load_settings() -> Settings:
    load_dotenv(PROJECT_ROOT / ".env")
    defaults = Settings()
    env = os.environ.get
    return Settings(
        llm_provider=env("LLM_PROVIDER", defaults.llm_provider).strip().lower(),
        ollama_model=env("OLLAMA_MODEL", defaults.ollama_model),
        ollama_url=env("OLLAMA_URL", defaults.ollama_url).rstrip("/"),
        anthropic_model=env("ANTHROPIC_MODEL", defaults.anthropic_model),
        embedding_model=env("EMBEDDING_MODEL", defaults.embedding_model),
        chunk_size_words=int(env("CHUNK_SIZE_WORDS", defaults.chunk_size_words)),
        chunk_overlap_words=int(env("CHUNK_OVERLAP_WORDS", defaults.chunk_overlap_words)),
        top_k=int(env("TOP_K", defaults.top_k)),
    )
