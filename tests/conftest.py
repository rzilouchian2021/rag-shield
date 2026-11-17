import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import Settings  # noqa: E402
from src.llm_client import LLMResponse  # noqa: E402


class FakeLLM:
    """Records the prompt and returns a fixed answer, so tests need no Ollama."""

    def __init__(self, answer="Escalate it [DOC-001]."):
        self.answer = answer
        self.user_prompt = ""

    def generate(self, system, user):
        self.user_prompt = user
        return LLMResponse(self.answer, "fake", 0.01)


@pytest.fixture
def settings(tmp_path):
    (tmp_path / "data" / "approved").mkdir(parents=True)
    (tmp_path / "data" / "untrusted").mkdir()
    (tmp_path / "data" / "quarantined").mkdir()
    return replace(
        Settings(), data_dir=tmp_path / "data", registry_path=tmp_path / "registry.json",
        chroma_path=tmp_path / "chroma", log_path=tmp_path / "events.jsonl",
    )


@pytest.fixture(autouse=True)
def isolated_log_key(tmp_path, monkeypatch):
    """Each test seals its logs with its own key, never the project's."""
    monkeypatch.setenv("RAG_SHIELD_LOG_KEY", str(tmp_path / "keys" / "log_hmac.key"))
