"""LLM providers behind one small interface. Keys are never logged or stored."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Protocol

import requests

from config.settings import Settings

TIMEOUT_SECONDS = 180


class LLMError(RuntimeError):
    """The model could not produce an answer. Message is safe to display."""


@dataclass
class LLMResponse:
    text: str
    model: str
    latency_seconds: float


class LLMClient(Protocol):
    def generate(self, system: str, user: str) -> LLMResponse: ...


class OllamaClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def generate(self, system: str, user: str) -> LLMResponse:
        s = self.settings
        payload = {
            "model": s.ollama_model, "system": system, "prompt": user, "stream": False,
            "options": {"temperature": s.temperature, "seed": s.seed, "num_ctx": 4096},
        }
        started = time.perf_counter()
        try:
            response = requests.post(f"{s.ollama_url}/api/generate", json=payload,
                                     timeout=TIMEOUT_SECONDS)
        except requests.ConnectionError as exc:
            raise LLMError(f"Cannot reach Ollama at {s.ollama_url}. Is it running?") from exc
        except requests.Timeout as exc:
            raise LLMError(f"Ollama did not answer within {TIMEOUT_SECONDS}s.") from exc
        if response.status_code == 404:
            raise LLMError(f"Model not found. Run: ollama pull {s.ollama_model}")
        if not response.ok:
            raise LLMError(f"Ollama returned HTTP {response.status_code}.")
        return LLMResponse(response.json()["response"].strip(), s.model_label,
                           time.perf_counter() - started)


class AnthropicClient:
    URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, settings: Settings):
        self.settings = settings
        self._key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not self._key:
            raise LLMError("ANTHROPIC_API_KEY is not set.")

    def generate(self, system: str, user: str) -> LLMResponse:
        s = self.settings
        started = time.perf_counter()
        try:
            response = requests.post(
                self.URL,
                headers={"x-api-key": self._key, "anthropic-version": "2023-06-01"},
                json={"model": s.anthropic_model, "max_tokens": 1024, "system": system,
                      "messages": [{"role": "user", "content": user}]},
                timeout=TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            # Do not chain request details into messages shown to users.
            raise LLMError("Could not reach the Anthropic API.") from None
        if not response.ok:
            raise LLMError(f"Anthropic API returned HTTP {response.status_code}.")
        text = "".join(b.get("text", "") for b in response.json()["content"]).strip()
        return LLMResponse(text, s.model_label, time.perf_counter() - started)


def build_llm(settings: Settings) -> LLMClient:
    return OllamaClient(settings) if settings.llm_provider == "ollama" else AnthropicClient(settings)
