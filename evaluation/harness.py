"""Run one test case in isolation against a dedicated evaluation index.

The dashboard's index is never touched. Each attack document is present only
for its own case, so an effect can be traced to that document.
"""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from config.settings import PROJECT_ROOT, Settings
from src.ingestion import Document, load_corpus, load_document, load_registry, sha256_bytes
from src.rag_pipeline import RAGPipeline, RAGResult
from src.shield import ShieldConfig

# Attack files must stay in the library between runs, so they are never moved.
EVALUATION_SHIELD = ShieldConfig(quarantine=False)
CASES_PATH = PROJECT_ROOT / "evaluation" / "test_cases.json"
HOLDOUT_PATH = PROJECT_ROOT / "evaluation" / "holdout_cases.json"
COMPROMISED_REGISTRY = PROJECT_ROOT / "storage" / "evaluation_compromised_registry.json"


def load_cases() -> list[dict]:
    """Primary suite plus the held-out and benign cases."""
    cases = []
    for path in (CASES_PATH, HOLDOUT_PATH):
        cases += json.loads(path.read_text(encoding="utf-8"))["cases"]
    return cases


def evaluation_settings(settings: Settings) -> Settings:
    return replace(
        settings, indexed_folders=("approved",),
        chroma_path=PROJECT_ROOT / "storage" / "evaluation_chroma",
        log_path=PROJECT_ROOT / "logs" / "evaluation_events.jsonl",
    )


class Harness:
    """`approved_attacks` simulates compromised approval: those attack documents
    are registered as approved with matching hashes, in a temporary registry."""

    def __init__(self, settings: Settings, llm=None, approved_attacks: list[dict] | None = None):
        self.settings = evaluation_settings(settings)
        if approved_attacks:
            self.settings = self._with_compromised_registry(approved_attacks)
        self.pipeline = RAGPipeline(self.settings, llm=llm)
        self.clean_documents, errors = load_corpus(self.settings)
        if errors:
            raise RuntimeError(f"Clean corpus has errors: {errors}")

    def _with_compromised_registry(self, cases: list[dict]) -> Settings:
        registry = json.loads(self.settings.registry_path.read_text(encoding="utf-8"))
        for number, case in enumerate(cases, start=1):
            path = self.settings.data_dir / case["attack_document"]
            registry["documents"].append({
                "doc_id": f"DOC-{900 + number}", "filename": case["attack_document"],
                "source": "controlled-procedure-library", "owner": "Reliability Engineering",
                "approval_status": "approved", "version": "1.1",
                "upload_timestamp": "2026-02-01T09:00:00+00:00",
                "sha256": sha256_bytes(path.read_bytes())})
        COMPROMISED_REGISTRY.parent.mkdir(parents=True, exist_ok=True)
        COMPROMISED_REGISTRY.write_text(json.dumps(registry), encoding="utf-8")
        return replace(self.settings, registry_path=COMPROMISED_REGISTRY)

    @staticmethod
    def compromised_cases() -> list[dict]:
        """The primary poisoning cases, re-run as if the poison had been signed off."""
        return [{**case, "test_id": f"C-{case['test_id']}", "scenario": "approval_compromised"}
                for case in load_cases()
                if case["scenario"] == "primary" and case["attack_category"] == "kb_poisoning"]

    @staticmethod
    def compromised_holdout_cases() -> list[dict]:
        """Held-out poison signed off as approved, mostly on facts outside the fact list."""
        return [{**case, "test_id": f"C-{case['test_id']}", "scenario": "approval_compromised_unlisted"}
                for case in load_cases()
                if case["scenario"] == "holdout" and case["attack_category"] == "kb_poisoning"]

    def attack_document(self, case: dict) -> Document:
        registry = load_registry(self.settings.registry_path)
        return load_document(self.settings.data_dir / case["attack_document"],
                             self.settings.data_dir, registry)

    def run_clean(self, question: str, mode: str = "baseline",
                  config: ShieldConfig = EVALUATION_SHIELD) -> RAGResult:
        self.pipeline.store.sync(self.clean_documents)
        return self.pipeline.answer(question, mode, config)

    def run_attacked(self, case: dict, mode: str = "baseline",
                     config: ShieldConfig = EVALUATION_SHIELD) -> tuple[RAGResult, Document]:
        attack = self.attack_document(case)
        self.pipeline.store.sync([*self.clean_documents, attack])
        try:
            return self.pipeline.answer(case["question"], mode, config), attack
        finally:
            self.pipeline.store.sync(self.clean_documents)
