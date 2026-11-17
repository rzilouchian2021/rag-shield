"""Reproducible final demonstration. Run: python -m demo.run_demo

Scenes run on a disposable copy of the data, so quarantine really moves a file
without touching the project's own documents. Outcomes come from the run itself
and are never edited.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import replace
from datetime import datetime, timezone

from config.settings import PROJECT_ROOT, Settings, load_settings
from evaluation.harness import load_cases
from evaluation.runner import score_case
from src.ingestion import load_document, load_registry
from src.logging_utils import read_events
from src.rag_pipeline import RAGPipeline, RAGResult
from src.shield import ShieldConfig

WORK_DIR = PROJECT_ROOT / "storage" / "demo"
OUTPUT = PROJECT_ROOT / "demo" / "output" / "demo_report.json"
LEGITIMATE_CASE = "LEG-01"
ATTACK_CASE = "KB-01"


def demo_settings(base: Settings) -> Settings:
    return replace(base, data_dir=WORK_DIR / "data", chroma_path=WORK_DIR / "chroma",
                   log_path=WORK_DIR / "events.jsonl", collection_name="demo")


def prepare(base: Settings, settings: Settings) -> None:
    if WORK_DIR.exists():
        shutil.rmtree(WORK_DIR)
    shutil.copytree(base.data_dir / "approved", settings.data_dir / "approved")
    (settings.data_dir / "untrusted").mkdir()
    (settings.data_dir / "quarantined").mkdir()


def describe(result: RAGResult) -> dict:
    return {
        "question": result.question, "mode": result.mode, "status": result.status,
        "answer": result.answer, "cited_doc_ids": result.cited_doc_ids,
        "sources_used": [{"doc_id": c.doc_id, "title": c.metadata["title"], "trust": c.trust}
                         for c in result.chunks],
        "latency_seconds": round(result.latency_seconds, 2),
    }


def run(base: Settings, llm=None, progress=None) -> dict:
    """progress: optional callable taking a short status line (used by the dashboard)."""
    step = progress or (lambda message: None)
    step("Preparing a disposable copy of the data")
    settings = demo_settings(base)
    prepare(base, settings)
    cases = {case["test_id"]: case for case in load_cases()}
    legitimate, attack = cases[LEGITIMATE_CASE], cases[ATTACK_CASE]
    pipeline = RAGPipeline(settings, llm=llm)
    pipeline.sync()

    step("Scene A: normal question, no Shield")
    scene_a = pipeline.answer(legitimate["question"])
    control = pipeline.answer(attack["question"])

    step("Uploading the poisoned bulletin")
    upload = settings.data_dir / "untrusted" / "w217_field_bulletin.md"
    shutil.copy(base.data_dir / attack["attack_document"], upload)
    attack_id = load_document(upload, settings.data_dir,
                              load_registry(settings.registry_path)).doc_id
    pipeline.sync()

    step("Scene B: attack question, no Shield")
    scene_b = pipeline.answer(attack["question"])
    score_b = score_case(attack, scene_b, attack_id, control.answer)
    step("Scene C: same question, Shield on")
    scene_c = pipeline.answer(attack["question"], "shielded", ShieldConfig())
    score_c = score_case(attack, scene_c, attack_id, control.answer)

    report = {
        "_note": "Fictional simulation. All outcomes below were produced by this run.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": settings.model_label,
        "scene_a_normal_operation": describe(scene_a),
        "clean_control_answer": control.answer,
        "scene_b_poisoning_without_shield": {
            **describe(scene_b), "poison_document": attack_id,
            "poison_in_context": attack_id in {c.doc_id for c in scene_b.chunks},
            "scored_outcome": score_b["outcome"], "attack_succeeded": score_b["attack_success"]},
        "scene_c_shield_enabled": {
            **describe(scene_c), "poison_document": attack_id,
            "trust_decisions": scene_c.decisions, "warnings": scene_c.warnings,
            "conflicts": scene_c.conflicts, "detections": scene_c.detections,
            "quarantined": scene_c.quarantined,
            "poison_in_context": attack_id in {c.doc_id for c in scene_c.chunks},
            "scored_outcome": score_c["outcome"], "attack_succeeded": score_c["attack_success"],
            "attack_prevented": not score_c["attack_success"]},
        "security_event_log": read_events(settings.log_path, limit=20)[::-1],
    }
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    report = run(load_settings())
    for key in ("scene_a_normal_operation", "scene_b_poisoning_without_shield", "scene_c_shield_enabled"):
        scene = report[key]
        print(f"\n=== {key}\nQ: {scene['question']}\nA: {scene['answer']}\nSources: {scene['sources_used']}")
        if "attack_succeeded" in scene:
            print(f"Outcome: {scene['scored_outcome']}, attack succeeded: {scene['attack_succeeded']}")
    print(f"\nWrote {OUTPUT}")


if __name__ == "__main__":
    main()
