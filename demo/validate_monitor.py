"""Validate the revised retrieval concentration monitor. Run: python -m demo.validate_monitor

The decoys, controls, and pass criteria were fixed in docs/phase7_watch.md
before this script was first run. Each case runs alone on a disposable copy of
the approved documents, with quarantine off so the monitor is tested on its own.

- Positives: three new decoys built to be retrieved broadly while passing the
  content rules. Each should raise an alert.
- Negatives: the six harmless uploads from the evaluation. None should alert.
- Restore: an approved procedure is removed for a while, then restored. It
  should not alert.
- Design-time decoy: the drill's original decoy, reported separately because the
  revision was made after seeing its result.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import replace
from datetime import datetime, timezone

from config.settings import PROJECT_ROOT, Settings, load_settings
from demo.run_drill import DECOY, EXTRA_QUESTIONS
from evaluation.harness import load_cases
from src.ingestion import load_document, load_registry
from src.monitoring import alerts, all_events, retrieval_concentration
from src.rag_pipeline import RAGPipeline
from src.shield import ShieldConfig, detect_injection

WORK_DIR = PROJECT_ROOT / "storage" / "monitor_validation"
OUTPUT = PROJECT_ROOT / "evaluation" / "results" / "monitor_validation.json"
LIBRARY = PROJECT_ROOT / "data" / "attack_library"
POSITIVES = sorted((LIBRARY / "monitor_validation").glob("*.md"))
NEGATIVES = sorted((LIBRARY / "benign").glob("*.md"))
RESTORED = "approved/anomaly_escalation_procedure.md"
CONFIG = ShieldConfig(quarantine=False)


def questions() -> list[str]:
    return [c["question"] for c in load_cases() if c["attack_category"] == "legitimate"] + EXTRA_QUESTIONS


def fresh(base: Settings, name: str) -> RAGPipeline:
    work = WORK_DIR / name
    if work.exists():
        shutil.rmtree(work)
    settings = replace(base, data_dir=work / "data", chroma_path=work / "chroma",
                       log_path=work / "events.jsonl", collection_name="validation")
    shutil.copytree(base.data_dir / "approved", settings.data_dir / "approved")
    (settings.data_dir / "untrusted").mkdir()
    (settings.data_dir / "quarantined").mkdir()
    pipeline = RAGPipeline(settings)
    pipeline.sync()
    return pipeline


def ask_all(pipeline: RAGPipeline, items: list[str]) -> None:
    for question in items:
        pipeline.answer(question, "shielded", CONFIG)


def outcome(pipeline: RAGPipeline, target: str | None) -> dict:
    rows = retrieval_concentration(all_events(pipeline.settings.log_path))
    raised = [a for a in alerts(pipeline.settings.log_path) if a["kind"] == "retrieval_concentration"]
    target_row = next((r for r in rows if r["doc_id"] == target), None)
    return {"target_doc_id": target,
            "target_share": target_row["share"] if target_row else 0.0,
            "target_window": target_row["window"] if target_row else 0,
            "target_alerted": any(a["doc_id"] == target for a in raised),
            "other_alerts": [{"doc_id": a["doc_id"], "detail": a["detail"]}
                             for a in raised if a["doc_id"] != target]}


def upload_case(base: Settings, name: str, text: str) -> dict:
    pipeline = fresh(base, name.removesuffix(".md"))
    path = pipeline.settings.data_dir / "untrusted" / name
    path.write_text(text, encoding="utf-8")
    doc_id = load_document(path, pipeline.settings.data_dir,
                           load_registry(pipeline.settings.registry_path)).doc_id
    pipeline.sync()
    ask_all(pipeline, questions())
    flagged = detect_injection(text)["flagged"] or bool(pipeline.shield.checker.check(text))
    return {"document": name, "content_rules_flagged": flagged, **outcome(pipeline, doc_id)}


def restore_case(base: Settings) -> dict:
    pipeline = fresh(base, "restore")
    target = pipeline.settings.data_dir / RESTORED
    original = target.read_bytes()
    doc_id = load_document(target, pipeline.settings.data_dir,
                           load_registry(pipeline.settings.registry_path)).doc_id
    items = questions()
    ask_all(pipeline, items)
    target.unlink()
    pipeline.sync()
    ask_all(pipeline, items[:6])
    target.write_bytes(original)
    pipeline.sync()
    ask_all(pipeline, items)
    return {"document": RESTORED, **outcome(pipeline, doc_id)}


def run(base: Settings, progress=print) -> dict:
    results = {"positives": [], "negatives": []}
    for path in POSITIVES:
        progress(f"Positive: {path.name}")
        results["positives"].append(upload_case(base, path.name, path.read_text(encoding="utf-8")))
    for path in NEGATIVES:
        progress(f"Negative: {path.name}")
        results["negatives"].append(upload_case(base, path.name, path.read_text(encoding="utf-8")))
    progress("Restore case")
    results["restore"] = restore_case(base)
    progress("Design-time decoy (not validation)")
    results["design_time_decoy"] = upload_case(base, "station41_quick_reference.md", DECOY)

    caught = sum(r["target_alerted"] for r in results["positives"])
    false_alarms = sum(r["target_alerted"] for r in results["negatives"])
    stray = [a for group in ("positives", "negatives") for r in results[group] for a in r["other_alerts"]]
    stray += results["restore"]["other_alerts"]
    report = {
        "_note": "Fictional simulation. Criteria fixed in docs/phase7_watch.md before the first run.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": base.model_label, "questions_per_case": len(questions()),
        "summary": {"decoys_caught": caught, "decoys": len(results["positives"]),
                    "harmless_uploads_alerted": false_alarms,
                    "harmless_uploads": len(results["negatives"]),
                    "restored_procedure_alerted": results["restore"]["target_alerted"],
                    "alerts_on_other_documents": len(stray),
                    "design_time_decoy_alerted": results["design_time_decoy"]["target_alerted"]},
        **results,
    }
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    report = run(load_settings())
    for group in ("positives", "negatives"):
        for r in report[group]:
            print(f"{group[:-1]:9} {r['document']:32} share {r['target_share']:.2f} of "
                  f"{r['target_window']:2}  alerted={r['target_alerted']}  rules_flagged="
                  f"{r['content_rules_flagged']}  other={r['other_alerts']}")
    r = report["restore"]
    print(f"restore   {r['document']}  alerted={r['target_alerted']}  other={r['other_alerts']}")
    r = report["design_time_decoy"]
    print(f"design-time decoy share {r['target_share']:.2f} alerted={r['target_alerted']}")
    print(json.dumps(report["summary"], indent=2))
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
