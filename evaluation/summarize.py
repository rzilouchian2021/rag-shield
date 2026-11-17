"""Turn raw runs into summaries and charts. Run: python -m evaluation.summarize"""
from __future__ import annotations

import json

import pandas as pd

from config.settings import PROJECT_ROOT, load_settings
from evaluation import review
from evaluation.charts import ablation_chart, attack_success_chart
from evaluation.harness import load_cases
from evaluation.metrics import apply_review, summarize
from evaluation.scoring import has_safe_fact

REVIEW_PATH = PROJECT_ROOT / "evaluation" / "adjudications.json"
CORE = ("baseline", "shield_full")


def main() -> None:
    results = load_settings().results_dir
    runs = pd.read_csv(results / "evaluation_runs.csv", keep_default_na=False)
    runs["latency_seconds"] = pd.to_numeric(runs.latency_seconds)
    for column in ("flagged_injection", "flagged_conflict", "attack_doc_in_context", "safe_fact_present",
                   "attribution_correct", "any_detection", "attack_success", "needs_review"):
        runs[column] = runs[column].astype(str) == "True"
    # Benign scoring is recomputed from the case file, so a corrected pattern needs no rerun.
    benign = {c["test_id"]: c for c in load_cases() if c["attack_category"] == "benign_upload"}
    for index in runs.index[runs.attack_category == "benign_upload"]:
        if runs.at[index, "status"] == "answered":
            case = benign[runs.at[index, "test_id"]]
            correct = has_safe_fact(case["scoring"], runs.at[index, "answer"])
            runs.at[index, "outcome"] = "correct" if correct else "incorrect"
    reviews = json.loads(REVIEW_PATH.read_text(encoding="utf-8")) if REVIEW_PATH.exists() else []
    frame = apply_review(runs, reviews)
    core = summarize(frame[frame.config.isin(CORE)])
    core.to_csv(results / "evaluation_summary.csv", index=False)
    # Control comparisons use rule-based scoring only; only the core runs get manual review.
    ablation = summarize(apply_review(runs, []))
    ablation.to_csv(results / "ablation_summary.csv", index=False)
    charts = results / "charts"
    charts.mkdir(exist_ok=True)
    attack_success_chart(core).write_html(charts / "attack_success.html", include_plotlyjs="cdn")
    if ablation.config.nunique() > 2:
        ablation_chart(ablation).write_html(charts / "ablation.html", include_plotlyjs="cdn")
    unreviewed = frame[frame.config.isin(CORE) & (frame.needs_review | (frame.verdict == "clear"))]
    keys = {(r["test_id"], r["answer_sha256"]) for r in reviews}
    open_items = [r.test_id for r in unreviewed.itertuples()
                  if (r.test_id, r.answer_sha256) not in keys]
    print(f"Summaries written. Answers awaiting manual review: {len(open_items)}")
    state = review.status(reviews)
    print(f"Group confirmation: {state['confirmed']} of {state['total']} verdicts confirmed, "
          f"{state['changed_from_proposal']} changed from the proposal, {state['disputed']} disputed")


if __name__ == "__main__":
    main()
