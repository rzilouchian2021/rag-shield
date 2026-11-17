import math

import pandas as pd
import pytest

from evaluation.charts import attack_success_chart
from evaluation.metrics import apply_review, attack_metrics, benign_metrics, legitimate_metrics, wilson, summarize


def row(**kw):
    base = dict(test_id="T", answer_sha256="a", config="baseline", scenario="primary",
                attack_category="kb_poisoning", attack_success=False, verdict="safe",
                flagged_injection=False, flagged_conflict=False, attack_doc_in_context=True,
                status="answered", safe_fact_present=True, attribution_correct=True,
                any_detection=False, outcome="correct", latency_seconds=2.0)
    return {**base, **kw}


def test_wilson_known_values():
    low, high = wilson(5, 10)
    assert round(low, 3) == 0.237 and round(high, 3) == 0.763
    assert wilson(0, 10)[0] == 0 and round(wilson(0, 10)[1], 3) == 0.278
    assert math.isnan(wilson(0, 0)[0])


def test_detection_and_prevention_are_counted_separately():
    frame = pd.DataFrame([
        row(verdict="clear", flagged_conflict=True),   # detected, not prevented
        row(verdict="safe", flagged_injection=True),   # detected and prevented
        row(verdict="safe"),                           # prevented, not detected
        row(verdict="partial"),                        # neither
    ])
    m = attack_metrics(frame)
    assert (m["attempts"], m["clear_successes"], m["partial_successes"]) == (4, 1, 1)
    assert m["attack_success_rate"] == 0.25 and m["attack_success_rate_incl_partial"] == 0.5
    assert (m["detected"], m["false_negatives"], m["detection_rate"]) == (2, 2, 0.5)
    assert (m["detected_not_prevented"], m["detected_and_prevented"], m["prevented_not_detected"]) == (1, 1, 1)


def test_withheld_counts_against_legitimate_accuracy():
    frame = pd.DataFrame([row(), row(outcome="withheld", status="withheld", latency_seconds=0.0)])
    m = legitimate_metrics(frame)
    assert (m["correct"], m["accuracy"], m["withheld"]) == (1, 0.5, 1)
    assert m["mean_latency_seconds"] == 2.0


def test_benign_false_positive_rate_denominator():
    frame = pd.DataFrame([row(flagged_injection=True), row(), row(), row()])
    assert benign_metrics(frame)["false_positive_rate"] == 0.25


def test_review_overrides_rules_and_unreviewed_success_stays_clear():
    runs = pd.DataFrame([row(test_id="A", attack_success=True), row(test_id="B", attack_success=True),
                         row(test_id="C")]).drop(columns="verdict")
    frame = apply_review(runs, [{"test_id": "A", "answer_sha256": "a", "verdict": "safe"}])
    assert frame.verdict.tolist() == ["safe", "clear", "safe"]


def test_review_only_applies_to_that_exact_answer():
    runs = pd.DataFrame([row(test_id="A", attack_success=True, answer_sha256="new")]).drop(columns="verdict")
    assert apply_review(runs, [{"test_id": "A", "answer_sha256": "old", "verdict": "safe"}]).verdict[0] == "clear"


def test_summary_chart_comes_from_summary_values():
    frame = pd.DataFrame([row(verdict="clear"), row(config="shield_full")])
    figure = attack_success_chart(summarize(frame))
    values = {trace.name: list(trace.x) for trace in figure.data}
    assert values == {"Baseline": [100.0], "RAG Shield": [0.0]}


@pytest.mark.parametrize("config_name", ["only_trust_retrieval", "without_safe_response"])
def test_ablation_configs_exist_and_differ_from_full(config_name):
    from evaluation.run_evaluation import shield_configs
    configs = shield_configs()
    assert config_name in configs and configs[config_name] != configs["shield_full"]
    assert len(configs) == 12 and not configs["shield_all_off"].quarantine
