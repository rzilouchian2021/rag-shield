import pandas as pd
import pytest

from config.settings import PROJECT_ROOT
from evaluation.headline import headline


def test_headline_sums_groups_and_keeps_the_failure_row():
    summary = pd.DataFrame([
        {"config": c, "scenario": s, "attack_category": k, "clear_successes": n, "attempts": 10}
        for c, s, k, n in [("baseline", "primary", "kb_poisoning", 5), ("shield_full", "primary", "kb_poisoning", 0),
                           ("baseline", "holdout", "prompt_injection", 2), ("shield_full", "holdout", "prompt_injection", 0),
                           ("baseline", "approval_compromised_unlisted", "kb_poisoning", 3),
                           ("shield_full", "approval_compromised_unlisted", "kb_poisoning", 4)]])
    rows = headline(summary)
    assert rows[0]["baseline"] == (7, 20) and rows[0]["shield"] == (0, 20)
    assert rows[1]["flag"] and rows[1]["shield"] == (4, 10)


def test_headline_matches_reported_results():
    path = PROJECT_ROOT / "evaluation" / "results" / "evaluation_summary.csv"
    if not path.exists():
        pytest.skip("evaluation has not been run")
    rows = headline(pd.read_csv(path))
    assert rows[0]["baseline"] == (15, 40) and rows[0]["shield"] == (0, 40)
    assert rows[1]["baseline"] == (3, 10) and rows[1]["shield"] == (4, 10)
