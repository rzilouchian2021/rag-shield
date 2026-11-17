import json

import pandas as pd
import pytest

from config.settings import PROJECT_ROOT
from evaluation import review
from evaluation.export_fair import LIMITATIONS, apply_review_status
from evaluation.harness import load_cases


def entries():
    return [{"test_id": "KB-01", "answer_sha256": "a", "config": "baseline", "verdict": "clear",
             "reviewed_by": "Claude (proposed; group to confirm)"},
            {"test_id": "C-KB-02", "answer_sha256": "b", "config": "shield_full",
             "verdict": "partial", "reviewed_by": "Claude (proposed; group to confirm)"}]


def test_confirm_keeps_proposal_and_records_reviewer():
    data = entries()
    review.confirm(data, "KB-01", "baseline", "a", "partial", " Reza ", "hedged")
    entry = data[0]
    assert entry["verdict"] == "partial" and entry["proposed_verdict"] == "clear"
    assert entry["confirmations"][0]["reviewer"] == "Reza"
    assert review.status(data) == {"total": 2, "confirmed": 1, "pending": 1,
                                   "changed_from_proposal": 1, "disputed": 0}


def test_disagreement_is_counted_and_latest_wins():
    data = entries()
    review.confirm(data, "KB-01", "baseline", "a", "clear", "A")
    review.confirm(data, "KB-01", "baseline", "a", "safe", "B")
    assert data[0]["verdict"] == "safe" and data[0]["proposed_verdict"] == "clear"
    assert review.status(data)["disputed"] == 1


@pytest.mark.parametrize("args", [("KB-01", "baseline", "a", "maybe", "A"),
                                  ("KB-01", "baseline", "a", "clear", "  "),
                                  ("KB-99", "baseline", "a", "clear", "A"),
                                  ("KB-01", "shield_full", "a", "clear", "A")])
def test_confirm_rejects_bad_input(args):
    with pytest.raises(ValueError):
        review.confirm(entries(), *args)


def test_save_round_trips(tmp_path):
    path = tmp_path / "adjudications.json"
    data = entries()
    review.confirm(data, "KB-01", "baseline", "a", "safe", "A")
    review.save(path, data)
    assert review.load(path) == data
    assert not list(tmp_path.glob("*.tmp"))


def test_review_items_join_answers_and_signed_off_cases():
    runs = pd.DataFrame([
        {"test_id": "KB-01", "config": "baseline", "answer_sha256": "a", "answer": "A1",
         "control_answer": "C1", "outcome": "adopted", "scenario": "primary"},
        {"test_id": "KB-01", "config": "shield_full", "answer_sha256": "a", "answer": "wrong",
         "control_answer": "", "outcome": "", "scenario": "primary"}])
    items = review.review_items(entries(), runs, load_cases())
    assert items[0]["answer"] == "A1" and items[0]["case"]["test_id"] == "KB-01"
    assert items[1]["answer"] is None and items[1]["case"]["test_id"] == "KB-02"


def test_every_project_verdict_matches_a_run_and_case():
    runs_path = PROJECT_ROOT / "evaluation" / "results" / "evaluation_runs.csv"
    if not runs_path.exists():
        pytest.skip("evaluation has not been run")
    data = review.load(PROJECT_ROOT / "evaluation" / "adjudications.json")
    items = review.review_items(data, pd.read_csv(runs_path, keep_default_na=False), load_cases())
    assert all(i["answer"] is not None and i["case"] for i in items)
    assert all(e["verdict"] in review.VERDICTS for e in data)


def test_fair_status_reports_partial_and_full_confirmation():
    base = {"known_limitations": list(LIMITATIONS)}
    partial = apply_review_status(json.loads(json.dumps(base)), review.status(entries()))
    assert "0 of 2" in partial["_status"]
    data = entries()
    for e in data:
        review.confirm(data, e["test_id"], e["config"], e["answer_sha256"], e["verdict"], "A")
    full = apply_review_status(json.loads(json.dumps(base)), review.status(data))
    assert "All 2 manual verdicts were confirmed" in full["_status"]
    assert not any("proposed until" in l for l in full["known_limitations"])
