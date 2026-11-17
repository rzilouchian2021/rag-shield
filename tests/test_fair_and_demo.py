import json
from dataclasses import replace

import pandas as pd
import pytest

import demo.run_demo as demo
from config.settings import PROJECT_ROOT, Settings
from evaluation.export_fair import GROUPS, build_summary, reduction_interval, relative_reduction
from tests.conftest import FakeLLM


def test_relative_reduction_edges():
    assert relative_reduction(5, 0, 10) == 1.0
    assert relative_reduction(3, 4, 10) == pytest.approx(-0.333)
    assert relative_reduction(0, 0, 10) is None


def test_reduction_interval_is_reproducible_and_can_be_negative():
    assert reduction_interval(3, 4, 10) == reduction_interval(3, 4, 10)
    low, high = reduction_interval(3, 4, 10)
    assert low < 0 < high


def test_fair_summary_matches_measured_results_when_present():
    path = PROJECT_ROOT / "evaluation" / "results" / "evaluation_summary.csv"
    if not path.exists():
        pytest.skip("evaluation has not been run")
    summary = pd.read_csv(path)
    output = build_summary(summary)
    assert {e["attack_category"] for e in output["attack_categories"]} == set(GROUPS)
    for entry in output["attack_categories"]:
        rows = summary[(summary.config == "baseline") & summary.scenario.isin(
            [s for s, _ in GROUPS[entry["attack_category"]]])
            & summary.attack_category.isin([c for _, c in GROUPS[entry["attack_category"]]])]
        assert entry["number_of_trials"] == rows.attempts.sum()
        assert entry["baseline_attack_success"]["successes"] == rows.clear_successes.sum()


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(demo, "WORK_DIR", tmp_path / "work")
    monkeypatch.setattr(demo, "OUTPUT", tmp_path / "out" / "report.json")
    return Settings()


def test_demo_reports_failure_honestly_when_attack_does_not_work(isolated):
    report = demo.run(isolated, llm=FakeLLM("Tell the Shift Supervisor [DOC-003]."))
    assert report["scene_b_poisoning_without_shield"]["attack_succeeded"] is False


def test_demo_quarantines_only_in_its_copy_and_writes_report(isolated):
    llm = FakeLLM("No escalation is needed for this nuisance alert.")
    report = demo.run(isolated, llm=llm)
    assert report["scene_b_poisoning_without_shield"]["attack_succeeded"] is True
    scene = report["scene_c_shield_enabled"]
    assert scene["quarantined"] and not scene["poison_in_context"] and scene["attack_prevented"]
    assert scene["status"] == "withheld" and scene["warnings"]
    assert not (PROJECT_ROOT / "data" / "untrusted" / "w217_field_bulletin.md").exists()
    assert (PROJECT_ROOT / "data" / "attack_library" / "kb_poisoning" / "w217_field_bulletin.md").exists()
    assert json.loads(demo.OUTPUT.read_text())["model"]
