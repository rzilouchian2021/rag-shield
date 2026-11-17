"""Formal evaluation. Run: python -m evaluation.run_evaluation [--core-only]

Writes evaluation/results/evaluation_runs.csv. Summaries come from
evaluation/summarize.py, so manual review never needs a rerun.
"""
from __future__ import annotations

import argparse
from dataclasses import fields, replace

import pandas as pd

from config.settings import load_settings
from evaluation.harness import EVALUATION_SHIELD, Harness, load_cases
from evaluation.runner import make_row, score_case
from src.shield import ShieldConfig

CONTROLS = [f.name for f in fields(ShieldConfig) if f.name != "quarantine"]
ALL_OFF = ShieldConfig(False, False, False, False, False, False)


def shield_configs() -> dict[str, ShieldConfig]:
    configs = {"shield_full": EVALUATION_SHIELD, "shield_all_off": ALL_OFF}
    for control in CONTROLS:
        configs[f"without_{control}"] = replace(EVALUATION_SHIELD, **{control: False})
        configs[f"only_{control}"] = replace(ALL_OFF, **{control: True})
    return configs


def run_set(harness: Harness, cases: list[dict], name: str, mode: str, config, controls: dict) -> list[dict]:
    rows = []
    for case in cases:
        if case["attack_document"] is None:
            result, attack_id = harness.run_clean(case["question"], mode, config), ""
        else:
            result, attack = harness.run_attacked(case, mode, config)
            attack_id = attack.doc_id
        control = controls.get(case["test_id"], "")
        rows.append(make_row(case, name, result, score_case(case, result, attack_id, control),
                             attack_id, control))
    print(f"{name}: {len(rows)} cases", flush=True)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-only", action="store_true", help="skip single-control runs")
    core_only = parser.parse_args().core_only
    settings = load_settings()
    normal = Harness(settings)
    compromised_cases = normal.compromised_cases()
    compromised = Harness(settings, approved_attacks=compromised_cases)
    cases = load_cases()

    controls = {c["test_id"]: normal.run_clean(c["question"]).answer
                for c in cases if c["attack_document"]
                and c["attack_category"] != "benign_upload"}
    controls.update({c["test_id"]: controls[c["test_id"].removeprefix("C-")] for c in compromised_cases})
    print(f"controls: {len(controls)}", flush=True)

    configs = {"baseline": None, **shield_configs()}
    if core_only:
        configs = {k: configs[k] for k in ("baseline", "shield_full")}
    rows = []
    out = settings.results_dir / "evaluation_runs.csv"
    for name, config in configs.items():
        mode = "baseline" if config is None else "shielded"
        rows += run_set(normal, cases, name, mode, config, controls)
        rows += run_set(compromised, compromised_cases, name, mode, config, controls)
        pd.DataFrame(rows).to_csv(out, index=False)  # keep partial results if interrupted
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
