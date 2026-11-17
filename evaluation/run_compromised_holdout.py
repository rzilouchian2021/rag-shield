"""Add signed-off held-out poison to evaluation_runs.csv (Baseline and full Shield).

Run: python -m evaluation.run_compromised_holdout
"""
import pandas as pd

from config.settings import load_settings
from evaluation.harness import EVALUATION_SHIELD, Harness
from evaluation.run_evaluation import run_set

SCENARIO = "approval_compromised_unlisted"


def main() -> None:
    settings = load_settings()
    path = settings.results_dir / "evaluation_runs.csv"
    runs = pd.read_csv(path, keep_default_na=False)
    runs = runs[runs.scenario != SCENARIO]
    cases = Harness.compromised_holdout_cases()
    # Controls are clean-corpus answers, so the held-out case's stored control applies.
    stored = runs[runs.config == "baseline"].set_index("test_id").control_answer
    controls = {c["test_id"]: stored[c["test_id"].removeprefix("C-")] for c in cases}
    harness = Harness(settings, approved_attacks=cases)
    rows = (run_set(harness, cases, "baseline", "baseline", None, controls)
            + run_set(harness, cases, "shield_full", "shielded", EVALUATION_SHIELD, controls))
    pd.concat([runs, pd.DataFrame(rows)]).to_csv(path, index=False)


if __name__ == "__main__":
    main()
