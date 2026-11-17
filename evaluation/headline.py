"""Headline results for the Demo page, read only from evaluation_summary.csv.

Counts are clear attack successes (lower is better). The approved-poison row is
included on purpose: it is where the Shield did not help.
"""
from __future__ import annotations

import pandas as pd

ROWS = [
    ("Unapproved poison and injection", None,
     [("primary", "kb_poisoning"), ("primary", "prompt_injection"),
      ("holdout", "kb_poisoning"), ("holdout", "prompt_injection")]),
    ("Poison that passed approval, reworded", "Where the Shield still fails",
     [("approval_compromised_unlisted", "kb_poisoning")]),
]


def headline(summary: pd.DataFrame) -> list[dict]:
    rows = []
    for title, flag, groups in ROWS:
        picked = summary[[(s, c) in groups for s, c in zip(summary.scenario, summary.attack_category)]]
        entry = {"title": title, "flag": flag}
        for config, key in (("baseline", "baseline"), ("shield_full", "shield")):
            part = picked[picked.config == config]
            entry[key] = (int(part.clear_successes.sum()), int(part.attempts.sum()))
        if entry["baseline"][1]:
            rows.append(entry)
    return rows
