"""Plotly charts built only from measured summary files."""
from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

# Baseline (unprotected) is the warm color, the Shield the calm one.
BASELINE_COLOR = "#d9622b"
SHIELD_COLOR = "#2a78d6"
FONT = {"size": 15}
LABELS = {
    ("primary", "prompt_injection"): "Injection: primary",
    ("primary", "kb_poisoning"): "Poisoning: primary",
    ("holdout", "prompt_injection"): "Injection: held-out",
    ("holdout", "kb_poisoning"): "Poisoning: held-out",
    ("approval_compromised", "kb_poisoning"): "Poisoning: approval compromised",
    ("approval_compromised_unlisted", "kb_poisoning"): "Poisoning: approved, new wording",
}


def _attack_rows(summary: pd.DataFrame) -> pd.DataFrame:
    rows = summary[summary.attack_category.isin(["prompt_injection", "kb_poisoning"])].copy()
    rows["label"] = [LABELS[(s, c)] for s, c in zip(rows.scenario, rows.attack_category)]
    return rows


def attack_success_chart(summary: pd.DataFrame) -> go.Figure:
    rows = _attack_rows(summary)
    order = [label for label in LABELS.values() if label in set(rows.label)][::-1]
    counts = rows.pivot(index="label", columns="config", values="clear_successes")
    trials = rows.groupby("label").attempts.first()
    ticks = [f"{label}<br>{int(counts.baseline[label])} vs {int(counts.shield_full[label])} of "
             f"{int(trials[label])}" for label in order]
    figure = go.Figure()
    for config, name, color in (("shield_full", "RAG Shield", SHIELD_COLOR),
                                ("baseline", "Baseline", BASELINE_COLOR)):
        data = rows[rows.config == config].set_index("label").reindex(order)
        figure.add_bar(
            y=order, x=data.attack_success_rate * 100, name=name, orientation="h",
            marker={"color": color, "cornerradius": 4},
            error_x={"type": "data", "symmetric": False, "thickness": 1, "width": 3,
                     "array": (data.asr_ci_high - data.attack_success_rate) * 100,
                     "arrayminus": (data.attack_success_rate - data.asr_ci_low) * 100},
            customdata=data[["clear_successes", "attempts", "partial_successes"]],
            hovertemplate="%{y}<br>" + name + ": %{customdata[0]} of %{customdata[1]} clear, "
                          "%{customdata[2]} partial<extra></extra>",
        )
    figure.update_layout(
        template="plotly_white",
        title="Clear attack success with 95% intervals", barmode="group", bargap=0.3,
        bargroupgap=0.06, height=160 + 80 * len(order), font=FONT, legend={"traceorder": "reversed", "orientation": "h", "y": -0.18},
        xaxis={"title": "Attack success rate (%)", "range": [0, 100], "gridcolor": "rgba(128,128,128,0.2)"},
        yaxis={"automargin": True, "tickmode": "array", "tickvals": order, "ticktext": ticks},
        margin={"l": 10, "r": 20, "t": 50, "b": 10},
    )
    return figure


def ablation_chart(ablation: pd.DataFrame) -> go.Figure:
    rows = _attack_rows(ablation)
    # Keep only scenarios that were run under every setup.
    complete = rows.groupby("label").config.nunique() == rows.config.nunique()
    rows = rows[rows.label.isin(complete[complete].index)]
    columns = [label for label in LABELS.values() if label in set(rows.label)]
    configs = list(dict.fromkeys(rows.config))[::-1]
    grid = rows.pivot(index="config", columns="label", values="attack_success_rate").loc[configs, columns] * 100
    figure = go.Figure(go.Heatmap(
        z=grid.values, x=[c.replace(": ", "<br>") for c in columns], y=[c.replace("_", " ") for c in configs], zmin=0, zmax=100,
        colorscale=[[0, "#eaf2fc"], [1, "#184f95"]], xgap=2, ygap=2,
        text=grid.round(0).astype(int).astype(str).values + "%", texttemplate="%{text}",
        colorbar={"title": "Success %"},
        hovertemplate="%{y}<br>%{x}: %{z:.0f}% rule-scored success<extra></extra>",
    ))
    figure.update_layout(title="Attack success by control setup (rule-based scoring)",
                         template="plotly_white", height=180 + 44 * len(configs), font=FONT, margin={"l": 10, "r": 20, "t": 50, "b": 10},
                         xaxis={"side": "bottom", "tickangle": 0}, yaxis={"automargin": True})
    return figure
