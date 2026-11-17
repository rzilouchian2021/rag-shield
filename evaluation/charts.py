"""Plotly charts built only from measured summary files."""
from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

from config import palette

# Baseline (unprotected) is the warm color, the Shield the theme's blue.
BASELINE_COLOR = palette.BASELINE
SHIELD_COLOR = palette.SHIELD
# Sized for a projector; labels use dark ink rather than Plotly's light gray.
FONT = {"size": 16, "color": palette.INK}
AXIS = {"tickfont": {"size": 16, "color": palette.INK_MUTED}, "gridcolor": palette.RULE,
        "linecolor": palette.RULE}
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
    # Counts live in the row label, in each series' color and in the same top-to-bottom
    # order as the bars, so a 0 of 10 result is stated even when its bar has no length.
    ticks = [f"<b>{label}</b><br>"
             f"<span style='color:{palette.BASELINE_TEXT}'>Baseline {int(counts.baseline[label])} of {int(trials[label])}</span><br>"
             f"<span style='color:{SHIELD_COLOR}'>RAG Shield {int(counts.shield_full[label])} of {int(trials[label])}</span>"
             for label in order]
    figure = go.Figure()
    for config, name, color in (("shield_full", "RAG Shield", SHIELD_COLOR),
                                ("baseline", "Baseline", BASELINE_COLOR)):
        data = rows[rows.config == config].set_index("label").reindex(order)
        figure.add_bar(
            y=order, x=data.attack_success_rate * 100, name=name, orientation="h",
            marker={"color": color, "cornerradius": 4},
            error_x={"type": "data", "symmetric": False, "thickness": 1.5, "width": 4,
                     "color": palette.INK_MUTED,
                     "array": (data.asr_ci_high - data.attack_success_rate) * 100,
                     "arrayminus": (data.attack_success_rate - data.asr_ci_low) * 100},
            customdata=data[["clear_successes", "attempts", "partial_successes"]],
            hovertemplate="%{y}<br>" + name + ": %{customdata[0]} of %{customdata[1]} clear, "
                          "%{customdata[2]} partial<extra></extra>",
        )
    figure.update_layout(
        template="plotly_white",
        title={"text": "Clear attack success, with 95% intervals", "font": {"size": 20}},
        barmode="group", bargap=0.28, bargroupgap=0.08, height=140 + 104 * len(order), font=FONT,
        # Legend above the plot, so the color key is on screen before the first bar.
        legend={"traceorder": "reversed", "orientation": "h", "x": 0, "y": 1.0,
                "yanchor": "bottom", "font": {"size": 16}},
        xaxis={**AXIS, "title": "Attack success rate (%)", "range": [0, 100],
               "tickvals": [0, 20, 40, 60, 80, 100]},
        yaxis={**AXIS, "automargin": True, "tickmode": "array", "tickvals": order, "ticktext": ticks},
        plot_bgcolor=palette.PAGE, paper_bgcolor=palette.PAGE,
        margin={"l": 10, "r": 30, "t": 90, "b": 10},
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
        colorscale=[[0, palette.HEAT_LOW], [1, palette.HEAT_HIGH]], xgap=2, ygap=2,
        text=grid.round(0).astype(int).astype(str).values + "%", texttemplate="%{text}",
        colorbar={"title": "Success %"},
        hovertemplate="%{y}<br>%{x}: %{z:.0f}% rule-scored success<extra></extra>",
    ))
    figure.update_layout(title={"text": "Attack success by control setup (rule-based scoring)",
                                "font": {"size": 20}},
                         template="plotly_white", height=180 + 48 * len(configs), font=FONT,
                         plot_bgcolor=palette.PAGE, paper_bgcolor=palette.PAGE,
                         margin={"l": 10, "r": 20, "t": 60, "b": 10},
                         xaxis={**AXIS, "side": "bottom", "tickangle": 0},
                         yaxis={**AXIS, "automargin": True})
    return figure
