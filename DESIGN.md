---
name: RAG Shield
description: A projector-ready security console comparing Baseline RAG with RAG Shield on measured evidence.
colors:
  projector-paper: "#fafbfc"
  console-mist: "#eef1f5"
  station-ink: "#1b2430"
  slate-note: "#4a5565"
  hairline: "#d5dae3"
  shield-blue: "#1f5fae"
  exposure-orange: "#d9622b"
  exposure-orange-text: "#b4501f"
  exposure-orange-deep: "#9a4318"
  danger-text: "#a3262a"
  success-text: "#116a2e"
  warning-text: "#7a5600"
  info-text: "#14468a"
  heat-low: "#eaf2fc"
  heat-high: "#184f95"
typography:
  headline:
    fontFamily: "Atkinson Hyperlegible Next, sans-serif"
    fontSize: "2.5rem"
    fontWeight: 800
    lineHeight: 1.2
  title:
    fontFamily: "Atkinson Hyperlegible Next, sans-serif"
    fontSize: "1.625rem"
    fontWeight: 650
    lineHeight: 1.25
  subtitle:
    fontFamily: "Atkinson Hyperlegible Next, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 600
    lineHeight: 1.3
  body:
    fontFamily: "Atkinson Hyperlegible Next, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.6
  label:
    fontFamily: "Atkinson Hyperlegible Next, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 600
  figure:
    fontFamily: "Atkinson Hyperlegible Next, sans-serif"
    fontSize: "2rem"
    fontWeight: 700
    lineHeight: 1.2
    fontFeature: "tnum"
rounded:
  md: "0.5rem"
  bar: "4px"
spacing:
  tight: "0.75rem"
  section: "2rem"
components:
  button-primary:
    backgroundColor: "{colors.shield-blue}"
    textColor: "{colors.projector-paper}"
    rounded: "{rounded.md}"
  button-secondary:
    backgroundColor: "{colors.projector-paper}"
    textColor: "{colors.station-ink}"
    rounded: "{rounded.md}"
  nav-item-current:
    backgroundColor: "{colors.console-mist}"
    textColor: "{colors.station-ink}"
    rounded: "{rounded.md}"
  stat-figure:
    textColor: "{colors.station-ink}"
    typography: "{typography.figure}"
  stat-label:
    textColor: "{colors.slate-note}"
    typography: "{typography.label}"
---

# Design System: RAG Shield

## 1. Overview

**Creative North Star: "The Evidence Room"**

A quiet, well-lit room where everything on the table is labeled, measured, and traceable to where it came from. Nothing is decorated and nothing raises its voice; when something is wrong, it is obvious because everything else is calm. The dashboard is shown on a classroom projector, so legibility at a distance outranks density, and the Baseline-versus-Shield comparison outranks every other element on a page.

Built on Streamlit with its theme tokens (`.streamlit/config.toml`) plus a small set of shared styles in `app.py`. The single source for color values is `config/palette.py`; `tests/test_palette.py` fails if the Streamlit theme drifts from it. Light theme only, pinned on purpose for washed-out projectors.

This system rejects, by name: hacker or cyber aesthetics (neon on black, matrix green, glitch effects, skulls and padlocks); SaaS marketing dashboards (hero metrics with gradient accents, vanity KPIs, confetti); the default untouched Streamlit demo look where everything has the same weight; and alarmist red-everywhere security dashboards.

**Key Characteristics:**
- Projector scale: 18px root, nothing that matters below about 16px.
- One accent (Shield Blue) plus one story color (Exposure Orange), both with fixed meanings.
- Measured figures shown large only when they exist; empty states stay quiet.
- Status always stated in words and an icon, never by color alone.
- Comparison first, evidence one click deeper in expanders.

## 2. Colors

A restrained, cool-neutral palette with one accent and one warning-free story color.

### Primary
- **Shield Blue** (#1f5fae): primary actions, the current navigation item, and every chart mark for RAG Shield. 6.1:1 on Projector Paper, so it also works as text.

### Secondary
- **Exposure Orange** (#d9622b): Baseline (unprotected) data in charts, and nothing else. 3.5:1 against the page, which is enough for bars but not for text.
- **Exposure Orange Text** (#b4501f): the same hue deepened to 4.9:1 for Baseline labels and counts.
- **Exposure Orange Deep** (#9a4318): text on Exposure Orange's own tint, such as the "Unprotected" badge (5.7:1).

### Neutral
- **Projector Paper** (#fafbfc): the page.
- **Console Mist** (#eef1f5): sidebar, inputs, secondary panels, current nav item.
- **Station Ink** (#1b2430): body text and figures, 15:1 on Projector Paper.
- **Slate Note** (#4a5565): chart axes, stat labels, secondary notes, 7.3:1.
- **Hairline** (#d5dae3): borders and gridlines.

### Status text
Danger (#a3262a), Success (#116a2e), Warning (#7a5600), Info (#14468a). Each sits on Streamlit's 10% tint of its own hue at 5.8:1 or more.

### Named Rules
**The Fixed Meaning Rule.** Shield Blue always means "protected" in data and "act here" in controls. Exposure Orange always means Baseline. Never swap them, never use either decoratively.

**The Earned Red Rule.** Danger styling appears only for a real security outcome (an attack that succeeded, a failed retest, a tampered procedure). If a page is red without an incident, the page is wrong.

## 3. Typography

**Body Font:** Atkinson Hyperlegible Next (Google Fonts, with sans-serif fallback offline)
**Label/Mono Font:** Atkinson Hyperlegible Mono, for code, document IDs, and tabular figures

**Character:** Designed by the Braille Institute for legibility, which is exactly the projector brief. One family carries everything; hierarchy comes from size and weight (800 for page titles, 700 for sections), with tight tracking at display sizes.

### Hierarchy
- **Eyebrow** (700, 0.875rem, uppercase, 0.08em tracking, Shield Blue): one short context line above each page title, such as "Live comparison · fictional Station 41".
- **Headline** (800, 2.5rem, 1.2, -0.02em tracking): page titles, one per page.
- **Title** (700, 1.625rem, 1.25): page sections such as "Across the full evaluation".
- **Subtitle** (600, 1.25rem, 1.3): column heads such as "Baseline RAG" and "RAG Shield".
- **Body** (400, 1rem at an 18px root, 1.6): answers and explanations. Streamlit's columns keep answer lines near 65 to 75 characters.
- **Label** (600, 0.875rem): stat labels and captions, about 16px on screen.
- **Figure** (700, 2rem, tabular numerals): measured values in the stat row only.

### Named Rules
**The Back Row Rule.** If a fact matters to the story, it must be readable from the back of a classroom: 16px minimum, dark ink, never light gray. Chart text is 16px Station Ink or Slate Note, never Plotly's default gray.

## 4. Elevation

Flat. Depth comes from tonal layering (Projector Paper page, Console Mist panels) and Hairline borders, never shadows. Expanders and tables use a 1px Hairline border; nothing floats except Streamlit's own popovers.

### Named Rules
**The Flat Table Rule.** Surfaces are flat at rest. If something needs to stand out, it gets space and weight, not a shadow.

## 5. Components

### Buttons
- **Shape:** gently rounded (0.5rem).
- **Primary:** Shield Blue fill with Projector Paper text. At most one per view, reserved for the action the page exists for (for example "Record verdict").
- **Secondary:** outlined, Station Ink text. The default for everything else, including "Run integrity scan" and "Run drill".
- **Guarded actions:** anything slow or that moves files sits behind a popover that explains the consequence, with the primary button inside ("Purge and retest" opens to "Purge and retest now").

### Navigation
- Streamlit's native page navigation in the sidebar, grouped as Presentation (Demo, Evaluation, Watch), Assistant (Ask, Documents, Quarantine), and Group work (Review verdicts).
- Each page has its own URL; the Demo is the default at `/`.
- Items are 32px tall with Material icons; the current page sits on Console Mist.

### Verdict callouts (signature component)
- Streamlit alerts with a bold lead ("**Attack succeeded.**" or "**Attack stopped.**"), a one-sentence explanation, and a Material icon (`gpp_bad` or `verified_user`).
- On the Demo, Baseline and Shield callouts sit side by side in two equal columns under one shared question.

### Comparison panels
- On the Demo, each side is a bordered container with a status badge ("Unprotected" in Exposure Orange, "Protected" in Shield Blue), a subtitle, its verdict callout, then the answer.

### Measured-results strip
- Proportion bars of clear attack successes (lower is better), Baseline above RAG Shield, each with its count ("15 of 40"). Built only from `evaluation_summary.csv` via `evaluation/headline.py`. The approved-poison row stays in, flagged "Where the Shield still fails" in Danger text.

### Stat row
- A responsive grid (`.rs-stats`) of label, figure, and note. Figure in Station Ink at 2rem with tabular numerals.
- When a value has not been measured yet, the figure is replaced by a quiet Slate Note sentence ("Nothing quarantined yet"). Never a large "none" or "0" placeholder.

### Data tables
- `st.dataframe` with readable headers. Ratios are shown as percentages, booleans as "Yes" or "No" (never checkboxes, which look editable). Timestamps are shown as "YYYY-MM-DD HH:MM UTC".

### Charts
- Plotly, rendered with `theme=None` so these tokens apply. Legend on top. Each row label states both counts in the series colors ("Baseline 5 of 10", "RAG Shield 0 of 10"), so a zero result is always visible. Error bars in Slate Note.

## 6. Do's and Don'ts

### Do:
- **Do** take every color from `config/palette.py`, and update `.streamlit/config.toml` with it.
- **Do** put the Baseline-versus-Shield comparison in the first screen of any page that has one, with detail in expanders below.
- **Do** state outcomes in words with an icon: "Attack succeeded" or "Attack stopped", not just red or green.
- **Do** show limitations and failures with the same visual weight as successes.
- **Do** pass `anchor=False` to every Streamlit heading; the hidden anchors add empty keyboard stops.
- **Do** render untrusted text (model answers, document text) only as escaped Markdown or code, never inside raw HTML.

### Don't:
- **Don't** use hacker or cyber aesthetics: neon on black, matrix green, glitch effects, skulls and padlocks.
- **Don't** build SaaS marketing dashboards: hero metrics with gradient accents, vanity KPIs, celebratory confetti.
- **Don't** fall back to the default untouched Streamlit demo look, where everything is the same weight and nothing guides the eye.
- **Don't** make it an alarmist red-everywhere security dashboard that makes every state look like an emergency.
- **Don't** let Streamlit's chart theme override chart styling (`st.plotly_chart(..., theme=None)`), and don't use Plotly's default gray text.
- **Don't** preselect answers in review forms; reviewers decide first, then compare.
- **Don't** use text smaller than about 16px for anything the room needs to read.
