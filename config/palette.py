"""The dashboard's color tokens, in one place. See DESIGN.md.

`.streamlit/config.toml` repeats these values because TOML cannot import them;
tests/test_palette.py fails if the two drift apart.
"""

# Surfaces and text
PAGE = "#fafbfc"          # Projector Paper: app background
PANEL = "#eef1f5"         # Console Mist: sidebar, inputs, secondary panels
INK = "#1b2430"           # Station Ink: body text (15:1 on Page)
INK_MUTED = "#4a5565"     # Slate Note: chart axes and labels (7.3:1 on Page)
RULE = "#d5dae3"          # Hairline: borders and gridlines

# The one accent, and the story's two series
SHIELD = "#1f5fae"        # Shield Blue: primary actions, current page, RAG Shield data
BASELINE = "#d9622b"      # Exposure Orange: Baseline (unprotected) data only
BASELINE_TEXT = "#b4501f" # Exposure Orange, deepened for text (4.9:1 on Page)
BASELINE_DEEP = "#9a4318" # Exposure Orange on its own tint, e.g. the "Unprotected" badge (5.7:1)

# Status text, each at least 5.8:1 on its own 10% tint
DANGER_TEXT = "#a3262a"
SUCCESS_TEXT = "#116a2e"
WARNING_TEXT = "#7a5600"
INFO_TEXT = "#14468a"

# Sequential scale for the control heatmap (light to Shield Blue's deep shade)
HEAT_LOW = "#eaf2fc"
HEAT_HIGH = "#184f95"
