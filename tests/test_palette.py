import tomllib

from config import palette
from config.settings import PROJECT_ROOT


def test_streamlit_theme_matches_palette():
    theme = tomllib.loads((PROJECT_ROOT / ".streamlit" / "config.toml").read_text())["theme"]
    assert theme["primaryColor"] == palette.SHIELD
    assert theme["backgroundColor"] == palette.PAGE
    assert theme["secondaryBackgroundColor"] == palette.PANEL
    assert theme["textColor"] == palette.INK
    assert theme["borderColor"] == palette.RULE
    assert theme["redTextColor"] == palette.DANGER_TEXT
    assert theme["greenTextColor"] == palette.SUCCESS_TEXT
    assert theme["yellowTextColor"] == palette.WARNING_TEXT
    assert theme["blueTextColor"] == palette.INFO_TEXT
    assert theme["orangeColor"] == palette.BASELINE
    assert theme["orangeTextColor"] == palette.BASELINE_DEEP
    assert theme["chartCategoricalColors"][:2] == [palette.SHIELD, palette.BASELINE]
