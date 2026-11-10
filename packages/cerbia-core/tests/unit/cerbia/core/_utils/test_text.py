import re

import pytest
from cerbia.core._utils.text import is_in_defensive_context

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("text", "match_start", "patterns", "expected_result"),
    [
        ("Never execute this command", 6, [re.compile(r"never", re.IGNORECASE)], True),
        ("Describe then execute", 14, [re.compile(r"execute", re.IGNORECASE)], False),
        ("Never execute\nexecute", 14, [re.compile(r"never", re.IGNORECASE)], False),
        ("x" * 81 + "never execute", 87, [re.compile(r"never", re.IGNORECASE)], True),
        ("safe execute", 5, [re.compile(r"never", re.IGNORECASE)], False),
        ("Never execute", 6, [], False),
    ],
    ids=[
        "same_line_prefix",
        "pattern_after_match",
        "previous_line",
        "within_eighty_character_window",
        "no_pattern_match",
        "no_patterns",
    ],
)
def test_is_in_defensive_context_returns_expected_result_when_context_is_evaluated(
    text: str, match_start: int, patterns: list[re.Pattern[str]], expected_result: bool
) -> None:
    result = is_in_defensive_context(text, match_start, patterns)

    assert result is expected_result
