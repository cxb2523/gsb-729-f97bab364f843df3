import pytest
from cerbia.core.scanners.malicious_url._math import levenshtein

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("first", "second", "expected_distance"),
    [
        ("", "", 0),
        ("", "abc", 3),
        ("abc", "", 3),
        ("same", "same", 0),
        ("kitten", "sitting", 3),
        ("abc", "adc", 1),
    ],
    ids=["both_empty", "first_empty", "second_empty", "same_values", "multiple_edits", "substitution"],
)
def test_malicious_url_math_returns_edit_distance_when_values_are_provided(
    first: str, second: str, expected_distance: int
) -> None:
    result = levenshtein(first, second)

    assert result == expected_distance


def test_malicious_url_math_returns_same_distance_when_input_order_is_reversed() -> None:
    result = levenshtein("flaw", "lawn")

    reverse_result = levenshtein("lawn", "flaw")

    assert result == 2
    assert reverse_result == result
