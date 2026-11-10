import pytest
from cerbia.core.scanners.xss._validations import in_safe_range

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("position", "ranges", "expected_result"),
    [
        (5, [(5, 10)], True),
        (10, [(5, 10)], True),
        (7, [(5, 10)], True),
        (4, [(5, 10)], False),
        (11, [(5, 10)], False),
        (12, [(0, 3), (10, 15)], True),
        (5, [], False),
    ],
    ids=["range_start", "range_end", "inside_range", "before_range", "after_range", "second_range", "no_ranges"],
)
def test_in_safe_range_returns_expected_result_when_position_and_ranges_are_provided(
    position: int, ranges: list[tuple[int, int]], expected_result: bool
) -> None:
    result = in_safe_range(position, ranges)

    assert result is expected_result
