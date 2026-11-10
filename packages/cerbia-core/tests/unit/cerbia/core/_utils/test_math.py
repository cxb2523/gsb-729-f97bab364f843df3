import math

import pytest
from cerbia.core._utils.math import shannon_entropy

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("counts", "total", "expected_entropy"),
    [
        ([1, 1], 2, 1.0),
        ([2, 2, 2, 2], 8, 2.0),
        ([3, 1], 4, 0.81),
        ([1, 0, 1], 2, 1.0),
        ([0, 0], 0, 0.0),
    ],
    ids=["two_equal_symbols", "four_equal_symbols", "skewed_distribution", "zero_counts_ignored", "zero_total"],
)
def test_shannon_entropy_returns_expected_entropy_when_counts_are_provided(
    counts: list[int], total: int, expected_entropy: float
) -> None:
    result = shannon_entropy(counts, total)

    assert result == pytest.approx(expected_entropy, rel=1e-2)
    assert result >= 0
    assert math.isfinite(result)
