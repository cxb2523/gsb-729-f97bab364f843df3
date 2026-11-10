import pytest
from cerbia.core.score_aggregators.max import MaxScoreAggregator

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("scores", "expected_score"),
    [
        ([0.2], 0.2),
        ([0.2, 0.9, 0.5], 0.9),
    ],
    ids=["single_score", "highest_score"],
)
def test_max_score_aggregator_returns_highest_score_when_scores_are_provided(
    scores: list[float], expected_score: float
) -> None:
    aggregator = MaxScoreAggregator()

    result = aggregator.compute(scores)

    assert result == expected_score


def test_max_score_aggregator_returns_zero_when_scores_are_empty() -> None:
    aggregator = MaxScoreAggregator()

    result = aggregator.compute([])

    assert result == 0.0
