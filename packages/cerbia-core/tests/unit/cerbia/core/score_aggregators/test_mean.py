import pytest
from cerbia.core.score_aggregators.mean import MeanScoreAggregator

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("scores", "expected_score"),
    [
        ([0.2], 0.2),
        ([0.2, 0.4, 0.6], 0.4),
    ],
    ids=["single_score", "multiple_scores"],
)
def test_mean_score_aggregator_returns_arithmetic_mean_when_scores_are_provided(
    scores: list[float], expected_score: float
) -> None:
    aggregator = MeanScoreAggregator()

    result = aggregator.compute(scores)

    assert result == pytest.approx(expected_score)


def test_mean_score_aggregator_returns_zero_when_scores_are_empty() -> None:
    aggregator = MeanScoreAggregator()

    result = aggregator.compute([])

    assert result == 0.0
