import pytest
from cerbia.core.score_aggregators.max_with_bonus import MaxWithBonusScoreAggregator

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("scores", "expected_score"),
    [
        ([0.6], 0.6),
        ([0.2, 0.6, 0.4], 0.7),
    ],
    ids=["single_score", "multiple_scores"],
)
def test_max_with_bonus_score_aggregator_returns_maximum_with_default_bonus_when_scores_are_provided(
    scores: list[float], expected_score: float
) -> None:
    aggregator = MaxWithBonusScoreAggregator()

    result = aggregator.compute(scores)

    assert result == pytest.approx(expected_score)


def test_max_with_bonus_score_aggregator_uses_custom_bonus_when_configured() -> None:
    aggregator = MaxWithBonusScoreAggregator(bonus=0.1)

    result = aggregator.compute([0.2, 0.6, 0.4])

    assert result == pytest.approx(0.8)


def test_max_with_bonus_score_aggregator_caps_score_at_one_when_bonus_exceeds_maximum() -> None:
    aggregator = MaxWithBonusScoreAggregator()

    result = aggregator.compute([0.9, 0.8, 0.7])

    assert result == 1.0


def test_max_with_bonus_score_aggregator_returns_zero_when_scores_are_empty() -> None:
    aggregator = MaxWithBonusScoreAggregator()

    result = aggregator.compute([])

    assert result == 0.0
