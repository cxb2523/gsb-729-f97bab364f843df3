import pytest
from cerbia.core.config import ScoreAggregatorConfig
from cerbia.core.factories.score_aggregator import ScoreAggregatorFactory
from cerbia.core.score_aggregators.base import ScoreAggregator
from cerbia.core.score_aggregators.max import MaxScoreAggregator
from cerbia.core.score_aggregators.max_with_bonus import MaxWithBonusScoreAggregator
from cerbia.core.score_aggregators.mean import MeanScoreAggregator

pytestmark = pytest.mark.unit


class _ScoreAggregatorStub:
    def __init__(self, multiplier: float, **kwargs: str) -> None:
        self.multiplier = multiplier

    def compute(self, scores: list[float]) -> float:
        return sum(scores) * self.multiplier


def test_score_aggregator_factory_builds_configured_score_aggregator() -> None:
    config = ScoreAggregatorConfig(
        score_aggregator=f"{__name__}._ScoreAggregatorStub",
        init_args={"multiplier": 0.5},
    )

    result = ScoreAggregatorFactory.build(config)

    assert isinstance(result, ScoreAggregator)
    assert isinstance(result, _ScoreAggregatorStub)
    assert result.multiplier == 0.5


@pytest.mark.parametrize(
    ("score_aggregator", "init_args", "expected_type"),
    [
        ("cerbia.core.score_aggregators.MaxScoreAggregator", {}, MaxScoreAggregator),
        ("cerbia.core.score_aggregators.MeanScoreAggregator", {}, MeanScoreAggregator),
        (
            "cerbia.core.score_aggregators.MaxWithBonusScoreAggregator",
            {"bonus": 0.1},
            MaxWithBonusScoreAggregator,
        ),
    ],
    ids=["max", "mean", "max_with_bonus"],
)
def test_score_aggregator_factory_builds_public_aggregator_when_configured(
    score_aggregator: str,
    init_args: dict[str, float],
    expected_type: type[ScoreAggregator],
) -> None:
    config = ScoreAggregatorConfig(score_aggregator=score_aggregator, init_args=init_args)

    result = ScoreAggregatorFactory.build(config)

    assert isinstance(result, expected_type)
    if isinstance(result, MaxWithBonusScoreAggregator):
        assert result.bonus == 0.1
