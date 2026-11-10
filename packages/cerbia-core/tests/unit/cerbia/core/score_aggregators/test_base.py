import pytest
from cerbia.core.score_aggregators.base import ScoreAggregator

pytestmark = pytest.mark.unit


class _ScoreAggregatorStub:
    def compute(self, scores: list[float]) -> float:
        return max(scores, default=0.0)


class _CallableOnlyAggregatorStub:
    def __call__(self, scores: list[float]) -> float:
        return max(scores, default=0.0)


def test_score_aggregator_contract_is_satisfied_by_class_with_required_members() -> None:
    aggregator = _ScoreAggregatorStub()

    assert isinstance(aggregator, ScoreAggregator)


def test_score_aggregator_contract_is_not_satisfied_by_class_without_required_members() -> None:
    candidate = _CallableOnlyAggregatorStub()

    assert not isinstance(candidate, ScoreAggregator)
