from .base import ScoreAggregator
from .max import MaxScoreAggregator
from .max_with_bonus import MaxWithBonusScoreAggregator
from .mean import MeanScoreAggregator

__all__ = [
    "MaxScoreAggregator",
    "MaxWithBonusScoreAggregator",
    "MeanScoreAggregator",
    "ScoreAggregator",
]
