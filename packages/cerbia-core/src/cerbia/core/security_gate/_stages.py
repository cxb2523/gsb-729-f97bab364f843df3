from dataclasses import dataclass

from ..config import CascadeStageConfig
from ..scanners.base import Scanner
from ..score_aggregators import ScoreAggregator

__all__ = ["BuiltStage"]


@dataclass(frozen=True, slots=True)
class BuiltStage:
    """Constructed stage and its own scanners.

    Args:
        config (CascadeStageConfig): Validated stage configuration.
        scanners (tuple[Scanner, ...]): Constructed scanners in execution order.
        score_aggregator (ScoreAggregator | None): Constructed aggregator; None causes an operational fault.

    Attributes:
        config (CascadeStageConfig): Stage configuration.
        scanners (tuple[Scanner, ...]): This stage's ordered scanners.
        score_aggregator (ScoreAggregator | None): Aggregator for this stage's weighted BLOCK scores.
    """

    config: CascadeStageConfig
    scanners: tuple[Scanner, ...]
    score_aggregator: ScoreAggregator | None
