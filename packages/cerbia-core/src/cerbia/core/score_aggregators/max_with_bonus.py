import logging

logger = logging.getLogger(__name__)


class MaxWithBonusScoreAggregator:
    """Returns the maximum score with bonus.

    Formula: ``max(scores) + bonus × (n − 1)``.

    Rewards detection convergence: when multiple scanners flag the same entry independently, the aggregated score rises
    above any single scanner's risk score.

    Args:
        bonus (float): Increment per additional failing scanner beyond the first. Defaults to ``0.05``.
    """

    def __init__(self, bonus: float = 0.05) -> None:
        self.bonus = bonus

    def compute(self, scores: list[float]) -> float:
        """Aggregate multiple scores into a single composite score.

        Args:
            scores (list[float]): List of scores to aggregate, typically in range [0.0, 1.0].

        Returns:
            float: The aggregated score, in range [0.0, 1.0].
        """
        score = min(1.0, max(scores) + self.bonus * (len(scores) - 1)) if scores else 0.0
        logger.debug(
            "Maximum score with bonus selected: %s",
            score,
            extra={
                "operation": "compute",
                "stage": "aggregation",
                "component_kind": "score_aggregator",
                "outcome": "completed",
                "processed_count": len(scores),
            },
        )
        return score
