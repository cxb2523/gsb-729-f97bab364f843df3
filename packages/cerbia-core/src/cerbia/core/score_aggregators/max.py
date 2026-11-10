import logging

logger = logging.getLogger(__name__)


class MaxScoreAggregator:
    """Returns the maximum (worst) score.

    This strategy selects the highest score, representing the worst-case scenario where any single scanner's high risk
    score is treated as the final score. Returns 0.0 if the scores list is empty.
    """

    def compute(self, scores: list[float]) -> float:
        """Aggregate multiple scores into a single composite score.

        Args:
            scores (list[float]): List of scores to aggregate, typically in range [0.0, 1.0].

        Returns:
            float: The aggregated score, in range [0.0, 1.0].
        """
        score = max(scores) if scores else 0.0
        logger.debug(
            "Maximum score selected: %s",
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
