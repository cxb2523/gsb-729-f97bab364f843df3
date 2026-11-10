import logging

logger = logging.getLogger(__name__)


class MeanScoreAggregator:
    """Computes the arithmetic mean of scores.

    This aggregation strategy averages all provided scores, returning 0.0 if the scores list is empty.
    """

    def compute(self, scores: list[float]) -> float:
        """Aggregate multiple scores into a single composite score.

        Args:
            scores (list[float]): List of scores to aggregate, typically in range [0.0, 1.0].

        Returns:
            float: The aggregated score, in range [0.0, 1.0].
        """
        score = sum(scores) / len(scores) if scores else 0.0
        logger.debug(
            "Scores averaged: %s",
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
