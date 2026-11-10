from typing import Protocol, runtime_checkable


@runtime_checkable
class ScoreAggregator(Protocol):
    """Protocol defining the interface for score aggregator implementations.

    A score aggregator aggregates multiple scores into a single composite score, implementing a specific aggregation
    strategy (e.g., average, worst-case, etc.).
    """

    def compute(self, scores: list[float]) -> float:
        """Aggregate multiple scores into a single composite score.

        Args:
            scores (list[float]): List of scores to aggregate, typically in range [0.0, 1.0].

        Returns:
            float: The aggregated score, typically in range [0.0, 1.0].
        """
        ...
