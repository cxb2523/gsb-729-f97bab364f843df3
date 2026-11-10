from ..config import ScoreAggregatorConfig
from ..score_aggregators import ScoreAggregator
from .base import Factory


class ScoreAggregatorFactory(Factory[ScoreAggregatorConfig, ScoreAggregator]):
    """Factory for building ScoreAggregator instances from ScoreAggregatorConfig.

    This factory dynamically imports and instantiates score aggregator classes based on configuration, ensuring the
    created instances satisfy the ScoreAggregator interface.
    """

    @classmethod
    def get_output_type(cls) -> type[ScoreAggregator]:
        """Return the expected type of the output produced by the factory.

        Returns:
            type[ScoreAggregator]: The expected type of the output.
        """
        return ScoreAggregator
