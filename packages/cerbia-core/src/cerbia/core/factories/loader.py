from ..config import LoaderConfig
from ..loaders.base import Loader
from .base import Factory


class LoaderFactory(Factory[LoaderConfig, Loader]):
    """Factory for building Loader instances from LoaderConfig.

    This factory dynamically imports and instantiates loader classes based on configuration, ensuring the
    created instances satisfy the Loader interface.
    """

    @classmethod
    def get_output_type(cls) -> type[Loader]:
        """Return the expected type of the output produced by the factory.

        Returns:
            type[Loader]: The expected type of the output.
        """
        return Loader
