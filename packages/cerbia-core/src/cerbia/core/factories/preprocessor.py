from ..config import PreprocessorConfig
from ..preprocessors.base import Preprocessor
from .base import Factory


class PreprocessorFactory(Factory[PreprocessorConfig, Preprocessor]):
    """Factory for building Preprocessor instances from PreprocessorConfig.

    This factory dynamically imports and instantiates preprocessor classes based on configuration, ensuring the created
    instances satisfy the Preprocessor interface.
    """

    @classmethod
    def get_output_type(cls) -> type[Preprocessor]:
        """Return the expected type of the output produced by the factory.

        Returns:
            type[Preprocessor]: The expected type of the output.
        """
        return Preprocessor
