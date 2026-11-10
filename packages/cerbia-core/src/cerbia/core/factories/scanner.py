from ..config import ScannerConfig
from ..scanners.base import Scanner
from .base import Factory


class ScannerFactory(Factory[ScannerConfig, Scanner]):
    """Factory for building Scanner instances from ScannerConfig.

    This factory dynamically imports and instantiates scanner classes based on configuration, ensuring the created
    instances satisfy the Scanner interface.
    """

    @classmethod
    def get_output_type(cls) -> type[Scanner]:
        """Return the expected type of the output produced by the factory.

        Returns:
            type[Scanner]: The expected type of the output.
        """
        return Scanner
