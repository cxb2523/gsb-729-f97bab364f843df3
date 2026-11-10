from typing import Protocol, runtime_checkable

from ..models.entries import Entry


@runtime_checkable
class Preprocessor(Protocol):
    """Contract that every content preprocessor must satisfy.

    Preprocessors transform or expand entries before they reach the scanning gates. They receive the full list of loaded
    entries and return the complete set: clean entries unchanged plus derived entries for any that required
    transformation.

    Attributes:
        preprocessor_id (str): Unique machine-readable identifier.
        preprocessor_name (str): Human-readable display name.
    """

    preprocessor_id: str
    preprocessor_name: str

    def process(self, entries: list[Entry]) -> list[Entry]:
        """Process entries, passing clean ones through and deriving new ones.

        Args:
            entries (list[Entry]): The entries loaded by the loader.

        Returns:
            list[Entry]: Preprocessed entries, including clean ones and any derived entries.
        """
        ...
