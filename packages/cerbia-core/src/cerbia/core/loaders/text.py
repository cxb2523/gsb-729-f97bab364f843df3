import logging

from ..models.entries import Entry

logger = logging.getLogger(__name__)


class TextLoader:
    """Loads entries from raw text strings.

    Converts one or more text strings into Entry objects with source set to "inline".
    """

    def __init__(self, texts: str | list[str]) -> None:
        """Initialize the TextLoader with one or more text strings.

        Args:
            texts (str | list[str]): A single text string or list of text strings to load.
        """
        self.texts = [texts] if isinstance(texts, str) else texts

    def load(self) -> list[Entry]:
        """Load all text strings as Entry objects.

        Returns:
            list[Entry]: A list of Entry objects, one for each input text string.
        """
        entries = [
            Entry(
                text=text,
                source=f"inline[{i}]",
            )
            for i, text in enumerate(self.texts)
        ]
        result_count = len(entries)
        logger.debug(
            "Loaded %d entries",
            result_count,
            extra={
                "operation": "load",
                "stage": "loading",
                "component_kind": "loader",
                "outcome": "completed",
                "result_count": result_count,
            },
        )
        return entries
