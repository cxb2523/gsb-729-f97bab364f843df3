import logging

from ...models.entries import Entry
from ._normalization import normalize

logger = logging.getLogger(__name__)


class WhitespaceNormalizationPreprocessor:
    """Normalizes evasive whitespace patterns before scanning.

    Applies a fixed sequence of transformations to defeat whitespace-based obfuscation: mid-line tab replacement,
    letter-spaced de-jamming, excessive space collapse, and excessive newline collapse. Entries that require no
    normalization are passed through unchanged.

    Args:
        max_consecutive_spaces (int): Minimum run length of consecutive spaces that triggers collapse into a single
            space.
        max_consecutive_newlines (int): Minimum run length of consecutive newlines that triggers collapse into two
            newlines.

    Attributes:
        preprocessor_id (str): Unique identifier for this preprocessor.
        preprocessor_name (str): Human-readable name for this preprocessor.
    """

    def __init__(self, max_consecutive_spaces: int = 6, max_consecutive_newlines: int = 6) -> None:
        self.preprocessor_id = "whitespace_normalization"
        self.preprocessor_name = "Whitespace Normalization"
        self._max_consecutive_spaces = max_consecutive_spaces
        self._max_consecutive_newlines = max_consecutive_newlines

    def process(self, entries: list[Entry]) -> list[Entry]:
        """Run whitespace normalization on a list of entries.

        For each entry, applies the normalization pipeline and records what was changed in the derived entry's metadata.
        Entries whose text is unchanged are passed through as-is.

        Args:
            entries (list[Entry]): Input entries to process.

        Returns:
            list[Entry]: clean entries unchanged and new derived entries with transformation metadata attached.
        """
        output: list[Entry] = []

        for entry in entries:
            normalized_text, metadata = normalize(
                entry.text, self._max_consecutive_spaces, self._max_consecutive_newlines
            )

            if normalized_text == entry.text:
                output.append(entry)
                continue

            derived_entry = entry.derive(normalized_text, self.preprocessor_id)
            derived_entry.metadata.preprocessors[self.preprocessor_id] = metadata
            output.append(derived_entry)

        processed_count = len(entries)
        result_count = len(output)
        logger.debug(
            "%s entries normalized",
            processed_count,
            extra={
                "operation": "process",
                "stage": "normalization",
                "component_kind": "preprocessor",
                "outcome": "completed",
                "processed_count": processed_count,
                "result_count": result_count,
            },
        )
        return output
