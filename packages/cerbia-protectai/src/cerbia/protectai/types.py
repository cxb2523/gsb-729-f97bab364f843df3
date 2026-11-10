from enum import StrEnum, auto


class MatchStrategy(StrEnum):
    """Input strategy for feeding text to the classification pipeline.

    Attributes:
        FULL: Pass the entire text as a single input.
        CHUNKS: Split text into overlapping sliding-window chunks.
    """

    FULL = auto()
    CHUNKS = auto()
