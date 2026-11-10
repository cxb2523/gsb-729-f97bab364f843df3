from enum import StrEnum, auto


class MatchStrategy(StrEnum):
    """Strategy for matching patterns against text.

    Attributes:
        SEARCH: Use re.search() to find any occurrence of the pattern.
        ALL: Use re.finditer() to find all non-overlapping occurrences of the pattern.
        FULL_MATCH: Use re.fullmatch() to require the entire text to match the pattern.
    """

    SEARCH = auto()
    ALL = auto()
    FULL_MATCH = auto()
