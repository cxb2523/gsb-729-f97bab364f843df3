import re
from functools import lru_cache, partial

from ._constants import LETTER_SPACED, MIDLINE_TAB


def _dejam(dejammed_sequences: list[str], match: re.Match[str]) -> str:
    dejammed_sequences.append(match.group())
    return re.sub(r"[ \t]", "", match.group())


@lru_cache
def _compiled_patterns(
    max_consecutive_spaces: int, max_consecutive_newlines: int
) -> tuple[re.Pattern[str], re.Pattern[str]]:
    """Return the reusable collapse patterns for a threshold combination."""
    return (
        re.compile(r" {" + str(max_consecutive_spaces) + r",}"),
        re.compile(r"\n{" + str(max_consecutive_newlines) + r",}"),
    )


def normalize(
    text: str, max_consecutive_spaces: int, max_consecutive_newlines: int
) -> tuple[str, dict[str, int | list[str]]]:
    """Apply the normalization pipeline to raw text.

    Transformation order:
        1. Replace mid-line tabs with spaces (indentation tabs preserved).
        2. De-jam letter-spaced sequences.
        3. Collapse runs of ``max_consecutive_spaces``+ spaces into one.
        4. Collapse runs of ``max_consecutive_newlines``+ newlines into two.

    Args:
        text (str): Raw input text.
        max_consecutive_spaces (int): Minimum run length of consecutive spaces that triggers collapse into a single
            space.
        max_consecutive_newlines (int): Minimum run length of consecutive newlines that triggers collapse into two
            newlines.

    Returns:
        tuple[str, dict[str, int | list[str]]]: A tuple of (normalized_text, metadata) where metadata records counts of
            each transformation applied and any de-jammed sequences.
    """
    tabs_replaced = 0
    spaces_collapsed = 0
    newlines_collapsed = 0
    dejammed_sequences: list[str] = []

    text, tabs_replaced = MIDLINE_TAB.subn(" ", text)
    text = LETTER_SPACED.sub(partial(_dejam, dejammed_sequences), text)

    space_pattern, newline_pattern = _compiled_patterns(max_consecutive_spaces, max_consecutive_newlines)

    text, spaces_collapsed = space_pattern.subn(" ", text)
    text, newlines_collapsed = newline_pattern.subn("\n\n", text)

    return text, {
        "spaces_collapsed": spaces_collapsed,
        "newlines_collapsed": newlines_collapsed,
        "tabs_replaced": tabs_replaced,
        "dejammed_sequences": dejammed_sequences,
    }
