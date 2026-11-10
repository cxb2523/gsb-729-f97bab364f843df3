import html
from urllib.parse import unquote

from ._constants import ZERO_WIDTH_PATTERN


def normalize_for_detection(text: str) -> str:
    """Strip HTML entities, URL-encoding, and zero-width chars for comparison.

    Args:
        text (str): Raw LLM output.

    Returns:
        str: Cleaned text suitable for canary token matching.
    """
    decoded = html.unescape(text)
    decoded = unquote(decoded)

    return ZERO_WIDTH_PATTERN.sub("", decoded)
