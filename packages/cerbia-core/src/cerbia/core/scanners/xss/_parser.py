from html.parser import HTMLParser

from ._constants import CODE_TAGS


def _build_line_offsets(text: str) -> list[int]:
    offsets = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            offsets.append(i + 1)

    return offsets


class _CodeBlockParser(HTMLParser):
    """A simple HTML parser that identifies the ranges of text inside <code>, <pre>, and <textarea> tags.

    This is used to suppress XSS matches inside code blocks when the `html_context_aware` option is enabled in the
    XssScanner.

    Args:
        source (str): The original HTML source text to parse.

    Attributes:
        ranges (list[tuple[int, int]]): A list of tuples representing the start and end offsets of text ranges inside
            <code>, <pre>, and <textarea> tags.
    """

    def __init__(self, source: str) -> None:
        super().__init__()
        self.ranges: list[tuple[int, int]] = []
        self._source = source
        self._line_offsets = _build_line_offsets(source)
        self._current_tag: str | None = None
        self._start_offset: int = 0

    def _abs_offset(self) -> int:
        line, col = self.getpos()
        return self._line_offsets[line - 1] + col

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Handle the start of an HTML tag.

        If the tag is <code>, <pre>, or <textarea>, record the current position as the start of a code block.

        Args:
            tag (str): The name of the tag (e.g., "code", "pre", "textarea").
            attrs (list[tuple[str, str | None]]): A list of (attribute, value) pairs for the tag's attributes.

        Returns:
            None
        """
        if tag.lower() in CODE_TAGS:
            self._current_tag = tag.lower()
            self._start_offset = self._abs_offset()

    def handle_endtag(self, tag: str) -> None:
        """Handle the end of an HTML tag.

        If the tag is <code>, <pre>, or <textarea> and matches the current open tag, record the range from the start
        offset to the current position as a code block.

        Args:
            tag (str): The name of the tag (e.g., "code", "pre", "textarea").

        Returns:
            None
        """
        if tag.lower() == self._current_tag:
            self.ranges.append((self._start_offset, self._abs_offset()))
            self._current_tag = None


def extract_code_ranges(text: str) -> list[tuple[int, int]]:
    """Extract the ranges of text inside <code>, <pre>, and <textarea> tags.

    Args:
        text (str): The input HTML text to parse.

    Returns:
        list[tuple[int, int]]: A list of tuples representing the start and end offsets of text ranges inside <code>,
            <pre>, and <textarea> tags.
    """
    parser = _CodeBlockParser(text)

    try:
        parser.feed(text)
    except Exception:
        return []

    return parser.ranges
