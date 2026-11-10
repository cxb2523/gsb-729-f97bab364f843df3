import re


def is_in_defensive_context(
    text: str,
    match_start: int,
    defensive_patterns: list[re.Pattern[str]],
) -> bool:
    """Check whether a regex match sits inside defensive / negated text.

    Looks at a window of up to 80 characters before *match_start*, bounded by the current line, for well-known negation
    or instructional words that indicate the surrounding sentence is a security rule rather than an attack.

    Args:
        text (str): The full text being scanned.
        match_start (int): Character offset where the regex match begins.
        defensive_patterns (list[re.Pattern[str]]): Compiled patterns that signal defensive context.

    Returns:
        bool: ``True`` when a defensive pattern matches in the prefix window.
    """
    line_start = text.rfind("\n", 0, match_start) + 1
    window_start = max(line_start, match_start - 80)
    prefix = text[window_start:match_start]
    return any(p.search(prefix) for p in defensive_patterns)
