from ..._utils.url import normalize_for_matching


def format_url_finding(url: str, display_limit: int = 60) -> str:
    """Generates a formatted string for a URL finding, ensuring it is normalized and truncated if necessary.

    Args:
        url (str): The URL to format.
        display_limit (int): Maximum length of the formatted string. Defaults to 60.

    Returns:
        str: A formatted string representing the URL finding, truncated if it exceeds the display limit.
    """
    normalized = normalize_for_matching(url)
    display = normalized if normalized is not None else url

    if len(display) <= display_limit:
        return display

    return f"{display[: display_limit - 3]}..."
