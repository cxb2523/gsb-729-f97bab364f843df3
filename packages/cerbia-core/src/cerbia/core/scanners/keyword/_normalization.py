import unicodedata


def normalize_unicode(text: str) -> str:
    """Normalize Unicode text to a consistent form for reliable pattern matching.

    Applies NFKC normalization to standardize character representations, then removes all combining marks (e.g.,
    accents) to further reduce obfuscation opportunities.

    Args:
        text (str): Input string to normalize.

    Returns:
        str: Normalized string with consistent Unicode representation and no combining marks.
    """
    nfkc = unicodedata.normalize("NFKC", text)
    return "".join(c for c in unicodedata.normalize("NFD", nfkc) if unicodedata.category(c) != "Mn")
