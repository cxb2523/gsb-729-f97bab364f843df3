from ..._utils.math import shannon_entropy


def charset_entropy(data: str, charset: frozenset[str]) -> float:
    """Computes the Shannon entropy of a string based on a given character set.

    Args:
        data (str): The input string to analyze.
        charset (frozenset[str]): The character set to consider for entropy calculation.

    Returns:
        float: The calculated Shannon entropy of the input string.
    """
    if not data:
        return 0.0

    freq: dict[str, int] = {}
    for c in data:
        if c in charset:
            freq[c] = freq.get(c, 0) + 1

    total = sum(freq.values())
    return shannon_entropy(freq.values(), total)
