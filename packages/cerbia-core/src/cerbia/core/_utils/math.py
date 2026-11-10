import math
from collections.abc import Iterable


def shannon_entropy(counts: Iterable[int], total: int) -> float:
    """Shannon entropy from pre-computed frequency counts.

    Args:
        counts (Iterable[int]): Frequency of each observed symbol.
        total (int): Sum of all counts (total observations).

    Returns:
        float: Entropy in bits. Zero when *total* is zero.
    """
    if total == 0:
        return 0.0

    return -sum((c / total) * math.log2(c / total) for c in counts if c > 0)
