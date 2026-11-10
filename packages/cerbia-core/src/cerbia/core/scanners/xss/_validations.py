def in_safe_range(pos: int, ranges: list[tuple[int, int]]) -> bool:
    """Check if a position is within any of the given safe ranges.

    Args:
        pos (int): Position to check.
        ranges (list[tuple[int, int]]): List of safe ranges as (start, end) tuples.

    Returns:
        bool: True if the position is within a safe range, False otherwise.
    """
    return any(start <= pos <= end for start, end in ranges)
