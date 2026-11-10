from ..models.scans import Finding
from ..types import Action


def build_rationale(is_safe: bool, failed: list[Finding], blocked: list[Finding]) -> str:
    """Build a human-readable rationale summarizing the gate verdict.

    Args:
        is_safe (bool): Whether the gate passed.
        failed (list[Finding]): All findings that flagged the content (``risk_score > 0.0``).
        blocked (list[Finding]): Subset of *failed* with ``action=BLOCK``.

    Returns:
        str: A one-line summary suitable for display or logging.
    """
    if is_safe:
        warned = [f for f in failed if f.action == Action.WARN]
        if warned:
            scanner_names = ", ".join(f.scanner_name for f in warned)
            return f"Passed with warnings: {scanner_names}"

        return "All scanners passed"

    if len(blocked) == 1:
        return f"{blocked[0].scanner_name}: {blocked[0].rationale}"

    scanner_names = ", ".join(f.scanner_name for f in blocked)
    return f"{len(blocked)} scanners blocked: {scanner_names}"
