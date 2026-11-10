from collections import Counter
from collections.abc import Generator
from contextlib import AbstractContextManager, contextmanager
from contextvars import ContextVar

from ._types import RejectionReason

_ACTIVE_REJECTIONS: ContextVar[Counter[RejectionReason] | None] = ContextVar(
    "speculative_decoding_rejections", default=None
)


@contextmanager
def _capture_rejections() -> Generator[Counter[RejectionReason], None, None]:
    """Bind a fresh rejection-reason counter to the current speculative decode pass.

    Yields:
        Counter[RejectionReason]: Counter populated with rejection reasons recorded during the active pass.
    """
    rejections: Counter[RejectionReason] = Counter()
    token = _ACTIVE_REJECTIONS.set(rejections)

    try:
        yield rejections

    finally:
        _ACTIVE_REJECTIONS.reset(token)


def capture_rejections() -> AbstractContextManager[Counter[RejectionReason]]:
    """Create a context manager for isolated rejection-reason accounting.

    Returns:
        AbstractContextManager[Counter[RejectionReason]]: Context manager that binds a fresh per-pass rejection counter.
    """
    return _capture_rejections()


def record_rejection(*, reason: RejectionReason | None) -> None:
    """Increment the active rejection counter for a concrete reason.

    Args:
        reason (RejectionReason | None): High-level rejection reason to record.
    """
    if reason is None:
        return

    rejections = _ACTIVE_REJECTIONS.get()
    if rejections is not None:
        rejections[reason] += 1
