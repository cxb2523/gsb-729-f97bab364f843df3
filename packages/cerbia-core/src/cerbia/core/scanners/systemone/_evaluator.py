from typing import Protocol

from ...apis.systemone import SystemOneResponse
from ...models.scans import ScanOutcome


class SystemOneEvaluator(Protocol):
    """Application contract for interpreting a System One API response."""

    def __call__(self, response: SystemOneResponse, /) -> ScanOutcome:
        """Evaluate a typed API response and return its scanner outcome.

        Args:
            response (SystemOneResponse): Typed System One response to interpret.

        Returns:
            ScanOutcome: The application-defined outcome for the response.
        """
        ...
