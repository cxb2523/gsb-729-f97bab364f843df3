from typing import Protocol

from ...apis.decisions import DecisionsResponse
from ...models.scans import ScanOutcome


class DecisionsEvaluator(Protocol):
    """Application contract for interpreting a Decisions API response."""

    def __call__(self, response: DecisionsResponse, /) -> ScanOutcome:
        """Evaluate a typed API response and return its scanner outcome.

        Args:
            response (DecisionsResponse): Typed Decisions response to interpret.

        Returns:
            ScanOutcome: The application-defined outcome for the response.
        """
        ...
