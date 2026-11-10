from typing import Protocol, runtime_checkable

from ..types import ContentType
from ._models import GateVerdict

__all__ = ["SecurityGate"]


@runtime_checkable
class SecurityGate(Protocol):
    """One entry scan, independent of the gate's internal topology."""

    def scan(self, text: str, *, content_type: ContentType = ContentType.UNKNOWN) -> GateVerdict:
        """Evaluate one input entry.

        Args:
            text (str): Text to scan.
            content_type (ContentType): Metadata used for scanner compatibility routing.

        Returns:
            GateVerdict: Verdict and collected scanner results.
        """
        ...
