from pathlib import Path
from typing import Protocol, runtime_checkable

from ..models import ArtifactCoords

__all__ = ["ArtifactSource"]


@runtime_checkable
class ArtifactSource(Protocol):
    """Runtime contract for fetching immutable ML artifacts.

    Implementations are expected to resolve pinned artifact coordinates into a local filesystem path and to expose a
    cheap availability probe for the same coordinates.
    """

    def fetch(self, artifact: ArtifactCoords) -> Path:
        """Materialize an artifact locally and return its resolved path.

        Args:
            artifact (ArtifactCoords): Exact coordinates of the artifact to retrieve.

        Returns:
            Path: Local filesystem path that callers can pass to model-loading code.
        """
        ...

    def is_available(self, artifact: ArtifactCoords) -> bool:
        """Report whether the artifact is already available to this source.

        Args:
            artifact (ArtifactCoords): Exact coordinates of the artifact to check.

        Returns:
            bool: ``True`` when ``fetch`` can resolve the artifact from the source's current local state without
                additional downloads.
        """
        ...
