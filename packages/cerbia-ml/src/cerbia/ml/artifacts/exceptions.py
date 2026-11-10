from cerbia.core.exceptions import CerbIAError

from ..models import ArtifactCoords

__all__ = ["ArtifactFetchError"]


class ArtifactFetchError(CerbIAError):
    """Failure raised when an artifact source cannot materialize an artifact.

    Args:
        artifact (ArtifactCoords): Coordinates of the artifact that could not be fetched.
        source (str): Stable identifier of the artifact source implementation.
        message (str | None): Optional explicit error message. When omitted, a default message derived from ``artifact``
            and ``source`` is used.

    Attributes:
        artifact (ArtifactCoords): Coordinates of the artifact whose retrieval failed.
        source (str): Source identifier that reported the fetch failure.
    """

    def __init__(self, artifact: ArtifactCoords, source: str, message: str | None = None) -> None:
        self.artifact = artifact
        self.source = source

        super().__init__(message or f"Failed to fetch artifact {artifact!r} from source {source!r}")
