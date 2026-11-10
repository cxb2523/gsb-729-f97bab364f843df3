from logging import getLogger
from pathlib import Path

from huggingface_hub import snapshot_download
from huggingface_hub.constants import HF_HUB_CACHE
from huggingface_hub.errors import HfHubHTTPError

from ..models import ArtifactCoords
from .exceptions import ArtifactFetchError

__all__ = ["HuggingFaceHubSource"]

logger = getLogger(__name__)


class HuggingFaceHubSource:
    """Artifact source backed by the local HuggingFace Hub cache.

    Args:
        cache_dir (Path | None): Optional custom HuggingFace cache directory. When omitted, the default ``HF_HUB_CACHE``
            location is used.

    """

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._cache_dir = Path(cache_dir) if cache_dir is not None else None

    def fetch(self, artifact: ArtifactCoords) -> Path:
        """Download one artifact snapshot and return its resolved local path.

        Args:
            artifact (ArtifactCoords): Coordinates of the artifact to materialize from the local HuggingFace Hub cache.

        Returns:
            Path: Local path to the requested artifact.

        Raises:
            ArtifactFetchError: If the HuggingFace Hub client cannot download or resolve the requested artifact.
        """
        try:
            snapshot_path = Path(
                snapshot_download(
                    repo_id=artifact.ref,
                    revision=artifact.revision,
                    cache_dir=str(self._cache_dir) if self._cache_dir is not None else None,
                    allow_patterns=self._allow_patterns(artifact),
                )
            )
        except HfHubHTTPError as exc:
            raise ArtifactFetchError(artifact=artifact, source="huggingface-hub", message=str(exc)) from exc

        effective_cache = self._cache_dir if self._cache_dir is not None else Path(HF_HUB_CACHE)
        refs_dir = self._repo_cache_dir(artifact, effective_cache) / "refs"
        refs_dir.mkdir(parents=True, exist_ok=True)

        (refs_dir / artifact.revision).write_text(artifact.revision, encoding="utf-8")

        artifact_path = self._artifact_path(snapshot_path, artifact)
        logger.debug(
            "Artifact fetched",
            extra={
                "operation": "fetch",
                "stage": "artifact",
                "component_kind": "artifact_source",
                "outcome": "completed",
            },
        )
        return artifact_path

    def is_available(self, artifact: ArtifactCoords) -> bool:
        """Return whether the artifact already exists in the local HF cache.

        Args:
            artifact (ArtifactCoords): Coordinates of the artifact to probe.

        Returns:
            bool: ``True`` when the requested artifact path already exists inside the effective cache directory.
        """
        effective_cache = self._cache_dir if self._cache_dir is not None else Path(HF_HUB_CACHE)
        snapshot_path = self._repo_cache_dir(artifact, effective_cache) / "snapshots" / artifact.revision

        return self._artifact_path(snapshot_path, artifact).exists()

    @staticmethod
    def _allow_patterns(artifact: ArtifactCoords) -> list[str] | None:
        """Build selective download patterns for a specific artifact.

        Args:
            artifact (ArtifactCoords): Coordinates describing an optional subfolder and/or file.

        Returns:
            list[str] | None: Allow-pattern list for ``snapshot_download`` or
                ``None`` when the full snapshot is required.
        """
        if artifact.subfolder and artifact.filename:
            return [f"{artifact.subfolder}/{artifact.filename}"]

        if artifact.subfolder:
            return [f"{artifact.subfolder}/**"]

        if artifact.filename:
            return [artifact.filename]

        return None

    @staticmethod
    def _artifact_path(snapshot_path: Path, artifact: ArtifactCoords) -> Path:
        """Resolve the concrete artifact path beneath a snapshot directory.

        Args:
            snapshot_path (Path): Root path returned by the HuggingFace cache.
            artifact (ArtifactCoords): Coordinates describing any nested subfolder or filename.

        Returns:
            Path: Filesystem path for the requested artifact.
        """
        artifact_path = snapshot_path
        if artifact.subfolder is not None:
            artifact_path /= artifact.subfolder

        if artifact.filename is not None:
            artifact_path /= artifact.filename

        return artifact_path

    @staticmethod
    def _repo_cache_dir(artifact: ArtifactCoords, cache_dir: Path) -> Path:
        """Return the cache directory used for a repository-backed artifact.

        Args:
            artifact (ArtifactCoords): Artifact whose repository cache path should be derived.
            cache_dir (Path): Effective HuggingFace cache root.

        Returns:
            Path: Repository-specific cache directory under ``cache_dir``.
        """
        return cache_dir / f"models--{artifact.ref.replace('/', '--')}"
