import pytest
from cerbia.ml.artifacts.exceptions import ArtifactFetchError
from cerbia.ml.models import ArtifactCoords

pytestmark = pytest.mark.unit


def test_artifact_fetch_error_preserves_artifact_source_and_default_message() -> None:
    artifact = ArtifactCoords(ref="org/model", revision="a" * 40)

    error = ArtifactFetchError(artifact=artifact, source="huggingface-hub")

    assert error.artifact == artifact
    assert error.source == "huggingface-hub"
    expected_message = (
        "Failed to fetch artifact ArtifactCoords(ref='org/model', revision='"
        + "a" * 40
        + "', subfolder=None, filename=None) from source 'huggingface-hub'"
    )
    assert str(error) == expected_message


def test_artifact_fetch_error_uses_explicit_message_when_provided() -> None:
    artifact = ArtifactCoords(ref="org/model", revision="a" * 40)

    error = ArtifactFetchError(artifact=artifact, source="huggingface-hub", message="Download failed")

    assert str(error) == "Download failed"
