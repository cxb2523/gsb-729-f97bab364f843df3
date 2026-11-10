from pathlib import Path

import pytest
from cerbia.ml.artifacts.exceptions import ArtifactFetchError
from cerbia.ml.artifacts.huggingface_hub import HuggingFaceHubSource
from cerbia.ml.models import ArtifactCoords
from huggingface_hub.errors import HfHubHTTPError

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("subfolder", "filename", "expected_patterns"),
    [
        (None, None, None),
        ("model", None, ["model/**"]),
        (None, "model.onnx", ["model.onnx"]),
        ("model", "model.onnx", ["model/model.onnx"]),
    ],
)
def test_huggingface_hub_source_builds_selective_download_patterns(
    subfolder: str | None, filename: str | None, expected_patterns: list[str] | None
) -> None:
    artifact = ArtifactCoords(ref="org/model", revision="a" * 40, subfolder=subfolder, filename=filename)

    result = HuggingFaceHubSource._allow_patterns(artifact)

    assert result == expected_patterns


def test_huggingface_hub_source_fetches_snapshot_writes_revision_reference_and_returns_artifact_path(
    mocker, tmp_path: Path
) -> None:
    artifact = ArtifactCoords(ref="org/model", revision="a" * 40, subfolder="onnx", filename="model.onnx")
    snapshot_path = tmp_path / "snapshot"
    snapshot_download = mocker.patch(
        "cerbia.ml.artifacts.huggingface_hub.snapshot_download",
        return_value=str(snapshot_path),
    )
    source = HuggingFaceHubSource(cache_dir=tmp_path / "cache")

    result = source.fetch(artifact)

    assert result == snapshot_path / "onnx" / "model.onnx"
    snapshot_download.assert_called_once_with(
        repo_id="org/model",
        revision="a" * 40,
        cache_dir=str(tmp_path / "cache"),
        allow_patterns=["onnx/model.onnx"],
    )
    reference_path = tmp_path / "cache" / "models--org--model" / "refs" / ("a" * 40)
    assert reference_path.read_text() == "a" * 40


def test_huggingface_hub_source_uses_default_cache_for_fetch_and_availability(mocker, tmp_path: Path) -> None:
    artifact = ArtifactCoords(ref="org/model", revision="a" * 40, subfolder="onnx", filename="model.onnx")
    snapshot_path = tmp_path / "downloaded-snapshot"
    snapshot_download = mocker.patch(
        "cerbia.ml.artifacts.huggingface_hub.snapshot_download",
        return_value=str(snapshot_path),
    )
    mocker.patch("cerbia.ml.artifacts.huggingface_hub.HF_HUB_CACHE", str(tmp_path / "default-cache"))
    source = HuggingFaceHubSource()

    result = source.fetch(artifact)

    assert result == snapshot_path / "onnx" / "model.onnx"
    assert snapshot_download.call_args.kwargs["cache_dir"] is None
    reference_path = tmp_path / "default-cache" / "models--org--model" / "refs" / ("a" * 40)
    assert reference_path.read_text() == "a" * 40

    cached_artifact_path = (
        tmp_path / "default-cache" / "models--org--model" / "snapshots" / ("a" * 40) / "onnx" / "model.onnx"
    )
    cached_artifact_path.parent.mkdir(parents=True)
    cached_artifact_path.touch()

    assert source.is_available(artifact) is True


def test_huggingface_hub_source_reports_availability_for_requested_artifact(tmp_path: Path) -> None:
    artifact = ArtifactCoords(ref="org/model", revision="a" * 40, filename="model.onnx")
    source = HuggingFaceHubSource(cache_dir=tmp_path)
    artifact_path = tmp_path / "models--org--model" / "snapshots" / ("a" * 40) / "model.onnx"

    assert source.is_available(artifact) is False

    artifact_path.parent.mkdir(parents=True)
    artifact_path.touch()

    assert source.is_available(artifact) is True


def test_huggingface_hub_source_raises_artifact_fetch_error_when_download_fails(mocker, tmp_path: Path) -> None:
    artifact = ArtifactCoords(ref="org/model", revision="a" * 40)
    mocker.patch(
        "cerbia.ml.artifacts.huggingface_hub.snapshot_download",
        side_effect=HfHubHTTPError("Request failed"),
    )
    source = HuggingFaceHubSource(cache_dir=tmp_path)

    with pytest.raises(ArtifactFetchError) as exc_info:
        source.fetch(artifact)

    assert exc_info.value.artifact == artifact
    assert exc_info.value.source == "huggingface-hub"
