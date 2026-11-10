import pytest
from cerbia.core.exceptions import CerbIAError
from cerbia.ml.adapters.classifiers.huggingface_classifier._classifier import HuggingFaceClassifierAdapter
from cerbia.ml.adapters.classifiers.huggingface_classifier._models import HuggingFaceClassifierAdapterConfig
from cerbia.ml.models import ArtifactCoords
from pydantic import ValidationError

pytestmark = pytest.mark.unit


def test_huggingface_classifier_adapter_configures_pipeline_dependencies(mocker) -> None:
    model_artifact = ArtifactCoords(ref="org/model", revision="a" * 40, subfolder="onnx-model")
    tokenizer_artifact = ArtifactCoords(ref="org/tokenizer", revision="b" * 40, subfolder="tokenizer-files")
    config = HuggingFaceClassifierAdapterConfig(
        tokenizer_kwargs={"use_fast": False},
        model_kwargs={"provider": "CPUExecutionProvider"},
        pipeline_kwargs={"top_k": None},
    )
    tokenizer = mocker.Mock()
    model = mocker.Mock()
    pipeline = mocker.Mock()
    load_tokenizer = mocker.patch(
        "cerbia.ml.adapters.classifiers.huggingface_classifier._classifier.AutoTokenizer.from_pretrained",
        return_value=tokenizer,
    )
    load_model = mocker.patch(
        "cerbia.ml.adapters.classifiers.huggingface_classifier._classifier.ORTModelForSequenceClassification.from_pretrained",
        return_value=model,
    )
    build_pipeline = mocker.patch(
        "cerbia.ml.adapters.classifiers.huggingface_classifier._classifier.transformers_pipeline",
        return_value=pipeline,
    )

    adapter = HuggingFaceClassifierAdapter(model_artifact, tokenizer_artifact, config, local_files_only=False)

    assert adapter._pipeline is pipeline
    load_tokenizer.assert_called_once_with(
        "org/tokenizer",
        revision="b" * 40,
        subfolder="tokenizer-files",
        local_files_only=False,
        use_fast=False,
    )
    load_model.assert_called_once_with(
        "org/model",
        revision="a" * 40,
        subfolder="onnx-model",
        local_files_only=False,
        provider="CPUExecutionProvider",
    )
    build_pipeline.assert_called_once_with(task="text-classification", model=model, tokenizer=tokenizer, top_k=None)


def test_huggingface_classifier_adapter_raises_cerbia_error_when_tokenizer_loading_fails(mocker) -> None:
    model_artifact = ArtifactCoords(ref="org/model", revision="a" * 40)
    tokenizer_artifact = ArtifactCoords(ref="org/tokenizer", revision="b" * 40)
    original_error = OSError("tokenizer unavailable")
    mocker.patch(
        "cerbia.ml.adapters.classifiers.huggingface_classifier._classifier.AutoTokenizer.from_pretrained",
        side_effect=original_error,
    )

    with pytest.raises(CerbIAError, match="Failed to load tokenizer 'org/tokenizer'"):
        HuggingFaceClassifierAdapter(
            model_artifact,
            tokenizer_artifact,
            HuggingFaceClassifierAdapterConfig(),
            local_files_only=False,
        )


def test_huggingface_classifier_adapter_raises_cerbia_error_when_model_loading_fails(mocker) -> None:
    artifact = ArtifactCoords(ref="org/model", revision="a" * 40)
    original_error = OSError("model unavailable")
    mocker.patch(
        "cerbia.ml.adapters.classifiers.huggingface_classifier._classifier.AutoTokenizer.from_pretrained",
        return_value=mocker.Mock(),
    )
    mocker.patch(
        "cerbia.ml.adapters.classifiers.huggingface_classifier._classifier.ORTModelForSequenceClassification.from_pretrained",
        side_effect=original_error,
    )

    with pytest.raises(CerbIAError, match="Failed to load model 'org/model'"):
        HuggingFaceClassifierAdapter(artifact, artifact, HuggingFaceClassifierAdapterConfig(), local_files_only=False)


def test_huggingface_classifier_adapter_returns_empty_result_when_inputs_are_empty() -> None:
    adapter = object.__new__(HuggingFaceClassifierAdapter)
    adapter._pipeline = pytest.fail

    assert adapter.classify([]) == []


@pytest.mark.parametrize(
    ("inputs", "raw_results", "expected"),
    [
        (["first"], [{"label": "SAFE", "score": 0.9}], [[("SAFE", 0.9)]]),
        (
            ["first", "second"],
            [
                {"label": "SAFE", "score": 0.9},
                {"label": "UNSAFE", "score": 0.8},
            ],
            [[("SAFE", 0.9)], [("UNSAFE", 0.8)]],
        ),
        (
            ["first", "second"],
            [
                [{"label": "SAFE", "score": 0.9}, {"label": "IGNORED", "score": 0.1}],
                [{"label": "UNSAFE", "score": 0.8}, {"label": "IGNORED", "score": 0.2}],
            ],
            [[("SAFE", 0.9)], [("UNSAFE", 0.8)]],
        ),
    ],
)
def test_huggingface_classifier_adapter_normalizes_pipeline_results(mocker, inputs, raw_results, expected) -> None:
    adapter = object.__new__(HuggingFaceClassifierAdapter)
    adapter._pipeline = mocker.Mock(return_value=raw_results)

    result = adapter.classify(inputs)

    assert [[(item.label, item.score) for item in batch] for batch in result] == expected


def test_huggingface_classifier_adapter_raises_cerbia_error_when_pipeline_batch_size_is_unexpected(mocker) -> None:
    adapter = object.__new__(HuggingFaceClassifierAdapter)
    adapter._pipeline = mocker.Mock(return_value=[{"label": "SAFE", "score": 0.9}])

    with pytest.raises(CerbIAError, match="expected 2 results, got 1"):
        adapter.classify(["first", "second"])


def test_huggingface_classifier_adapter_rejects_empty_pipeline_output_for_nonempty_inputs(mocker) -> None:
    adapter = object.__new__(HuggingFaceClassifierAdapter)
    adapter._pipeline = mocker.Mock(return_value=[])

    with pytest.raises(CerbIAError, match="expected 1 results, got 0"):
        adapter.classify(["first"])


def test_huggingface_classifier_adapter_rejects_malformed_pipeline_results(mocker) -> None:
    adapter = object.__new__(HuggingFaceClassifierAdapter)
    adapter._pipeline = mocker.Mock(return_value=[{"score": 0.9}])

    with pytest.raises(ValidationError, match="label"):
        adapter.classify(["first"])
