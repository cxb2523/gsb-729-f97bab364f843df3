from logging import getLogger
from typing import Protocol

from cerbia.core.exceptions import CerbIAError
from optimum.onnxruntime import ORTModelForSequenceClassification
from transformers import AutoTokenizer
from transformers import pipeline as transformers_pipeline
from transformers.utils import logging as transformers_logging

from ....models import ArtifactCoords
from ..models import ClassificationResult
from ._models import HuggingFaceClassifierAdapterConfig

__all__ = ["HuggingFaceClassifierAdapter"]

logger = getLogger(__name__)


class _HuggingFaceClassificationPipeline(Protocol):
    def __call__(self, inputs: list[str]) -> list[dict[str, object]] | list[list[dict[str, object]]]: ...


class HuggingFaceClassifierAdapter:
    """Text-classification adapter backed by transformers or Optimum ONNX.

    Args:
        model_artifact (ArtifactCoords): Descriptor artifact identifying the model to load.
        tokenizer_artifact (ArtifactCoords): Descriptor artifact identifying the tokenizer to load.
        config (HuggingFaceClassifierAdapterConfig): Validated adapter configuration.
        local_files_only (bool): If ``True``, only use locally cached assets and do not attempt to download missing
            files from HuggingFace Hub.
    """

    def __init__(
        self,
        model_artifact: ArtifactCoords,
        tokenizer_artifact: ArtifactCoords,
        config: HuggingFaceClassifierAdapterConfig,
        local_files_only: bool = True,
    ) -> None:
        transformers_logging.set_verbosity_error()
        transformers_logging.disable_progress_bar()
        try:
            tokenizer = AutoTokenizer.from_pretrained(
                tokenizer_artifact.ref,
                revision=tokenizer_artifact.revision,
                subfolder=tokenizer_artifact.subfolder,
                local_files_only=local_files_only,
                **config.tokenizer_kwargs,
            )
            logger.debug(
                "Tokenizer loaded: %s",
                tokenizer_artifact.ref,
                extra={
                    "operation": "tokenizer_load",
                    "stage": "classifier",
                    "component_kind": "classifier",
                    "outcome": "completed",
                },
            )
        except OSError as exc:
            raise CerbIAError(f"Failed to load tokenizer '{tokenizer_artifact.ref}'.") from exc

        try:
            model = ORTModelForSequenceClassification.from_pretrained(
                model_artifact.ref,
                revision=model_artifact.revision,
                subfolder=model_artifact.subfolder or "",
                local_files_only=local_files_only,
                **config.model_kwargs,
            )
        except OSError as exc:
            raise CerbIAError(f"Failed to load model '{model_artifact.ref}'.") from exc

        logger.debug(
            "Classifier model loaded: %s",
            model_artifact.ref,
            extra={
                "operation": "model_load",
                "stage": "classifier",
                "component_kind": "classifier",
                "outcome": "completed",
            },
        )

        self._pipeline: _HuggingFaceClassificationPipeline = transformers_pipeline(
            task="text-classification",
            model=model,
            tokenizer=tokenizer,
            **config.pipeline_kwargs,
        )

        transformers_logging.set_verbosity_warning()
        transformers_logging.enable_progress_bar()

    def classify(self, inputs: list[str]) -> list[list[ClassificationResult]]:
        """Classify a batch of input strings.

        Args:
            inputs (list[str]): Ordered batch of strings to score.

        Returns:
            list[list[ClassificationResult]]: Per-input classifier results in a stable batched shape.
        """
        if not inputs:
            logger.debug(
                "No input provided",
                extra={
                    "operation": "classify",
                    "stage": "classifier",
                    "component_kind": "classifier",
                    "outcome": "empty",
                },
            )
            return []

        raw_results = self._pipeline(inputs)
        expected_batch_size = len(inputs)

        if not raw_results:
            raise CerbIAError(f"Unexpected classifier output shape: expected {expected_batch_size} results, got 0")

        if len(raw_results) != expected_batch_size:
            raise CerbIAError(
                f"Unexpected classifier output shape: expected {expected_batch_size} results, got {len(raw_results)}"
            )

        results = [
            [ClassificationResult.model_validate(result[0] if isinstance(result, list) else result)]
            for result in raw_results
        ]

        logger.debug(
            "Classification completed",
            extra={
                "operation": "classify",
                "stage": "classifier",
                "component_kind": "classifier",
                "outcome": "completed",
            },
        )
        return results
