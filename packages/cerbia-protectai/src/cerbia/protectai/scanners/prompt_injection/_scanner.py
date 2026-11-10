from abc import ABC, abstractmethod
from logging import getLogger

from cerbia.core.models.scans import ScanOutcome
from cerbia.core.types import Action, ContentType, Severity
from cerbia.ml.adapters.classifiers.huggingface_classifier import (
    HuggingFaceClassifierAdapter,
    HuggingFaceClassifierAdapterConfig,
)
from cerbia.ml.adapters.classifiers.models import ClassificationResult
from cerbia.ml.models import ArtifactCoords

from ...types import MatchStrategy
from ._defaults import (
    DEFAULT_MODEL_FILENAME,
    DEFAULT_MODEL_KWARGS,
    DEFAULT_MODEL_REF,
    DEFAULT_MODEL_REVISION,
    DEFAULT_MODEL_SUBFOLDER,
    DEFAULT_PIPELINE_KWARGS,
    DEFAULT_TOKENIZER_FILENAME,
    DEFAULT_TOKENIZER_KWARGS,
    DEFAULT_TOKENIZER_REF,
    DEFAULT_TOKENIZER_REVISION,
    DEFAULT_TOKENIZER_SUBFOLDER,
)
from ._text import chunk_text

logger = getLogger(__name__)


class BaseProtectAIPromptInjectionScanner(ABC):
    """Detects prompt injection using a DeBERTa-v3 classification model.

    Supports two input strategies via ``MatchStrategy``: full text or sliding-window chunks.

    Args:
        scanner_id (str): Stable scanner identifier used in results.
        scanner_name (str): Human-readable scanner name.
        match_type (MatchStrategy | str): Input strategy — ``FULL`` or ``CHUNKS``.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when injection is detected.
        content_types (tuple[ContentType, ...] | list[str] | None): Supported content types for this scanner.

    Attributes:
        scanner_id (str): Stable scanner identifier used in results.
        scanner_name (str): Human-readable scanner name.
        severity (Severity): Severity assigned to findings from this scanner.
        action (Action): Enforcement action associated with unsafe findings.
        content_types (tuple[ContentType, ...] | None): Content types accepted by the scanner, or ``None`` for any type.
    """

    def __init__(
        self,
        scanner_id: str,
        scanner_name: str,
        match_type: MatchStrategy | str = MatchStrategy.FULL,
        chunk_size: int = 256,
        chunk_overlap: int = 25,
        severity: Severity = Severity.CRITICAL,
        action: Action = Action.BLOCK,
        content_types: tuple[ContentType, ...] | list[str] | None = (ContentType.TEXT,),
    ) -> None:
        self.scanner_id = scanner_id
        self.scanner_name = scanner_name
        self.severity = severity
        self.action = action
        self.content_types = tuple(content_types) if content_types is not None else None

        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap
        self._match_type: MatchStrategy = MatchStrategy(match_type)

    @abstractmethod
    def _compute_labels(self, texts: list[str]) -> list[list[ClassificationResult]]: ...

    def scan(self, text: str) -> ScanOutcome:
        """Classify text for prompt injection.

        Args:
            text (str): Input text to analyse.

        Returns:
            ScanOutcome: Verdict containing safety flag, risk score, rationale, and optional match spans.

        Raises:
            Exception: Propagates inference-time errors raised by the underlying classifier pipeline.
        """
        if not text.strip():
            logger.debug(
                "No input provided",
                extra={
                    "operation": "scan",
                    "stage": "inference",
                    "component_kind": "scanner",
                    "outcome": "empty",
                },
            )
            return ScanOutcome(risk_score=0.0, rationale="Empty input")

        highest_score = 0.0

        inputs = self._get_inputs(text)
        results = self._compute_labels(inputs)
        result_count = len(results)

        for result in results:
            for entry in result:
                score_value = entry.score
                score = score_value if entry.label == "INJECTION" else 1 - score_value

                highest_score = max(highest_score, score)

        highest_score = round(highest_score, 4)

        if results:
            logger.debug(
                "%s matches found",
                result_count,
                extra={
                    "operation": "scan",
                    "stage": "inference",
                    "component_kind": "scanner",
                    "outcome": "matched",
                    "result_count": result_count,
                },
            )
        else:
            logger.debug(
                "No matches found",
                extra={
                    "operation": "scan",
                    "stage": "inference",
                    "component_kind": "scanner",
                    "outcome": "no_result",
                    "result_count": result_count,
                },
            )

        return ScanOutcome(risk_score=highest_score, rationale=f"Prompt injection score: {highest_score}")

    def _get_inputs(self, text: str) -> list[str]:
        if self._match_type == MatchStrategy.CHUNKS:
            return chunk_text(text, self._chunk_size, self._chunk_overlap)

        return [text]


class ProtectAIPromptInjectionScanner(BaseProtectAIPromptInjectionScanner):
    """Detects prompt injection using a DeBERTa-v3 classification model hosted locally.

    Runs a text-classification pipeline (ONNX Runtime preferred, falls back to transformers + PyTorch) and supports
    two input strategies via ``MatchStrategy``: full text or sliding-window chunks.

    Requires the ``ml`` extras group.

    Args:
        model_ref (str): Model artifact reference for the DeBERTa-v3 model.
        model_revision (str): Model artifact revision for the DeBERTa-v3 model.
        model_subfolder (str | None): Model artifact subfolder for the DeBERTa-v3 model.
        model_filename (str | None): Model artifact filename for the DeBERTa-v3 model.
        model_kwargs (dict | None): Additional keyword arguments for the model loading function.
        pipeline_kwargs (dict | None): Additional keyword arguments for the text-classification pipeline.
        tokenizer_ref (str): Tokenizer artifact reference for the DeBERTa-v3 tokenizer.
        tokenizer_revision (str): Tokenizer artifact revision for the DeBERTa-v3 tokenizers.
        tokenizer_subfolder (str | None): Tokenizer artifact subfolder for the DeBERTa-v3 tokenizer.
        tokenizer_filename (str | None): Tokenizer artifact filename for the DeBERTa-v3 tokenizer.
        tokenizer_kwargs (dict | None): Additional keyword arguments for the tokenizer loading function.
        local_files_only (bool): Whether to restrict artifact loading to local cache only.
        chunk_size (int): Size of sliding-window chunks when ``match_type`` is ``CHUNKS``.
        chunk_overlap (int): Overlap size of sliding-window chunks when ``match_type`` is ``CHUNKS``.
        match_type (MatchStrategy | str): Input strategy — ``FULL`` or ``CHUNKS``.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when injection is detected.
        content_types (tuple[ContentType, ...] | list[str] | None): Supported content types for this scanner.

    Attributes:
        scanner_id (str): Stable scanner identifier used in results.
        scanner_name (str): Human-readable scanner name.
        severity (Severity): Severity assigned to findings from this scanner.
        action (Action): Enforcement action associated with unsafe findings.
        content_types (tuple[ContentType, ...] | None): Content types accepted by the scanner, or ``None`` for any type.
    """

    def __init__(
        self,
        model_ref: str = DEFAULT_MODEL_REF,
        model_revision: str = DEFAULT_MODEL_REVISION,
        model_subfolder: str | None = DEFAULT_MODEL_SUBFOLDER,
        model_filename: str | None = DEFAULT_MODEL_FILENAME,
        model_kwargs: dict | None = None,
        pipeline_kwargs: dict | None = None,
        tokenizer_ref: str = DEFAULT_TOKENIZER_REF,
        tokenizer_revision: str = DEFAULT_TOKENIZER_REVISION,
        tokenizer_subfolder: str | None = DEFAULT_TOKENIZER_SUBFOLDER,
        tokenizer_filename: str | None = DEFAULT_TOKENIZER_FILENAME,
        tokenizer_kwargs: dict | None = None,
        local_files_only: bool = True,
        chunk_size: int = 256,
        chunk_overlap: int = 25,
        match_type: MatchStrategy | str = MatchStrategy.FULL,
        severity: Severity = Severity.CRITICAL,
        action: Action = Action.BLOCK,
        content_types: tuple[ContentType, ...] | list[str] | None = (ContentType.TEXT,),
    ) -> None:
        super().__init__(
            scanner_id="protectai_prompt_injection",
            scanner_name="ProtectAI Prompt Injection",
            match_type=match_type,
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            severity=severity,
            action=action,
            content_types=content_types,
        )

        adapter_config = HuggingFaceClassifierAdapterConfig(
            pipeline_kwargs=dict(pipeline_kwargs or DEFAULT_PIPELINE_KWARGS),
            tokenizer_kwargs=dict(tokenizer_kwargs or DEFAULT_TOKENIZER_KWARGS),
            model_kwargs=dict(model_kwargs or DEFAULT_MODEL_KWARGS),
        )

        self._adapter = HuggingFaceClassifierAdapter(
            model_artifact=ArtifactCoords(
                ref=model_ref, revision=model_revision, subfolder=model_subfolder, filename=model_filename
            ),
            tokenizer_artifact=ArtifactCoords(
                ref=tokenizer_ref,
                revision=tokenizer_revision,
                subfolder=tokenizer_subfolder,
                filename=tokenizer_filename,
            ),
            config=adapter_config,
            local_files_only=local_files_only,
        )

    def _compute_labels(self, texts: list[str]) -> list[list[ClassificationResult]]:
        return self._adapter.classify(texts)
