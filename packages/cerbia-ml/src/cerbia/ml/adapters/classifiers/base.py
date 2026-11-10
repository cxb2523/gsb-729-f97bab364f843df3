from typing import Protocol

from .models import ClassificationResult

__all__ = ["ClassifierAdapter"]


class ClassifierAdapter(Protocol):
    """Contract for ML classification runtimes."""

    def classify(self, inputs: list[str]) -> list[list[ClassificationResult]]:
        """Classify a batch of input strings.

        Args:
            inputs (list[str]): Ordered batch of strings to classify.

        Returns:
            list[list[ClassificationResult]]: Per-input classifier results.
        """
        ...
