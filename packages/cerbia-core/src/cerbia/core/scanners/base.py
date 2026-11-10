from typing import Protocol, runtime_checkable

from ..models.scans import ScanOutcome
from ..types import Action, ContentType, Severity


@runtime_checkable
class Scanner(Protocol):
    """Contract that every security scanner must satisfy.

    All scanner-specific configuration belongs in the constructor, not in the scan call. This keeps the scan interface
    uniform across all scanners.

    Attributes:
        scanner_id (str): Unique machine-readable identifier (e.g. ``"prompt_injection"``).
        scanner_name (str): Human-readable display name (e.g. ``"Prompt Injection"``).
        severity (Severity): Default severity level for findings produced by this scanner.
        action (Action): Default action to take when this scanner flags content.
        content_types (tuple[ContentType, ...] | None): Content types this scanner supports, or ``None`` for all types.
    """

    scanner_id: str
    scanner_name: str
    severity: Severity
    action: Action
    content_types: tuple[ContentType, ...] | None

    def scan(self, text: str) -> ScanOutcome:
        """Analyze a text fragment and return a safety verdict.

        Args:
            text (str): The raw text to scan. Can be a user prompt (Gate 0)or an LLM response (Gate 3).

        Returns:
            ScanOutcome: Verdict containing safety flag, risk score, rationale, and optional match spans.
        """
        ...
