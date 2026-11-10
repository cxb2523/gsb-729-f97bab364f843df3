from pydantic import BaseModel, Field

from ..types import Action, Severity

__all__ = ["Finding", "MatchSpan", "ScanOutcome", "SkippedScanner"]


class MatchSpan(BaseModel):
    """Location of a single match detected by a scanner.

    Attributes:
        start (int): Start offset in the scanned text (inclusive).
        end (int): End offset in the scanned text (exclusive).
    """

    start: int
    end: int


class ScanOutcome(BaseModel):
    """Result returned by a scanner's ``scan()`` method.

    Attributes:
        risk_score (float): How likely the text contains a threat, ``0.0`` (safe) to ``1.0`` (dangerous).
        rationale (str): Human-readable explanation.
        matches (list[MatchSpan]): Spans of matched content in the scanned text.
    """

    risk_score: float = Field(ge=0.0, le=1.0)
    rationale: str
    matches: list[MatchSpan] = Field(default_factory=list)


class Finding(BaseModel):
    """Single scanner result produced during a gate scan.

    Attributes:
        scanner_id (str): Identifier of the scanner that produced this finding.
        scanner_name (str): Human-readable scanner name.
        risk_score (float): How likely the text contains a threat, ``0.0`` (safe) to ``1.0`` (dangerous).
        severity (Severity): Severity level inherited from the scanner.
        action (Action): Action to take for this finding (inherited from the scanner).
        rationale (str): Human-readable explanation.
        matches (list[MatchSpan]): Spans of matched content, forwarded from the scanner's ``ScanOutcome``.
        stage (str | None): Owning cascade stage ID; None for a simple gate and omitted from serialization when None.
    """

    scanner_id: str
    scanner_name: str
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: Severity
    action: Action
    rationale: str
    matches: list[MatchSpan] = Field(default_factory=list)
    stage: str | None = Field(default=None, exclude_if=lambda value: value is None)


class SkippedScanner(BaseModel):
    """A scanner skipped during a gate scan due to content-type routing or the explicit ``"skip"`` on error policy.

    Attributes:
        scanner_id (str): Identifier of the skipped scanner.
        scanner_name (str): Human-readable scanner name.
        reason (str): Why the scanner was skipped (e.g. content-type mismatch).
    """

    scanner_id: str
    scanner_name: str
    reason: str
