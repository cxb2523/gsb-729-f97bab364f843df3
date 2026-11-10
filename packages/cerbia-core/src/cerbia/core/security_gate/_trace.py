from enum import StrEnum, auto

__all__ = ["FailureCode", "StageDecision"]


class StageDecision(StrEnum):
    ALLOW = auto()
    BLOCK = auto()
    DEFER = auto()


class FailureCode(StrEnum):
    """Operational fault categories used in cascade summaries.

    Attributes:
        SCANNER_ERROR (FailureCode): Scanner invocation or finding construction failed.
        UNSUPPORTED_CONTENT (FailureCode): Scanner is incompatible with the input content type.
        MISSING_EVIDENCE (FailureCode): Aggregator is missing or the cascade produced no terminal decision.
        INVALID_AGGREGATE (FailureCode): Aggregate is not a finite score in [0.0, 1.0].
        AGGREGATOR_ERROR (FailureCode): Aggregator invocation failed.
    """

    SCANNER_ERROR = auto()
    UNSUPPORTED_CONTENT = auto()
    MISSING_EVIDENCE = auto()
    INVALID_AGGREGATE = auto()
    AGGREGATOR_ERROR = auto()
