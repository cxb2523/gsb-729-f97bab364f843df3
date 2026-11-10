from enum import StrEnum, auto

__all__ = ["Action", "ContentType", "ScannerErrorPolicy", "Severity"]


class Severity(StrEnum):
    """Severity levels for security findings.

    Higher severity scanners contribute more to the aggregated risk score.

    Attributes:
        CRITICAL: Weight ``1.0``.
        HIGH: Weight ``0.75``.
        MEDIUM: Weight ``0.5``.
        LOW: Weight ``0.25``.
    """

    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()

    @property
    def weight(self) -> float:
        """Weight derived from severity level.

        Returns:
            float: Weight factor.
        """
        return {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.75,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.25,
        }[self]


class Action(StrEnum):
    """Actions to take on security findings.

    Attributes:
        BLOCK: Block the operation entirely.
        WARN: Issue a warning but allow the operation.
        PASS: Allow the operation without warning.
    """

    BLOCK = auto()
    WARN = auto()
    PASS = auto()


class ScannerErrorPolicy(StrEnum):
    """Actions to take when a scanner raises during execution.

    Attributes:
        FAIL: Re-raise the scanner exception immediately.
        BLOCK: Continue scanning and return an unsafe verdict.
        SKIP: Continue scanning and record a sanitized skipped scanner.
    """

    FAIL = auto()
    BLOCK = auto()
    SKIP = auto()


class ContentType(StrEnum):
    """Content types for content-type routing in security scanning.

    Attributes:
        TEXT: Plain text content.
        URL: URL content.
        CODE: Code content.
        UNKNOWN: Unknown content type.
    """

    TEXT = auto()
    URL = auto()
    CODE = auto()
    UNKNOWN = auto()
