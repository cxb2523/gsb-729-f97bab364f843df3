import logging
import re

from ...i18n import get_patterns
from ...models.scans import ScanOutcome
from ...types import Action, ContentType, Severity
from ._validation import classify_characters

logger = logging.getLogger(__name__)


class InvisibleTextScanner:
    """Detects hidden Unicode characters used for steganographic injection.

    Scans for zero-width characters, bidi overrides, and Unicode format-control (Cf category) codepoints that LLMs can
    interpret but humans cannot see.

    Args:
        threshold (int): Number of invisible characters allowed before flagging. Defaults to ``3``.
        languages (list[str] | None): ISO-639-1 codes to load patterns for. Defaults to all supported languages.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when invisible text is detected.

    Attributes:
        scanner_id (str): Unique identifier for the scanner.
        scanner_name (str): Human-readable name for the scanner.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when invisible text is detected.
    """

    def __init__(
        self,
        threshold: int = 3,
        languages: list[str] | None = None,
        severity: Severity = Severity.CRITICAL,
        action: Action = Action.BLOCK,
        content_types: tuple[ContentType, ...] | list[str] | None = None,
    ) -> None:
        self.scanner_id = "invisible_text"
        self.scanner_name = "Invisible Text"
        self.severity = severity
        self.action = action
        self.content_types = tuple(content_types) if content_types is not None else None
        self._threshold = threshold
        suspicious = get_patterns(languages=languages, keys=["keyword_suspicious_keywords"])
        self._suspicious_patterns: list[re.Pattern[str]] = suspicious.get("keyword_suspicious_keywords", [])

    def scan(self, text: str) -> ScanOutcome:
        """Scan text for hidden Unicode characters used in steganographic injection.

        Args:
            text (str): Input text to analyse.

        Returns:
            ScanOutcome: Verdict containing safety flag, risk score, rationale, and optional match spans.
        """
        counts, found_chars, cleaned_chars = classify_characters(text)
        invisible_count, bidi_count, cf_count, tag_count, co_cn_count = counts

        total = invisible_count + bidi_count + cf_count + tag_count + co_cn_count

        if total == 0:
            outcome = ScanOutcome(risk_score=0.0, rationale="No invisible characters found")
            logger.debug(
                "No matches found",
                extra={
                    "operation": "scan",
                    "stage": "detection",
                    "component_kind": "scanner",
                    "outcome": "completed",
                    "match_count": len(found_chars),
                },
            )
            return outcome

        if total <= self._threshold:
            outcome = ScanOutcome(
                risk_score=0.2,
                rationale=f"Minor invisible chars ({total}): {', '.join(found_chars)}",
            )
            logger.debug(
                "%s minor matches found",
                len(found_chars),
                extra={
                    "operation": "scan",
                    "stage": "detection",
                    "component_kind": "scanner",
                    "outcome": "completed",
                    "match_count": len(found_chars),
                },
            )
            return outcome

        risk_score = min(1.0, 0.7 + total * 0.03)

        cleaned_text = "".join(cleaned_chars)
        if any(p.search(cleaned_text) for p in self._suspicious_patterns):
            risk_score = min(1.0, risk_score + 0.15)

        parts: list[str] = []
        if invisible_count:
            parts.append(f"{invisible_count} zero-width")

        if bidi_count:
            parts.append(f"{bidi_count} bidi-override")

        if cf_count:
            parts.append(f"{cf_count} format-control")

        if tag_count:
            parts.append(f"{tag_count} tag-chars")

        if co_cn_count:
            parts.append(f"{co_cn_count} private-use/unassigned")

        detail = ", ".join(parts)
        samples = ", ".join(found_chars[:5])

        outcome = ScanOutcome(
            risk_score=risk_score,
            rationale=f"Suspicious invisible characters ({total}): {detail}. Samples: {samples}",
        )
        match_count = len(found_chars)
        logger.debug(
            "%s matches found",
            match_count,
            extra={
                "operation": "scan",
                "stage": "detection",
                "component_kind": "scanner",
                "outcome": "completed",
                "match_count": match_count,
            },
        )
        return outcome
