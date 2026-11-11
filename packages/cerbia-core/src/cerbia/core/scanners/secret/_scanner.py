import logging
import re

from ...models.scans import MatchSpan, ScanOutcome
from ...types import Action, ContentType, Severity
from ._constants import (
    BASE64_CHARS,
    BASE64_ENTROPY_THRESHOLD,
    ENTROPY_MIN_LENGTH,
    HEX_CHARS,
    HEX_ENTROPY_THRESHOLD,
    HIGH_ENTROPY_PATTERN,
)
from ._defaults import DEFAULT_SECRET_PATTERNS
from ._math import charset_entropy

logger = logging.getLogger(__name__)


class SecretScanner:
    """Detects leaked API keys, tokens, credentials, and private keys.

    Args:
        patterns (list[tuple[str, str]] | None): List of ``(name, regex)`` pairs to use for secret detection. If not
            provided, a default set of patterns will be used.
        extra_patterns (list[tuple[str, str]] | None): Additional ``(name, regex)`` pairs to append to the pattern set.
        entropy_detection (bool): Enable Shannon entropy fallback for unknown secrets.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when secrets are detected.

    Attributes:
        scanner_id (str): Unique identifier for the scanner.
        scanner_name (str): Human-readable name for the scanner.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when secrets are detected.
        content_types (tuple[ContentType, ...] | None): Supported content types for scanning
    """

    def __init__(
        self,
        patterns: list[tuple[str, str, float]] | None = None,
        extra_patterns: list[tuple[str, str, float]] | None = None,
        entropy_detection: bool = False,
        severity: Severity = Severity.CRITICAL,
        action: Action = Action.BLOCK,
        content_types: tuple[ContentType, ...] | list[str] | None = (
            ContentType.TEXT,
            ContentType.URL,
            ContentType.CODE,
        ),
    ) -> None:
        self.scanner_id = "secrets"
        self.scanner_name = "Secrets"
        self.severity = severity
        self.action = action
        self.content_types = tuple(content_types) if content_types is not None else None
        self._entropy_detection = entropy_detection

        self._patterns: list[tuple[str, re.Pattern[str], float]] = []

        if patterns:
            self._patterns = [(name, re.compile(regex), risk_score) for name, regex, risk_score in patterns]
        else:
            self._patterns = DEFAULT_SECRET_PATTERNS.copy()

        if extra_patterns:
            for name, regex, risk_score in extra_patterns:
                self._patterns.append((name, re.compile(regex), risk_score))

    def scan(self, text: str) -> ScanOutcome:
        """Scan text for leaked API keys, tokens, and credentials.

        Args:
            text (str): Input text to analyse.

        Returns:
            ScanOutcome: Verdict with match spans for detected secrets.
        """
        matches, hits = self._scan_patterns(text)

        if self._entropy_detection:
            entropy_matches, entropy_hits = self._scan_entropy(text, matches)
            matches.extend(entropy_matches)
            hits.extend(entropy_hits)

        if not hits:
            outcome = ScanOutcome(risk_score=0.0, rationale="No secrets detected")
            logger.debug(
                "No matches found",
                extra={
                    "operation": "scan",
                    "stage": "detection",
                    "component_kind": "scanner",
                    "outcome": "completed",
                    "match_count": len(hits),
                },
            )
            return outcome

        max_risk_score = max(h[1] for h in hits)
        details = "; ".join(name for name, _ in hits[:5])

        outcome = ScanOutcome(
            risk_score=max_risk_score,
            rationale=f"Secret(s) detected ({len(hits)}): {details}",
            matches=matches,
        )
        match_count = len(hits)
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

    def _scan_patterns(self, text: str) -> tuple[list[MatchSpan], list[tuple[str, float]]]:
        hits: list[tuple[str, float]] = []
        matches: list[MatchSpan] = []

        for name, pattern, risk_score in self._patterns:
            for match in pattern.finditer(text):
                hits.append((name, risk_score))
                matches.append(MatchSpan(start=match.start(), end=match.end()))

        return matches, hits

    def _scan_entropy(
        self, text: str, pattern_matches: list[MatchSpan]
    ) -> tuple[list[MatchSpan], list[tuple[str, float]]]:
        hits: list[tuple[str, float]] = []
        matches: list[MatchSpan] = []
        sorted_spans = sorted(pattern_matches, key=lambda span: span.start)
        span_index = 0
        max_end = -1

        for match in HIGH_ENTROPY_PATTERN.finditer(text):
            candidate = match.group()
            if len(candidate) < ENTROPY_MIN_LENGTH:
                continue

            while span_index < len(sorted_spans) and sorted_spans[span_index].start <= match.start():
                max_end = max(max_end, sorted_spans[span_index].end)
                span_index += 1

            if max_end >= match.end():
                continue

            is_hex = all(c in HEX_CHARS for c in candidate)
            charset, threshold = (
                (HEX_CHARS, HEX_ENTROPY_THRESHOLD) if is_hex else (BASE64_CHARS, BASE64_ENTROPY_THRESHOLD)
            )
            entropy = charset_entropy(candidate, charset)

            if entropy >= threshold:
                kind = "hex" if is_hex else "base64"
                hits.append((f"High Entropy ({kind}, {entropy:.1f})", 0.70))
                matches.append(MatchSpan(start=match.start(), end=match.end()))

        return matches, hits
