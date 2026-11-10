from logging import getLogger

from ...models.scans import MatchSpan, ScanOutcome
from ...types import Action, ContentType, Severity
from ._normalization import normalize_for_detection

logger = getLogger(__name__)


class CanaryLeakScanner:
    """Detects canary token leakage in LLM output.

    Supports exact matching, partial-fragment detection, case-insensitive matching, and input normalization (HTML
    entities, URL encoding, zero-width character removal).

    Args:
        canary_tokens (list[str] | None): Tokens to monitor.
        min_partial_length (int): Minimum fragment length for partial matching.
        case_insensitive (bool): Whether to match case-insensitively.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when leakage is detected.

    Attributes:
        scanner_id (str): Unique identifier for the scanner.
        scanner_name (str): Human-readable name for the scanner.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when leakage is detected.
        content_types (tuple[ContentType, ...] | None): Supported content types for scanning.
    """

    def __init__(
        self,
        canary_tokens: list[str] | None = None,
        min_partial_length: int = 8,
        case_insensitive: bool = False,
        severity: Severity = Severity.CRITICAL,
        action: Action = Action.BLOCK,
        content_types: tuple[ContentType, ...] | list[str] | None = None,
    ) -> None:
        self.scanner_id = "canary"
        self.scanner_name = "Canary Leak"
        self.severity = severity
        self.action = action
        self.content_types = tuple(content_types) if content_types is not None else None
        self._tokens: set[str] = set(canary_tokens or [])
        self._min_partial_length = min_partial_length
        self._case_insensitive = case_insensitive

    def add_token(self, token: str) -> None:
        """Add a canary token to monitor for leakage.

        Args:
            token (str): Canary token to add to the monitoring set.
        """
        self._tokens.add(token)

    def scan(self, text: str) -> ScanOutcome:
        """Scan text for canary token leakage.

        Args:
            text (str): LLM-generated output to check.

        Returns:
            ScanOutcome: Verdict with match spans for leaked canary tokens.
        """
        if not self._tokens:
            logger.debug(
                "No canary tokens configured",
                extra={
                    "operation": "scan",
                    "stage": "scanning",
                    "component_kind": "scanner",
                    "outcome": "completed",
                    "candidate_count": 0,
                    "match_count": 0,
                },
            )
            return ScanOutcome(risk_score=0.0, rationale="No canary tokens configured")

        normalized = normalize_for_detection(text)
        compare_text = normalized.lower() if self._case_insensitive else normalized
        tokens = self._tokens
        candidate_count = len(tokens)

        leak_types: list[str] = []
        matches: list[MatchSpan] = []

        for token in tokens:
            compare_token = token.lower() if self._case_insensitive else token
            token_matches, token_leak_types = self._check_token(compare_text, compare_token)
            matches.extend(token_matches)
            leak_types.extend(token_leak_types)

        if not matches:
            logger.debug(
                "No matches found",
                extra={
                    "operation": "scan",
                    "stage": "scanning",
                    "component_kind": "scanner",
                    "outcome": "completed",
                    "candidate_count": candidate_count,
                    "match_count": 0,
                },
            )
            return ScanOutcome(
                risk_score=0.0, rationale=f"No canary token leakage detected (checked {len(self._tokens)} token(s))"
            )

        full_leaks = leak_types.count("full")
        partial_leaks = leak_types.count("partial")
        match_count = len(matches)
        risk_score = 1.0 if full_leaks else 0.75

        parts: list[str] = []
        if full_leaks:
            parts.append(f"{full_leaks} full")

        if partial_leaks:
            parts.append(f"{partial_leaks} partial")

        logger.debug(
            "%s matches found",
            match_count,
            extra={
                "operation": "scan",
                "stage": "scanning",
                "component_kind": "scanner",
                "outcome": "completed",
                "candidate_count": candidate_count,
                "match_count": match_count,
            },
        )
        return ScanOutcome(
            risk_score=risk_score,
            rationale=f"Canary token leaked ({', '.join(parts)})",
            matches=matches,
        )

    def _check_token(self, compare_text: str, compare_token: str) -> tuple[list[MatchSpan], list[str]]:
        idx = compare_text.find(compare_token)
        if idx >= 0:
            return [MatchSpan(start=idx, end=idx + len(compare_token))], ["full"]

        if self._min_partial_length > 0 and len(compare_token) > self._min_partial_length:
            for i in range(len(compare_token) - self._min_partial_length + 1):
                fragment = compare_token[i : i + self._min_partial_length]
                frag_idx = compare_text.find(fragment)
                if frag_idx >= 0:
                    return [MatchSpan(start=frag_idx, end=frag_idx + len(fragment))], ["partial"]

        return [], []
