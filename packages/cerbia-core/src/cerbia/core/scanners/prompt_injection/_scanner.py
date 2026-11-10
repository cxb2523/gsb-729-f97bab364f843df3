import logging
import re

from ..._utils.text import is_in_defensive_context
from ...i18n import get_patterns
from ...models.scans import MatchSpan, ScanOutcome
from ...types import Action, ContentType, Severity
from ._constants import BASE_RISK_SCORE, CATEGORY_BONUS, MATCH_INCREMENT, MAX_RISK_SCORE

logger = logging.getLogger(__name__)


class PromptInjectionScanner:
    """Detects prompt injection attempts via multilingual regex patterns.

    Loads patterns from the i18n registry for the requested languages and scans across all registered category keys.
    Uses accumulative risk scoring: each additional match and each additional category raise the reported risk score.

    Args:
        languages (list[str] | None): ISO-639-1 codes to load patterns for. Defaults to all supported languages.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when injection is detected.

    Attributes:
        scanner_id (str): Unique identifier for the scanner.
        scanner_name (str): Human-readable name for the scanner.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when injection is detected.
        content_types (tuple[ContentType, ...] | list[str] | None): Content types to scan.
    """

    i18n_keys = [
        "instruction_override",
        "exfiltration",
        "role_hijack",
        "context_manipulation",
        "privilege_escalation",
        "fake_authority",
        "task_deflection",
    ]

    def __init__(
        self,
        languages: list[str] | None = None,
        severity: Severity = Severity.CRITICAL,
        action: Action = Action.BLOCK,
        content_types: tuple[ContentType, ...] | list[str] | None = (ContentType.TEXT,),
    ) -> None:
        self.scanner_id = "prompt_injection"
        self.scanner_name = "Prompt Injection"
        self.severity = severity
        self.action = action
        self.content_types = tuple(content_types) if content_types is not None else None
        self._patterns = get_patterns(languages=languages, keys=self.i18n_keys)
        defensive = get_patterns(languages=languages, keys=["defensive_context"])
        self._defensive_patterns: list[re.Pattern[str]] = defensive.get("defensive_context", [])

    def scan(self, text: str) -> ScanOutcome:
        """Scan text for prompt injection attempts.

        Args:
            text (str): Input text to analyse.

        Returns:
            ScanOutcome: Verdict containing safety flag, risk score, rationale, and optional match spans.
        """
        hits: list[tuple[str, str]] = []
        matches: list[MatchSpan] = []

        for category, patterns in self._patterns.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    if is_in_defensive_context(text, match.start(), self._defensive_patterns):
                        continue

                    hits.append((category, match.group()[:80]))
                    matches.append(MatchSpan(start=match.start(), end=match.end()))

        if not hits:
            outcome = ScanOutcome(risk_score=0.0, rationale="No injection patterns found")
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

        unique_categories = {cat for cat, _ in hits}
        risk_score = min(
            MAX_RISK_SCORE,
            BASE_RISK_SCORE + MATCH_INCREMENT * (len(hits) - 1) + CATEGORY_BONUS * (len(unique_categories) - 1),
        )

        snippets = "; ".join(f"[{cat}] '{snip}'" for cat, snip in hits)
        rationale = f"Injection detected ({len(hits)} match(es)): {snippets}"

        outcome = ScanOutcome(risk_score=risk_score, rationale=rationale, matches=matches)
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
