import logging
import re

from ..._constants import LEET_TRANSLATE_TABLE
from ..._utils.text import is_in_defensive_context
from ...i18n import get_patterns
from ...models.scans import ScanOutcome
from ...types import Action, ContentType, Severity
from ._constants import CODE_PATTERNS
from ._normalization import normalize_unicode
from ._types import MatchStrategy

logger = logging.getLogger(__name__)


class KeywordScanner:
    """Detects suspicious keywords that indicate injection or evasion attempts.

    Loads language-dependent patterns from the i18n registry and combines them with universal code-level patterns.
    Particularly useful on decoded content produced by preprocessors.

    Args:
        languages (list[str] | None): ISO-639-1 codes to load patterns for. Defaults to all supported languages.
        extra_patterns (list[tuple[str, str]] | None): Additional ``(name, regex)`` pairs appended to the pattern set.
        match_strategy (MatchStrategy): Strategy for matching patterns against the input text.
        redact (bool): Whether to redact matching snippets in the rationale.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when keywords are found.
        content_types (tuple[ContentType, ...] | list[str] | None): Content types to scan. Defaults to
            ``(ContentType.TEXT,)``.

    Attributes:
        scanner_id (str): Unique identifier for the scanner.
        scanner_name (str): Human-readable name for the scanner.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when keywords are found.
    """

    i18n_keys = [
        "keyword_instruction_override",
        "keyword_system_prompt",
        "keyword_exfiltration",
        "keyword_instruction_manipulation",
        "keyword_suspicious_keywords",
    ]

    def __init__(
        self,
        languages: list[str] | None = None,
        extra_patterns: list[tuple[str, str]] | None = None,
        match_strategy: MatchStrategy = MatchStrategy.SEARCH,
        redact: bool = False,
        severity: Severity = Severity.HIGH,
        action: Action = Action.BLOCK,
        content_types: tuple[ContentType, ...] | list[str] | None = (ContentType.TEXT,),
    ) -> None:
        self.scanner_id = "keyword"
        self.scanner_name = "Keyword"
        self.severity = severity
        self.action = action
        self.content_types = tuple(content_types) if content_types is not None else None
        self._match_strategy = match_strategy
        self._redact = redact

        i18n_patterns = get_patterns(languages=languages, keys=self.i18n_keys)
        defensive = get_patterns(languages=languages, keys=["defensive_context"])
        self._defensive_patterns: list[re.Pattern[str]] = defensive.get("defensive_context", [])
        self._patterns: list[tuple[str, re.Pattern[str]]] = []

        for key, compiled in i18n_patterns.items():
            label = key.removeprefix("keyword_").replace("_", " ").title()
            for pattern in compiled:
                self._patterns.append((label, pattern))

        self._patterns.extend(CODE_PATTERNS)

        if extra_patterns:
            for name, regex in extra_patterns:
                self._patterns.append((name, re.compile(regex, re.IGNORECASE)))

    def scan(self, text: str) -> ScanOutcome:
        """Scan text for suspicious keywords.

        Args:
            text (str): Input text to analyse.

        Returns:
            ScanOutcome: Verdict containing safety flag, risk score, rationale, and optional match spans.
        """
        normalized = normalize_unicode(text).translate(LEET_TRANSLATE_TABLE)

        hits: list[tuple[str, str]] = []
        for name, pattern in self._patterns:
            hits.extend(self._match_pattern(normalized, name, pattern))

        if not hits:
            outcome = ScanOutcome(risk_score=0.0, rationale="No suspicious keywords found")
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

        risk_score = min(1.0, 0.80 + len(hits) * 0.05)
        if self._redact:
            details = "; ".join(f"{name} ('[REDACTED]')" for name, _ in hits[:5])

        else:
            details = "; ".join(f"{name} ('{snippet}')" for name, snippet in hits[:5])

        outcome = ScanOutcome(
            risk_score=risk_score,
            rationale=f"Suspicious keyword(s) ({len(hits)}): {details}",
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

    def _match_pattern(self, normalized: str, name: str, pattern: re.Pattern[str]) -> list[tuple[str, str]]:
        hits: list[tuple[str, str]] = []
        if self._match_strategy == MatchStrategy.FULL_MATCH:
            match = pattern.fullmatch(normalized)
            if match:
                hits.append((name, match.group()[:40]))

        elif self._match_strategy == MatchStrategy.ALL:
            for match in pattern.finditer(normalized):
                if not is_in_defensive_context(normalized, match.start(), self._defensive_patterns):
                    hits.append((name, match.group()[:40]))

        else:
            match = pattern.search(normalized)
            if match and not is_in_defensive_context(normalized, match.start(), self._defensive_patterns):
                hits.append((name, match.group()[:40]))

        return hits
