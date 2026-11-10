import html
import logging
from urllib.parse import unquote

from ...models.scans import ScanOutcome
from ...types import Action, ContentType, Severity
from ._constants import ALL_PATTERNS, UNICODE_ESCAPE_RE
from ._parser import extract_code_ranges
from ._validations import in_safe_range

logger = logging.getLogger(__name__)


class XssScanner:
    """Detects HTML/script injection vectors in LLM output.

    Applies pre-scan normalization (HTML entities, URL encoding, Unicode escapes), then checks against 19 XSS vector
    patterns. Optionally uses HTML context parsing to reduce false positives inside code blocks.

    Args:
        html_context_aware (bool): When ``True``, suppress matches inside ``<code>``, ``<pre>``, or ``<textarea>`` tags.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when XSS vectors are detected.
        content_types (tuple[ContentType, ...] | list[str] | None): Content types to scan. Defaults to
            ``(ContentType.TEXT, ContentType.CODE)``.

    Attributes:
        scanner_id (str): Unique identifier for the scanner.
        scanner_name (str): Human-readable name for the scanner.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when XSS vectors are detected.
        content_types (tuple[ContentType, ...] | None): Content types to scan.
    """

    def __init__(
        self,
        html_context_aware: bool = False,
        severity: Severity = Severity.HIGH,
        action: Action = Action.BLOCK,
        content_types: tuple[ContentType, ...] | list[str] | None = (ContentType.TEXT, ContentType.CODE),
    ) -> None:
        self.scanner_id = "xss"
        self.scanner_name = "XSS"
        self.severity = severity
        self.action = action
        self.content_types = tuple(content_types) if content_types is not None else None
        self._html_context_aware = html_context_aware

    def scan(self, text: str) -> ScanOutcome:
        """Scan text for cross-site scripting vectors.

        Args:
            text (str): Input text to analyse.

        Returns:
            ScanOutcome: Verdict containing safety flag, risk score, rationale, and optional match spans.
        """
        parsed_html = html.unescape(text)
        parsed_html = unquote(parsed_html)

        normalized = UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), parsed_html)

        safe_ranges = extract_code_ranges(normalized) if self._html_context_aware else []

        hits: list[tuple[str, float, str, int]] = []

        for name, pattern, risk_score, sev_label in ALL_PATTERNS:
            for match in pattern.finditer(normalized):
                pos = match.start()
                if safe_ranges and in_safe_range(pos, safe_ranges):
                    continue

                hits.append((name, risk_score, sev_label, pos))

        if not hits:
            outcome = ScanOutcome(risk_score=0.0, rationale="No XSS vectors detected")
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
        details = ", ".join(f"{name} at pos {pos} ({sev})" for name, _, sev, pos in hits[:5])

        outcome = ScanOutcome(
            risk_score=max_risk_score,
            rationale=f"XSS vector(s) detected ({len(hits)}): {details}",
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
