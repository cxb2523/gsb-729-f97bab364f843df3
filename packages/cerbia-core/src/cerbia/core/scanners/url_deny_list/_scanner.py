from logging import getLogger
from pathlib import Path
from typing import assert_never

from ..._utils.url import extract_urls
from ...models.scans import MatchSpan, ScanOutcome
from ...registries.url import UrlRegistry
from ...types import Action, ContentType, Severity
from ..url_allow_list._format import format_url_finding

logger = getLogger(__name__)


class UrlDenyListScanner:
    """Detect URLs matching the full-URL wildcard deny store of a URL registry.

    Args:
        blocked_domains (list[str] | str | Path): Blocked full-URL wildcard patterns or a .txt file.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when a denylisted URL is detected.
        content_types: Optional list/tuple of content types supported by the scanner.
        url_registry (UrlRegistry | None): Optional shared allow/deny registry.

    Attributes:
        scanner_id (str): Unique identifier for the scanner.
        scanner_name (str): Human-readable name for the scanner.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when denylisted URLs are detected.
        content_types (tuple[ContentType, ...] | None): Supported content types for scanning.
    """

    def __init__(
        self,
        blocked_domains: list[str] | str | Path,
        severity: Severity = Severity.HIGH,
        action: Action = Action.BLOCK,
        url_registry: UrlRegistry | None = None,
        content_types: tuple[ContentType, ...] | list[str] | None = (
            ContentType.TEXT,
            ContentType.URL,
            ContentType.CODE,
        ),
    ) -> None:
        self.scanner_id: str = "url_denylist"
        self.scanner_name: str = "URL Denylist"
        self.severity: Severity = severity
        self.action: Action = action
        self.content_types: tuple[ContentType | str, ...] | None = (
            tuple(content_types) if content_types is not None else None
        )

        self._url_registry: UrlRegistry = url_registry if url_registry is not None else UrlRegistry()
        match blocked_domains:
            case list():
                for entry in blocked_domains:
                    self._url_registry.register(entry, denied=True)
            case str() | Path():
                self._url_registry.register_file(blocked_domains, denied=True)
            case unreachable:
                assert_never(unreachable)

    def scan(self, text: str) -> ScanOutcome:
        """Scan text for URLs on the denylist.

        Args:
            text (str): Input text to analyse.

        Returns:
            ScanOutcome: Verdict containing safety flag, risk score, rationale, and optional match spans.
        """
        urls = extract_urls(text)
        if not urls:
            logger.debug(
                "No URLs found",
                extra={
                    "operation": "scan",
                    "stage": "scanning",
                    "component_kind": "scanner",
                    "outcome": "completed",
                    "candidate_count": 0,
                    "match_count": 0,
                },
            )
            return ScanOutcome(risk_score=0.0, rationale="No URLs found")

        candidate_count = len(urls)
        blocked = [match for match in urls if self._url_registry.is_denied(match.group())]
        findings = [format_url_finding(match.group()) for match in blocked]

        if not findings:
            logger.debug(
                "%s URL(s) found, none on denylist",
                candidate_count,
                extra={
                    "operation": "scan",
                    "stage": "scanning",
                    "component_kind": "scanner",
                    "outcome": "completed",
                    "candidate_count": candidate_count,
                    "match_count": 0,
                },
            )
            return ScanOutcome(risk_score=0.0, rationale="No URLs on denylist")

        detail = "; ".join(findings[:5])
        rationale = f"URL(s) on denylist ({len(findings)}): {detail}"
        match_count = len(findings)
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
            risk_score=0.95,
            rationale=rationale,
            matches=[MatchSpan(start=match.start(), end=match.end()) for match in blocked],
        )
