import logging
import re
from collections.abc import Callable
from ipaddress import AddressValueError, IPv6Address

from ...exceptions import CerbIAConfigError
from ...models.scans import MatchSpan, ScanOutcome
from ...types import Action, ContentType, Severity
from ._checksums import CHECKSUM_VALIDATORS
from ._constants import AT_BLOCK, DOT_BLOCK, EMAIL_DOMAIN_CONTINUATION, EMAIL_DOMAIN_LABEL, PII_PATTERNS

logger = logging.getLogger(__name__)


class PiiScanner:
    """Detects personally identifiable information (PII) in text.

    Args:
        extra_patterns (list[tuple[str, str]] | None): Additional ``(name, regex_string)`` pairs.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when PII is detected.
        content_types (tuple[ContentType, ...] | list[str] | None): Supported content types.
        validate_checksums (bool): Whether to validate algorithmic checksums for applicable PII types
            (e.g., Modulo 23 for Spanish DNI/NIE, Luhn for credit cards, Modulo 97 for IBAN).
            When True, candidate matches failing checksum validation are discarded.
            This reduces noise but can also miss sensitive identifiers with typos.
            Defaults to False for backward compatibility.
        custom_validators (dict[str, Callable[[str], bool]] | None): Optional mapping of pattern names
            to custom checksum validator functions.
        email_domains (list[str] | None): Exact, case-insensitive domains to detect in built-in email patterns.
            None detects all domains; an empty list disables built-in email detection only.
            Entries must be bare ASCII DNS domains with at least two labels, no whitespace,
            and no leading/trailing hyphens or dots. URLs, @ prefixes, and wildcards are rejected.
            Subdomains must be explicitly listed. Malformed domain strings raise CerbIAConfigError.

    Attributes:
        scanner_id (str): Unique identifier for the scanner.
        scanner_name (str): Human-readable name for the scanner.
        severity (Severity): Severity level for produced findings.
        action (Action): Action to take when PII is detected.
        content_types (tuple[ContentType, ...] | None): Supported content types for scanning.
        validate_checksums (bool): Whether checksum validation is enabled.
    """

    def __init__(
        self,
        extra_patterns: list[tuple[str, str]] | None = None,
        severity: Severity = Severity.HIGH,
        action: Action = Action.WARN,
        content_types: tuple[ContentType, ...] | list[str] | None = (ContentType.TEXT,),
        validate_checksums: bool = False,
        custom_validators: dict[str, Callable[[str], bool]] | None = None,
        email_domains: list[str] | None = None,
    ) -> None:
        self.scanner_id = "pii"
        self.scanner_name = "PII"
        self.severity = severity
        self.action = action
        self.content_types = tuple(content_types) if content_types is not None else None
        self.validate_checksums = validate_checksums

        self._email_domains: frozenset[str] | None = self._validate_email_domains(email_domains)

        self._patterns = PII_PATTERNS.copy()
        if self._email_domains is not None:
            for index, (name, pattern, risk_score) in enumerate(self._patterns):
                if name == "Email (obfuscated)":
                    pattern = re.compile(
                        rf"(?i)[a-z0-9._%+-]+{AT_BLOCK}[a-z0-9.-]+{DOT_BLOCK}"
                        rf"{EMAIL_DOMAIN_LABEL}(?:(?:\.|{DOT_BLOCK}){EMAIL_DOMAIN_LABEL})*"
                    )
                    self._patterns[index] = (name, pattern, risk_score)

        if extra_patterns:
            for name, regex in extra_patterns:
                self._patterns.append((name, re.compile(regex), 0.80))

        self._validators = CHECKSUM_VALIDATORS.copy()
        if custom_validators:
            self._validators.update(custom_validators)

    @staticmethod
    def _validate_email_domains(email_domains: list[str] | None) -> frozenset[str] | None:
        if email_domains is None:
            return None

        for domain in email_domains:
            if (
                len(domain) > 253
                or re.fullmatch(
                    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+",
                    domain,
                )
                is None
            ):
                raise CerbIAConfigError("email_domains entries must be bare ASCII DNS domains")

        return frozenset(domain.lower() for domain in email_domains)

    def _matches_email_domain(self, index: int, name: str, match: re.Match[str]) -> bool:
        if self._email_domains is None or index >= len(PII_PATTERNS) or name not in {"Email", "Email (obfuscated)"}:
            return True

        candidate = re.sub(AT_BLOCK, "@", match.group(), flags=re.IGNORECASE)
        domain = re.sub(DOT_BLOCK, ".", candidate, flags=re.IGNORECASE).rsplit("@", 1)[1]

        continuation = EMAIL_DOMAIN_CONTINUATION.match(match.string, match.end())
        return domain.lower() in self._email_domains and continuation is None

    @staticmethod
    def _matches_ipv6(index: int, name: str, match: re.Match[str]) -> bool:
        if index >= len(PII_PATTERNS) or name != "IPv6":
            return True

        try:
            IPv6Address(match.group())
        except AddressValueError:
            return False
        return True

    def scan(self, text: str) -> ScanOutcome:
        """Scan text for personally identifiable information.

        Args:
            text (str): Input text to analyse.

        Returns:
            ScanOutcome: Verdict with match spans for detected PII.
        """
        hits: list[tuple[str, float]] = []
        matches: list[MatchSpan] = []

        for index, (name, pattern, risk_score) in enumerate(self._patterns):
            for match in pattern.finditer(text):
                if not self._matches_email_domain(index, name, match):
                    continue
                if not self._matches_ipv6(index, name, match):
                    continue
                if (
                    self.validate_checksums
                    and (validator := self._validators.get(name)) is not None
                    and not validator(match.group())
                ):
                    continue
                hits.append((name, risk_score))
                matches.append(MatchSpan(start=match.start(), end=match.end()))

        if not hits:
            outcome = ScanOutcome(risk_score=0.0, rationale="No PII detected")
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

        max_risk = max(h[1] for h in hits)
        type_counts: dict[str, int] = {}
        for name, _ in hits:
            type_counts[name] = type_counts.get(name, 0) + 1

        summary = ", ".join(f"{name} ({count})" for name, count in list(type_counts.items())[:5])
        outcome = ScanOutcome(
            risk_score=max_risk,
            rationale=f"PII detected ({len(hits)} match(es)): {summary}",
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
