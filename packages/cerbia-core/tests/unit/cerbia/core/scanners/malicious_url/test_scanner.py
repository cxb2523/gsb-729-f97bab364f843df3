import pytest
from cerbia.core.models.scans import MatchSpan
from cerbia.core.registries.url import UrlRegistry
from cerbia.core.scanners.malicious_url import MaliciousUrlScanner
from cerbia.core.types import Action, ContentType, Severity

pytestmark = pytest.mark.unit


def test_malicious_url_scanner_returns_safe_outcome_when_text_contains_no_urls() -> None:
    scanner = MaliciousUrlScanner()

    result = scanner.scan("No links are present.")

    assert result.risk_score == 0.0
    assert result.rationale == "No URLs found"
    assert result.matches == []


def test_malicious_url_scanner_returns_safe_outcome_when_url_has_no_indicators() -> None:
    scanner = MaliciousUrlScanner(
        suspicious_tlds=[],
        shortener_domains=[],
        popular_domains=[],
    )

    result = scanner.scan("https://example.com/docs")

    assert result.risk_score == 0.0
    assert result.rationale == "All 1 URL(s) appear safe"
    assert result.matches == []


def test_malicious_url_scanner_returns_safe_outcome_when_all_urls_are_allowlisted() -> None:
    registry = UrlRegistry(["https://example.com/*"])
    scanner = MaliciousUrlScanner(url_registry=registry)

    result = scanner.scan("https://example.com/docs")

    assert result.risk_score == 0.0
    assert result.rationale == "All URLs on allowlist"
    assert result.matches == []


def test_malicious_url_scanner_evaluates_unallowlisted_url_when_text_contains_mixed_urls() -> None:
    registry = UrlRegistry(["https://example.com/*"])
    scanner = MaliciousUrlScanner(suspicious_tlds=["xyz"], url_registry=registry)

    result = scanner.scan("https://example.com/docs https://evil.xyz/path")

    assert result.risk_score == 0.75
    assert result.rationale == "Suspicious URL(s) (1 flag(s)): Suspicious TLD (.xyz) (https://evil.xyz/path)"
    assert result.matches == [MatchSpan(start=25, end=46)]


def test_malicious_url_scanner_detects_data_uri_when_data_uri_is_present() -> None:
    scanner = MaliciousUrlScanner()

    result = scanner.scan("data:text/html,<script>alert(1)</script>")

    assert result.risk_score == 0.9
    assert result.rationale == "Suspicious URL(s) (1 flag(s)): Data URI (data:text/html,<script>alert(1)</script>)"
    assert result.matches == [MatchSpan(start=0, end=14)]


@pytest.mark.parametrize(
    ("url", "scanner", "expected_reason", "expected_score"),
    [
        ("https://192.0.2.1/path", MaliciousUrlScanner(), "IP-based URL", 0.8),
        ("https://evil.xyz/path", MaliciousUrlScanner(suspicious_tlds=["xyz"]), "Suspicious TLD (.xyz)", 0.75),
        (
            "https://go.short.example/path",
            MaliciousUrlScanner(shortener_domains=["short.example"]),
            "URL shortener",
            0.7,
        ),
        ("https://example.com/?ReDiReCt=https://evil.example", MaliciousUrlScanner(), "Redirect param 'ReDiReCt'", 0.8),
        ("https://xn--paypa-4ve.com/path", MaliciousUrlScanner(), "Punycode/IDN domain", 0.85),
        ("https://a.b.c.d.example.com/path", MaliciousUrlScanner(), "Excessive subdomains", 0.65),
        ("https://example.com/%00%01%02%03%04%05", MaliciousUrlScanner(), "URL-encoding obfuscation", 0.75),
        (
            "https://gooogle.com/path",
            MaliciousUrlScanner(popular_domains=["google.com"]),
            "Possible typosquatting of google.com",
            0.85,
        ),
    ],
    ids=[
        "ip_host",
        "suspicious_tld",
        "shortener_subdomain",
        "redirect_parameter",
        "punycode",
        "excessive_subdomains",
        "percent_encoding",
        "typosquatting",
    ],
)
def test_malicious_url_scanner_returns_finding_when_url_has_malicious_indicator(
    url: str, scanner: MaliciousUrlScanner, expected_reason: str, expected_score: float
) -> None:
    result = scanner.scan(url)

    assert result.risk_score == expected_score
    assert result.rationale == f"Suspicious URL(s) (1 flag(s)): {expected_reason} ({url})"
    assert result.matches == [MatchSpan(start=0, end=len(url))]


def test_malicious_url_scanner_emits_one_span_per_flagged_occurrence_when_multiple_heuristics_match() -> None:
    # Given
    scanner = MaliciousUrlScanner(suspicious_tlds=["xyz"], shortener_domains=["evil.xyz"])
    url = "HTTPS://EVIL.xyz/é"
    text = f"前🙂 ({url}), https://safe.example/docs; {url}!"
    # When
    result = scanner.scan(text)
    # Then
    assert result.risk_score == 0.75
    assert result.rationale.startswith("Suspicious URL(s) (4 flag(s)):")
    assert result.matches == [
        MatchSpan(start=text.index(url), end=text.index(url) + len(url)),
        MatchSpan(start=text.rindex(url), end=text.rindex(url) + len(url)),
    ]


def test_malicious_url_scanner_preserves_denied_url_span_when_matching_allow_rule_exists() -> None:
    # Given
    registry = UrlRegistry(["https://*.xyz/*"])
    registry.register("https://blocked.xyz/*", denied=True)
    scanner = MaliciousUrlScanner(suspicious_tlds=["xyz"], url_registry=registry)
    text = "https://allowed.xyz/doc (https://blocked.xyz/doc)."
    # When
    result = scanner.scan(text)
    # Then
    start = text.index("https://blocked")
    assert result.matches == [MatchSpan(start=start, end=start + len("https://blocked.xyz/doc"))]
    assert result.risk_score == 0.75


def test_malicious_url_scanner_uses_data_uri_match_span_when_payload_and_allowed_url_follow() -> None:
    # Given
    scanner = MaliciousUrlScanner(url_registry=UrlRegistry(["*"]))
    text = "前🙂 data: text/html,<svg>payload</svg> https://safe.example/"
    # When
    result = scanner.scan(text)
    # Then
    assert result.risk_score == 0.9
    assert result.matches == [MatchSpan(start=3, end=18)]


def test_malicious_url_scanner_keeps_data_uri_and_url_spans_when_both_are_detected() -> None:
    # Given
    scanner = MaliciousUrlScanner(suspicious_tlds=["xyz"])
    text = "data:text/html,payload https://evil.xyz/doc"
    # When
    result = scanner.scan(text)
    # Then
    assert result.risk_score == 0.9
    assert result.matches == [MatchSpan(start=0, end=14), MatchSpan(start=23, end=43)]


def test_malicious_url_scanner_uses_highest_score_and_limits_rationale_to_first_five_flags() -> None:
    scanner = MaliciousUrlScanner(suspicious_tlds=["xyz"], shortener_domains=["evil.xyz"])

    result = scanner.scan("https://192.0.2.1/?redirect=https://evil.xyz https://evil.xyz/%00%01%02%03%04%05")

    assert result.risk_score == 0.8
    assert result.rationale.startswith("Suspicious URL(s) (5 flag(s)):")
    assert "IP-based URL" in result.rationale
    assert "Redirect param 'redirect'" in result.rationale


def test_malicious_url_scanner_preserves_configuration_when_custom_values_are_provided() -> None:
    registry = UrlRegistry()
    scanner = MaliciousUrlScanner(
        severity=Severity.CRITICAL,
        action=Action.WARN,
        suspicious_tlds=["custom"],
        shortener_domains=["short.example"],
        popular_domains=["popular.example"],
        url_registry=registry,
        content_types=[ContentType.URL],
    )

    assert scanner.scanner_id == "url_malicious"
    assert scanner.scanner_name == "Malicious URL"
    assert scanner.severity is Severity.CRITICAL
    assert scanner.action is Action.WARN
    assert scanner.content_types == (ContentType.URL,)
    assert scanner._suspicious_tlds == frozenset(["custom"])
    assert scanner._shortener_domains == frozenset(["short.example"])
    assert scanner._popular_domains == frozenset(["popular.example"])
    assert scanner._url_registry is registry
