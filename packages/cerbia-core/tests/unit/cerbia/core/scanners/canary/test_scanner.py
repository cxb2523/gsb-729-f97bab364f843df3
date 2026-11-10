import pytest
from cerbia.core.scanners.canary import CanaryLeakScanner
from cerbia.core.types import Action, ContentType, Severity

pytestmark = pytest.mark.unit


def test_canary_leak_scanner_returns_safe_outcome_when_tokens_are_not_configured() -> None:
    scanner = CanaryLeakScanner()

    result = scanner.scan("CANARY-secret")

    assert result.risk_score == 0.0
    assert result.rationale == "No canary tokens configured"
    assert result.matches == []


def test_canary_leak_scanner_detects_full_leak_when_configured_token_is_present() -> None:
    scanner = CanaryLeakScanner(["CANARY-secret"])

    result = scanner.scan("Response: CANARY-secret")

    assert result.risk_score == 1.0
    assert result.rationale == "Canary token leaked (1 full)"
    assert [(match.start, match.end) for match in result.matches] == [(10, 23)]


def test_canary_leak_scanner_detects_added_token_when_token_is_added_after_creation() -> None:
    scanner = CanaryLeakScanner()
    scanner.add_token("CANARY-secret")

    result = scanner.scan("CANARY-secret")

    assert result.risk_score == 1.0
    assert [(match.start, match.end) for match in result.matches] == [(0, 13)]


def test_canary_leak_scanner_detects_partial_leak_when_token_fragment_is_present() -> None:
    scanner = CanaryLeakScanner(["CANARY-secret-token"], min_partial_length=8)

    result = scanner.scan("Leaked: secret-token!")

    assert result.risk_score == 0.75
    assert result.rationale == "Canary token leaked (1 partial)"
    assert [(match.start, match.end) for match in result.matches] == [(8, 16)]


@pytest.mark.parametrize(
    ("min_partial_length", "token", "text"),
    [
        (0, "CANARY-secret", "secret-"),
        (6, "secret", "secre"),
    ],
    ids=["partial_matching_disabled", "token_at_partial_threshold"],
)
def test_canary_leak_scanner_returns_safe_outcome_when_partial_leak_cannot_be_matched(
    min_partial_length: int, token: str, text: str
) -> None:
    scanner = CanaryLeakScanner([token], min_partial_length=min_partial_length)

    result = scanner.scan(text)

    assert result.risk_score == 0.0
    assert result.rationale == "No canary token leakage detected (checked 1 token(s))"
    assert result.matches == []


@pytest.mark.parametrize(
    ("text", "case_insensitive", "expected_score"),
    [
        ("CANARY-secret", False, 0.0),
        ("CANARY-secret", True, 1.0),
    ],
    ids=["case_sensitive", "case_insensitive"],
)
def test_canary_leak_scanner_matches_token_according_to_case_configuration(
    text: str, case_insensitive: bool, expected_score: float
) -> None:
    scanner = CanaryLeakScanner(["canary-secret"], case_insensitive=case_insensitive)

    result = scanner.scan(text)

    assert result.risk_score == expected_score


@pytest.mark.parametrize(
    "text",
    [
        "CANARY&#45;secret",
        "CANARY%2Dsecret",
        "CANARY\u200b-secret",
    ],
    ids=["html_entity", "url_encoded", "zero_width"],
)
def test_canary_leak_scanner_detects_full_leak_when_token_is_obfuscated(text: str) -> None:
    scanner = CanaryLeakScanner(["CANARY-secret"])

    result = scanner.scan(text)

    assert result.risk_score == 1.0
    assert [(match.start, match.end) for match in result.matches] == [(0, 13)]


def test_canary_leak_scanner_reports_full_and_partial_leaks_when_multiple_tokens_match() -> None:
    scanner = CanaryLeakScanner(["CANARY-full", "CANARY-partial"], min_partial_length=8)

    result = scanner.scan("CANARY-full and -partial")

    assert result.risk_score == 1.0
    assert result.rationale == "Canary token leaked (1 full, 1 partial)"
    assert {(match.start, match.end) for match in result.matches} == {(0, 11), (16, 24)}


def test_canary_leak_scanner_preserves_configuration_when_custom_values_are_provided() -> None:
    scanner = CanaryLeakScanner(
        severity=Severity.HIGH,
        action=Action.WARN,
        content_types=[ContentType.TEXT, ContentType.CODE],
    )

    assert scanner.scanner_id == "canary"
    assert scanner.scanner_name == "Canary Leak"
    assert scanner.severity is Severity.HIGH
    assert scanner.action is Action.WARN
    assert scanner.content_types == (ContentType.TEXT, ContentType.CODE)
