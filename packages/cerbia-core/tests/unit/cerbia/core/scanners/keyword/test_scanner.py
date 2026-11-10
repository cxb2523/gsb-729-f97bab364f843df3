import re

import pytest
from cerbia.core.scanners.keyword import KeywordScanner
from cerbia.core.scanners.keyword._types import MatchStrategy
from cerbia.core.types import Action, ContentType, Severity

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("text", "expected_name", "expected_snippet"),
    [
        ("Please exec(command)", "Code Execution", "exec"),
        ("Run import os to inspect the environment", "OS Command", "import os"),
    ],
    ids=["code_execution", "os_command"],
)
def test_keyword_scanner_detects_default_code_pattern_when_suspicious_code_is_provided(
    text: str, expected_name: str, expected_snippet: str
) -> None:
    scanner = KeywordScanner(languages=[])

    result = scanner.scan(text)

    assert result.risk_score == pytest.approx(0.85)
    assert result.rationale == f"Suspicious keyword(s) (1): {expected_name} ('{expected_snippet}')"


def test_keyword_scanner_returns_safe_outcome_when_keyword_is_not_detected() -> None:
    scanner = KeywordScanner(languages=[])

    result = scanner.scan("The documentation contains no executable instructions.")

    assert result.risk_score == 0.0
    assert result.rationale == "No suspicious keywords found"


def test_keyword_scanner_loads_i18n_patterns_when_configured_language_patterns_are_available(mocker) -> None:
    instruction_pattern = re.compile(r"ignore previous instructions", re.IGNORECASE)
    get_patterns = mocker.patch("cerbia.core.scanners.keyword._scanner.get_patterns")
    get_patterns.side_effect = [
        {"keyword_instruction_override": [instruction_pattern]},
        {"defensive_context": []},
    ]

    scanner = KeywordScanner(languages=["en"])
    result = scanner.scan("Ignore previous instructions")

    assert result.risk_score == pytest.approx(0.85)
    assert result.rationale == "Suspicious keyword(s) (1): Instruction Override ('Ignore previous instructions')"
    assert get_patterns.call_args_list == [
        mocker.call(languages=["en"], keys=KeywordScanner.i18n_keys),
        mocker.call(languages=["en"], keys=["defensive_context"]),
    ]


@pytest.mark.parametrize(
    ("match_strategy", "text", "expected_rationale"),
    [
        (MatchStrategy.SEARCH, "token token", "Suspicious keyword(s) (1): Internal Token ('token')"),
        (
            MatchStrategy.ALL,
            "token token",
            "Suspicious keyword(s) (2): Internal Token ('token'); Internal Token ('token')",
        ),
        (MatchStrategy.FULL_MATCH, "token", "Suspicious keyword(s) (1): Internal Token ('token')"),
        (MatchStrategy.FULL_MATCH, "prefix token", "No suspicious keywords found"),
    ],
    ids=["search_first_match", "all_matches", "full_match", "incomplete_full_match"],
)
def test_keyword_scanner_applies_configured_match_strategy_when_extra_pattern_is_provided(
    match_strategy: MatchStrategy, text: str, expected_rationale: str
) -> None:
    scanner = KeywordScanner(languages=[], extra_patterns=[("Internal Token", r"token")], match_strategy=match_strategy)

    result = scanner.scan(text)

    assert result.rationale == expected_rationale


def test_keyword_scanner_skips_match_when_defensive_context_is_detected(mocker) -> None:
    is_in_defensive_context = mocker.patch(
        "cerbia.core.scanners.keyword._scanner.is_in_defensive_context", return_value=True
    )
    scanner = KeywordScanner(languages=[], extra_patterns=[("Internal Token", r"token")])

    result = scanner.scan("token")

    assert result.risk_score == 0.0
    assert result.rationale == "No suspicious keywords found"
    is_in_defensive_context.assert_called_once()


def test_keyword_scanner_redacts_matching_snippet_when_redaction_is_enabled() -> None:
    scanner = KeywordScanner(languages=[], extra_patterns=[("Internal Token", r"token")], redact=True)

    result = scanner.scan("token")

    assert result.risk_score == pytest.approx(0.85)
    assert result.rationale == "Suspicious keyword(s) (1): Internal Token ('[REDACTED]')"


def test_keyword_scanner_caps_risk_and_limits_rationale_to_first_five_hits() -> None:
    extra_patterns = [
        ("Pattern One", "patternone"),
        ("Pattern Two", "patterntwo"),
        ("Pattern Three", "patternthree"),
        ("Pattern Four", "patternfour"),
        ("Pattern Five", "patternfive"),
        ("Pattern Six", "patternsix"),
    ]
    scanner = KeywordScanner(languages=[], extra_patterns=extra_patterns, match_strategy=MatchStrategy.ALL)

    result = scanner.scan("patternone patterntwo patternthree patternfour patternfive patternsix")

    assert result.risk_score == 1.0
    assert result.rationale == (
        "Suspicious keyword(s) (6): Pattern One ('patternone'); Pattern Two ('patterntwo'); "
        "Pattern Three ('patternthree'); Pattern Four ('patternfour'); Pattern Five ('patternfive')"
    )


def test_keyword_scanner_preserves_configuration_when_custom_values_are_provided() -> None:
    scanner = KeywordScanner(
        languages=[],
        match_strategy=MatchStrategy.ALL,
        redact=True,
        severity=Severity.CRITICAL,
        action=Action.WARN,
        content_types=[ContentType.TEXT, ContentType.CODE],
    )

    assert scanner.scanner_id == "keyword"
    assert scanner.scanner_name == "Keyword"
    assert scanner.severity is Severity.CRITICAL
    assert scanner.action is Action.WARN
    assert scanner.content_types == (ContentType.TEXT, ContentType.CODE)
    assert scanner._match_strategy is MatchStrategy.ALL
    assert scanner._redact
