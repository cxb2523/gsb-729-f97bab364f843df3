import pytest
from cerbia.core.models.scans import MatchSpan, ScanOutcome
from cerbia.core.types import Action, ContentType, Severity
from cerbia.presidio.scanners.pii import PresidioPiiScanner

pytestmark = pytest.mark.unit


def test_presidio_pii_scanner_builds_english_analyzer_with_configured_values(mocker) -> None:
    nlp_engine = mocker.Mock()
    provider = mocker.Mock()
    provider.create_engine.return_value = nlp_engine
    nlp_provider = mocker.patch("cerbia.presidio.scanners.pii.NlpEngineProvider", return_value=provider)
    analyzer_engine = mocker.patch("cerbia.presidio.scanners.pii.AnalyzerEngine")

    scanner = PresidioPiiScanner(
        entities=["EMAIL_ADDRESS"],
        severity=Severity.MEDIUM,
        action=Action.WARN,
        content_types=[ContentType.TEXT, ContentType.CODE],
    )

    assert scanner.scanner_id == "presidio_pii"
    assert scanner.scanner_name == "Presidio PII"
    assert scanner.severity is Severity.MEDIUM
    assert scanner.action is Action.WARN
    assert scanner.content_types == (ContentType.TEXT, ContentType.CODE)
    nlp_provider.assert_called_once_with(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
    )
    analyzer_engine.assert_called_once_with(nlp_engine=nlp_engine, supported_languages=["en"])


def test_presidio_pii_scanner_uses_default_configuration(mocker) -> None:
    scanner = _build_scanner(mocker)

    assert scanner.severity is Severity.HIGH
    assert scanner.action is Action.BLOCK
    assert scanner.content_types == (ContentType.TEXT,)


def test_presidio_pii_scanner_accepts_all_content_types(mocker) -> None:
    scanner = _build_scanner(mocker, content_types=None)

    assert scanner.content_types is None


def test_presidio_pii_scanner_returns_empty_input_outcome_without_analyzing(mocker) -> None:
    scanner = _build_scanner(mocker)

    result = scanner.scan("  \n")

    assert result == ScanOutcome(risk_score=0.0, rationale="Empty input")
    scanner._analyzer.analyze.assert_not_called()


def test_presidio_pii_scanner_returns_safe_outcome_when_analyzer_finds_no_pii(mocker) -> None:
    scanner = _build_scanner(mocker)
    scanner._analyzer.analyze.return_value = []

    result = scanner.scan("Safe text")

    assert result == ScanOutcome(risk_score=0.0, rationale="No PII detected")
    scanner._analyzer.analyze.assert_called_once_with(
        text="Safe text",
        language="en",
        entities=None,
    )


def test_presidio_pii_scanner_forwards_empty_entity_list_to_analyzer(mocker) -> None:
    scanner = _build_scanner(mocker, entities=[])
    scanner._analyzer.analyze.return_value = []

    scanner.scan("Safe text")

    scanner._analyzer.analyze.assert_called_once_with(
        text="Safe text",
        language="en",
        entities=[],
    )


def test_presidio_pii_scanner_maps_analyzer_results_to_outcome(mocker) -> None:
    scanner = _build_scanner(mocker, entities=["EMAIL_ADDRESS", "PHONE_NUMBER"])
    scanner._analyzer.analyze.return_value = [
        _build_analyzer_result(mocker, "EMAIL_ADDRESS", 0.85, 8, 24),
        _build_analyzer_result(mocker, "PHONE_NUMBER", 0.9, 31, 43),
        _build_analyzer_result(mocker, "EMAIL_ADDRESS", 0.75, 48, 64),
    ]

    result = scanner.scan("Contact jane@example.com or +1-555-0100; backup jane@work.example")

    assert result == ScanOutcome(
        risk_score=0.9,
        rationale="PII detected (3 entity/ies): EMAIL_ADDRESS (2), PHONE_NUMBER (1)",
        matches=[MatchSpan(start=8, end=24), MatchSpan(start=31, end=43), MatchSpan(start=48, end=64)],
    )
    scanner._analyzer.analyze.assert_called_once_with(
        text="Contact jane@example.com or +1-555-0100; backup jane@work.example",
        language="en",
        entities=["EMAIL_ADDRESS", "PHONE_NUMBER"],
    )


def test_presidio_pii_scanner_limits_rationale_to_first_five_entity_types(mocker) -> None:
    scanner = _build_scanner(mocker)
    scanner._analyzer.analyze.return_value = [
        _build_analyzer_result(mocker, f"TYPE_{index}", 0.5, index, index + 1) for index in range(6)
    ]

    result = scanner.scan("content")

    assert result.rationale == "PII detected (6 entity/ies): TYPE_0 (1), TYPE_1 (1), TYPE_2 (1), TYPE_3 (1), TYPE_4 (1)"


def _build_scanner(
    mocker,
    entities: list[str] | None = None,
    content_types: tuple[ContentType, ...] | list[str] | None = (ContentType.TEXT,),
) -> PresidioPiiScanner:
    provider = mocker.Mock()
    provider.create_engine.return_value = mocker.Mock()
    mocker.patch("cerbia.presidio.scanners.pii.NlpEngineProvider", return_value=provider)
    analyzer = mocker.Mock()
    mocker.patch("cerbia.presidio.scanners.pii.AnalyzerEngine", return_value=analyzer)

    return PresidioPiiScanner(
        entities=entities,
        content_types=content_types,
    )


def _build_analyzer_result(mocker, entity_type: str, score: float, start: int, end: int):
    return mocker.Mock(entity_type=entity_type, score=score, start=start, end=end)
