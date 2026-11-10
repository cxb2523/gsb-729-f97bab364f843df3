import pytest
from cerbia.core.models.scans import Finding, MatchSpan, ScanOutcome, SkippedScanner
from cerbia.core.security_gate._execution import CompletedScan, FailedScan, UnsupportedScan, execute_scanner
from cerbia.core.types import Action, ContentType, Severity
from pydantic import ValidationError

from .test_gate import _ScannerStub

pytestmark = pytest.mark.unit


class _ObservedScanner(_ScannerStub):
    def __init__(self, outcome: ScanOutcome) -> None:
        super().__init__("observed", outcome, severity=Severity.HIGH, action=Action.WARN)
        self.inputs: list[str] = []
        self.error: BaseException | None = None

    def scan(self, text: str) -> ScanOutcome:
        self.inputs.append(text)
        if self.error is not None:
            raise self.error
        return self.outcome


class _ExtendedOutcome(ScanOutcome):
    optional_metadata: str | None = None


@pytest.mark.parametrize("metadata", [None, "scanner-owned"])
@pytest.mark.parametrize("score", [0.0, 1e-12, 0.8])
def test_completed_retains_raw_outcome_when_optional_fields_are_present(metadata: str | None, score: float) -> None:
    # Given: scanner-owned optional metadata and intentionally non-sorted match spans.
    outcome = _ExtendedOutcome(
        risk_score=score,
        rationale="Synthetic",
        matches=[MatchSpan(start=7, end=9), MatchSpan(start=1, end=3)],
        optional_metadata=metadata,
    )
    before = outcome.model_dump_json()
    scanner = _ObservedScanner(outcome)
    # When: executing the scanner once.
    result = execute_scanner(scanner, "synthetic input", ContentType.TEXT)
    # Then: the raw object survives intact; finding fields remain unweighted and ordered.
    assert isinstance(result, CompletedScan)
    assert result.outcome is outcome
    assert result.outcome.model_dump_json() == before
    assert result.finding == Finding(
        scanner_id="observed",
        scanner_name="Observed",
        risk_score=score,
        severity=Severity.HIGH,
        action=Action.WARN,
        rationale="Synthetic",
        matches=outcome.matches,
    )
    assert scanner.inputs == ["synthetic input"]


@pytest.mark.parametrize("content_type", [ContentType.TEXT, ContentType.UNKNOWN])
def test_completed_executes_when_content_is_supported_or_unknown(content_type: ContentType) -> None:
    # Given: a text-only scanner.
    scanner = _ObservedScanner(ScanOutcome(risk_score=0.0, rationale="Safe"))
    scanner.content_types = (ContentType.TEXT,)
    # When: checking supported or legacy UNKNOWN routing.
    result = execute_scanner(scanner, "input", content_type)
    # Then: both invoke exactly once.
    assert isinstance(result, CompletedScan)
    assert result.outcome is scanner.outcome
    assert scanner.inputs == ["input"]


def test_unsupported_skips_invocation_when_content_is_incompatible() -> None:
    # Given: a text/code scanner and URL input.
    scanner = _ObservedScanner(ScanOutcome(risk_score=1.0, rationale="Unused"))
    scanner.content_types = (ContentType.TEXT, ContentType.CODE)
    # When: evaluating eligibility.
    result = execute_scanner(scanner, "https://example.com", ContentType.URL)
    # Then: the existing skip contract is returned without executing the scanner.
    assert result == UnsupportedScan(
        SkippedScanner(
            scanner_id="observed",
            scanner_name="Observed",
            reason="content_type 'url' not supported (accepts: text, code)",
        )
    )
    assert scanner.inputs == []


def test_failure_retains_original_error_when_scanner_raises(caplog: pytest.LogCaptureFixture) -> None:
    # Given: an exception with an existing cause and sensitive-looking synthetic text.
    scanner = _ObservedScanner(ScanOutcome(risk_score=0.0, rationale="Unused"))
    error = RuntimeError("synthetic private failure")
    cause = ValueError("synthetic cause")
    error.__cause__ = cause
    scanner.error = error
    # When: executing without any gate policy.
    result = execute_scanner(scanner, "input", ContentType.UNKNOWN)
    # Then: the original instance/cause survive and the helper emits no policy logs.
    assert isinstance(result, FailedScan)
    assert result.error is error
    assert result.error.__cause__ is cause
    assert scanner.inputs == ["input"]
    assert caplog.records == []


def test_failure_returns_validation_error_when_finding_construction_is_malformed() -> None:
    # Given: a plugin outcome mutated past its validated score boundary.
    scanner = _ObservedScanner(ScanOutcome(risk_score=0.0, rationale="Synthetic"))
    scanner.outcome.risk_score = 2.0
    # When: constructing the gate finding.
    result = execute_scanner(scanner, "input", ContentType.TEXT)
    # Then: construction errors remain operational failures, not fabricated threat findings.
    assert isinstance(result, FailedScan)
    assert isinstance(result.error, ValidationError)
    assert result.error.errors()[0]["loc"] == ("risk_score",)


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(2)])
def test_system_exception_propagates_when_plugin_interrupts(error: BaseException) -> None:
    # Given: a scanner interruption outside the legacy Exception boundary.
    scanner = _ObservedScanner(ScanOutcome(risk_score=0.0, rationale="Unused"))
    scanner.error = error
    # When: executing the plugin.
    with pytest.raises(type(error)) as raised:
        execute_scanner(scanner, "input", ContentType.TEXT)
    # Then: system exceptions are not converted into scanner failure data.
    assert raised.value is error


def test_completed_has_no_cross_entry_state_when_scanner_is_reused() -> None:
    # Given: an earlier completed execution.
    scanner = _ObservedScanner(ScanOutcome(risk_score=0.8, rationale="First"))
    first = execute_scanner(scanner, "first", ContentType.TEXT)
    scanner.outcome = ScanOutcome(risk_score=0.0, rationale="Second")
    # When: executing the same scanner for another input.
    second = execute_scanner(scanner, "second", ContentType.TEXT)
    # Then: each result owns only its entry's original outcome.
    assert isinstance(first, CompletedScan)
    assert isinstance(second, CompletedScan)
    assert first.outcome.risk_score == 0.8
    assert second.outcome is scanner.outcome
    assert second.finding.risk_score == 0.0
    assert scanner.inputs == ["first", "second"]
