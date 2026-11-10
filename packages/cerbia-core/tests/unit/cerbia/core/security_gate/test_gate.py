import logging

import pytest
from cerbia.core.models.scans import MatchSpan, ScanOutcome, SkippedScanner
from cerbia.core.score_aggregators import MeanScoreAggregator
from cerbia.core.security_gate import SimpleGate
from cerbia.core.types import Action, ContentType, ScannerErrorPolicy, Severity

pytestmark = pytest.mark.unit


class _ScannerStub:
    def __init__(
        self,
        scanner_id: str,
        outcome: ScanOutcome,
        *,
        severity: Severity = Severity.MEDIUM,
        action: Action = Action.PASS,
        content_types: tuple[ContentType, ...] | None = None,
    ) -> None:
        self.scanner_id = scanner_id
        self.scanner_name = scanner_id.replace("-", " ").title()
        self.outcome = outcome
        self.severity = severity
        self.action = action
        self.content_types = content_types
        self.calls: list[str] = []
        self.error: BaseException | None = None

    def scan(self, text: str) -> ScanOutcome:
        self.calls.append(text)
        if self.error is not None:
            raise self.error
        return self.outcome


def scanner(identifier: str, score: float = 0.0, action: Action = Action.BLOCK) -> _ScannerStub:
    return _ScannerStub(
        identifier, ScanOutcome(risk_score=score, rationale="Synthetic"), severity=Severity.CRITICAL, action=action
    )


@pytest.mark.parametrize("fail_fast", [True, False])
def test_fail_fast_compares_finding_not_eventual_mean(fail_fast: bool) -> None:
    first, second = scanner("first", 0.8), scanner("second", 0.2)
    gate = SimpleGate("legacy", [first, second], MeanScoreAggregator(), threshold=0.6, fail_fast=fail_fast)

    verdict = gate.scan("synthetic")

    assert second.calls == ([] if fail_fast else ["synthetic"])
    assert verdict.score == (0.8 if fail_fast else 0.5)
    assert verdict.is_safe is (not fail_fast)


@pytest.mark.parametrize("score", [0.0, 1e-12, 1e-9, 1.01e-9])
def test_near_zero_is_aggregate_evidence_but_tolerated_by_fail_fast(score: float) -> None:
    first, second = scanner("first", score), scanner("second")
    gate = SimpleGate("legacy", [first, second], MeanScoreAggregator(), threshold=0.0)

    verdict = gate.scan("synthetic")

    assert second.calls == (["synthetic"] if score <= 1e-9 else [])
    assert verdict.score == score
    assert verdict.is_safe is (score == 0.0)


@pytest.mark.parametrize("fail_fast", [True, False])
def test_block_error_keeps_existing_evidence_and_execution_order(fail_fast: bool) -> None:
    failing, tail = scanner("failure"), scanner("tail")
    failing.error = RuntimeError("private failure")
    gate = SimpleGate(
        "legacy",
        [scanner("near-zero", 1e-12), failing, tail],
        MeanScoreAggregator(),
        fail_fast=fail_fast,
        on_scanner_error=ScannerErrorPolicy.BLOCK,
    )

    verdict = gate.scan("synthetic")

    assert not verdict.is_safe
    assert verdict.score == 1e-12
    assert verdict.rationale == "Scanner execution failed: Failure"
    assert [finding.scanner_id for finding in verdict.findings] == (
        ["near-zero"] if fail_fast else ["near-zero", "tail"]
    )
    assert "private failure" not in verdict.model_dump_json()
    assert verdict.skipped_scanners == []


def test_fail_policy_preserves_exception_and_cause_and_stops_tail() -> None:
    failing, tail = scanner("failure"), scanner("tail")
    cause = ValueError("private cause")
    error = RuntimeError("private failure")
    error.__cause__ = cause
    failing.error = error
    gate = SimpleGate("legacy", [failing, tail], MeanScoreAggregator(), on_scanner_error=ScannerErrorPolicy.FAIL)

    with pytest.raises(RuntimeError) as caught:
        gate.scan("synthetic")

    assert caught.value is error
    assert caught.value.__cause__ is cause
    assert tail.calls == []


def test_skip_policy_returns_sanitized_record_and_continues() -> None:
    failing, tail = scanner("failure"), scanner("tail")
    failing.error = RuntimeError("private failure")
    gate = SimpleGate("legacy", [failing, tail], MeanScoreAggregator(), on_scanner_error=ScannerErrorPolicy.SKIP)

    verdict = gate.scan("synthetic")

    assert verdict.is_safe
    assert tail.calls == ["synthetic"]
    assert [finding.scanner_id for finding in verdict.findings] == ["tail"]
    assert verdict.skipped_scanners == [
        SkippedScanner(scanner_id="failure", scanner_name="Failure", reason="scanner execution failed")
    ]


@pytest.mark.parametrize("policy", [ScannerErrorPolicy.BLOCK, ScannerErrorPolicy.SKIP])
def test_handled_failure_logs_no_input_exception_or_traceback(policy: ScannerErrorPolicy, caplog) -> None:
    failing = scanner("failure")
    failing.error = RuntimeError("synthetic-private-exception")
    gate = SimpleGate("policy", [failing, scanner("tail")], MeanScoreAggregator(), on_scanner_error=policy)

    with caplog.at_level(logging.ERROR, logger="cerbia"):
        verdict = gate.scan("synthetic-private-input")

    assert len(caplog.records) == 1
    assert caplog.records[0].exc_info is None
    assert "synthetic-private" not in caplog.text + verdict.model_dump_json()
    if policy is ScannerErrorPolicy.BLOCK:
        assert "Blocking gate due to error policy." in caplog.text


@pytest.mark.parametrize("content_type", [ContentType.UNKNOWN, ContentType.TEXT, ContentType.URL])
def test_content_routing_preserves_unknown_compatibility_and_skips_mismatch(content_type: ContentType) -> None:
    subject = scanner("text")
    subject.content_types = (ContentType.TEXT,)
    gate = SimpleGate("legacy", [subject], MeanScoreAggregator())

    verdict = gate.scan("synthetic", content_type=content_type)

    executes = content_type in (ContentType.UNKNOWN, ContentType.TEXT)
    assert subject.calls == (["synthetic"] if executes else [])
    assert len(verdict.findings) == int(executes)
    assert verdict.is_safe
    assert len(verdict.skipped_scanners) == int(not executes)


def test_empty_gate_returns_safe_without_aggregation(mocker) -> None:
    aggregator = mocker.Mock()

    verdict = SimpleGate("gate", [], aggregator).scan("synthetic")

    assert verdict.is_safe
    assert verdict.score == 0.0
    assert verdict.findings == []
    aggregator.compute.assert_not_called()


def test_completed_findings_keep_spans_and_warn_without_block_aggregation(mocker) -> None:
    subject = scanner("warning", 0.2, Action.WARN)
    subject.outcome.matches = [MatchSpan(start=2, end=5)]
    aggregator = mocker.Mock()

    verdict = SimpleGate("gate", [subject], aggregator).scan("synthetic")

    assert verdict.is_safe
    assert verdict.score == 0.0
    assert verdict.rationale == "Passed with warnings: Warning"
    assert verdict.findings[0].matches == [MatchSpan(start=2, end=5)]
    aggregator.compute.assert_not_called()


@pytest.mark.parametrize("threshold,safe", [(0.61, True), (0.6, False)])
def test_weighted_blocking_score_uses_legacy_threshold_equality(threshold: float, safe: bool, mocker) -> None:
    subject = scanner("blocking", 0.8)
    subject.severity = Severity.HIGH
    aggregator = mocker.Mock()
    aggregator.compute.return_value = 0.6
    gate = SimpleGate("gate", [subject], aggregator, threshold=threshold)

    verdict = gate.scan("synthetic")

    assert verdict.is_safe is safe
    assert verdict.score == 0.6
    aggregator.compute.assert_called_once_with([0.8 * 0.75])
