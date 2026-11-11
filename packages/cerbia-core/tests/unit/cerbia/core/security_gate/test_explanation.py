import pytest
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.score_aggregators import MeanScoreAggregator
from cerbia.core.security_gate import (
    ExclusionReason,
    GateVerdict,
    SimpleGate,
    explain_gate_score,
)
from cerbia.core.types import Action, ScannerErrorPolicy, Severity

pytestmark = pytest.mark.unit


class _ScannerStub:
    def __init__(
        self,
        scanner_id: str,
        outcome: ScanOutcome,
        *,
        severity: Severity = Severity.CRITICAL,
        action: Action = Action.BLOCK,
    ) -> None:
        self.scanner_id = scanner_id
        self.scanner_name = scanner_id.replace("-", " ").title()
        self.outcome = outcome
        self.severity = severity
        self.action = action
        self.content_types = None
        self.error: BaseException | None = None

    def scan(self, text: str) -> ScanOutcome:
        if self.error is not None:
            raise self.error
        return self.outcome


def scanner(
    identifier: str,
    score: float = 0.0,
    action: Action = Action.BLOCK,
    severity: Severity = Severity.CRITICAL,
) -> _ScannerStub:
    return _ScannerStub(
        identifier, ScanOutcome(risk_score=score, rationale="Synthetic"), severity=severity, action=action
    )


def test_explanation_matches_verdict_and_contributions_sum_to_one() -> None:
    gate = SimpleGate(
        "gate",
        [
            scanner("blocker", 0.8, severity=Severity.CRITICAL),
            scanner("second-blocker", 0.4, severity=Severity.HIGH),
            scanner("warner", 0.9, action=Action.WARN),
            scanner("zero", 0.0),
        ],
        MeanScoreAggregator(),
        fail_fast=False,
        threshold=0.5,
    )

    verdict = gate.scan("synthetic input")
    explanation = verdict.explanation

    assert explanation is not None
    assert explanation.total_score == verdict.score == pytest.approx(0.55)
    assert explanation.is_safe is verdict.is_safe is False
    assert explanation.threshold == 0.5
    assert explanation.forced_unsafe is False
    assert explanation.scanner_failures == []

    counted = {item.scanner_id: item for item in explanation.counted_findings}
    assert set(counted) == {"blocker", "second-blocker"}
    assert counted["blocker"].risk_score == 0.8
    assert counted["blocker"].severity is Severity.CRITICAL
    assert counted["blocker"].weight == 1.0
    assert counted["blocker"].weighted_score == pytest.approx(0.8)
    assert counted["blocker"].near_zero is False
    assert counted["second-blocker"].severity is Severity.HIGH
    assert counted["second-blocker"].weight == 0.75
    assert counted["second-blocker"].weighted_score == pytest.approx(0.3)
    assert counted["blocker"].contribution == pytest.approx(0.8 / 1.1)
    assert sum(item.contribution for item in counted.values()) == pytest.approx(1.0)

    excluded = {item.scanner_id: item for item in explanation.excluded_findings}
    assert set(excluded) == {"warner", "zero"}
    assert excluded["warner"].reason is ExclusionReason.ACTION_NOT_BLOCK
    assert excluded["warner"].action is Action.WARN
    assert excluded["zero"].reason is ExclusionReason.ZERO_RISK_SCORE

    assert explain_gate_score(verdict, 0.5) == explanation
    assert GateVerdict.model_validate_json(verdict.model_dump_json()) == verdict


def test_scanner_failure_marks_forced_unsafe_without_leaking_details() -> None:
    failing = scanner("failure")
    failing.error = RuntimeError("private-exception-detail")
    gate = SimpleGate("gate", [failing], MeanScoreAggregator(), on_scanner_error=ScannerErrorPolicy.BLOCK)

    verdict = gate.scan("sensitive-input-text")
    explanation = verdict.explanation

    assert verdict.is_safe is False
    assert explanation is not None
    assert explanation.is_safe is False
    assert explanation.total_score == verdict.score == 0.0
    assert explanation.forced_unsafe is True
    assert explanation.scanner_failures == ["Failure"]
    assert explanation.counted_findings == []

    payload = verdict.model_dump_json()
    assert "private-exception-detail" not in payload
    assert "sensitive-input-text" not in payload


def test_empty_gate_produces_zero_score_explanation() -> None:
    verdict = SimpleGate("gate", [], MeanScoreAggregator()).scan("synthetic")
    explanation = verdict.explanation

    assert verdict.is_safe is True
    assert explanation is not None
    assert explanation.total_score == 0.0
    assert explanation.is_safe is True
    assert explanation.counted_findings == []
    assert explanation.excluded_findings == []
    assert explanation.forced_unsafe is False


def test_all_findings_excluded_produces_zero_score_explanation() -> None:
    gate = SimpleGate(
        "gate",
        [scanner("warner", 0.9, action=Action.WARN), scanner("zero", 0.0)],
        MeanScoreAggregator(),
        fail_fast=False,
        threshold=0.5,
    )

    verdict = gate.scan("synthetic")
    explanation = verdict.explanation

    assert explanation is not None
    assert explanation.total_score == verdict.score == 0.0
    assert explanation.is_safe is verdict.is_safe is True
    assert explanation.counted_findings == []
    assert len(explanation.excluded_findings) == 2


def test_near_zero_block_finding_is_counted_and_flagged() -> None:
    gate = SimpleGate("gate", [scanner("tiny", 1e-12)], MeanScoreAggregator(), threshold=0.0)

    verdict = gate.scan("synthetic")
    explanation = verdict.explanation

    assert explanation is not None
    assert explanation.total_score == verdict.score == 1e-12
    assert explanation.is_safe is verdict.is_safe is False
    assert len(explanation.counted_findings) == 1
    assert explanation.counted_findings[0].near_zero is True
    assert explanation.counted_findings[0].contribution == 1.0
    assert explanation.excluded_findings == []


def test_verdict_defaults_to_no_explanation_and_omits_it_from_json() -> None:
    verdict = GateVerdict(is_safe=True, score=0.0, rationale="All scanners passed", findings=[], skipped_scanners=[])

    assert verdict.explanation is None
    assert "explanation" not in verdict.model_dump_json()


def test_pure_function_infers_scanner_failures_from_rationale() -> None:
    verdict = GateVerdict(
        is_safe=False,
        score=0.0,
        rationale="Scanner execution failed: Failure",
        findings=[],
        skipped_scanners=[],
    )

    explanation = explain_gate_score(verdict, 0.0)

    assert explanation.is_safe is False
    assert explanation.forced_unsafe is True
    assert explanation.scanner_failures == ["Failure"]
