import pytest
from cerbia.core.config import CascadeStageConfig, ScannerConfig, ScoreAggregatorConfig
from cerbia.core.models.scans import Finding, ScanOutcome
from cerbia.core.score_aggregators import MaxScoreAggregator, MaxWithBonusScoreAggregator, MeanScoreAggregator
from cerbia.core.security_gate._execution import CompletedScan
from cerbia.core.security_gate._policy import OperationalFault, StageEvaluation, aggregate_scores, evaluate_stage
from cerbia.core.security_gate._stages import BuiltStage
from cerbia.core.types import Action, Severity
from pydantic import JsonValue

from .cascade_support import Aggregate

pytestmark = pytest.mark.unit


def built(aggregator=None) -> BuiltStage:
    return BuiltStage(
        CascadeStageConfig(
            id="policy",
            scanners=[ScannerConfig(scanner="custom.Scanner")],
            score_aggregator=ScoreAggregatorConfig(score_aggregator="custom.Aggregator"),
            threshold=0.9,
            defer_above=0.2,
        ),
        (),
        aggregator,
    )


def completed(risk: float, action: Action = Action.BLOCK, severity: Severity = Severity.CRITICAL) -> CompletedScan:
    return CompletedScan(
        finding=Finding(
            scanner_id="a", scanner_name="a", risk_score=risk, action=action, severity=severity, rationale="local"
        ),
        outcome=ScanOutcome(risk_score=risk, rationale="local"),
    )


@pytest.mark.parametrize("risk,severity,score", [(0.6, Severity.CRITICAL, 0.6), (0.8, Severity.LOW, 0.2)])
def test_policy_weights_only_positive_block_evidence(risk: float, severity: Severity, score: float) -> None:
    result = evaluate_stage(
        built(MaxScoreAggregator()),
        [completed(risk, severity=severity), completed(1.0, Action.WARN), completed(1.0, Action.PASS)],
        final=True,
    )

    assert isinstance(result, StageEvaluation)
    assert result.score == score
    assert result.decision == "allow"


def test_zero_evidence_does_not_invoke_plugin() -> None:
    Aggregate.inputs.clear()

    result = evaluate_stage(built(Aggregate()), [completed(0.0), completed(1.0, Action.WARN)], final=True)

    assert isinstance(result, StageEvaluation)
    assert result.score == 0.0
    assert Aggregate.inputs == []


@pytest.mark.parametrize(
    "aggregator,score",
    [(MaxScoreAggregator(), 0.8), (MeanScoreAggregator(), 0.5), (MaxWithBonusScoreAggregator(), 0.85)],
)
def test_policy_uses_configured_real_aggregation_strategy(aggregator, score: float) -> None:
    result = evaluate_stage(built(aggregator), [completed(0.8), completed(0.2)], final=True)

    assert isinstance(result, StageEvaluation)
    assert result.score == pytest.approx(score)


@pytest.mark.parametrize("risk,safe", [(0.0, True), (0.9, True), (0.90001, False)])
def test_final_policy_never_defers_and_allows_threshold_equality(risk: float, safe: bool) -> None:
    result = evaluate_stage(built(MaxScoreAggregator()), [completed(risk)], final=True)

    assert isinstance(result, StageEvaluation)
    assert result.decision == ("allow" if safe else "block")


@pytest.mark.parametrize("invalid", [True, float("nan"), float("inf"), -0.1, 1.01, "0.5", None])
def test_plugin_boundary_rejects_malformed_scores(invalid: JsonValue, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Aggregate, "result", invalid)
    monkeypatch.setattr(Aggregate, "error", None)

    result = aggregate_scores(built(Aggregate()), [0.5])

    assert isinstance(result, OperationalFault)
    assert result.category == "invalid_aggregate"
    assert result.error.__cause__ is not None


def test_missing_aggregator_produces_owned_operational_fault() -> None:
    result = evaluate_stage(built(), [completed(0.5)], final=True)

    assert isinstance(result, OperationalFault)
    assert result.category == "missing_evidence"
