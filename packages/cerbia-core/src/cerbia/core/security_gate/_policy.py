from dataclasses import dataclass
from typing import Annotated, Final, assert_never

from pydantic import Field, TypeAdapter, ValidationError

from ..types import Action
from ._errors import CascadeExecutionError
from ._execution import CompletedScan
from ._stages import BuiltStage
from ._trace import FailureCode, StageDecision

_SCORE: Final[TypeAdapter[float]] = TypeAdapter(
    Annotated[float, Field(strict=True, ge=0.0, le=1.0, allow_inf_nan=False)]
)


@dataclass(frozen=True, slots=True)
class StageEvaluation:
    score: float
    decision: StageDecision
    rationale: str


@dataclass(frozen=True, slots=True)
class OperationalFault:
    error: Exception
    category: FailureCode


def aggregate_scores(stage: BuiltStage, scores: list[float]) -> float | OperationalFault:
    if stage.score_aggregator is None:
        return OperationalFault(
            CascadeExecutionError(stage.config.id, FailureCode.MISSING_EVIDENCE), FailureCode.MISSING_EVIDENCE
        )

    try:
        score = stage.score_aggregator.compute(scores)
    except Exception as error:
        # Third-party aggregators have no exception contract; fail must preserve the exact exception.
        return OperationalFault(error, FailureCode.AGGREGATOR_ERROR)

    try:
        return _SCORE.validate_python(score)
    except ValidationError as error:
        fault = CascadeExecutionError(stage.config.id, FailureCode.INVALID_AGGREGATE)
        fault.__cause__ = error
        return OperationalFault(fault, FailureCode.INVALID_AGGREGATE)


def evaluate_stage(
    stage: BuiltStage,
    own: list[CompletedScan],
    *,
    final: bool = False,
) -> StageEvaluation | OperationalFault:
    config = stage.config
    if stage.score_aggregator is None:
        return OperationalFault(
            CascadeExecutionError(config.id, FailureCode.MISSING_EVIDENCE), FailureCode.MISSING_EVIDENCE
        )

    scores = [
        scan.outcome.risk_score * scan.finding.severity.weight
        for scan in own
        if scan.finding.action == Action.BLOCK and scan.outcome.risk_score > 0
    ]

    score = 0.0
    if scores:
        aggregate = aggregate_scores(stage, scores)
        match aggregate:
            case OperationalFault():
                return aggregate
            case float() | int():
                score = aggregate
            case unreachable:
                assert_never(unreachable)

    if score > config.threshold:
        return StageEvaluation(score, StageDecision.BLOCK, "Score exceeds threshold")
    if final:
        return StageEvaluation(score, StageDecision.ALLOW, "Final stage score does not exceed threshold")

    if config.defer_above is not None and score > config.defer_above:
        return StageEvaluation(score, StageDecision.DEFER, "Score exceeds defer boundary")

    return StageEvaluation(score, StageDecision.ALLOW, "Score is within allow band")
