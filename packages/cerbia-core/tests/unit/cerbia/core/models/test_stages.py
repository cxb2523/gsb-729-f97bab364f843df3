from copy import deepcopy

import pytest
from cerbia.core.models.scans import SkippedScanner
from cerbia.core.models.stages import StageResult, validate_stages
from cerbia.core.security_gate import GateVerdict
from pydantic import ValidationError

pytestmark = pytest.mark.unit


def verdict() -> GateVerdict:
    return GateVerdict.model_validate(
        {
            "is_safe": False,
            "score": 0.6,
            "rationale": "retained",
            "findings": [
                {
                    "scanner_id": scanner,
                    "scanner_name": scanner,
                    "risk_score": score,
                    "severity": "critical",
                    "action": "block",
                    "rationale": "retained",
                    "stage": stage,
                }
                for scanner, score, stage in [("a", 0.6, "first"), ("b", 0.0, "final")]
            ],
            "skipped_scanners": [],
            "stages": [
                {"id": "first", "result": "defer", "score": 0.6},
                {"id": "final", "result": "block", "score": 0.6},
            ],
        }
    )


@pytest.mark.parametrize("result,score", [("allow", None), ("defer", None), ("not_reached", 0.1)])
def test_stage_score_must_match_disposition(result: str, score: float | None) -> None:
    with pytest.raises(ValidationError, match="stage_score"):
        StageResult.model_validate({"id": "stage", "result": result, "score": score})


@pytest.mark.parametrize("result", ["block", "not_reached"])
def test_unscored_stage_serializes_without_score(result: str) -> None:
    stage = StageResult.model_validate({"id": "stage", "result": result})

    assert stage.model_dump(mode="json") == {"id": "stage", "result": result}


@pytest.mark.parametrize("field", ["text", "evidence_from", "finding_indexes"])
def test_public_stage_does_not_accept_private_provenance(field: str) -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        StageResult.model_validate({"id": "stage", "result": "allow", "score": 0.0, field: "private"})


@pytest.mark.parametrize("case", ["empty", "no_terminal", "unreached_first", "after_terminal", "duplicate_id"])
def test_stage_validator_rejects_inconsistent_routing(case: str) -> None:
    result = verdict()
    stages = list(result.stages or ())
    match case:
        case "empty":
            stages = []
        case "no_terminal":
            stages = stages[:1]
        case "unreached_first":
            stages = [StageResult(id="first", result="not_reached")]
        case "after_terminal":
            stages[0] = StageResult(id="first", result="allow", score=0.6)
        case "duplicate_id":
            stages[1] = StageResult(id="first", result="block", score=0.6)
    result.stages = tuple(stages)

    with pytest.raises(ValueError):
        validate_stages(result, result.score)


@pytest.mark.parametrize(
    "case", ["missing", "unknown", "reverse", "duplicate", "not_reached", "safe", "score", "skipped"]
)
def test_stage_validator_rejects_ownership_or_terminal_mismatch(case: str) -> None:
    result = verdict()
    match case:
        case "missing":
            result.findings[0].stage = None
        case "unknown":
            result.findings[0].stage = "unknown"
        case "reverse":
            result.findings.reverse()
        case "duplicate":
            result.findings.append(deepcopy(result.findings[-1]))
        case "not_reached":
            result.stages = (
                StageResult(id="first", result="block", score=0.6),
                StageResult(id="final", result="not_reached"),
            )
        case "safe":
            result.is_safe = True
        case "score":
            result.score = 0.7
        case "skipped":
            result.skipped_scanners = [SkippedScanner(scanner_id="other", scanner_name="Other", reason="unknown owner")]

    with pytest.raises(ValueError):
        validate_stages(result, result.score)


def test_simple_result_rejects_stage_owned_finding() -> None:
    result = verdict()
    result.stages = None

    with pytest.raises(ValueError, match="simple findings must omit stage"):
        validate_stages(result, result.score)
