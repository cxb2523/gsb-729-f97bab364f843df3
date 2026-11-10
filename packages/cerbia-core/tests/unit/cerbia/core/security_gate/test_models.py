import pytest
from cerbia.core.models.stages import StageResult
from cerbia.core.security_gate import GateVerdict
from pydantic import ValidationError

pytestmark = pytest.mark.unit


def test_simple_verdict_preserves_explicit_null_stage_wire_contract() -> None:
    result = GateVerdict(is_safe=True, score=0.0, rationale="All scanners passed", findings=[], skipped_scanners=[])

    assert result.model_dump_json() == (
        '{"is_safe":true,"score":0.0,"rationale":"All scanners passed",'
        '"findings":[],"skipped_scanners":[],"stages":null}'
    )


def test_gate_verdict_invokes_stage_ownership_validator() -> None:
    stages = (StageResult(id="last", result="block", score=0.6),)
    with pytest.raises(ValidationError, match="stage terminal result must match verdict"):
        GateVerdict(
            is_safe=True,
            score=0.6,
            rationale="retained",
            findings=[],
            skipped_scanners=[],
            stages=stages,
        )


def test_operational_block_roundtrips_only_bounded_stage_summary() -> None:
    result = GateVerdict.model_validate(
        {
            "is_safe": False,
            "score": 1.0,
            "rationale": "Cascade stage first: scanner_error",
            "findings": [],
            "skipped_scanners": [],
            "stages": [{"id": "first", "result": "block"}, {"id": "final", "result": "not_reached"}],
        }
    )

    assert result.model_dump(mode="json")["stages"] == [
        {"id": "first", "result": "block"},
        {"id": "final", "result": "not_reached"},
    ]
    assert GateVerdict.model_validate_json(result.model_dump_json()) == result
