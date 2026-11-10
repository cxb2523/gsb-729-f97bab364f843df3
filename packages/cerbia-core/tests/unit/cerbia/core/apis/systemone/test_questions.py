import pytest
from cerbia.core.apis.systemone import NoulQuestion, SystemOneChoiceQuestion, SystemOneScoreQuestion
from pydantic import ValidationError

pytestmark = pytest.mark.unit


def test_text_descriptions_and_optional_noul_criteria_survive_wire_serialization() -> None:
    raw = {"instructions": "Assess", "criteria": {"true": "Allowed", "false": None}}
    question = NoulQuestion.model_validate(raw)

    assert question.model_dump(mode="json", exclude_unset=True) == raw
    assert NoulQuestion().model_dump(mode="json", exclude_unset=True) == {}


@pytest.mark.parametrize(
    "model,payload",
    [
        (NoulQuestion, {"instructions": {"nested": [float("nan")]}}),
        (SystemOneChoiceQuestion, {"criteria": {"a": True}}),
        (SystemOneChoiceQuestion, {"criteria": {"": "Description"}}),
        (SystemOneScoreQuestion, {"criteria": [None, "High"]}),
        (SystemOneScoreQuestion, {"criteria": ["Only"]}),
    ],
)
def test_question_consumer_boundary_rejects_invalid_descriptions_ids_and_rubrics(model, payload) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)
