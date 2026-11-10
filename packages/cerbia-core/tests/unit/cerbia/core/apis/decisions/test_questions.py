import pytest
from cerbia.core.apis.decisions import ChoiceQuestion, PredicateQuestion, ScoreQuestion
from pydantic import ValidationError

pytestmark = pytest.mark.unit


def test_choice_options_require_unique_values_but_distinguish_boolean_from_string() -> None:
    raw = {"name": "q", "instructions": "Choose", "choices": [{"value": True}, {"value": "true"}]}

    question = ChoiceQuestion.model_validate(raw)

    assert [option.value for option in question.choices] == [True, "true"]
    raw["choices"] = [{"value": "a"}, {"value": "a"}]
    with pytest.raises(ValidationError, match="Duplicate entries"):
        ChoiceQuestion.model_validate(raw)


@pytest.mark.parametrize("count", [1, 11])
def test_score_rubric_rejects_outside_product_level_limits(count: int) -> None:
    with pytest.raises(ValidationError):
        ScoreQuestion.model_validate(
            {"name": "q", "instructions": "Score", "levels": [{"label": str(i)} for i in range(count)]}
        )


def test_question_boundary_hides_untrusted_extra_metadata() -> None:
    with pytest.raises(ValidationError) as caught:
        PredicateQuestion.model_validate({"name": "q", "instructions": "Assess", "extra": "private-input"})
    assert "private-input" not in str(caught.value)
