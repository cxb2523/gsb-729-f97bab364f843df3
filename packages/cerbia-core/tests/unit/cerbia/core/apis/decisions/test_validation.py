from copy import deepcopy
from typing import TypedDict

import pytest
from cerbia.core.apis.decisions import DecisionsResponse
from cerbia.core.apis.decisions._questions import ChoiceQuestion, PredicateQuestion, ScoreQuestion
from cerbia.core.apis.decisions._validation import validate_decisions
from pydantic import JsonValue

pytestmark = pytest.mark.unit


class Payload(TypedDict):
    model: str
    answers: list[dict[str, JsonValue]]
    usage: dict[str, JsonValue]


def payload() -> Payload:
    return {
        "model": "m",
        "answers": [
            {"type": "predicate", "name": "p", "probability": 0.2},
            {
                "type": "choice",
                "name": "c",
                "choice": True,
                "confidence": 0.1,
                "probabilities": [{"value": True, "probability": 0.8}, {"value": "true", "probability": 0.2}],
            },
            {
                "type": "score",
                "name": "s",
                "score": 0.8,
                "confidence": 0.1,
                "probabilities": [
                    {"value": 0, "label": "Low", "probability": 0.2},
                    {"value": 1, "label": "High", "probability": 0.8},
                ],
            },
        ],
        "usage": {
            "input_tokens": 1,
            "output_tokens": 0,
            "total_tokens": 1,
            "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
            "output_tokens_details": {"reasoning_tokens": 0},
        },
    }


def questions() -> list[ChoiceQuestion | PredicateQuestion | ScoreQuestion]:
    return [
        PredicateQuestion(name="p", instructions="Assess"),
        ChoiceQuestion.model_validate(
            {"name": "c", "instructions": "Choose", "choices": [{"value": True}, {"value": "true"}]}
        ),
        ScoreQuestion.model_validate(
            {"name": "s", "instructions": "Score", "levels": [{"label": "Low"}, {"label": "High"}]}
        ),
    ]


def test_validator_preserves_out_of_order_answers_and_boolean_string_choice_identity() -> None:
    raw = payload()
    raw["answers"].reverse()
    response = DecisionsResponse.model_validate(raw)

    validate_decisions(questions(), response)

    assert response.model_dump(mode="json") == raw


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "duplicate_id",
        "type",
        "refusal",
        "choice_domain",
        "nonmax_choice",
        "sum",
        "score",
        "score_domain",
        "rubric",
    ],
)
def test_protocol_validator_rejects_inconsistent_answers(case: str) -> None:
    raw = deepcopy(payload())
    answers = raw["answers"]
    choice_probabilities = answers[1]["probabilities"]
    score_probabilities = answers[2]["probabilities"]
    assert isinstance(choice_probabilities, list)
    assert isinstance(choice_probabilities[1], dict)
    assert isinstance(score_probabilities, list)
    assert isinstance(score_probabilities[1], dict)
    if case == "missing":
        answers.pop()
    elif case == "duplicate_id":
        answers.append(deepcopy(answers[0]))
    elif case == "type":
        answers[0] = {"type": "refusal", "name": "p"}
    elif case == "refusal":
        answers[0] = {"type": "refusal", "name": None}
    elif case == "choice_domain":
        choice_probabilities[1]["value"] = "other"
    elif case == "nonmax_choice":
        answers[1]["choice"] = "true"
    elif case == "sum":
        choice_probabilities[1]["probability"] = 0.3
    elif case == "score":
        answers[2]["score"] = 0.5
    elif case == "score_domain":
        score_probabilities[1]["value"] = 2
    else:
        score_probabilities[1]["label"] = "Wrong"

    configured_questions = questions()
    response = DecisionsResponse.model_validate(raw)
    with pytest.raises(ValueError):
        validate_decisions(configured_questions, response)


@pytest.mark.parametrize("answer_index", [1, 2], ids=["duplicate_choice_value", "duplicate_score_index"])
def test_validator_rejects_duplicate_probability_keys_before_dictionary_collapse(answer_index: int) -> None:
    # Given: collapsing the duplicate would leave the original valid distribution and rubric.
    raw = payload()
    probabilities = raw["answers"][answer_index]["probabilities"]
    assert isinstance(probabilities, list)
    probabilities.append(deepcopy(probabilities[0]))
    response = DecisionsResponse.model_validate(raw)
    configured_questions = questions()

    # When / Then: our uniqueness guard rejects the successfully parsed response.
    with pytest.raises(ValueError, match="^Duplicate entries$"):
        validate_decisions(configured_questions, response)
