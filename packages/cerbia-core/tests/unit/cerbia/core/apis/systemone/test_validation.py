import pytest
from cerbia.core.apis.systemone import NoulQuestion, SystemOneChoiceQuestion, SystemOneResponse, SystemOneScoreQuestion
from cerbia.core.apis.systemone._validation import validate_systemone
from pydantic import JsonValue

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("case", ["valid", "ids", "domain", "choice", "sum", "score", "legend"])
def test_systemone_validator_correlates_ids_domains_distribution_and_legend(case: str) -> None:
    questions = {
        "p": NoulQuestion(),
        "c": SystemOneChoiceQuestion(criteria={"a": None, "b": None}),
        "s": SystemOneScoreQuestion(criteria=("Low", "High")),
    }
    answers: dict[str, JsonValue] = {
        "p": {"type": "noul", "noul": 0.1},
        "c": {"type": "choice", "choice": "a", "confidence": 0.1, "probabilities": {"a": 0.8, "b": 0.2}},
        "s": {
            "type": "score",
            "score": 0.8,
            "confidence": 0.1,
            "probabilities": {"0": 0.2, "1": 0.8},
            "legend": {"0": "Low", "1": "High"},
        },
    }
    choice = answers["c"]
    score = answers["s"]
    assert isinstance(choice, dict)
    assert isinstance(score, dict)
    if case == "ids":
        answers.pop("p")
    elif case == "domain":
        choice["probabilities"] = {"a": 0.8, "other": 0.2}
    elif case == "choice":
        choice["choice"] = "b"
    elif case == "sum":
        probabilities = choice["probabilities"]
        assert isinstance(probabilities, dict)
        probabilities["b"] = 0.3
    elif case == "score":
        score["score"] = 0.5
    elif case == "legend":
        score["legend"] = {"0": "Low", "1": "Wrong"}
    response = SystemOneResponse.model_validate(
        {"model": "m", "answers": answers, "usage": {"input_tokens": 1, "output_tokens": 0}}
    )

    if case == "valid":
        validate_systemone(questions, response)
    else:
        with pytest.raises(ValueError):
            validate_systemone(questions, response)
