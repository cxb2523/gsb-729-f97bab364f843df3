import pytest
from cerbia.core.apis.systemone import NoulQuestion, SystemOneResponse
from cerbia.core.exceptions import CerbIAConfigError, CerbIAError
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.scanners import SystemOneScanner

pytestmark = pytest.mark.unit


def subject() -> SystemOneScanner:
    return SystemOneScanner({"q": NoulQuestion()}, "application_policy.evaluate_answers", "m")


def test_evaluator_receives_systemone_response_and_owns_risk(mocker) -> None:
    scanner = subject()
    response = mocker.Mock(spec=SystemOneResponse)
    ask = mocker.patch.object(scanner._api, "ask", return_value=response)
    outcome = ScanOutcome(risk_score=0.2, rationale="Application owned")
    evaluator = mocker.Mock(return_value=outcome)
    scanner._evaluator = evaluator

    assert scanner.scan("text") is outcome

    evaluator.assert_called_once_with(response)
    ask.assert_called_once_with("text", {"q": NoulQuestion()})


@pytest.mark.parametrize("path", ["literal", "application_policy.missing", "application_policy.__name__"])
def test_evaluator_configuration_rejects_invalid_import_or_callable(path: str) -> None:
    questions = {"q": NoulQuestion()}
    with pytest.raises(CerbIAConfigError):
        SystemOneScanner(questions, path, "m")


def test_evaluator_exception_keeps_cause_and_invalid_result_is_owned(mocker) -> None:
    scanner = subject()
    mocker.patch.object(scanner._api, "ask", return_value=mocker.Mock())
    original = RuntimeError("private application")

    def fail(response):
        raise original

    scanner._evaluator = fail

    with pytest.raises(CerbIAError, match="System One evaluator raised") as caught:
        scanner.scan("text")
    assert caught.value.__cause__ is original
    scanner._evaluator = lambda response: None
    with pytest.raises(CerbIAError, match="Evaluator must return ScanOutcome"):
        scanner.scan("text")


@pytest.mark.parametrize(
    "questions",
    [
        {},
        {"": {"type": "noul"}},
        {1: {"type": "noul"}},
        [{"type": "predicate", "name": "q"}],
        {"q": {"type": "predicate"}},
    ],
)
def test_question_boundary_rejects_invalid_ids_shape_and_other_protocol(questions) -> None:
    with pytest.raises(CerbIAConfigError, match="Invalid System One scanner questions"):
        SystemOneScanner(questions, "application_policy.evaluate_answers", "m")
