from types import ModuleType

import pytest
from cerbia.core.apis.decisions import DecisionsResponse, PredicateQuestion
from cerbia.core.exceptions import CerbIAConfigError, CerbIAError
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.scanners import DecisionsScanner

pytestmark = pytest.mark.unit


def subject() -> DecisionsScanner:
    return DecisionsScanner(
        [PredicateQuestion(name="q", instructions="Assess")], "application_policy.evaluate_answers", "m"
    )


def test_evaluator_resolved_once_receives_typed_response_and_returns_own_outcome(
    application_policy: ModuleType, monkeypatch: pytest.MonkeyPatch, mocker, application_outcome: ScanOutcome
) -> None:
    scanner = subject()
    response = mocker.Mock(spec=DecisionsResponse)
    ask = mocker.patch.object(scanner._api, "ask", return_value=response)
    evaluations = []
    scanner._evaluator = lambda result: evaluations.append(result) or application_outcome
    monkeypatch.setattr(application_policy, "evaluate_answers", lambda response: pytest.fail("resolved again"))

    assert scanner.scan("first") is application_outcome
    assert scanner.scan("second") is application_outcome

    assert evaluations == [response, response]
    assert ask.call_count == 2
    assert scanner._questions == (PredicateQuestion(name="q", instructions="Assess"),)


@pytest.mark.parametrize(
    "path,cause",
    [
        ("literal", None),
        ("missing_policy.evaluate", ModuleNotFoundError),
        ("application_policy.missing", AttributeError),
        ("application_policy.__name__", None),
        (None, AttributeError),
    ],
)
def test_invalid_evaluator_configuration_is_owned_and_chained(path, cause) -> None:
    questions = [PredicateQuestion(name="q", instructions="Assess")]
    with pytest.raises(CerbIAConfigError) as caught:
        DecisionsScanner(questions, path, "m")
    if cause is not None:
        assert isinstance(caught.value.__cause__, cause)
    assert "missing_policy" not in str(caught.value)


def test_evaluator_import_failure_keeps_original_cause(monkeypatch: pytest.MonkeyPatch) -> None:
    original = RuntimeError("private import")

    def fail(name):
        raise original

    monkeypatch.setattr("importlib.import_module", fail)

    with pytest.raises(CerbIAConfigError, match="Could not import evaluator") as caught:
        subject()
    assert caught.value.__cause__ is original


@pytest.mark.parametrize("invalid", [None, {"risk_score": 0, "rationale": "private"}])
def test_evaluator_must_return_scan_outcome(invalid, mocker) -> None:
    scanner = subject()
    mocker.patch.object(scanner._api, "ask", return_value=mocker.Mock())
    scanner._evaluator = lambda response: invalid

    with pytest.raises(CerbIAError, match="^Evaluator must return ScanOutcome$"):
        scanner.scan("text")


def test_evaluator_exception_is_chained_but_api_exception_propagates(mocker) -> None:
    scanner = subject()
    original = RuntimeError("private evaluator")

    def fail(response):
        raise original

    scanner._evaluator = fail
    mocker.patch.object(scanner._api, "ask", return_value=mocker.Mock())

    with pytest.raises(CerbIAError, match="Decision evaluator raised") as caught:
        scanner.scan("text")
    assert caught.value.__cause__ is original
    mocker.patch.object(scanner._api, "ask", side_effect=original)
    with pytest.raises(RuntimeError) as caught:
        scanner.scan("text")
    assert caught.value is original


@pytest.mark.parametrize("count", [1, 400])
def test_question_count_boundary_accepts_supported_count(count: int) -> None:
    questions = [PredicateQuestion(name=f"q{index}", instructions="Assess") for index in range(count)]
    scanner = DecisionsScanner(questions, "application_policy.evaluate_answers", "m")
    assert scanner._questions == tuple(questions)


@pytest.mark.parametrize(
    "questions",
    [
        [],
        [{"type": "predicate", "name": "q", "instructions": "Assess"}] * 2,
        [{"type": "predicate", "name": f"q{index}", "instructions": "Assess"} for index in range(401)],
        {"q": {"type": "noul"}},
    ],
)
def test_question_topology_rejects_empty_duplicate_over_limit_and_other_protocol(questions) -> None:
    with pytest.raises(CerbIAConfigError, match="Invalid Decisions scanner questions"):
        DecisionsScanner(questions, "application_policy.evaluate_answers", "m")
