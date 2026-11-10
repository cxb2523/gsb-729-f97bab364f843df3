import json
from types import ModuleType

import httpx2
import pytest
from cerbia.core.apis import APIError
from cerbia.core.apis.decisions import DecisionsResponse
from cerbia.core.apis.systemone import SystemOneResponse
from cerbia.core.exceptions import CerbIAError
from cerbia.core.models.scans import MatchSpan, ScanOutcome
from cerbia.core.security_gate._execution import CompletedScan
from cerbia.core.security_gate._policy import OperationalFault, StageEvaluation, evaluate_stage
from cerbia.core.security_gate._stages import BuiltStage

from .cascade_contract_support import Contract, Fallback, Protocol, Response
from .protocol_support import MockHTTP, case

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("protocol", ["decisions", "systemone"])
@pytest.mark.parametrize("kind", ["choice"])
@pytest.mark.parametrize(
    ("risk", "terminal", "fallbacks"),
    [
        (0.20001, "fallback", 1),
    ],
    ids=[
        "above-defer-band",
    ],
)
def test_compatible_allow_boundary_or_defer_with_real_api(
    protocol: Protocol,
    kind: str,
    risk: float,
    terminal: str,
    fallbacks: int,
    mock_http: MockHTTP,
    application_policy: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    outcome = ScanOutcome(risk_score=risk, rationale="Evaluator", matches=[MatchSpan(start=1, end=3)])
    contract = Contract(protocol, outcome, kind)
    monkeypatch.setattr(application_policy, "evaluate_answers", contract.evaluate)
    mock_http(contract.handle)
    runner = contract.runner()
    retained: list[ScanOutcome] = []

    def observe(
        stage: BuiltStage,
        evidence: list[CompletedScan],
        *,
        final: bool = False,
    ) -> StageEvaluation | OperationalFault:
        retained.extend(scan.outcome for scan in evidence)
        return evaluate_stage(stage, evidence, final=final)

    monkeypatch.setattr("cerbia.core.security_gate._cascade.evaluate_stage", observe)
    # When
    entry = runner.scan().entry_results[0]
    # Then
    assert entry.findings[-1].stage == terminal
    assert entry.is_safe is (risk <= 0.9)
    fallback = runner.gate.scanners[-1]
    assert isinstance(fallback, Fallback)
    assert fallback.calls == fallbacks
    assert retained[0] is outcome
    assert len(contract.requests) == len(contract.evaluations) == 1
    assert isinstance(contract.evaluations[0], DecisionsResponse if protocol == "decisions" else SystemOneResponse)
    assert contract.evaluations[0].answers
    assert str(contract.requests[0].url) == f"https://assessment.test/gateway/v1/{protocol}"
    question, _ = case(protocol, kind)
    wire = json.loads(contract.requests[0].content)
    assert wire["questions"] == ([question] if protocol == "decisions" else {"q": question})
    assert wire["input" if protocol == "decisions" else "state"] == "evidence"
    assert entry.findings[0].matches == outcome.matches
    assert entry.stages is not None
    assert entry.stages[-1].result == ("allow" if fallbacks else "not_reached")


@pytest.mark.parametrize("protocol", ["decisions", "systemone"])
@pytest.mark.parametrize("mode", ["malformed", "evaluator"])
@pytest.mark.parametrize("policy", ["fail", "block"])
def test_failure_refusal_or_invalid_evidence_never_allows(
    protocol: Protocol,
    mode: str,
    policy: str,
    mock_http: MockHTTP,
    application_policy: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    contract = Contract(protocol, ScanOutcome(risk_score=0.19, rationale="opaque"), mode=mode)
    cause = RuntimeError("private evaluator detail")
    if mode == "transport":
        cause = httpx2.ConnectError("fixture transport")
        contract.error = cause
    elif mode == "evaluator":
        contract.error = cause

    def evaluate(response: Response) -> ScanOutcome | None:
        if mode == "invalid_type":
            return None
        return contract.evaluate(response)

    monkeypatch.setattr(application_policy, "evaluate_answers", evaluate)
    mock_http(contract.handle)
    runner = contract.runner(policy=policy)
    # When / Then
    if policy == "fail":
        with pytest.raises((APIError, CerbIAError)) as caught:
            runner.scan()
        if mode == "evaluator":
            assert caught.value.__cause__ is cause
        if mode == "transport":
            assert caught.value.__context__ is cause
    else:
        entry = runner.scan().entry_results[0]
        assert not entry.is_safe
        assert entry.aggregated_score == 1
        assert entry.findings == []
        assert entry.stages is not None
        assert entry.stages[0].result == "block"
        assert entry.stages[0].score is None
        assert entry.stages[1].result == "not_reached"
        assert "private evaluator detail" not in entry.model_dump_json()
    fallback = runner.gate.scanners[-1]
    assert isinstance(fallback, Fallback)
    assert fallback.calls == 0
    assert len(contract.requests) == 1
