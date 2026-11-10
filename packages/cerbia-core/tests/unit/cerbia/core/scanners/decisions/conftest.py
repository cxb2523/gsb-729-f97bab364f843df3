import sys
from collections.abc import Callable
from types import ModuleType

import httpx2
import pytest
from cerbia.core.apis.decisions import DecisionsResponse
from cerbia.core.apis.systemone import SystemOneResponse
from cerbia.core.models.scans import MatchSpan, ScanOutcome


@pytest.fixture
def evaluations() -> list[DecisionsResponse | SystemOneResponse]:
    return []


@pytest.fixture
def application_outcome() -> ScanOutcome:
    return ScanOutcome(risk_score=0.8, rationale="Application policy", matches=[MatchSpan(start=1, end=3)])


@pytest.fixture(autouse=True)
def application_policy(
    monkeypatch: pytest.MonkeyPatch,
    evaluations: list[DecisionsResponse | SystemOneResponse],
    application_outcome: ScanOutcome,
) -> ModuleType:
    module = ModuleType("application_policy")

    def evaluate_answers(response: DecisionsResponse | SystemOneResponse) -> ScanOutcome:
        evaluations.append(response)
        return application_outcome

    monkeypatch.setattr(module, "evaluate_answers", evaluate_answers, raising=False)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch) -> Callable[[Callable[[httpx2.Request], httpx2.Response]], None]:
    def install(handler: Callable[[httpx2.Request], httpx2.Response]) -> None:
        monkeypatch.setattr(httpx2.HTTPTransport, "handle_request", lambda self, request: handler(request))

    return install
