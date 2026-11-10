from collections.abc import Callable

import httpx2
import pytest
import yaml
from cerbia.core.config import SimpleGateConfig
from cerbia.core.factories import ScannerFactory
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.runner import Runner
from pydantic import JsonValue

type MockHTTP = Callable[[Callable[[httpx2.Request], httpx2.Response]], None]
pytestmark = pytest.mark.integration


def api_key() -> str:
    return "yaml-test-key"


@pytest.mark.parametrize("format,kind", [("decisions", "predicate"), ("systemone", "noul")])
@pytest.mark.parametrize("authenticated", [False, True])
@pytest.mark.parametrize("base_path", ["", "/gateway"])
@pytest.mark.parametrize("trailing_slash", ["/"])
def test_auth_when_yaml_builds_runner_and_factory(
    mock_http: MockHTTP,
    format: str,
    kind: str,
    authenticated: bool,
    application_outcome: ScanOutcome,
    base_path: str,
    trailing_slash: str,
) -> None:
    # Given: all constructor arguments come from ordinary YAML values.
    auth = f"api_key_provider: {__name__}.api_key" if authenticated else ""
    questions = (
        "[{type: predicate, name: q, instructions: Assess}]"
        if format == "decisions"
        else "{q: {type: noul, instructions: Assess}}"
    )
    config = SimpleGateConfig.model_validate(
        yaml.safe_load(f"""
name: yaml-decisions
loaders:
  - loader: cerbia.core.loaders.TextLoader
    init_args:
      texts: [evidence]
scanners:
  - scanner: cerbia.core.scanners.{format}.{"DecisionsScanner" if format == "decisions" else "SystemOneScanner"}
    init_args:
      model: m
      base_url: https://assessment.test{base_path}{trailing_slash}
      {auth}
      questions: {questions}
      evaluator: application_policy.evaluate_answers
score_aggregator:
  score_aggregator: cerbia.core.score_aggregators.MaxScoreAggregator
""")
    )
    requests: list[httpx2.Request] = []
    usage: dict[str, JsonValue] = {"input_tokens": 1, "output_tokens": 0}
    if format == "decisions":
        usage.update(
            total_tokens=1,
            input_tokens_details={"cached_tokens": 0, "cache_write_tokens": 0},
            output_tokens_details={"reasoning_tokens": 0},
        )

    def handle(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(
            200,
            json={
                "model": "m",
                "usage": usage,
                "answers": [{"type": "predicate", "name": "q", "probability": 0.8}]
                if format == "decisions"
                else {"q": {"type": "noul", "noul": 0.8}},
            },
        )

    mock_http(handle)
    # When
    result = Runner(config).scan()
    outcome = ScannerFactory.build(config.scanners[0]).scan("evidence")
    # Then
    assert not result.is_safe
    assert outcome is application_outcome
    finding = result.entry_results[0].findings[0]
    assert finding.risk_score == application_outcome.risk_score
    assert finding.rationale == application_outcome.rationale
    assert finding.matches == application_outcome.matches
    assert finding.scanner_id == format
    assert len(requests) == 2
    assert all(str(request.url) == f"https://assessment.test{base_path}/v1/{format}" for request in requests)
    assert all(
        request.headers.get("Authorization") == ("Bearer yaml-test-key" if authenticated else None)
        for request in requests
    )
    assert all(request.headers["Content-Type"] == "application/json" for request in requests)
