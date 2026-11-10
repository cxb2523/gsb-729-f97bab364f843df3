import json
import traceback
from collections.abc import Callable
from types import ModuleType

import httpx2
import pytest
from cerbia.core.apis.decisions import DecisionsResponse
from cerbia.core.apis.systemone import SystemOneResponse
from cerbia.core.config import SimpleGateConfig
from cerbia.core.exceptions import CerbIAError
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.runner import Runner
from cerbia.core.types import ScannerErrorPolicy

type MockHTTP = Callable[[Callable[[httpx2.Request], httpx2.Response]], None]
pytestmark = pytest.mark.integration


@pytest.mark.parametrize("malformed", [False, True])
def test_blocking_verdict_when_runner_scans_risky_text_or_api_fails(mock_http: MockHTTP, malformed: bool) -> None:
    # Given
    requests: list[httpx2.Request] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        if malformed:
            return httpx2.Response(200, content=b"invalid-json-secret")
        return httpx2.Response(
            200,
            json={
                "model": "m",
                "answers": {"q": {"type": "noul", "noul": 0.8}},
                "usage": {"input_tokens": 1, "output_tokens": 0},
            },
        )

    mock_http(handle)
    config = SimpleGateConfig.model_validate(
        {
            "name": "text-decisions",
            "threshold": 0.5,
            "on_scanner_error": "block",
            "loaders": [{"loader": "cerbia.core.loaders.TextLoader", "init_args": {"texts": ["untrusted text"]}}],
            "scanners": [
                {
                    "scanner": "cerbia.core.scanners.SystemOneScanner",
                    "init_args": {
                        "model": "m",
                        "base_url": "https://assessment.test",
                        "questions": {"q": {"type": "noul", "instructions": "Assess text"}},
                        "evaluator": "application_policy.evaluate_answers",
                    },
                }
            ],
            "score_aggregator": {"score_aggregator": "cerbia.core.score_aggregators.MaxScoreAggregator"},
        }
    )
    runner = Runner(config)
    # When
    result = runner.scan()
    # Then
    assert not result.is_safe
    findings = result.entry_results[0].findings
    assert [finding.risk_score for finding in findings] == ([] if malformed else [0.8])
    assert len(requests) == 1
    assert json.loads(requests[0].content)["state"] == "untrusted text"
    assert "secret" not in result.model_dump_json()


@pytest.mark.parametrize("policy", [ScannerErrorPolicy.BLOCK, ScannerErrorPolicy.SKIP, ScannerErrorPolicy.FAIL])
def test_gate_error_policy_when_application_evaluator_raises(
    mock_http: MockHTTP,
    application_policy: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    policy: ScannerErrorPolicy,
) -> None:
    # Given
    original = RuntimeError("application-private-content")

    def evaluate(response: DecisionsResponse | SystemOneResponse) -> ScanOutcome:
        raise original

    monkeypatch.setattr(application_policy, "evaluate_answers", evaluate)
    mock_http(
        lambda request: httpx2.Response(
            200,
            json={
                "model": "m",
                "answers": {"q": {"type": "noul", "noul": 0.8}},
                "usage": {"input_tokens": 1, "output_tokens": 0},
            },
        )
    )
    runner = Runner(
        SimpleGateConfig.model_validate(
            {
                "name": "decisions",
                "on_scanner_error": policy,
                "loaders": [{"loader": "cerbia.core.loaders.TextLoader", "init_args": {"texts": ["text"]}}],
                "scanners": [
                    {
                        "scanner": "cerbia.core.scanners.SystemOneScanner",
                        "init_args": {
                            "model": "m",
                            "base_url": "https://assessment.test",
                            "questions": {"q": {"type": "noul"}},
                            "evaluator": "application_policy.evaluate_answers",
                        },
                    }
                ],
                "score_aggregator": {"score_aggregator": "cerbia.core.score_aggregators.MaxScoreAggregator"},
            }
        )
    )
    # When / Then
    if policy == ScannerErrorPolicy.FAIL:
        with pytest.raises(CerbIAError, match="^System One evaluator raised an exception$") as error:
            runner.scan()
        assert error.value.__cause__ is original
        formatted = "".join(traceback.format_exception(error.value))
        assert "application-private-content" in formatted
        assert "evaluate" in [frame.name for frame in traceback.extract_tb(original.__traceback__)]
    else:
        result = runner.scan()
        assert result.is_safe is (policy == ScannerErrorPolicy.SKIP)
        assert "application-private-content" not in result.model_dump_json()
        gate_records = [record for record in caplog.records if record.name == "cerbia.core.security_gate._gate"]
        assert len(gate_records) == 1
        assert gate_records[0].exc_info is None
        assert "application-private-content" not in repr(gate_records[0].__dict__)
    assert "application-private-content" not in caplog.text
