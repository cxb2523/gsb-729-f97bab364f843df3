import json
from collections.abc import Callable

import httpx2
import pytest
from cerbia.core.apis import APIConfigError, APIError
from cerbia.core.apis import systemone as api

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("model,text", [("requested", "Untrusted text"), (" \t ", "")])
def test_typed_answers_when_client_asks_about_text(
    mock_http: Callable[[Callable[[httpx2.Request], httpx2.Response]], None],
    model: str,
    text: str,
) -> None:
    # Given
    question = api.NoulQuestion(instructions="Assess text")
    requests: list[httpx2.Request] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(
            200,
            json={
                "model": "resolved",
                "answers": {"q": {"type": "noul", "noul": 0.8}},
                "usage": {"input_tokens": 1, "output_tokens": 0},
            },
        )

    mock_http(handle)
    client = api.SystemOneClient(model=model, base_url="https://assessment.test")
    # When
    response = client.ask(text, {"q": question})
    # Then
    assert isinstance(response, api.SystemOneResponse)
    assert response.model == "resolved"
    assert json.loads(requests[0].content) == {
        "model": model,
        "state": text,
        "questions": {"q": question.model_dump(mode="json", exclude_unset=True) | {"type": question.type}},
    }
    assert requests[0].url.path == "/v1/systemone"
    assert "Authorization" not in requests[0].headers
    assert requests[0].headers["Content-Type"] == "application/json"


@pytest.mark.parametrize(
    "body",
    [
        b"secret-not-json",
        b'{"model":"m","answers":{},"usage":{"input_tokens":1,"output_tokens":0}}',
        b'{"model":"m","answers":{"q":{"type":"refusal"}},"usage":{"input_tokens":1,"output_tokens":0}}',
    ],
)
def test_client_rejects_malformed_or_wrong_protocol_payload(body: bytes, mock_http) -> None:
    mock_http(lambda request: httpx2.Response(200, content=body))
    client = api.SystemOneClient(model="m", base_url="https://api.test")
    questions = {"q": api.NoulQuestion()}
    with pytest.raises(APIError, match="^API request failed$"):
        client.ask("text", questions)


def test_client_rejects_invalid_model_and_nontext_before_transport(mock_http) -> None:
    with pytest.raises(APIConfigError):
        api.SystemOneClient(model="")
    mock_http(lambda request: pytest.fail("invalid text sent"))
    client = api.SystemOneClient(model="m", base_url="https://api.test")
    questions = {"q": api.NoulQuestion()}
    with pytest.raises(APIError):
        client.ask(None, questions)
