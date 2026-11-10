from collections.abc import Callable

import httpx2
from cerbia.core.scanners import DecisionsScanner, SystemOneScanner
from pydantic import JsonValue

type MockHTTP = Callable[[Callable[[httpx2.Request], httpx2.Response]], None]


def usage(format: str) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {"input_tokens": 12, "output_tokens": 2}
    if format == "decisions":
        result.update(
            input_tokens_details={"cached_tokens": 3, "cache_write_tokens": 1},
            output_tokens_details={"reasoning_tokens": 0},
            total_tokens=14,
        )
    return result


def case(format: str, kind: str) -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
    question: dict[str, JsonValue] = {"type": kind, "instructions": "Assess evidence"}
    answer: dict[str, JsonValue] = {"type": kind}
    if format == "decisions":
        question["name"] = "q"
        answer["name"] = "q"
    match kind:
        case "predicate":
            answer["probability"] = 0.8
        case "noul":
            answer["noul"] = 0.8
        case "choice":
            question.update(
                {"choices": [{"value": "safe"}, {"value": "risk"}]}
                if format == "decisions"
                else {"criteria": {"safe": "Allowed", "risk": "Threat"}}
            )
            answer.update(choice="safe", confidence=0.07)
            answer["probabilities"] = (
                [{"value": "safe", "probability": 0.6}, {"value": "risk", "probability": 0.4}]
                if format == "decisions"
                else {"safe": 0.6, "risk": 0.4}
            )
        case "score":
            question.update(
                {"levels": [{"label": "Low"}, {"label": "High"}]}
                if format == "decisions"
                else {"criteria": ["Low", "High"]}
            )
            answer.update(score=0.8, confidence=0.02)
            answer["probabilities"] = (
                [{"value": 0, "label": "Low", "probability": 0.2}, {"value": 1, "label": "High", "probability": 0.8}]
                if format == "decisions"
                else {"0": 0.2, "1": 0.8}
            )
            if format == "systemone":
                answer["legend"] = {"0": "Low", "1": "High"}
        case _:
            raise AssertionError(kind)
    return question, answer


def make_scanner(
    mock_http: MockHTTP, format: str, kind: str
) -> tuple[DecisionsScanner | SystemOneScanner, list[httpx2.Request]]:
    question, answer = case(format, kind)
    body = {
        "model": "resolved-model",
        "answers": [answer] if format == "decisions" else {"q": answer},
        "usage": usage(format),
    }
    requests: list[httpx2.Request] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(200, json=body)

    mock_http(handle)
    if format == "decisions":
        return DecisionsScanner(
            questions=[question],
            model="requested-model",
            base_url="https://assessment.test",
            evaluator="application_policy.evaluate_answers",
        ), requests
    scanner = SystemOneScanner(
        model="requested-model",
        base_url="https://assessment.test",
        questions={"q": question},
        evaluator="application_policy.evaluate_answers",
    )
    return scanner, requests
