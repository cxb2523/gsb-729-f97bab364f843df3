from dataclasses import dataclass, field
from typing import Literal

import httpx2
import yaml
from cerbia.core.apis.decisions import DecisionsResponse
from cerbia.core.apis.systemone import SystemOneResponse
from cerbia.core.config import parse_config
from cerbia.core.models.entries import Entry
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.runner import Runner
from cerbia.core.types import Action, ContentType, Severity
from pydantic import JsonValue

from .protocol_support import case, usage

type Protocol = Literal["decisions", "systemone"]
type Response = DecisionsResponse | SystemOneResponse


class Entries:
    def load(self) -> list[Entry]:
        return [Entry(text="evidence", source="fixture", content_type=ContentType.TEXT)]


class Fallback:
    scanner_id = "fallback"
    scanner_name = "Ordinary fallback"
    severity = Severity.CRITICAL
    action = Action.BLOCK
    content_types = None
    calls = 0

    def scan(self, text: str) -> ScanOutcome:
        self.calls += 1
        return ScanOutcome(risk_score=0, rationale="Fallback")


@dataclass(slots=True)
class Contract:
    """Mutable request/evaluator counters belonging to a single test invocation."""

    protocol: Protocol
    outcome: ScanOutcome
    kind: str = "score"
    requests: list[httpx2.Request] = field(default_factory=list)
    evaluations: list[Response] = field(default_factory=list)
    error: Exception | None = None
    mode: str = "valid"

    def evaluate(self, response: Response) -> ScanOutcome:
        self.evaluations.append(response)
        if self.error is not None:
            raise self.error
        return self.outcome

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if self.mode == "transport":
            assert self.error is not None
            raise self.error
        _, answer = case(self.protocol, self.kind)
        if self.mode == "refusal":
            answer.clear()
            answer.update({"type": "refusal", "name": "q"} if self.protocol == "decisions" else {"type": "refusal"})
        answers: JsonValue = [answer] if self.protocol == "decisions" else {"q": answer}
        body: dict[str, JsonValue] = {
            "model": "fixture-model",
            "usage": usage(self.protocol),
            "answers": answers,
        }
        if self.mode == "malformed":
            body["answers"] = None
        return httpx2.Response(200, json=body)

    def runner(self, *, policy: str = "fail", base_path: str = "/gateway/") -> Runner:
        question, _ = case(self.protocol, self.kind)
        questions = [question] if self.protocol == "decisions" else {"q": question}
        name = "DecisionsScanner" if self.protocol == "decisions" else "SystemOneScanner"
        document = f"""
name: api-cascade
loaders:
  - loader: {__name__}.Entries
type: cascade
on_scanner_error: {policy}
stages:
    - id: primary
      scanners:
        - scanner: cerbia.core.scanners.{name}
          init_args:
            model: fixture-model
            base_url: https://assessment.test{base_path}
            severity: critical
            evaluator: application_policy.evaluate_answers
            questions: QUESTIONS
      score_aggregator:
        score_aggregator: cerbia.core.score_aggregators.MaxScoreAggregator
      threshold: 0.9
      defer_above: 0.2
    - id: fallback
      scanners:
        - scanner: {__name__}.Fallback
      score_aggregator:
        score_aggregator: cerbia.core.score_aggregators.MaxScoreAggregator
      threshold: 0.9
"""
        encoded = yaml.safe_dump(questions, default_flow_style=True).strip()
        return Runner(parse_config(yaml.safe_load(document.replace("QUESTIONS", encoded))))
