from cerbia.core.config import CascadeGateConfig
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.runner import Runner
from cerbia.core.types import Action, ContentType, Severity
from pydantic import JsonValue


class Leaf:
    scanner_name = "Local leaf"
    calls: list[str] = []
    constructions: list[str] = []
    failures: dict[str, BaseException] = {}

    def __init__(
        self,
        scanner_id: str,
        risk: float = 0.0,
        *,
        action: Action = Action.BLOCK,
        severity: Severity = Severity.CRITICAL,
        content_types: tuple[ContentType, ...] | None = None,
    ) -> None:
        self.scanner_id = scanner_id
        self.risk = risk
        self.action = action
        self.severity = severity
        self.content_types = content_types
        self.constructions.append(scanner_id)

    def scan(self, text: str) -> ScanOutcome:
        self.calls.append(self.scanner_id)
        if self.scanner_id in self.failures:
            raise self.failures.pop(self.scanner_id)
        return ScanOutcome(risk_score=self.risk if text != "clean" else 0.0, rationale="Local outcome")


class Aggregate:
    inputs: list[list[float]] = []
    result: float = 0.5
    error: Exception | None = None

    def compute(self, scores: list[float]) -> float:
        self.inputs.append(list(scores))
        if self.error is not None:
            raise self.error
        return self.result


def leaf(scanner_id: str, risk: float = 0.0, **settings: JsonValue) -> dict[str, JsonValue]:
    return {"scanner": f"{__name__}.Leaf", "init_args": {"scanner_id": scanner_id, "risk": risk, **settings}}


def numerical(
    stage_id: str,
    scanners: list[dict[str, JsonValue]],
    *,
    final: bool = True,
    threshold: float = 0.9,
    defer_above: float | None = None,
    aggregator: str = "Max",
) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "id": stage_id,
        "scanners": list(scanners),
        "score_aggregator": {"score_aggregator": f"cerbia.core.score_aggregators.{aggregator}ScoreAggregator"},
        "threshold": threshold,
    }
    if defer_above is not None:
        result["defer_above"] = defer_above
    elif not final:
        result["defer_above"] = 0.2
    if aggregator == "Local":
        result["score_aggregator"] = {"score_aggregator": f"{__name__}.Aggregate"}
    return result


def veto(scanners: list[dict[str, JsonValue]]) -> dict[str, JsonValue]:
    return numerical("guard", scanners, final=False, threshold=0.01, defer_above=0.0)


def config(stages: list[dict[str, JsonValue]], *, policy: str = "fail") -> CascadeGateConfig:
    Leaf.calls.clear()
    Leaf.constructions.clear()
    Leaf.failures.clear()
    Aggregate.inputs.clear()
    Aggregate.error = None
    return CascadeGateConfig.model_validate(
        {
            "name": "cascade",
            "loaders": [{"loader": "cerbia.core.loaders.TextLoader", "init_args": {"texts": "sample"}}],
            "type": "cascade",
            "on_scanner_error": policy,
            "stages": stages,
        }
    )


def runner(stages: list[dict[str, JsonValue]], *, policy: str = "fail") -> Runner:
    return Runner(config(stages, policy=policy))
