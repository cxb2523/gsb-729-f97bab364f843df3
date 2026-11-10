import pytest
from cerbia.core.apis.decisions import DecisionsResponse
from cerbia.core.apis.systemone import SystemOneResponse
from cerbia.core.config import CascadeGateConfig, ScoreAggregatorConfig, SimpleGateConfig, parse_config
from cerbia.core.exceptions import CerbIAConfigError
from cerbia.core.factories import GateFactory
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.registries.url import UrlRegistry
from cerbia.core.security_gate import BuiltStage, CascadeGate, SecurityGate, SimpleGate
from cerbia.core.types import Action, ContentType, Severity
from pydantic import JsonValue

pytestmark = pytest.mark.unit


class LocalScanner:
    scanner_name = "Local"
    severity = Severity.CRITICAL
    content_types: tuple[ContentType, ...] | None = None
    constructions: list[str] = []
    scans: list[str] = []

    def __init__(
        self, scanner_id: str = "local", action: Action = Action.BLOCK, url_registry: UrlRegistry | None = None
    ) -> None:
        self.scanner_id = scanner_id
        self.action = action
        self.registry = url_registry
        self.constructions.append(scanner_id)

    def scan(self, text: str) -> ScanOutcome:
        self.scans.append(self.scanner_id)
        return ScanOutcome(risk_score=0.0, rationale="Local clean")


def evaluate_answers(response: DecisionsResponse | SystemOneResponse) -> ScanOutcome:
    return ScanOutcome(risk_score=0.0, rationale="Local clean")


def local(scanner_id: str = "local", action: str = "block") -> dict[str, JsonValue]:
    return {"scanner": f"{__name__}.LocalScanner", "init_args": {"scanner_id": scanner_id, "action": action}}


def numerical(stage_id: str, scanners: list[dict[str, JsonValue]], *, final: bool = True) -> dict[str, JsonValue]:
    return {
        "id": stage_id,
        "scanners": list(scanners),
        "score_aggregator": {"score_aggregator": "cerbia.core.score_aggregators.MaxScoreAggregator"},
        "threshold": 0.9,
        **({"defer_above": 0.2} if not final else {}),
    }


def cascade(stages: list[dict[str, JsonValue]]) -> CascadeGateConfig:
    return CascadeGateConfig.model_validate({"name": "cascade", "type": "cascade", "stages": stages})


@pytest.mark.parametrize("nested", [False, True])
def test_build_simple_when_configured_preserves_real_gate_settings(nested: bool) -> None:
    # Given
    settings = {
        "scanners": [local()],
        "threshold": 0.3,
        "fail_fast": False,
        "on_scanner_error": "fail",
        "score_aggregator": {"score_aggregator": "cerbia.core.score_aggregators.MeanScoreAggregator"},
    }
    config = parse_config({"name": "simple", **settings, **({"type": "simple"} if nested else {})})
    # When
    gate = GateFactory.build_simple(config)
    # Then
    assert isinstance(gate, SimpleGate)
    assert isinstance(gate, SecurityGate)
    assert (gate.name, gate.threshold, gate.fail_fast, gate.on_scanner_error) == ("simple", 0.3, False, "fail")


@pytest.mark.parametrize("gate_type", ["simple", "cascade"])
def test_build_when_configured_returns_security_gate_protocol(gate_type: str) -> None:
    # Given
    config = (
        parse_config(
            {
                "name": "simple",
                "scanners": [local()],
                "score_aggregator": {"score_aggregator": "cerbia.core.score_aggregators.MaxScoreAggregator"},
            }
        )
        if gate_type == "simple"
        else cascade([numerical("last", [local()])])
    )
    # When
    gate = GateFactory.build(config)
    # Then
    assert isinstance(gate, SecurityGate)
    assert isinstance(gate, SimpleGate if gate_type == "simple" else CascadeGate)


def test_construction_when_building_stages_creates_each_leaf_once_without_scans() -> None:
    # Given
    LocalScanner.constructions.clear()
    LocalScanner.scans.clear()
    config = cascade(
        [
            numerical("guard", [local("guard")], final=False),
            numerical("first", [local("first")], final=False),
            numerical("last", [local("last")]),
        ]
    )
    # When
    stages = GateFactory.build_stages(config)
    # Then
    assert isinstance(stages, tuple)
    assert all(isinstance(stage, BuiltStage) for stage in stages)
    assert [stage.config for stage in stages] == config.stages
    assert all(isinstance(stage.scanners, tuple) for stage in stages)
    assert all(stage.score_aggregator is not None for stage in stages)
    assert LocalScanner.constructions == ["guard", "first", "last"]
    assert LocalScanner.scans == []


@pytest.mark.parametrize("same_stage", [False, True])
def test_duplicate_when_actual_ids_repeat_rejects_before_scan(same_stage: bool) -> None:
    # Given
    LocalScanner.scans.clear()
    stages = (
        [numerical("last", [local("same"), local("same")])]
        if same_stage
        else [numerical("first", [local("same")], final=False), numerical("last", [local("same")])]
    )
    config = cascade(stages)
    # When / Then
    with pytest.raises(CerbIAConfigError, match="same") as error:
        GateFactory.build_stages(config)
    assert "last" in str(error.value)
    assert LocalScanner.scans == []


@pytest.mark.parametrize("action", ["warn", "pass"])
@pytest.mark.parametrize("final", [False, True])
def test_invalid_when_numerical_has_no_own_block_scanner_rejects(action: str, final: bool) -> None:
    # Given
    stages = [numerical("first", [local("first", action)], final=final)]
    if not final:
        stages.append(numerical("last", [local("last")]))
    config = cascade(stages)
    # When / Then
    with pytest.raises(CerbIAConfigError, match="first.*block"):
        GateFactory.build_stages(config)


@pytest.mark.parametrize("scanner_id", ["", "  ", 3, None])
def test_invalid_when_scanner_id_is_not_nonempty_string_rejects(scanner_id: JsonValue) -> None:
    # Given
    config = cascade(
        [numerical("last", [{"scanner": f"{__name__}.LocalScanner", "init_args": {"scanner_id": scanner_id}}])]
    )
    # When / Then
    with pytest.raises(CerbIAConfigError, match="last.*scanner"):
        GateFactory.build_stages(config)


@pytest.mark.parametrize("action", ["unsupported", None, True])
def test_invalid_when_runtime_action_is_not_supported_rejects_before_scan(action: JsonValue) -> None:
    # Given
    scanner: dict[str, JsonValue] = {"scanner": f"{__name__}.LocalScanner", "init_args": {"action": action}}
    config = cascade([numerical("last", [scanner])])
    # When / Then
    with pytest.raises(CerbIAConfigError, match="last.*local.*action"):
        GateFactory.build_stages(config)


def test_isolation_when_stage_builds_repeat_keeps_shared_registry_per_build() -> None:
    # Given
    config = cascade([numerical("first", [local("first")], final=False), numerical("last", [local("last")])])
    # When
    first, second = GateFactory.build_stages(config), GateFactory.build_stages(config)
    # Then
    a, b = first[0].scanners[0], first[1].scanners[0]
    c = second[0].scanners[0]
    assert isinstance(a, LocalScanner)
    assert isinstance(b, LocalScanner)
    assert isinstance(c, LocalScanner)
    assert isinstance(a.registry, UrlRegistry)
    assert a.registry is b.registry
    assert a.registry is not c.registry


@pytest.mark.parametrize("duplicate", [False, True])
def test_duplicate_decisions_when_differently_configured_uses_actual_identity(duplicate: bool) -> None:
    # Given
    decisions: dict[str, JsonValue] = {
        "scanner": "cerbia.core.scanners.DecisionsScanner",
        "init_args": {
            "model": "first",
            "base_url": "https://assessment.test",
            "evaluator": f"{__name__}.evaluate_answers",
            "questions": [{"type": "predicate", "name": "q", "instructions": "Assess"}],
        },
    }
    args = decisions["init_args"]
    assert isinstance(args, dict)
    second: dict[str, JsonValue] = (
        {**decisions, "init_args": {**args, "model": "second"}}
        if duplicate
        else {
            "scanner": "cerbia.core.scanners.SystemOneScanner",
            "init_args": {
                "model": "second",
                "base_url": "https://assessment.test",
                "evaluator": f"{__name__}.evaluate_answers",
                "questions": {"q": {"type": "noul", "instructions": "Assess"}},
            },
        }
    )
    config = cascade([numerical("first", [decisions], final=False), numerical("last", [second])])
    # When / Then
    if duplicate:
        with pytest.raises(CerbIAConfigError, match="last.*decisions.*first"):
            GateFactory.build_stages(config)
    else:
        stages = GateFactory.build_stages(config)
        assert [stage.scanners[0].scanner_id for stage in stages] == ["decisions", "systemone"]


def test_construction_when_simple_has_no_scanners_preserves_legacy_error() -> None:
    # Given
    config = SimpleGateConfig(
        name="empty",
        score_aggregator=ScoreAggregatorConfig(score_aggregator="cerbia.core.score_aggregators.MaxScoreAggregator"),
    )
    # When / Then
    with pytest.raises(CerbIAConfigError, match="^No scanners configured: set at least one scanner$"):
        GateFactory.build_simple(config)


@pytest.mark.parametrize("deny_first", [False, True])
def test_isolation_when_url_policies_span_stages_preserves_deny_precedence(deny_first: bool) -> None:
    # Given
    allow: dict[str, JsonValue] = {
        "scanner": "cerbia.core.scanners.UrlAllowListScanner",
        "init_args": {"allowed_domains": ["*"]},
    }
    deny: dict[str, JsonValue] = {
        "scanner": "cerbia.core.scanners.UrlDenyListScanner",
        "init_args": {"blocked_domains": ["*"]},
    }
    configs = [deny, allow] if deny_first else [allow, deny]
    config = cascade([numerical("first", [configs[0]], final=False), numerical("last", [configs[1]])])
    # When
    stages = GateFactory.build_stages(config)
    # Then
    assert all(stage.scanners[0].scan("https://example.com/").risk_score == 0.95 for stage in stages)


def test_invalid_when_simple_factory_receives_cascade_rejects_without_runtime_stub() -> None:
    # Given
    config = cascade([numerical("last", [local()])])
    # When / Then
    with pytest.raises(CerbIAConfigError, match="requires a simple gate"):
        GateFactory.build_simple(config)
