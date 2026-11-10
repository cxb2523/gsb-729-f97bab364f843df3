from copy import deepcopy
from types import MappingProxyType

import pytest
from cerbia.core.config import (
    CascadeGateConfig,
    ComponentConfig,
    GateType,
    LoaderConfig,
    PreprocessorConfig,
    ScannerConfig,
    ScoreAggregatorConfig,
    SimpleGateConfig,
    parse_config,
)
from cerbia.core.types import ScannerErrorPolicy
from pydantic import JsonValue, ValidationError

pytestmark = pytest.mark.unit

AGGREGATOR: dict[str, JsonValue] = {"score_aggregator": "not_installed.Maximum"}


def stage(identifier: str, **settings: JsonValue) -> dict[str, JsonValue]:
    return {
        "id": identifier,
        "scanners": [{"scanner": "not_installed.Scanner"}],
        "score_aggregator": AGGREGATOR,
        **settings,
    }


@pytest.mark.parametrize(
    "config,expected",
    [
        (LoaderConfig(loader="custom.Loader"), "custom.Loader"),
        (PreprocessorConfig(preprocessor="custom.Preprocessor"), "custom.Preprocessor"),
        (ScannerConfig(scanner="custom.Scanner"), "custom.Scanner"),
        (ScoreAggregatorConfig(score_aggregator="custom.Aggregator"), "custom.Aggregator"),
    ],
)
def test_component_returns_configured_factory_path(config: ComponentConfig, expected: str) -> None:
    assert config.component == expected


@pytest.mark.parametrize("explicit", [False, True])
def test_simple_tag_preserves_legacy_defaults_without_mutating_input(explicit: bool) -> None:
    raw: dict[str, JsonValue] = {"name": "simple", "score_aggregator": AGGREGATOR}
    if explicit:
        raw["type"] = "simple"
    before = deepcopy(raw)

    result = parse_config(raw)

    assert isinstance(result, SimpleGateConfig)
    assert result.type is GateType.SIMPLE
    assert result.threshold == 0.0
    assert result.fail_fast
    assert result.on_scanner_error is ScannerErrorPolicy.BLOCK
    assert result.model_dump(mode="json")["type"] == "simple"
    assert raw == before


@pytest.mark.parametrize("tag", [None, "unknown"])
def test_explicit_invalid_tag_is_not_defaulted(tag: JsonValue) -> None:
    with pytest.raises(ValidationError, match="union_tag_invalid"):
        parse_config({"name": "invalid", "type": tag, "score_aggregator": AGGREGATOR})


def test_readonly_mapping_receives_absent_simple_tag() -> None:
    raw = MappingProxyType({"name": "readonly", "score_aggregator": AGGREGATOR})

    result = parse_config(raw)

    assert isinstance(result, SimpleGateConfig)
    assert "type" not in raw


@pytest.mark.parametrize("policy", ["fail", "block", "skip"])
def test_simple_preserves_explicit_legacy_policy(policy: str) -> None:
    result = parse_config(
        {"name": "legacy", "score_aggregator": AGGREGATOR, "fail_fast": False, "on_scanner_error": policy}
    )

    assert isinstance(result, SimpleGateConfig)
    assert result.on_scanner_error.value == policy
    assert not result.fail_fast


@pytest.mark.parametrize("value,expected", [(True, 1.0), (False, 0.0), ("0.2", 0.2)])
def test_simple_keeps_legacy_threshold_coercion(value: JsonValue, expected: float) -> None:
    result = parse_config({"name": "legacy", "score_aggregator": AGGREGATOR, "threshold": value})

    assert result.threshold == expected


def test_threshold_inheritance_respects_override_and_does_not_mutate_input() -> None:
    raw = {
        "name": "cascade",
        "type": "cascade",
        "threshold": 0.8,
        "stages": [stage("first", defer_above=0.2), stage("last", threshold=0.6)],
    }
    before = deepcopy(raw)

    result = parse_config(raw)

    assert isinstance(result, CascadeGateConfig)
    assert [item.threshold for item in result.stages] == [0.8, 0.6]
    assert result.on_scanner_error is ScannerErrorPolicy.FAIL
    assert raw == before
    assert parse_config(result.model_dump(mode="json")) == result


def test_explicit_stage_threshold_needs_no_root_default() -> None:
    result = parse_config({"name": "cascade", "type": "cascade", "stages": [stage("last", threshold=0.0)]})

    assert isinstance(result, CascadeGateConfig)
    assert result.threshold is None
    assert result.stages[0].threshold == 0.0


@pytest.mark.parametrize("value", [None, float("nan"), True])
def test_explicit_invalid_root_threshold_is_rejected_even_with_overrides(value: JsonValue) -> None:
    raw = {"name": "cascade", "type": "cascade", "threshold": value, "stages": [stage("last", threshold=0.8)]}
    with pytest.raises(ValidationError, match="threshold"):
        parse_config(raw)


@pytest.mark.parametrize("override", [False, True])
@pytest.mark.parametrize("band", [0.8, 0.9])
def test_band_must_be_below_resolved_threshold(band: float, override: bool) -> None:
    first = stage("first", defer_above=band, **({"threshold": 0.8} if override else {}))
    raw = {
        "name": "cascade",
        "type": "cascade",
        "threshold": 0.95 if override else 0.8,
        "stages": [first, stage("last")],
    }

    with pytest.raises(ValidationError, match="defer_above must be smaller than threshold"):
        parse_config(raw)


@pytest.mark.parametrize(
    "stages,message",
    [
        ([], "stages"),
        ([stage("first"), stage("last")], "requires defer_above"),
        ([stage("last", defer_above=0.2)], "final stage last must omit defer_above"),
        ([stage("last", defer_above=None)], "defer_above must be a finite number"),
        ([stage("same", defer_above=0.2), stage("same")], "duplicate stage id"),
    ],
)
def test_custom_topology_rejects_invalid_stage_layout(stages: list[dict[str, JsonValue]], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        parse_config({"name": "cascade", "type": "cascade", "threshold": 0.8, "stages": stages})


def test_stage_without_threshold_or_root_default_is_rejected() -> None:
    raw = {"name": "cascade", "type": "cascade", "stages": [stage("last")]}
    with pytest.raises(ValidationError, match="threshold"):
        parse_config(raw)


@pytest.mark.parametrize("field", ["threshold", "defer_above"])
def test_explicit_null_stage_band_is_not_treated_as_absent(field: str) -> None:
    raw = {
        "name": "cascade",
        "type": "cascade",
        "threshold": 0.8,
        "stages": [stage("first", **{"defer_above": 0.2, field: None}), stage("last")],
    }
    with pytest.raises(ValidationError):
        parse_config(raw)


@pytest.mark.parametrize(
    "extra",
    [{"fail_fast": False}, {"on_scanner_error": "skip"}, {"scanners": []}, {"score_aggregator": AGGREGATOR}],
)
def test_cascade_rejects_simple_only_settings(extra: dict[str, JsonValue]) -> None:
    raw = {"name": "cascade", "type": "cascade", "stages": [stage("last", threshold=0.8)], **extra}
    with pytest.raises(ValidationError):
        parse_config(raw)


def test_obsolete_evidence_configuration_is_rejected_at_parser_boundary() -> None:
    raw = {
        "name": "cascade",
        "type": "cascade",
        "stages": [stage("last", threshold=0.8, evidence_from=["last"])],
    }
    with pytest.raises(ValidationError, match="extra_forbidden") as caught:
        parse_config(raw)

    assert caught.value.errors()[0]["loc"] == ("cascade", "stages", 0, "evidence_from")


def test_component_metadata_is_rejected_at_parser_boundary() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        parse_config(
            {
                "name": "simple",
                "score_aggregator": AGGREGATOR,
                "scanners": [{"scanner": "custom.Scanner", "label": "ignored"}],
            }
        )


def test_simple_rejects_nested_gate_and_cascade_stages() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        parse_config({"name": "old", "score_aggregator": AGGREGATOR, "gate": {"type": "simple"}, "stages": []})
