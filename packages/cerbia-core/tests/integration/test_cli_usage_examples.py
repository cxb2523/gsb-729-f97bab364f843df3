from pathlib import Path
from typing import Final

import pytest
import yaml
from cerbia.core.config import CascadeGateConfig, SimpleGateConfig, parse_config
from cerbia.core.runner import Runner

EXAMPLE: Final = Path(__file__).parents[4] / "examples" / "cli-usage"
pytestmark = pytest.mark.integration


def test_cli_examples_preserve_component_routing_when_split_into_stages() -> None:
    # Given
    simple_bytes = (EXAMPLE / "simple.cerbia.yaml").read_bytes()
    cascade_bytes = (EXAMPLE / "cascade.cerbia.yaml").read_bytes()

    # When
    simple = SimpleGateConfig.model_validate(yaml.safe_load(simple_bytes))
    cascade = CascadeGateConfig.model_validate(yaml.safe_load(cascade_bytes))

    # Then
    assert len(cascade.loaders) == len(simple.loaders) == 1
    assert cascade.loaders[0].loader == simple.loaders[0].loader
    assert cascade.loaders[0].init_args.keys() == simple.loaders[0].init_args.keys() == {"texts"}
    assert cascade.loaders[0].init_args["texts"][1:] == simple.loaders[0].init_args["texts"][1:]
    assert cascade.preprocessors == simple.preprocessors
    assert cascade.on_scanner_error == simple.on_scanner_error == "block"
    assert [stage.id for stage in cascade.stages] == ["text", "secrets-and-urls"]
    assert cascade.stages[0].scanners == simple.scanners[:3]
    assert cascade.stages[1].scanners == simple.scanners[3:]
    assert all(stage.score_aggregator == simple.score_aggregator for stage in cascade.stages)
    assert cascade.threshold == 0.5
    assert all(stage.threshold == 0.5 for stage in cascade.stages)
    assert cascade.stages[0].defer_above == 0.1
    assert "defer_above" not in cascade.stages[1].model_fields_set


def test_cascade_first_configured_entry_defers_then_blocks_on_url_allowlist() -> None:
    # Given
    config = parse_config(yaml.safe_load((EXAMPLE / "cascade.cerbia.yaml").read_bytes()))

    # When
    entry = Runner(config).scan().entry_results[0]

    # Then
    assert not entry.is_safe
    assert entry.stages is not None
    assert [(stage.id, stage.result) for stage in entry.stages] == [
        ("text", "defer"),
        ("secrets-and-urls", "block"),
    ]
    assert entry.stages[0].score == pytest.approx(0.2)
    assert entry.stages[1].score == pytest.approx(0.7125)
    assert len(entry.findings) == 6
    assert entry.findings[-1].scanner_id == "url_allowlist"
    assert entry.findings[-1].stage == "secrets-and-urls"
    assert entry.findings[-1].risk_score == pytest.approx(0.95)
