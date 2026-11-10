import logging
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from cerbia.cli import app
from cerbia.core.apis._http import HTTPClient
from cerbia.core.apis.decisions import DecisionsResponse
from cerbia.core.factories import GateFactory
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.scanners.canary import CanaryLeakScanner
from cerbia.core.scanners.invisible_text import InvisibleTextScanner
from cerbia.core.scanners.keyword import KeywordScanner
from typer.testing import CliRunner

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def restore_logging() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    for handler in root.handlers:
        if handler not in handlers:
            handler.close()
    root.handlers = handlers
    root.setLevel(level)


_CASCADE = """name: cascade-gate
loaders:
  - loader: cerbia.core.loaders.text.TextLoader
    init_args: {texts: [INPUT-PRIVATE-CANARY]}
type: cascade
stages:
    - id: guard
      scanners:
        - scanner: cerbia.core.scanners.canary.CanaryLeakScanner
          init_args: {canary_tokens: [TOKEN-PRIVATE-CANARY]}
      threshold: 0.5
      defer_above: 0.2
      score_aggregator:
        score_aggregator: cerbia.core.score_aggregators.max.MaxScoreAggregator
    - id: screen
      scanners:
        - scanner: cerbia.core.scanners.keyword.KeywordScanner
      score_aggregator:
        score_aggregator: cerbia.core.score_aggregators.max.MaxScoreAggregator
      threshold: 0.9
      defer_above: 0.2
    - id: final
      scanners:
        - scanner: cerbia.core.scanners.invisible_text.InvisibleTextScanner
      score_aggregator:
        score_aggregator: cerbia.core.score_aggregators.max.MaxScoreAggregator
      threshold: 0.55
"""


def test_cascade_privacy_when_valid_constructs_real_stages_without_scanning(tmp_path: Path) -> None:
    # Given
    path = tmp_path / "cascade.yaml"
    path.write_text(_CASCADE)
    with (
        patch.object(GateFactory, "build_stages", wraps=GateFactory.build_stages) as build,
        patch.object(CanaryLeakScanner, "scan", side_effect=AssertionError("must not scan")) as guard,
        patch.object(KeywordScanner, "scan", side_effect=AssertionError("must not scan")) as screen,
        patch.object(InvisibleTextScanner, "scan", side_effect=AssertionError("must not scan")) as final,
    ):
        # When
        result = CliRunner().invoke(app, ["validate", str(path)], env={"COLUMNS": "160"})
    # Then
    assert result.exit_code == 0, result.output
    assert build.call_count == 1
    assert guard.call_count == screen.call_count == final.call_count == 0
    output = " ".join(result.output.split())
    for text in (
        "guard",
        "screen",
        "final",
        "CanaryLeakScanner",
        "KeywordScanner",
        "InvisibleTextScanner",
        "MaxScoreAggregator",
        "score > threshold=0.5",
        "score > threshold=0.9",
        "score > defer_above=0.2",
        "score > threshold=0.55",
        "final: allow any score not blocked",
        "allow otherwise",
        "on_scanner_error=fail",
    ):
        assert text in output
    assert "PRIVATE-CANARY" not in result.output
    assert "init_args" not in result.output
    assert result.stdout == ""


@pytest.mark.parametrize("band", ["0.0"])
def test_rules_when_band_is_zero_or_positive_display_actual_policy(tmp_path: Path, band: str) -> None:
    # Given
    path = tmp_path / "rules.yaml"
    replacement = f"      defer_above: {band}\n"
    path.write_text(_CASCADE.replace("      defer_above: 0.2\n", replacement))
    # When
    result = CliRunner().invoke(app, ["validate", str(path)], env={"COLUMNS": "160"})
    # Then
    assert result.exit_code == 0
    output = " ".join(result.output.split())
    assert f"defer_above={band}" in output
    assert "final: allow any score not blocked" in output


@pytest.mark.parametrize("replacement", ["NaN"])
def test_invalid_when_threshold_malformed_rejects_before_construction(tmp_path: Path, replacement: str) -> None:
    # Given
    path = tmp_path / "invalid.yaml"
    path.write_text(_CASCADE.replace("0.9", replacement))
    with patch.object(GateFactory, "build", wraps=GateFactory.build) as build:
        # When
        result = CliRunner().invoke(app, ["validate", str(path)])
    # Then
    assert result.exit_code == 2
    assert "invalid configuration" in result.output
    assert build.call_count == 0
    assert "PRIVATE-CANARY" not in result.output


@pytest.mark.parametrize(
    "content",
    [
        _CASCADE.replace("InvisibleTextScanner", "MissingScanner"),
        _CASCADE.replace(
            "cerbia.core.scanners.invisible_text.InvisibleTextScanner", "cerbia.core.scanners.keyword.KeywordScanner"
        ),
    ],
)
def test_construction_privacy_when_later_component_is_invalid_exits_one(tmp_path: Path, content: str) -> None:
    # Given
    path = tmp_path / "construction.yaml"
    path.write_text(content)
    # When
    result = CliRunner().invoke(app, ["validate", str(path), "--log-level", "DEBUG"])
    # Then
    assert result.exit_code == 1
    assert "Invalid config" in result.output
    assert "PRIVATE-CANARY" not in result.output
    assert "init_args" not in result.output


def test_simple_when_type_is_absent_or_explicit_has_identical_output(tmp_path: Path) -> None:
    # Given
    raw = yaml.safe_load(_CASCADE)
    simple = raw["stages"][1]
    flat = {
        "name": raw["name"],
        "loaders": raw["loaders"],
        "scanners": simple["scanners"],
        "score_aggregator": simple["score_aggregator"],
    }
    nested = {**flat, "type": "simple"}
    flat_path, nested_path = tmp_path / "flat.yaml", tmp_path / "nested.yaml"
    flat_path.write_text(yaml.safe_dump(flat))
    nested_path.write_text(yaml.safe_dump(nested))
    baseline = CliRunner().invoke(app, ["validate", str(flat_path)])
    # When
    result = CliRunner().invoke(app, ["validate", str(nested_path)])
    # Then
    assert baseline.exit_code == result.exit_code == 0
    assert result.stderr == baseline.stderr
    assert result.stdout == baseline.stdout == ""


def test_construction_privacy_when_init_args_are_unsupported_exits_two(tmp_path: Path) -> None:
    # Given
    path = tmp_path / "construction.yaml"
    path.write_text(
        _CASCADE.replace(
            "InvisibleTextScanner\n",
            "InvisibleTextScanner\n          init_args: {unexpected: PASSWORD-PRIVATE-CANARY}\n",
        )
    )
    # When
    result = CliRunner().invoke(app, ["validate", str(path)])
    # Then
    assert result.exit_code == 2
    assert "Config validation failed" in result.output
    assert "PRIVATE-CANARY" not in result.output


def secret_provider() -> str:
    raise AssertionError("credentials must not be resolved during validation")


def evaluate(response: DecisionsResponse) -> ScanOutcome:
    raise AssertionError("evaluators must not execute during validation")


def test_privacy_when_remote_provider_configured_never_calls_http_or_provider(tmp_path: Path) -> None:
    # Given
    path = tmp_path / "remote.yaml"
    path.write_text(
        _CASCADE.replace(
            "scanner: cerbia.core.scanners.invisible_text.InvisibleTextScanner",
            f"""scanner: cerbia.core.scanners.decisions.DecisionsScanner
          init_args:
            model: MODEL-PRIVATE-CANARY
            base_url: https://synthetic.invalid
            evaluator: {__name__}.evaluate
            api_key_provider: {__name__}.secret_provider
            questions: [{{type: predicate, name: q, instructions: QUESTION-PRIVATE-CANARY}}]""",
        )
    )
    with patch.object(HTTPClient, "request", side_effect=AssertionError("must not call HTTP")) as post:
        # When
        result = CliRunner().invoke(app, ["validate", str(path)])
    # Then
    assert result.exit_code == 0, result.output
    assert post.call_count == 0
    assert "DecisionsScanner" in result.output
    assert "PRIVATE-CANARY" not in result.output
    assert "secret_provider" not in result.output


@pytest.mark.parametrize(
    "content",
    [
        _CASCADE.replace("threshold: 0.55", "threshold: 0.55\n      evidence_from: [screen, final]"),
        "- TOKEN-PRIVATE-CANARY\n",
        "name: [",
    ],
)
def test_invalid_privacy_when_stale_or_malformed_shape_rejects_before_build(tmp_path: Path, content: str) -> None:
    # Given
    path = tmp_path / "invalid.yaml"
    path.write_text(content)
    with patch.object(GateFactory, "build", wraps=GateFactory.build) as build:
        # When
        result = CliRunner().invoke(app, ["validate", str(path)])
    # Then
    assert result.exit_code == 2
    assert build.call_count == 0
    assert "PRIVATE-CANARY" not in result.output
