from pathlib import Path

import pytest
import typer
import yaml
from cerbia.cli.config import load_config_from_yaml
from cerbia.core.config import CascadeGateConfig
from cerbia.core.exceptions import CerbIAConfigError
from pydantic import JsonValue
from rich.console import Console

pytestmark = pytest.mark.unit


def test_load_config_from_yaml_returns_config_when_valid_yaml_mapping_is_provided(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        """name: gate
loaders:
  - loader: cerbia.core.loaders.text.TextLoader
scanners:
  - scanner: cerbia.core.scanners.keyword.KeywordScanner
score_aggregator:
  score_aggregator: cerbia.core.score_aggregators.max.MaxScoreAggregator
"""
    )

    result = load_config_from_yaml(path, Console(record=True))

    assert result.name == "gate"
    assert len(result.loaders) == 1


def test_load_config_from_yaml_exits_when_yaml_is_not_a_mapping(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("- item")
    console = Console(record=True)

    with pytest.raises(typer.Exit) as exc_info:
        load_config_from_yaml(path, console)

    assert exc_info.value.exit_code == 2
    assert "invalid configuration" in console.export_text()


def test_load_config_from_yaml_exits_when_configuration_error_is_raised(mocker, tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("name: gate")
    console = mocker.Mock()
    mocker.patch("cerbia.cli.config.parse_config", side_effect=CerbIAConfigError("Invalid"))

    with pytest.raises(typer.Exit) as exc_info:
        load_config_from_yaml(path, console)

    assert exc_info.value.exit_code == 2
    console.print.assert_called_once_with(f"[red]Error:[/red] invalid configuration in file: {path}")


def test_load_config_from_yaml_exits_with_actionable_error_when_file_is_missing(tmp_path: Path) -> None:
    path = tmp_path / "missing.yaml"
    console = Console(record=True)

    with pytest.raises(typer.Exit) as exc_info:
        load_config_from_yaml(path, console)

    output = console.export_text()
    assert exc_info.value.exit_code == 2
    assert "not found" in output.lower()
    assert path.name in output


@pytest.mark.parametrize("explicit", [None, 0.0, 0.6])
def test_cascade_threshold_override_when_loaded_preserves_explicit_stage_precedence(
    tmp_path: Path, explicit: float | None
) -> None:
    # Given
    aggregator: dict[str, JsonValue] = {"score_aggregator": "not_installed.Maximum"}
    final: dict[str, JsonValue] = {
        "id": "final",
        "scanners": [{"scanner": "not_installed.Scanner"}],
        "score_aggregator": aggregator,
    }
    if explicit is not None:
        final["threshold"] = explicit
    raw = {
        "name": "cascade",
        "type": "cascade",
        "threshold": 0.9,
        "stages": [
            {
                "id": "first",
                "defer_above": 0.2,
                "scanners": [{"scanner": "not_installed.Scanner"}],
                "score_aggregator": aggregator,
            },
            final,
        ],
    }
    path = tmp_path / "cascade.yaml"
    path.write_text(yaml.safe_dump(raw))

    # When
    parsed = load_config_from_yaml(path, Console(), threshold=0.8)

    # Then
    assert isinstance(parsed, CascadeGateConfig)
    assert parsed.threshold == 0.8
    assert [stage.threshold for stage in parsed.stages] == [0.8, 0.8 if explicit is None else explicit]


def test_cascade_threshold_override_when_boolean_rejects_before_import(tmp_path: Path) -> None:
    # Given
    path = tmp_path / "cascade.yaml"
    path.write_text(
        "name: cascade\ntype: cascade\nstages:\n  - id: final\n"
        "    threshold: 0.8\n    scanners: [{scanner: not_installed.Scanner}]\n"
        "    score_aggregator: {score_aggregator: not_installed.Maximum}\n"
    )
    console = Console()

    # When / Then
    with pytest.raises(typer.Exit) as caught:
        load_config_from_yaml(path, console, threshold=True)

    assert caught.value.exit_code == 2


def test_load_config_from_yaml_exits_with_actionable_error_when_path_is_directory(tmp_path: Path) -> None:
    path = tmp_path / "configs"
    path.mkdir()
    console = Console(record=True)

    with pytest.raises(typer.Exit) as exc_info:
        load_config_from_yaml(path, console)

    output = console.export_text()
    assert exc_info.value.exit_code == 2
    assert "directory" in output.lower()
    assert path.name in output


def test_load_config_from_yaml_exits_with_actionable_error_when_file_cannot_be_read(mocker, tmp_path: Path) -> None:
    path = tmp_path / "restricted.yaml"
    console = Console(record=True)
    mocker.patch("builtins.open", side_effect=PermissionError("access denied"))

    with pytest.raises(typer.Exit) as exc_info:
        load_config_from_yaml(path, console)

    output = console.export_text()
    assert exc_info.value.exit_code == 2
    assert "permission denied" in output.lower()
    assert path.name in output


def test_load_config_from_yaml_exits_with_actionable_error_when_yaml_is_malformed(tmp_path: Path) -> None:
    path = tmp_path / "malformed.yaml"
    path.write_text("loaders: [", encoding="utf-8")
    console = Console(record=True)

    with pytest.raises(typer.Exit) as exc_info:
        load_config_from_yaml(path, console)

    output = console.export_text()
    assert exc_info.value.exit_code == 2
    assert "YAML" in output
    assert path.name in output
