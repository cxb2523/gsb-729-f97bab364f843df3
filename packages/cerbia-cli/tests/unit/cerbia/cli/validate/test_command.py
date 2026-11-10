from pathlib import Path

import pytest
import typer
from cerbia.cli import app
from cerbia.cli.validate._command import validate
from cerbia.core.config import LoaderConfig, ScannerConfig, ScoreAggregatorConfig, SimpleGateConfig
from cerbia.core.exceptions import CerbIAError
from typer.testing import CliRunner

pytestmark = pytest.mark.unit

_VALID_CONFIG = """
name: baseline-gate
loaders:
  - loader: cerbia.core.loaders.text.TextLoader
    init_args:
      texts:
        - harmless input
scanners:
  - scanner: cerbia.core.scanners.keyword.KeywordScanner
score_aggregator:
  score_aggregator: cerbia.core.score_aggregators.max.MaxScoreAggregator
"""

_RUNNER_ERROR_CONFIG = """
name: broken-gate
loaders: []
scanners:
  - scanner: cerbia.core.scanners.keyword.KeywordScanner
score_aggregator:
  score_aggregator: cerbia.core.score_aggregators.max.MaxScoreAggregator
"""


def test_validate_exits_when_configuration_path_does_not_exist(mocker, tmp_path: Path) -> None:
    config_path = tmp_path / "missing.yaml"
    console = mocker.patch("cerbia.cli.validate._command.Console").return_value

    with pytest.raises(typer.Exit) as exc_info:
        validate(config=config_path)

    assert exc_info.value.exit_code == 2
    console.print.assert_called_once()


def test_validate_builds_runner_and_renders_summary_when_configuration_is_valid(mocker, tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.touch()
    config = _build_config()
    runner = mocker.Mock()
    mocker.patch("cerbia.cli.validate._command.Console")
    load_config = mocker.patch("cerbia.cli.validate._command.load_config_from_yaml", return_value=config)
    configure_logging = mocker.patch("cerbia.cli.validate._command.configure_logging")
    runner_factory = mocker.patch("cerbia.cli.validate._command.Runner", return_value=runner)
    render = mocker.patch("cerbia.cli.validate._command.render_validation_summary")

    validate(config=config_path, log_level="ERROR", log_file=tmp_path / "cerbia.log")

    load_config.assert_called_once_with(config_path, mocker.ANY)
    configure_logging.assert_called_once_with("ERROR", tmp_path / "cerbia.log", mocker.ANY)
    runner_factory.assert_called_once_with(config)
    render.assert_called_once_with(config, runner, mocker.ANY)


def test_validate_exits_when_runner_raises_cerbia_error(mocker, tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.touch()
    console = mocker.patch("cerbia.cli.validate._command.Console").return_value
    mocker.patch("cerbia.cli.validate._command.load_config_from_yaml", return_value=_build_config())
    mocker.patch("cerbia.cli.validate._command.configure_logging")
    mocker.patch("cerbia.cli.validate._command.Runner", side_effect=CerbIAError("Bearer VALIDATE-ERROR-CANARY"))

    with pytest.raises(typer.Exit) as exc_info:
        validate(config=config_path)

    assert exc_info.value.exit_code == 1
    console.print.assert_called_once_with("[red bold]✗ Invalid config[/red bold]")


def test_validate_hides_unexpected_runner_exceptions(mocker, tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.touch()
    console = mocker.patch("cerbia.cli.validate._command.Console").return_value
    mocker.patch("cerbia.cli.validate._command.load_config_from_yaml", return_value=_build_config())
    mocker.patch("cerbia.cli.validate._command.configure_logging")
    mocker.patch("cerbia.cli.validate._command.Runner", side_effect=TypeError("VALIDATE-EXCEPTION-CANARY"))

    with pytest.raises(typer.Exit) as exc_info:
        validate(config=config_path)

    assert exc_info.value.exit_code == 2
    console.print.assert_called_once_with("[red bold]✗ Config validation failed.[/red bold]")


def _build_config() -> SimpleGateConfig:
    return SimpleGateConfig(
        name="test-gate",
        loaders=[LoaderConfig(loader="test.Loader")],
        scanners=[ScannerConfig(scanner="test.Scanner")],
        score_aggregator=ScoreAggregatorConfig(score_aggregator="test.Aggregator"),
    )


def _write_config(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_validate_accepts_a_positional_config_path(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path / "valid.yaml", _VALID_CONFIG)

    result = CliRunner().invoke(app, ["validate", str(config_path)])

    assert result.exit_code == 0
    assert "Config valid" in result.output
    assert "baseline-gate" in result.output
    assert "loaders=yes" in result.output


def test_validate_reports_directory_config_as_usage_error(tmp_path: Path) -> None:
    config_directory = tmp_path / "configs"
    config_directory.mkdir()

    result = CliRunner().invoke(app, ["validate", str(config_directory)])

    assert result.exit_code == 2
    assert "Error:" in result.stderr
    assert "directory" in result.stderr.lower()
    assert config_directory.name in result.stderr


def test_validate_help_describes_a_single_yaml_config_file() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["validate", "--help"])

    assert result.exit_code == 0
    assert "single YAML configuration file" in result.output
    assert "directory" not in result.output.lower()
    assert "DEBUG/INFO/WARNING/ERROR/CRITICAL" in result.output


def test_validate_reports_missing_config_path_as_usage_error(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.yaml"

    result = CliRunner().invoke(app, ["validate", str(missing_path)])

    assert result.exit_code == 2
    assert "Error: configuration file not found" in result.output
    assert missing_path.name not in result.output


def test_validate_reports_non_mapping_config_as_usage_error(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path / "not-a-mapping.yaml", "- not\n- a mapping\n")

    result = CliRunner().invoke(app, ["validate", str(config_path)])

    assert result.exit_code == 2
    assert "Error: invalid configuration" in result.output


def test_validate_reports_malformed_yaml_as_usage_error(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path / "malformed.yaml", "name: [")

    result = CliRunner().invoke(app, ["validate", str(config_path)])

    assert result.exit_code == 2
    assert "Error:" in result.stderr
    assert "YAML" in result.stderr
    assert config_path.name in result.stderr


def test_validate_rejects_invalid_log_level_after_loading_config(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path / "valid.yaml", _VALID_CONFIG)

    result = CliRunner().invoke(app, ["validate", str(config_path), "--log-level", "verbose"])

    assert result.exit_code == 2
    assert "invalid log level" in result.output
    assert "VERBOSE" not in result.output


def test_validate_accepts_info_without_rendering_scan_progress(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path / "valid.yaml", _VALID_CONFIG)

    result = CliRunner().invoke(app, ["validate", str(config_path), "--log-level", "INFO"])

    assert result.exit_code == 0
    assert "Config valid" in result.output
    assert "Scanning..." not in result.stderr


def test_validate_rejects_trace_log_level(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path / "valid.yaml", _VALID_CONFIG)

    result = CliRunner().invoke(app, ["validate", str(config_path), "--log-level", "TRACE"])

    assert result.exit_code == 2
    assert "invalid log level" in result.output
    assert "TRACE" not in result.output


def test_validate_reports_runner_construction_error_with_exit_one(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path / "unbuildable.yaml", _RUNNER_ERROR_CONFIG)

    result = CliRunner().invoke(app, ["validate", str(config_path)])

    assert result.exit_code == 1
    assert "Invalid config" in result.output


def test_validate_creates_requested_log_file(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path / "valid.yaml", _VALID_CONFIG)
    log_path = tmp_path / "logs" / "validate.log"

    result = CliRunner().invoke(app, ["validate", str(config_path), "--log-file", str(log_path)])

    assert result.exit_code == 0
    assert log_path.is_file()


def test_validate_warns_before_overwriting_log_file(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path / "valid.yaml", _VALID_CONFIG)
    log_path = _write_config(tmp_path / "validate.log", "previous log content")

    result = CliRunner().invoke(app, ["validate", str(config_path), "--log-file", str(log_path)])

    assert result.exit_code == 0
    assert "Warning: overwriting existing log file" in result.output
    assert log_path.name not in result.output
