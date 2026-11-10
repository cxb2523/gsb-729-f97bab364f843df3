import json
from pathlib import Path
from typing import TypedDict
from unittest.mock import call

import pytest
import typer
from cerbia.cli import app
from cerbia.cli.scan._command import scan
from cerbia.core.config import LoaderConfig, ScannerConfig, ScoreAggregatorConfig, SimpleGateConfig
from cerbia.core.exceptions import CerbIAError
from cerbia.core.models.entries import Entry
from cerbia.core.models.results import EntryResult, ScanResult
from pydantic import TypeAdapter
from typer.testing import CliRunner

pytestmark = pytest.mark.unit


class _EntryResultPayload(TypedDict):
    is_safe: bool


class _ScanPayload(TypedDict):
    entry_results: list[_EntryResultPayload]
    is_safe: bool
    total_findings: int
    unsafe_entries: int


_SCAN_PAYLOAD_ADAPTER = TypeAdapter(_ScanPayload)


def test_scan_exits_when_output_path_is_not_json(mocker, tmp_path: Path) -> None:
    console = mocker.patch("cerbia.cli.scan._command.Console").return_value

    with pytest.raises(typer.Exit) as exc_info:
        scan(config=tmp_path / "config.yaml", output_path=tmp_path / "result.txt")

    assert exc_info.value.exit_code == 2
    assert console.print.call_args_list == [
        call("[bold]CerbIA CLI Scan[/bold]"),
        call("[bold]Running scan...[/bold]"),
        call("[red]Error:[/red] --output path must have a .json extension."),
    ]


def test_scan_exits_when_no_loader_is_configured_or_provided(mocker, tmp_path: Path) -> None:
    config = _build_config(loaders=[])
    console = mocker.patch("cerbia.cli.scan._command.Console").return_value
    mocker.patch("cerbia.cli.scan._command.load_config_from_yaml", return_value=config)
    mocker.patch("cerbia.cli.scan._command.configure_logging")

    with pytest.raises(typer.Exit) as exc_info:
        scan(config=tmp_path / "config.yaml")

    assert exc_info.value.exit_code == 2
    assert console.print.call_args_list == [
        call("[bold]CerbIA CLI Scan[/bold]"),
        call("[bold]Running scan...[/bold]"),
        call("[red]Error:[/red] provide --text, --file, or configure loaders in your config."),
    ]


def test_scan_overrides_config_loaders_and_threshold_when_cli_inputs_are_provided(mocker, tmp_path: Path) -> None:
    config = _build_config(loaders=[LoaderConfig(loader="configured.Loader")])
    result = ScanResult(entry_results=[EntryResult(entry=Entry(text="first", source="inline"))])
    runner = mocker.Mock()
    runner.scan.return_value = result
    mocker.patch("cerbia.cli.scan._command.Console")
    mocker.patch("cerbia.cli.scan._command.load_config_from_yaml", return_value=config)
    mocker.patch("cerbia.cli.scan._command.configure_logging")
    runner_factory = mocker.patch("cerbia.cli.scan._command.Runner", return_value=runner)
    render = mocker.patch("cerbia.cli.scan._command.render_scan_result")
    write_json = mocker.patch("cerbia.cli.scan._command.write_json_result")
    output_path = tmp_path / "result.json"

    with pytest.raises(typer.Exit) as exc_info:
        scan(config=tmp_path / "config.yaml", text=["first"], output_path=output_path, threshold=0.7)

    assert exc_info.value.exit_code == 0
    assert config.threshold == 0.7
    assert config.loaders == [
        LoaderConfig(loader="cerbia.core.loaders.text.TextLoader", init_args={"texts": ["first"]})
    ]
    runner_factory.assert_called_once_with(config)
    render.assert_called_once_with(result, False, mocker.ANY)
    write_json.assert_called_once_with(result, output_path)


def test_scan_filters_results_when_unsafe_only_is_enabled(mocker, tmp_path: Path) -> None:
    config = _build_config()
    unsafe_entry = EntryResult(entry=Entry(text="unsafe", source="inline"), is_safe=False)
    runner = mocker.Mock()
    runner.scan.return_value = ScanResult(
        entry_results=[EntryResult(entry=Entry(text="safe", source="inline")), unsafe_entry]
    )
    mocker.patch("cerbia.cli.scan._command.Console")
    mocker.patch("cerbia.cli.scan._command.load_config_from_yaml", return_value=config)
    mocker.patch("cerbia.cli.scan._command.configure_logging")
    mocker.patch("cerbia.cli.scan._command.Runner", return_value=runner)
    render = mocker.patch("cerbia.cli.scan._command.render_scan_result")

    with pytest.raises(typer.Exit) as exc_info:
        scan(config=tmp_path / "config.yaml", unsafe_only=True)

    assert exc_info.value.exit_code == 1
    assert render.call_args.args[0].entry_results == [unsafe_entry]


def test_scan_exits_when_runner_raises_cerbia_error(mocker, tmp_path: Path) -> None:
    config = _build_config()
    console = mocker.patch("cerbia.cli.scan._command.Console").return_value
    mocker.patch("cerbia.cli.scan._command.load_config_from_yaml", return_value=config)
    mocker.patch("cerbia.cli.scan._command.configure_logging")
    mocker.patch("cerbia.cli.scan._command.Runner").return_value.scan.side_effect = CerbIAError(
        "Bearer SCAN-ERROR-CANARY"
    )

    with pytest.raises(typer.Exit) as exc_info:
        scan(config=tmp_path / "config.yaml")

    assert exc_info.value.exit_code == 2
    assert console.print.call_args_list == [
        call("[bold]CerbIA CLI Scan[/bold]"),
        call("[bold]Running scan...[/bold]"),
        call("[red]Error:[/red] scan failed: Bearer SCAN-ERROR-CANARY"),
    ]


def test_scan_exits_when_runner_construction_raises_type_error(mocker, tmp_path: Path) -> None:
    config = _build_config()
    console = mocker.patch("cerbia.cli.scan._command.Console").return_value
    mocker.patch("cerbia.cli.scan._command.load_config_from_yaml", return_value=config)
    mocker.patch("cerbia.cli.scan._command.configure_logging")
    mocker.patch("cerbia.cli.scan._command.Runner", side_effect=TypeError("constructor error"))

    with pytest.raises(typer.Exit) as exc_info:
        scan(config=tmp_path / "config.yaml")

    assert exc_info.value.exit_code == 2
    assert console.print.call_args_list == [
        call("[bold]CerbIA CLI Scan[/bold]"),
        call("[bold]Running scan...[/bold]"),
        call("[red]Error:[/red] scan failed: constructor error"),
    ]


def test_scan_exits_when_runner_scan_raises_type_error(mocker, tmp_path: Path) -> None:
    config = _build_config()
    console = mocker.patch("cerbia.cli.scan._command.Console").return_value
    mocker.patch("cerbia.cli.scan._command.load_config_from_yaml", return_value=config)
    mocker.patch("cerbia.cli.scan._command.configure_logging")
    mocker.patch("cerbia.cli.scan._command.Runner").return_value.scan.side_effect = TypeError("scan error")

    with pytest.raises(typer.Exit) as exc_info:
        scan(config=tmp_path / "config.yaml")

    assert exc_info.value.exit_code == 2
    assert console.print.call_args_list == [
        call("[bold]CerbIA CLI Scan[/bold]"),
        call("[bold]Running scan...[/bold]"),
        call("[red]Error:[/red] scan failed: scan error"),
    ]


def test_scan_emits_a_fixed_info_milestone_and_uses_a_transient_status_while_scanning(mocker, tmp_path: Path) -> None:
    config = _build_config()
    console = mocker.patch("cerbia.cli.scan._command.Console").return_value
    progress_factory = mocker.patch("cerbia.cli.scan._command.Progress")
    progress = progress_factory.return_value
    mocker.patch("cerbia.cli.scan._command.SpinnerColumn")
    mocker.patch("cerbia.cli.scan._command.TextColumn")
    runner = mocker.Mock()
    runner.scan.return_value = ScanResult(entry_results=[])
    mocker.patch("cerbia.cli.scan._command.load_config_from_yaml", return_value=config)
    mocker.patch("cerbia.cli.scan._command.configure_logging")
    mocker.patch("cerbia.cli.scan._command.Runner", return_value=runner)
    mocker.patch("cerbia.cli.scan._command.render_scan_result")

    with pytest.raises(typer.Exit) as exc_info:
        scan(config=tmp_path / "config.yaml")

    assert exc_info.value.exit_code == 0
    assert console.print.call_args_list == [
        call("[bold]CerbIA CLI Scan[/bold]"),
        call("[bold]Running scan...[/bold]"),
    ]
    assert progress_factory.call_args.kwargs["transient"] is True
    progress.__enter__.assert_called_once_with()
    progress.__enter__.return_value.add_task.assert_called_once_with("Parsing configuration...", total=None)
    assert progress.__enter__.return_value.update.call_args_list == [
        call(progress.__enter__.return_value.add_task.return_value, description="Preparing components..."),
        call(progress.__enter__.return_value.add_task.return_value, description="Scanning..."),
    ]
    runner.scan.assert_called_once_with()
    progress.__exit__.assert_called_once_with(None, None, None)


def _build_config(*, loaders: list[LoaderConfig] | None = None) -> SimpleGateConfig:
    return SimpleGateConfig(
        name="test-gate",
        loaders=loaders if loaders is not None else [LoaderConfig(loader="test.Loader")],
        scanners=[ScannerConfig(scanner="test.Scanner")],
        score_aggregator=ScoreAggregatorConfig(score_aggregator="test.Aggregator"),
    )


def _write_scan_config(tmp_path: Path, texts: list[str]) -> Path:
    config_path = tmp_path / "scan.yaml"
    formatted_texts = "\n".join(f"        - {text}" for text in texts)
    config_path.write_text(
        f"""name: scan-contract
loaders:
  - loader: cerbia.core.loaders.text.TextLoader
    init_args:
      texts:
{formatted_texts}
scanners:
  - scanner: cerbia.core.scanners.canary._scanner.CanaryLeakScanner
    init_args:
      canary_tokens:
        - canary-token
score_aggregator:
  score_aggregator: cerbia.core.score_aggregators.max.MaxScoreAggregator
""",
        encoding="utf-8",
    )
    return config_path


def test_scan_reports_directory_config_as_usage_error(tmp_path: Path) -> None:
    config_directory = tmp_path / "configs"
    config_directory.mkdir()

    result = CliRunner().invoke(app, ["scan", "--config", str(config_directory)])

    assert result.exit_code == 2
    assert "Error:" in result.stderr
    assert "directory" in result.stderr.lower()
    assert config_directory.name in result.stderr


def test_scan_help_describes_a_single_yaml_config_file() -> None:

    result = CliRunner().invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    cleaned_output = " ".join(result.output.replace("│", " ").split())
    assert "single YAML configuration file" in cleaned_output
    assert "directory" not in result.output.lower()
    assert "DEBUG/INFO/WARNING/ERROR/CRITICAL" in result.output


def test_scan_reports_a_safe_real_core_result(tmp_path: Path) -> None:
    config_path = _write_scan_config(tmp_path, ["ordinary text"])
    output_path = tmp_path / "results.json"

    result = CliRunner().invoke(app, ["scan", "--config", str(config_path), "--output", str(output_path)])

    payload = _SCAN_PAYLOAD_ADAPTER.validate_json(output_path.read_text(encoding="utf-8"))
    assert result.exit_code == 0
    assert payload["is_safe"] is True
    assert "SAFE" in result.stderr


def test_scan_writes_info_milestone_to_log_file_without_spinner_artifacts(tmp_path: Path) -> None:
    config_path = _write_scan_config(tmp_path, ["ordinary text"])
    log_path = tmp_path / "scan.log"

    result = CliRunner().invoke(
        app,
        ["scan", "--config", str(config_path), "--log-level", "INFO", "--log-file", str(log_path)],
    )

    log_output = log_path.read_text(encoding="utf-8")
    assert result.exit_code == 0
    assert "SAFE" in result.stderr
    assert "Running scan..." in result.stderr
    assert "Parsing configuration..." not in log_output
    assert "Preparing components..." not in log_output
    assert "Scanning..." not in log_output
    assert "ordinary text" not in log_output


def test_scan_reports_an_unsafe_real_core_result(tmp_path: Path) -> None:
    config_path = _write_scan_config(tmp_path, ["the canary-token leaked"])
    output_path = tmp_path / "results.json"

    result = CliRunner().invoke(app, ["scan", "--config", str(config_path), "--output", str(output_path)])

    payload = _SCAN_PAYLOAD_ADAPTER.validate_json(output_path.read_text(encoding="utf-8"))
    assert result.exit_code == 1
    assert payload["is_safe"] is False
    assert "UNSAFE" in result.stderr


def test_scan_unsafe_only_filters_console_and_json_without_changing_exit_status(tmp_path: Path) -> None:
    config_path = _write_scan_config(tmp_path, ["ordinary text", "the canary-token leaked"])
    output_path = tmp_path / "results.json"

    result = CliRunner().invoke(
        app,
        ["scan", "--config", str(config_path), "--unsafe-only", "--output", str(output_path)],
    )

    payload = _SCAN_PAYLOAD_ADAPTER.validate_json(output_path.read_text(encoding="utf-8"))
    assert result.exit_code == 1
    assert "UNSAFE" in result.stderr
    assert "No canary token leakage detected" not in result.stderr
    assert "Canary token leaked" in result.stderr
    assert set(payload) == {"entry_results", "is_safe", "total_findings", "unsafe_entries"}
    assert len(payload["entry_results"]) == 1
    assert payload["entry_results"][0]["is_safe"] is False
    assert (payload["is_safe"], payload["total_findings"], payload["unsafe_entries"]) == (False, 1, 1)


def test_scan_overwrites_existing_json_output_with_a_warning(tmp_path: Path) -> None:
    config_path = _write_scan_config(tmp_path, ["ordinary text"])
    output_path = tmp_path / "results.json"
    output_path.write_text("stale", encoding="utf-8")

    result = CliRunner().invoke(app, ["scan", "--config", str(config_path), "--output", str(output_path)])

    payload = _SCAN_PAYLOAD_ADAPTER.validate_json(output_path.read_text(encoding="utf-8"))
    assert result.exit_code == 0
    assert payload["is_safe"] is True


def test_scan_reports_malformed_yaml_as_usage_error(tmp_path: Path) -> None:
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text("loaders: [", encoding="utf-8")

    result = CliRunner().invoke(app, ["scan", "--config", str(config_path)])

    assert result.exit_code == 2
    assert "Error:" in result.stderr
    assert "YAML" in result.stderr
    assert config_path.name in result.stderr


def test_scan_reports_missing_config_as_usage_error(tmp_path: Path) -> None:
    config_path = tmp_path / "missing.yaml"

    result = CliRunner().invoke(app, ["scan", "--config", str(config_path)])

    assert result.exit_code == 2
    assert "Error:" in result.stderr
    assert "not found" in result.stderr.lower()
    assert config_path.name in result.stderr


def test_scan_records_raw_unwritable_destination_failure(tmp_path: Path) -> None:
    config_path = _write_scan_config(tmp_path, ["ordinary text"])
    output_parent = tmp_path / "not-a-directory"
    output_parent.write_text("block output creation", encoding="utf-8")
    output_path = output_parent / "results.json"

    result = CliRunner().invoke(app, ["scan", "--config", str(config_path), "--output", str(output_path)])

    assert result.exit_code == 1
    assert isinstance(result.exception, FileExistsError)
    assert "SAFE" in result.stderr


def test_scan_uses_real_cli_text_and_file_loaders(tmp_path: Path) -> None:
    config_path = tmp_path / "scan.yaml"
    config_path.write_text(
        "\n".join(
            [
                "name: override",
                "scanners:",
                "  - scanner: cerbia.core.scanners.canary._scanner.CanaryLeakScanner",
                "    init_args:",
                "      canary_tokens: [canary-token]",
                "score_aggregator:",
                "  score_aggregator: cerbia.core.score_aggregators.max.MaxScoreAggregator",
            ]
        ),
        encoding="utf-8",
    )
    input_path = tmp_path / "input.txt"
    input_path.write_text("file content", encoding="utf-8")
    output_path = tmp_path / "results.json"

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--config",
            str(config_path),
            "--text",
            "inline content",
            "--file",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    sources = [entry["entry"]["source"] for entry in payload["entry_results"]]
    assert "inline[0]" in sources
    assert str(input_path.resolve()) in sources


def test_scan_applies_the_cli_threshold_override(tmp_path: Path) -> None:
    config_path = _write_scan_config(tmp_path, ["canary-token leaked"])
    output_path = tmp_path / "results.json"

    result = CliRunner().invoke(
        app,
        ["scan", "--config", str(config_path), "--threshold", "1.1", "--output", str(output_path)],
    )

    assert result.exit_code == 0
    assert '"is_safe": true' in output_path.read_text(encoding="utf-8")


def test_scan_applies_threshold_before_unsafe_only_filtering(tmp_path: Path) -> None:
    config_path = _write_scan_config(tmp_path, ["canary-token leaked"])
    output_path = tmp_path / "results.json"

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--config",
            str(config_path),
            "--threshold",
            "1.1",
            "--unsafe-only",
            "--output",
            str(output_path),
        ],
    )

    payload = _SCAN_PAYLOAD_ADAPTER.validate_json(output_path.read_text(encoding="utf-8"))
    assert result.exit_code == 0
    assert "No unsafe entries found" in result.stderr
    assert payload["entry_results"] == []
    assert (payload["is_safe"], payload["total_findings"], payload["unsafe_entries"]) == (True, 0, 0)


def test_scan_retains_error_exit_without_disclosing_configuration_values(tmp_path: Path) -> None:
    config_path = tmp_path / "invalid-loader.yaml"
    config_path.write_text(
        "\n".join(
            [
                "name: malformed-loader",
                "loaders:",
                "  - loader: cerbia.core.loaders.text.DoesNotExist",
                "    init_args:",
                "      texts: [content]",
                "scanners:",
                "  - scanner: cerbia.core.scanners.canary._scanner.CanaryLeakScanner",
                "score_aggregator:",
                "  score_aggregator: cerbia.core.score_aggregators.max.MaxScoreAggregator",
            ]
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["scan", "--config", str(config_path)])

    assert result.exit_code == 2
    assert "CerbIA CLI Scan" in result.stderr
    assert "Running scan..." in result.stderr
    assert "scan failed" in result.stderr
    assert "malformed-loader" not in result.stderr
    assert "DoesNotExist" in result.stderr


def test_scan_hides_unexpected_component_construction_exceptions(tmp_path: Path) -> None:
    config_path = tmp_path / "unexpected-exception.yaml"
    config_path.write_text(
        "\n".join(
            [
                "name: unexpected-exception",
                "loaders:",
                "  - loader: cerbia.core.loaders.text.TextLoader",
                "    init_args:",
                "      texts: [ordinary text]",
                "scanners:",
                "  - scanner: cerbia.core.scanners.keyword.KeywordScanner",
                "    init_args:",
                "      EXCEPTION-TEXT-CANARY: value",
                "score_aggregator:",
                "  score_aggregator: cerbia.core.score_aggregators.max.MaxScoreAggregator",
            ]
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["scan", "--config", str(config_path)])

    assert result.exit_code == 2
    assert "CerbIA CLI Scan" in result.stderr
    assert "Running scan..." in result.stderr
    assert "scan failed" in result.stderr
    assert "Traceback" not in result.stderr
    assert "TypeError" not in result.stderr
    assert "EXCEPTION-TEXT-CANARY" in result.stderr
