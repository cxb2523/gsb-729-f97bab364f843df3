import json
from pathlib import Path

import pytest
import yaml
from cerbia.cli import app
from cerbia.cli.scan import _command
from cerbia.core.config import CascadeGateConfig
from cerbia.core.exceptions import CerbIAError
from cerbia.core.models.results import ScanResult
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.scanners import CanaryLeakScanner, KeywordScanner
from typer.testing import CliRunner

from .cascade_support import write_cascade

pytestmark = pytest.mark.integration


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    invocations: list[str] = []
    canary_scan = CanaryLeakScanner.scan
    keyword_scan = KeywordScanner.scan

    def canary(scanner: CanaryLeakScanner, text: str) -> ScanOutcome:
        invocations.append("canary")
        if text == "operational failure":
            raise CerbIAError("synthetic scanner failure")
        return canary_scan(scanner, text)

    def keyword(scanner: KeywordScanner, text: str) -> ScanOutcome:
        invocations.append("keyword")
        return keyword_scan(scanner, text)

    monkeypatch.setattr(CanaryLeakScanner, "scan", canary)
    monkeypatch.setattr(KeywordScanner, "scan", keyword)
    return invocations


@pytest.mark.parametrize("text", ["ordinary text", "CASCADE_TOKEN"])
def test_cascade_exit_and_invocations_when_scanning_local_inputs(tmp_path: Path, calls: list[str], text: str) -> None:
    # Given: a real YAML/factory/Runner path with instrumented local leaf scanners.
    config = write_cascade(tmp_path / "cascade.yaml")
    output = tmp_path / "result.json"

    # When: invoking the actual public command.
    result = CliRunner().invoke(app, ["scan", "-c", str(config), "-t", text, "-o", str(output)])

    # Then: terminal decisions stop the fallback.
    expected_exit = {"ordinary text": 0, "CASCADE_TOKEN": 1}[text]
    assert result.exit_code == expected_exit, result.output
    assert calls == ["canary"]
    payload = ScanResult.model_validate_json(output.read_text())
    entry = payload.entry_results[0]
    assert entry.entry.text == text
    assert entry.findings[-1].stage == "guard"
    assert len(entry.findings) == len(calls)
    assert text not in json.dumps(json.loads(output.read_text())["entry_results"][0]["stages"])
    assert "guard" in result.stderr
    assert "final" in result.stderr
    if expected_exit == 1:
        assert "⊘ NOT REACHED" in result.stderr
    else:
        assert "score=0.00" in result.stderr


@pytest.mark.parametrize("threshold", ["0.2", "nan"])
def test_threshold_rejects_invalid_result_before_construction_when_gate_is_cascade(
    tmp_path: Path, mocker, threshold: str
) -> None:
    # Given: an inherited nonfinal threshold and a construction spy.
    config = write_cascade(tmp_path / "cascade.yaml")
    raw = yaml.safe_load(config.read_text())
    raw["threshold"] = 0.5
    raw["stages"][0].pop("threshold")
    config.write_text(yaml.safe_dump(raw))
    runner = mocker.spy(_command, "Runner")

    # When: the root override invalidates range or the defer band.
    result = CliRunner().invoke(app, ["scan", "-c", str(config), "--threshold", threshold])

    # Then: validation precedes every component/API construction.
    assert result.exit_code == 2
    assert "invalid configuration" in result.stderr
    assert "threshold" in result.stderr or "defer_above" in result.stderr
    runner.assert_not_called()


@pytest.mark.parametrize("root_present", [False, True])
def test_threshold_supplies_inherited_cascade_root_without_overriding_explicit_stages(
    tmp_path: Path, mocker, root_present: bool
) -> None:
    # Given
    config = write_cascade(tmp_path / "cascade.yaml")
    raw = yaml.safe_load(config.read_text())
    if root_present:
        raw["threshold"] = 0.5
    raw["stages"][0].pop("threshold")
    raw["stages"][1]["threshold"] = 0.0
    config.write_text(yaml.safe_dump(raw))
    construction = mocker.spy(_command, "Runner")

    # When
    result = CliRunner().invoke(app, ["scan", "-c", str(config), "--threshold", "0.8"])

    # Then
    assert result.exit_code == 0, result.output
    parsed = construction.call_args.args[0]
    assert isinstance(parsed, CascadeGateConfig)
    assert parsed.threshold == 0.8
    assert [stage.threshold for stage in parsed.stages] == [0.8, 0.0]


@pytest.mark.parametrize("policy", ["fail", "block"])
def test_error_policy_when_scanner_fails(tmp_path: Path, calls: list[str], policy: str) -> None:
    # Given: an actual cascade with an operational leaf fault.
    config = write_cascade(tmp_path / "cascade.yaml", policy=policy)
    output = tmp_path / "result.json"

    # When: scanning the deterministic fault input.
    result = CliRunner().invoke(app, ["scan", "-c", str(config), "-t", "operational failure", "-o", str(output)])

    # Then: fail is exit 2, fail-closed block is exit 1 with no fabricated threat finding.
    assert result.exit_code == (2 if policy == "fail" else 1), result.output
    assert calls == ["canary"]
    if policy == "block":
        entry = ScanResult.model_validate_json(output.read_text()).entry_results[0]
        assert entry.stages is not None
        assert entry.stages[0].score is None
        assert entry.stages[0].result == "block"
        assert entry.findings == []
        assert "scanner_error" in result.stderr
        assert "score=" not in result.stderr
    else:
        assert not output.exists()
        assert "scan failed" in result.stderr


def test_loader_precedence_when_text_and_file_override_nested_config(tmp_path: Path, calls: list[str]) -> None:
    # Given: configured input differs from both CLI inputs.
    config = write_cascade(tmp_path / "cascade.yaml")
    file = tmp_path / "input.txt"
    file.write_text("CASCADE_TOKEN")
    output = tmp_path / "result.json"

    # When: providing text and file together.
    result = CliRunner().invoke(
        app, ["scan", "-c", str(config), "-t", "ordinary text", "-f", str(file), "-o", str(output)]
    )

    # Then: CLI inputs replace, rather than append to, configured loaders in existing order.
    assert result.exit_code == 1, result.output
    entries = ScanResult.model_validate_json(output.read_text()).entry_results
    assert [entry.entry.text for entry in entries] == ["ordinary text", "CASCADE_TOKEN"]
    assert [entry.entry.source for entry in entries] == ["inline[0]", str(file.resolve())]
    assert calls == ["canary", "canary"]


def test_unsafe_only_when_all_safe_keeps_exit_zero(tmp_path: Path, calls: list[str]) -> None:
    # Given: a safe cascade entry and an existing postfilter.
    config = write_cascade(tmp_path / "cascade.yaml")
    output = tmp_path / "result.json"
    # When: requesting unsafe entries only.
    result = CliRunner().invoke(
        app, ["scan", "-c", str(config), "-t", "ordinary text", "--unsafe-only", "-o", str(output)]
    )

    # Then: execution remains complete even though the report has no entries.
    assert result.exit_code == 0, result.output
    assert calls == ["canary"]
    assert ScanResult.model_validate_json(output.read_text()).entry_results == []
    assert "No unsafe entries found" in result.stderr


def test_unsafe_only_when_mixed_inputs_still_executes_every_entry(tmp_path: Path, calls: list[str]) -> None:
    # Given: mixed safe/unsafe entries and the postfilter flag.
    config = write_cascade(tmp_path / "cascade.yaml")
    output = tmp_path / "result.json"
    # When: scanning both entries.
    result = CliRunner().invoke(
        app,
        ["scan", "-c", str(config), "-t", "ordinary text", "-t", "CASCADE_TOKEN", "--unsafe-only", "-o", str(output)],
    )

    # Then: only unsafe output remains, without skipping safe execution or losing trace.
    assert result.exit_code == 1, result.output
    assert calls == ["canary", "canary"]
    payload = ScanResult.model_validate_json(output.read_text())
    assert [entry.entry.text for entry in payload.entry_results] == ["CASCADE_TOKEN"]
    assert payload.entry_results[0].findings[-1].stage == "guard"


@pytest.mark.parametrize("raw", ["name: mixed\nthreshold: 0\ngate: {type: cascade, stages: []}"])
def test_invalid_config_when_parsing_rejects_without_scanning(tmp_path: Path, calls: list[str], raw: str) -> None:
    # Given: invalid YAML/schema input at the CLI boundary.
    config = tmp_path / "invalid.yaml"
    config.write_text(raw)

    # When: invoking scan.
    result = CliRunner().invoke(app, ["scan", "-c", str(config)])

    # Then: the existing error exit survives with no scanner side effect.
    assert result.exit_code == 2
    assert "Error:" in result.stderr
    assert calls == []


@pytest.mark.parametrize("threshold", ["0.5", "1.1"])
def test_explicit_simple_threshold_when_overridden_targets_root(
    tmp_path: Path, calls: list[str], threshold: str
) -> None:
    # Given: an explicit simple gate with a different configured threshold.
    config = tmp_path / "simple.yaml"
    config.write_text(
        "name: explicit\ntype: simple\nthreshold: 0\nscanners:\n"
        "  - scanner: cerbia.core.scanners.CanaryLeakScanner\n"
        "    init_args: {canary_tokens: [CASCADE_TOKEN]}\n"
        "score_aggregator:\n"
        "  score_aggregator: cerbia.core.score_aggregators.MaxScoreAggregator\n"
    )

    # When: overriding both input and threshold through the CLI.
    result = CliRunner().invoke(app, ["scan", "-c", str(config), "-t", "CASCADE_TOKEN", "--threshold", threshold])

    # Then: simple override behavior remains distinct from the private CLI's range restriction.
    assert result.exit_code == (1 if threshold == "0.5" else 0), result.output
    assert calls == ["canary"]


def test_literal_terminal_stage_preserves_cli_exit_and_json(tmp_path: Path) -> None:
    config = write_cascade(tmp_path / "cascade.yaml")
    raw = yaml.safe_load(config.read_text())
    raw["stages"][0]["id"] = "[/bold]guard"
    config.write_text(yaml.safe_dump(raw))
    output = tmp_path / "result.json"

    result = CliRunner().invoke(app, ["scan", "-c", str(config), "-t", "CASCADE_TOKEN", "-o", str(output)])

    assert result.exit_code == 1
    assert "[/bold]guard" in result.stderr
    entry = ScanResult.model_validate_json(output.read_text()).entry_results[0]
    assert entry.findings[0].stage == "[/bold]guard"
    assert entry.stages is not None
    assert entry.stages[1].result == "not_reached"
