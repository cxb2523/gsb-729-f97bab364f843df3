from io import StringIO

import pytest
from cerbia.cli.scan._ui import _build_stage_panel, render_scan_result
from cerbia.core.models.entries import Entry
from cerbia.core.models.results import EntryResult, ScanResult
from cerbia.core.models.scans import Finding, MatchSpan, SkippedScanner
from cerbia.core.types import Action, Severity
from rich.cells import cell_len
from rich.console import Console

pytestmark = pytest.mark.unit


def test_render_scan_result_renders_findings_matches_and_skipped_scanners() -> None:
    finding = Finding(
        scanner_id="scanner",
        scanner_name="Threat Scanner",
        risk_score=0.8,
        severity=Severity.HIGH,
        action=Action.BLOCK,
        rationale="Threat found",
        matches=[MatchSpan(start=2, end=5)],
    )
    result = ScanResult(
        entry_results=[
            EntryResult(
                entry=Entry(text="content", source="config.yaml"),
                is_safe=False,
                findings=[finding],
                skipped_scanners=[
                    SkippedScanner(scanner_id="skip", scanner_name="Skipped Scanner", reason="Not supported")
                ],
            )
        ]
    )
    output = StringIO()

    render_scan_result(result, False, Console(file=output, force_terminal=False, width=120))

    assert "matches: 2:5" in output.getvalue()
    assert "Skipped Scanner" in output.getvalue()


def test_render_scan_result_when_simple_unsafe_keeps_status_score_and_rationale() -> None:
    result = ScanResult(
        entry_results=[
            EntryResult(
                entry=Entry(text="content", source="config.yaml"),
                is_safe=False,
                aggregated_score=0.64,
                rationale="Threat found",
            )
        ]
    )
    output = StringIO()

    render_scan_result(result, False, Console(file=output, force_terminal=False))

    assert "✗ UNSAFE" in output.getvalue()
    assert "score=0.64 · Threat found" in output.getvalue()


def test_render_scan_result_hides_skipped_scanners_when_unsafe_only_is_enabled() -> None:
    result = ScanResult(
        entry_results=[
            EntryResult(
                entry=Entry(text="content", source="config.yaml"),
                is_safe=False,
                skipped_scanners=[
                    SkippedScanner(scanner_id="skip", scanner_name="Skipped Scanner", reason="Not supported")
                ],
            )
        ]
    )
    output = StringIO()

    render_scan_result(result, True, Console(file=output, force_terminal=False))

    assert "Skipped Scanner" not in output.getvalue()


def test_render_scan_result_shows_source_for_single_unsafe_entry_when_unsafe_only_is_enabled() -> None:
    result = ScanResult(
        entry_results=[
            EntryResult(
                entry=Entry(text="content", source="config.yaml", field_path="entries[0]"),
                is_safe=False,
            )
        ]
    )
    output = StringIO()

    render_scan_result(result, True, Console(file=output, force_terminal=False))

    assert "config.yaml:entries[0]" in output.getvalue()


def test_render_scan_result_shows_source_once_when_field_path_is_missing() -> None:
    result = ScanResult(entry_results=[EntryResult(entry=Entry(text="content", source="inline[0]"), is_safe=False)])
    output = StringIO()

    render_scan_result(result, True, Console(file=output, force_terminal=False))

    assert output.getvalue().count("inline[0]") == 1


def test_render_scan_result_keeps_markup_like_source_and_path_literal() -> None:
    result = ScanResult(
        entry_results=[
            EntryResult(
                entry=Entry(text="content", source="[bold]source[/bold]", field_path="[italic]payload.prompt[/italic]"),
                is_safe=False,
            )
        ]
    )
    output = StringIO()

    render_scan_result(result, True, Console(file=output, force_terminal=False))

    assert "[bold]source[/bold]:[italic]payload.prompt[/italic]" in output.getvalue()


def test_render_scan_result_renders_no_unsafe_entries_message_when_result_is_empty() -> None:
    output = StringIO()

    render_scan_result(ScanResult(), True, Console(file=output, force_terminal=False))

    assert "No unsafe entries found" in output.getvalue()


@pytest.mark.parametrize(
    "result,color,status",
    [
        ("allow", "green", "✓ SAFE"),
        ("block", "red", "✗ UNSAFE"),
        ("defer", "yellow", "◇ DEFER"),
        ("not_reached", "dim", "⊘ NOT REACHED"),
    ],
)
def test_stage_panel_preserves_disposition_and_score_footer(result: str, color: str, status: str) -> None:
    stages = [{"id": "stage", "result": result, "score": 0.64}]
    index, safe, score = 0, result != "block", 0.64

    if result == "defer":
        stages.append({"id": "last", "result": "allow", "score": 0.0})
        score = 0.0
    elif result == "not_reached":
        stages = [{"id": "done", "result": "allow", "score": 0.0}, {"id": "stage", "result": "not_reached"}]
        index, score = 1, 0.0

    entry = EntryResult.model_validate(
        {"entry": {"text": "safe", "source": "inline"}, "is_safe": safe, "aggregated_score": score, "stages": stages}
    )
    assert entry.stages is not None

    panel = _build_stage_panel(entry, entry.stages[index], False)

    assert panel.border_style == color
    assert str(panel.title) == f"stage · {status}"
    subtitle = str(panel.subtitle) if panel.subtitle is not None else None
    expected_subtitle = None if result == "not_reached" else "score=0.64"
    assert subtitle == expected_subtitle


def test_operational_block_renders_literal_stage_and_rationale_without_score() -> None:
    entry = EntryResult.model_validate(
        {
            "entry": {"text": "safe", "source": "inline"},
            "is_safe": False,
            "aggregated_score": 1.0,
            "rationale": "[/bold]private marker",
            "stages": [{"id": "[/bold]stage", "result": "block"}],
        }
    )
    assert entry.stages is not None

    panel = _build_stage_panel(entry, entry.stages[0], False)

    assert str(panel.title) == "[/bold]stage · ✗ UNSAFE"
    assert str(panel.subtitle) == "[/bold]private marker"


@pytest.mark.parametrize("width", [80, 120])
@pytest.mark.parametrize("name", ["[/bold]scanner", "[bold]scanner[/bold]", "N" * 100])
@pytest.mark.parametrize("cascade", [False, True])
def test_dynamic_finding_cells_are_literal_and_wrap_without_losing_rationale(
    width: int, name: str, cascade: bool
) -> None:
    finding = Finding(
        scanner_id="a",
        scanner_name=name,
        risk_score=0.8,
        severity=Severity.CRITICAL,
        action=Action.BLOCK,
        rationale="[/bold]RATIONALE_TOKEN",
        matches=[MatchSpan(start=0, end=3)],
        stage="first" if cascade else None,
    )
    entry = EntryResult.model_validate(
        {
            "entry": {"text": "bad", "source": "inline"},
            "is_safe": False,
            "aggregated_score": 0.8,
            "findings": [finding],
            "stages": [{"id": "first", "result": "block", "score": 0.8}, {"id": "last", "result": "not_reached"}]
            if cascade
            else None,
        }
    )
    output = StringIO()

    render_scan_result(
        ScanResult(entry_results=[entry]), False, Console(file=output, width=width, force_terminal=False)
    )

    rendered = output.getvalue()
    cells = [line.split("│")[1].strip() for line in rendered.splitlines() if line.startswith("│") and "│" in line[1:]]

    assert name in "".join(cells)
    assert "[/bold]RATIONALE_TOKEN" in rendered
    assert "matches: 0:3" in rendered
    assert max(map(cell_len, rendered.splitlines())) <= width


def test_stage_panels_group_only_owned_findings() -> None:
    entry = EntryResult.model_validate(
        {
            "entry": {"text": "safe", "source": "inline"},
            "stages": [
                {"id": "first", "result": "defer", "score": 0.1},
                {"id": "last", "result": "allow", "score": 0.0},
            ],
            "findings": [
                {
                    "scanner_id": scanner,
                    "scanner_name": scanner,
                    "risk_score": 0.0,
                    "severity": "critical",
                    "action": "block",
                    "rationale": scanner,
                    "stage": stage,
                }
                for scanner, stage in [("FIRST_ONLY", "first"), ("LAST_ONLY", "last")]
            ],
        }
    )
    assert entry.stages is not None

    rendered = []
    for stage in entry.stages:
        output = StringIO()
        Console(file=output, width=100).print(_build_stage_panel(entry, stage, False))
        rendered.append(output.getvalue())

    assert "FIRST_ONLY" in rendered[0]
    assert "LAST_ONLY" not in rendered[0]
    assert "LAST_ONLY" in rendered[1]
    assert "FIRST_ONLY" not in rendered[1]
