import math

from cerbia.core.models.results import EntryResult, ScanResult
from cerbia.core.models.stages import StageResult
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def render_scan_result(results: ScanResult, unsafe_only: bool, output_console: Console) -> None:
    """Render selected scan results with the established Rich panels.

    Args:
        results (ScanResult): The scan result to render.
        unsafe_only (bool): Omit near-zero-risk finding rows and skipped-scanner rows. The caller filters entries.
        output_console (Console): Rich console for output.
    """
    if unsafe_only and not results.entry_results:
        output_console.print(_build_no_unsafe_panel())
        return

    for entry_result in results.entry_results:
        source = entry_result.entry.source
        field_path = entry_result.entry.field_path
        panel = _build_gate_panel(entry_result, unsafe_only=unsafe_only)
        show_source_label = unsafe_only or len(results.entry_results) > 1

        if show_source_label:
            source_label = f"[bold white]{escape(source)}[/bold white]"
            if field_path and field_path != source:
                source_label += f":[white]{escape(field_path)}[/white]"
            output_console.print(f"\n{source_label}")

        output_console.print(panel)


def _build_no_unsafe_panel() -> Panel:
    return Panel(
        Text(""),
        title=Text("✓ No unsafe entries found", style="bold green"),
        border_style="green",
        padding=(0, 1),
    )


def _build_gate_panel(entry_result: EntryResult, unsafe_only: bool) -> Panel | Group:
    if entry_result.stages is not None:
        return Group(
            *(_build_stage_panel(entry_result, stage, unsafe_only) for stage in entry_result.stages),
        )

    is_safe = entry_result.is_safe
    border = "green" if is_safe else "red"
    status = Text("✓ SAFE", style="bold green") if is_safe else Text("✗ UNSAFE", style="bold red")

    table = Table(show_header=True, expand=True, show_edge=False, pad_edge=False)
    table.add_column("Scanner", style="cyan", width=24, overflow="fold")
    table.add_column("", justify="center", width=3)
    table.add_column("Rationale", ratio=5)

    for finding in entry_result.findings:
        is_safe_finding = math.isclose(finding.risk_score, 0.0, abs_tol=1e-9)
        if unsafe_only and is_safe_finding:
            continue

        marker = Text("✓", style="green") if is_safe_finding else Text("✗", style="red")
        rationale = Text(finding.rationale)

        if finding.matches:
            spans = ", ".join(f"{match.start}:{match.end}" for match in finding.matches)
            rationale = rationale.append(f" (matches: {spans})", style="dim")

        table.add_row(Text(finding.scanner_name), marker, rationale)

    if not unsafe_only:
        for skipped in entry_result.skipped_scanners:
            table.add_row(
                Text(skipped.scanner_name, style="dim"),
                Text("⊘", style="dim"),
                Text(skipped.reason, style="dim"),
            )

    subtitle = f"score={entry_result.aggregated_score:.2f} · {entry_result.rationale}"
    return Panel(
        table,
        title=status,
        subtitle=f"[dim]{subtitle}[/dim]",
        subtitle_align="left",
        border_style=border,
        padding=(0, 1),
    )


def _build_stage_panel(entry_result: EntryResult, stage: StageResult, unsafe_only: bool) -> Panel:
    disposition = {
        "allow": ("✓ SAFE", "green"),
        "block": ("✗ UNSAFE", "red"),
        "defer": ("◇ DEFER", "yellow"),
        "not_reached": ("⊘ NOT REACHED", "dim"),
    }
    status, border = disposition[stage.result]

    table = Table(show_header=True, expand=True, show_edge=False, pad_edge=False)
    table.add_column("Scanner", style="cyan", width=24, overflow="fold")
    table.add_column("", justify="center", width=3)
    table.add_column("Rationale", ratio=5)

    for finding in entry_result.findings:
        if finding.stage != stage.id:
            continue

        is_safe_finding = math.isclose(finding.risk_score, 0.0, abs_tol=1e-9)
        if unsafe_only and is_safe_finding:
            continue

        marker = Text("✓", style="green") if is_safe_finding else Text("✗", style="red")
        rationale = Text(finding.rationale)

        if finding.matches:
            spans = ", ".join(f"{match.start}:{match.end}" for match in finding.matches)
            rationale = rationale.append(f" (matches: {spans})", style="dim")

        table.add_row(Text(finding.scanner_name), marker, rationale)

    body: Table | Text = table
    if not table.row_count:
        body = Text("No findings in this stage.", style="dim")

    title = Text(stage.id).append(" · ").append(status, style=f"bold {border}")
    subtitle = None
    if stage.score is not None:
        subtitle = Text(f"score={stage.score:.2f}", style="dim")
    elif stage.result == "block":
        subtitle = Text(entry_result.rationale, style="dim")

    return Panel(
        body,
        title=title,
        subtitle=subtitle,
        subtitle_align="left",
        border_style=border,
        padding=(0, 1),
    )
