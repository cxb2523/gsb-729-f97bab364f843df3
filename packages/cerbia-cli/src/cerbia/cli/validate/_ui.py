from typing import assert_never

from cerbia.core.config import CerbIAConfig
from cerbia.core.runner import Runner
from cerbia.core.security_gate import CascadeGate, SimpleGate
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def render_validation_summary(config: CerbIAConfig, runner: Runner, output_console: Console) -> None:
    """Render the established validation table and status panel.

    Args:
        config (CerbIAConfig): Validated configuration instance.
        runner (Runner): Runner instance initialized with the configuration.
        output_console (Console): Rich console for output.
    """
    table = Table(show_header=True, expand=True, border_style="green")
    table.add_column("Gate", style="bold cyan", no_wrap=True)
    table.add_column("Scanners", ratio=3)
    table.add_column("#", justify="right", style="dim")

    match runner.gate:
        case CascadeGate() as gate:
            table = Table(show_header=True, expand=True, border_style="green", show_lines=True)
            table.add_column("Stage", style="bold cyan")
            table.add_column("Scanners")
            table.add_column("Rules", ratio=3)

            for stage in gate.stages:
                settings = stage.config
                rules = (
                    f"aggregator={type(stage.score_aggregator).__name__}\n"
                    f"block: score > threshold={settings.threshold}\n"
                )

                if stage is gate.stages[-1]:
                    rules += "final: allow any score not blocked"
                else:
                    if settings.defer_above is not None:
                        rules += f"defer: score > defer_above={settings.defer_above}\n"
                    rules += "allow otherwise"

                table.add_row(
                    Text(stage.config.id),
                    Text(", ".join(type(scanner).__name__ for scanner in stage.scanners)),
                    Text(rules),
                )

            output_console.print(Text(f"Gate: {gate.name} · cascade · on_scanner_error={gate.on_scanner_error}"))
        case SimpleGate():
            scanner_names = [type(scanner).__name__ for scanner in runner.gate.scanners]
            table.add_row(runner.gate.name, ", ".join(scanner_names), str(len(scanner_names)))
        case unreachable:
            assert_never(unreachable)

    loader_status = "[green]yes[/green]" if config.loaders else "[yellow]no[/yellow]"

    output_console.print(
        Panel(
            table,
            title="[bold green]✓ Config valid[/bold green]",
            subtitle=f"1 gate(s) · loaders={loader_status}",
            border_style="green",
            padding=(0, 1),
        )
    )
