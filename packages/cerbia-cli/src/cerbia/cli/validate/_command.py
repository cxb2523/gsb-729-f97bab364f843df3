from pathlib import Path
from typing import Annotated

import typer
from cerbia.core.exceptions import CerbIAError
from cerbia.core.runner import Runner
from rich.console import Console

from ..config import load_config_from_yaml
from ..logging import configure_logging
from ._ui import render_validation_summary

app = typer.Typer(no_args_is_help=True)


@app.command()
def validate(
    config: Annotated[Path, typer.Argument(help="Path to a single YAML configuration file.")],
    log_level: Annotated[
        str | None, typer.Option("--log-level", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL).")
    ] = None,
    log_file: Annotated[
        Path | None, typer.Option("--log-file", help="Write logs to this file instead of stderr.")
    ] = None,
) -> None:
    """Validate a single YAML configuration file and report gate structure.

    Parses the schema first, then eagerly initializes every configured component,
    including models. Does not scan inputs or assess model quality.

    Args:
        config (Path): YAML configuration path.
        log_level (str | None): Optional logging level override.
        log_file (Path | None): Optional log file path; an existing log file is overwritten.

    Raises:
        typer.Exit: With code 2 for handled file, schema, logging-level, or constructor type errors; with code 1
            for CerbIAError during component construction or summary rendering.
    """
    err_console = Console(stderr=True)

    if not config.exists():
        err_console.print("[red]Error:[/red] configuration file not found.")
        raise typer.Exit(code=2)

    cfg = load_config_from_yaml(config, err_console)
    configure_logging(log_level, log_file, err_console)

    try:
        runner = Runner(cfg)
        render_validation_summary(cfg, runner, err_console)

    except CerbIAError as exc:
        err_console.print("[red bold]✗ Invalid config[/red bold]")
        raise typer.Exit(code=1) from exc
    except TypeError as exc:
        err_console.print("[red bold]✗ Config validation failed.[/red bold]")
        raise typer.Exit(code=2) from exc
