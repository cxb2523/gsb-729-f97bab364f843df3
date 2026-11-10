import logging
from pathlib import Path
from typing import Final

import typer
from rich.console import Console

_LOG_LEVELS: Final = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
_LOG_FORMAT: Final = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def configure_logging(log_level: str | None, log_file: Path | None, output_console: Console) -> Path | None:
    """Configure application logging from CLI overrides.

    Args:
        log_level (str | None): Optional explicit log-level override from the CLI.
        log_file (Path | None): Optional explicit log-file path from the CLI.
        output_console (Console): Rich console for outputting warnings and errors.

    Returns:
        Path | None: The effective log file path, if any.

    Raises:
        typer.Exit: Raised with exit code ``2`` when the effective log level is invalid.
    """
    effective_level = (log_level or "INFO").upper()

    if effective_level not in _LOG_LEVELS:
        output_console.print(f"[red]Error:[/red] invalid log level. Choose from {', '.join(_LOG_LEVELS)}.")
        raise typer.Exit(code=2)

    is_default_configuration = log_level is None and log_file is None
    if is_default_configuration and logging.getLogger().handlers:
        return None

    handlers: list[logging.Handler] = []
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        if log_file.exists():
            output_console.print("[yellow]Warning:[/yellow] overwriting existing log file.")

        handlers.append(logging.FileHandler(log_file, mode="w"))

    else:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(
        level=effective_level,
        format=_LOG_FORMAT,
        handlers=handlers,
        force=not is_default_configuration,
    )

    return log_file
