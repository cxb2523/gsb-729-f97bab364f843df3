import logging
from pathlib import Path

import typer
import yaml
from cerbia.core.config import CerbIAConfig, GateType, parse_config
from cerbia.core.exceptions import CerbIAConfigError, CerbIAError
from pydantic import ValidationError
from rich.console import Console
from rich.text import Text
from yaml.error import YAMLError

logger = logging.getLogger(__name__)


def load_config_from_yaml(path: Path, output_console: Console, *, threshold: float | None = None) -> CerbIAConfig:
    """Load and validate configuration from a YAML file.

    Args:
        path (Path): Filesystem path to the config YAML file.
        output_console (Console): Rich console for outputting warnings and errors.
        threshold (float | None): Cascade root override applied before stage inheritance.

    Returns:
        CerbIAConfig: Validated configuration instance.

    Raises:
        typer.Exit: With code 2 if the file is missing, is a directory, cannot be read due to permissions, contains
            invalid YAML, or fails configuration validation, including a non-mapping YAML root.
    """
    try:
        logger.debug("Loading configuration")
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, dict):
            raise CerbIAConfigError(f"Expected YAML mapping, got {type(raw).__name__}")

        if threshold is not None and raw.get("type") == GateType.CASCADE:
            raw = {**raw, "threshold": threshold}

        config = parse_config(raw)
        logger.debug("Configuration loaded")

        return config

    except FileNotFoundError as exc:
        output_console.print(f"[red]Error:[/red] config file not found: {path}")
        raise typer.Exit(code=2) from exc
    except IsADirectoryError as exc:
        output_console.print(f"[red]Error:[/red] config path is a directory: {path}")
        raise typer.Exit(code=2) from exc
    except PermissionError as exc:
        if path.is_dir():
            output_console.print(f"[red]Error:[/red] config path is a directory: {path}")
            raise typer.Exit(code=2) from exc
        output_console.print(f"[red]Error:[/red] permission denied reading config file: {path}")
        raise typer.Exit(code=2) from exc
    except YAMLError as exc:
        output_console.print(f"[red]Error:[/red] invalid YAML in config file: {path}")
        raise typer.Exit(code=2) from exc
    except (CerbIAError, ValidationError) as exc:
        output_console.print(f"[red]Error:[/red] invalid configuration in file: {path}")

        if threshold is not None and isinstance(exc, ValidationError):
            _print_threshold_errors(exc, output_console)

        raise typer.Exit(code=2) from exc


def _print_threshold_errors(exc: ValidationError, output_console: Console) -> None:
    for error in exc.errors(include_input=False, include_url=False, include_context=False):
        location = ".".join(str(part) for part in error["loc"])
        output_console.print(Text(f"--threshold: {location}: {error['msg']}"))
