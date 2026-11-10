import logging
from pathlib import Path
from typing import Annotated, assert_never

import typer
from cerbia.core.config import CascadeGateConfig, LoaderConfig, SimpleGateConfig
from cerbia.core.exceptions import CerbIAError
from cerbia.core.models.results import ScanResult
from cerbia.core.runner import Runner
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..config import load_config_from_yaml
from ..logging import configure_logging
from ._data import write_json_result
from ._ui import render_scan_result

logger = logging.getLogger(__name__)

app = typer.Typer(no_args_is_help=True)


@app.command()
def scan(
    config: Annotated[Path, typer.Option("--config", "-c", help="Path to a single YAML configuration file.")],
    text: Annotated[
        list[str] | None, typer.Option("--text", "-t", help="Text to scan; repeatable (file mode only).")
    ] = None,
    file: Annotated[
        list[Path] | None, typer.Option("--file", "-f", help="File to scan; repeatable (file mode only).")
    ] = None,
    output_path: Annotated[Path | None, typer.Option("--output", "-o", help="Write JSON results to this file.")] = None,
    log_level: Annotated[
        str | None, typer.Option("--log-level", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL).")
    ] = None,
    log_file: Annotated[
        Path | None, typer.Option("--log-file", help="Write logs to this file instead of stderr.")
    ] = None,
    threshold: Annotated[
        float | None,
        typer.Option("--threshold", help="Override root threshold; explicit cascade stage thresholds take precedence."),
    ] = None,
    unsafe_only: Annotated[
        bool,
        typer.Option(
            "--unsafe-only",
            help=(
                "Report only entries where is_safe == False. Filters console output and entry_results in JSON; "
                "does not change scan execution or exit codes."
            ),
        ),
    ] = False,
) -> None:
    """Run security gates against input text or config-file entries.

    Args:
        config (Path): YAML configuration path.
        text (list[str] | None): Text inputs that override configured loaders, alone or together with file inputs.
        file (list[Path] | None): File inputs that override configured loaders, alone or together with text inputs.
        output_path (Path | None): Optional .json output path; an existing file is overwritten.
        log_level (str | None): Optional logging level override.
        log_file (Path | None): Optional log file path; an existing log file is overwritten.
        threshold (float | None): Root threshold override; explicit cascade stage thresholds take precedence.
        unsafe_only (bool): Filter output to unsafe entries and omit zero-risk findings and skipped scanners from
            console panels. Scan execution is unchanged.

    Raises:
        typer.Exit: With code 2 for handled configuration, input, logging, or scan errors; otherwise with code 0
            when the output results are safe, or 1 when they contain an unsafe entry.
    """
    err_console = Console(stderr=True)

    err_console.print("[bold]CerbIA CLI Scan[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        err_console.print("[bold]Running scan...[/bold]")
        task_id = progress.add_task("Parsing configuration...", total=None)

        if output_path is not None and output_path.suffix != ".json":
            err_console.print("[red]Error:[/red] --output path must have a .json extension.")
            raise typer.Exit(code=2)

        cfg = load_config_from_yaml(config, err_console, threshold=threshold)
        configure_logging(log_level, log_file, err_console)

        loaders: list[LoaderConfig] = []
        if text:
            loaders.append(LoaderConfig(loader="cerbia.core.loaders.text.TextLoader", init_args={"texts": text}))

        if file:
            loaders.append(
                LoaderConfig(
                    loader="cerbia.core.loaders.file.FileLoader", init_args={"paths": [str(path) for path in file]}
                )
            )

        if loaders:
            if cfg.loaders:
                logger.warning("CLI input overrides the loaders configured in the config file")

            match cfg:
                case SimpleGateConfig():
                    cfg.loaders = loaders
                case CascadeGateConfig():
                    cfg = cfg.model_copy(update={"loaders": loaders})
                case unreachable:
                    assert_never(unreachable)

        if threshold is not None and isinstance(cfg, SimpleGateConfig):
            cfg.threshold = threshold

        if not cfg.loaders:
            err_console.print("[red]Error:[/red] provide --text, --file, or configure loaders in your config.")
            raise typer.Exit(code=2)

        progress.update(task_id, description="Preparing components...")
        try:
            runner = Runner(cfg)

            progress.update(task_id, description="Scanning...")
            results = runner.scan()
        except (CerbIAError, TypeError) as exc:
            err_console.print("[red]Error:[/red] scan failed: " + str(exc))
            raise typer.Exit(code=2) from exc

    if unsafe_only:
        results = ScanResult(entry_results=[entry for entry in results.entry_results if not entry.is_safe])

    render_scan_result(results, unsafe_only, err_console)

    if output_path is not None:
        write_json_result(results, output_path)

    raise typer.Exit(code=0 if results.is_safe else 1)
