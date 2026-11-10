"""CerbIA CLI package."""

import typer

from .scan import scan_command
from .validate import validate_command


def _build_app() -> typer.Typer:
    """Build the CerbIA CLI application.

    Returns:
        typer.Typer: The CerbIA CLI application.
    """
    app = typer.Typer(
        name="cerbia",
        help="LLM security scanning — language-agnostic guardrails for AI agents.",
        no_args_is_help=True,
    )

    app.add_typer(scan_command)
    app.add_typer(validate_command)

    return app


app = _build_app()
