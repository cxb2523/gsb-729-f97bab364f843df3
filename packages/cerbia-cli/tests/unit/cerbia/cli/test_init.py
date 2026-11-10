import pytest
from cerbia.cli import app
from typer.testing import CliRunner

pytestmark = pytest.mark.unit


def test_root_help_lists_registered_commands() -> None:
    # Given: the root CerbIA application
    runner = CliRunner()

    # When: requesting root help
    result = runner.invoke(app, ["--help"])

    # Then: both public commands are registered
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "validate" in result.output
