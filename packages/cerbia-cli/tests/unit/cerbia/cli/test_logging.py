import logging
from io import StringIO
from pathlib import Path

import pytest
import typer
from cerbia.cli.logging import configure_logging
from rich.console import Console

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("level", "expected"),
    [("debug", "DEBUG"), ("warning", "WARNING"), ("error", "ERROR"), ("critical", "CRITICAL")],
)
def test_configure_logging_uses_explicit_supported_level_and_stream_handler(mocker, level: str, expected: str) -> None:
    basic_config = mocker.patch("cerbia.cli.logging.logging.basicConfig")

    result = configure_logging(level, None, mocker.Mock())

    assert result is None
    assert basic_config.call_args.kwargs["level"] == expected
    assert isinstance(basic_config.call_args.kwargs["handlers"][0], logging.StreamHandler)


def test_configure_logging_creates_file_handler_and_warns_without_disclosing_path(mocker, tmp_path: Path) -> None:
    log_file = tmp_path / "logs" / "cerbia.log"
    log_file.parent.mkdir()
    log_file.write_text("previous")
    console = mocker.Mock()
    handler = mocker.patch("cerbia.cli.logging.logging.FileHandler")
    mocker.patch("cerbia.cli.logging.logging.basicConfig")

    result = configure_logging("ERROR", log_file, console)

    assert result == log_file
    handler.assert_called_once_with(log_file, mode="w")
    console.print.assert_called_once_with("[yellow]Warning:[/yellow] overwriting existing log file.")


@pytest.mark.parametrize("level", ["trace", "verbose"])
def test_configure_logging_exits_when_log_level_is_unsupported(mocker, level: str) -> None:
    console = mocker.Mock()

    with pytest.raises(typer.Exit) as exc_info:
        configure_logging(level, None, console)

    assert exc_info.value.exit_code == 2
    console.print.assert_called_once_with(
        "[red]Error:[/red] invalid log level. Choose from DEBUG, INFO, WARNING, ERROR, CRITICAL."
    )


def test_configure_logging_configures_legacy_warning_stderr_defaults_without_host_handlers() -> None:
    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers[:]
    original_level = root_logger.level
    root_logger.handlers.clear()

    try:
        returned_path = configure_logging(None, None, Console(stderr=True))

        assert returned_path is None
        assert root_logger.level == logging.INFO
        assert len(root_logger.handlers) == 1
        assert isinstance(root_logger.handlers[0], logging.StreamHandler)
        assert root_logger.handlers[0].formatter is not None
        assert root_logger.handlers[0].formatter._fmt == "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    finally:
        root_logger.handlers[:] = original_handlers
        root_logger.setLevel(original_level)


def test_configure_logging_preserves_host_root_state_by_default() -> None:
    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers[:]
    original_level = root_logger.level
    sentinel_output = StringIO()
    sentinel = logging.StreamHandler(sentinel_output)
    sentinel_filter = logging.Filter()
    sentinel.setLevel(logging.WARNING)
    sentinel.addFilter(sentinel_filter)
    sentinel.setFormatter(logging.Formatter("host:%(message)s"))
    root_logger.handlers[:] = [sentinel]
    root_logger.setLevel(logging.WARNING)

    try:
        returned_path = configure_logging(None, None, Console(stderr=True))

        assert returned_path is None
        assert root_logger.handlers == [sentinel]
        assert root_logger.level == logging.WARNING
        assert sentinel.level == logging.WARNING
        assert sentinel.filters == [sentinel_filter]
        assert sentinel.formatter is not None
        assert sentinel.formatter._fmt == "host:%(message)s"
        logging.getLogger("cerbia.cli.contract").warning("safe record")
        assert sentinel_output.getvalue() == "host:safe record\n"
    finally:
        root_logger.handlers[:] = original_handlers
        root_logger.setLevel(original_level)


def test_configure_logging_replaces_existing_handlers_when_explicit_file_is_requested(tmp_path: Path) -> None:
    root_logger = logging.getLogger()
    existing_handler = logging.NullHandler()
    root_logger.addHandler(existing_handler)
    log_path = tmp_path / "logs" / "command.log"

    returned_path = configure_logging(None, log_path, Console(stderr=True))

    assert returned_path == log_path
    assert existing_handler not in root_logger.handlers
    assert log_path.is_file()


def test_configure_logging_truncates_existing_explicit_log_file(tmp_path: Path) -> None:
    log_path = tmp_path / "command.log"
    log_path.write_text("STALE-LOG-CANARY\n", encoding="utf-8")

    configure_logging(None, log_path, Console(stderr=True))
    logging.getLogger("cerbia.cli.contract").warning("replacement record")

    contents = log_path.read_text(encoding="utf-8")
    assert "STALE-LOG-CANARY" not in contents
    assert "replacement record" in contents
