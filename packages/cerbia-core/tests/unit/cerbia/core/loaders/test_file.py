from pathlib import Path

import pytest
from cerbia.core.loaders.file import FileLoader

pytestmark = pytest.mark.unit


def test_file_loader_creates_entry_when_explicit_file_is_loaded(tmp_path: Path) -> None:
    file_path = tmp_path / "settings.yml"
    file_path.write_text("token: secret", encoding="utf-8")
    loader = FileLoader(file_path)

    result = loader.load()

    assert [(entry.text, entry.source) for entry in result] == [("token: secret", str(file_path.resolve()))]


def test_file_loader_preserves_entry_metadata_when_loading_a_file(tmp_path: Path) -> None:
    file_path = tmp_path / "characterized.txt"
    file_path.write_text("characterized content", encoding="utf-8")

    result = FileLoader(file_path).load()

    assert [(entry.text, entry.source, entry.field_path) for entry in result] == [
        ("characterized content", str(file_path.resolve()), None)
    ]


def test_file_loader_skips_explicit_file_when_extension_does_not_match(tmp_path: Path) -> None:
    file_path = tmp_path / "settings.yml"
    file_path.write_text("token: secret", encoding="utf-8")
    loader = FileLoader(file_path, extensions=[".txt"])

    result = loader.load()

    assert result == []


def test_file_loader_loads_matching_files_recursively_when_directory_is_loaded(tmp_path: Path) -> None:
    root_file = tmp_path / "root.txt"
    nested_directory = tmp_path / "nested"
    nested_file = nested_directory / "child.txt"
    root_file.write_text("root", encoding="utf-8")
    nested_directory.mkdir()
    nested_file.write_text("child", encoding="utf-8")
    loader = FileLoader(tmp_path, extensions=[".txt"])

    result = loader.load()

    assert [(entry.text, entry.source) for entry in result] == [
        ("child", str(nested_file.resolve())),
        ("root", str(root_file.resolve())),
    ]


def test_file_loader_loads_mixed_file_and_directory_inputs(tmp_path: Path) -> None:
    explicit_file = tmp_path / "explicit.txt"
    directory = tmp_path / "directory"
    directory_file = directory / "directory.txt"
    explicit_file.write_text("explicit", encoding="utf-8")
    directory.mkdir()
    directory_file.write_text("directory", encoding="utf-8")
    loader = FileLoader([explicit_file, directory], extensions=[".txt"])

    result = loader.load()

    assert [(entry.text, entry.source) for entry in result] == [
        ("explicit", str(explicit_file.resolve())),
        ("directory", str(directory_file.resolve())),
    ]


def test_file_loader_loads_all_file_extensions_when_filter_is_not_configured(tmp_path: Path) -> None:
    yaml_file = tmp_path / "config.yml"
    text_file = tmp_path / "notes.txt"
    yaml_file.write_text("config", encoding="utf-8")
    text_file.write_text("notes", encoding="utf-8")
    loader = FileLoader(tmp_path)

    result = loader.load()

    assert [(entry.text, entry.source) for entry in result] == [
        ("config", str(yaml_file.resolve())),
        ("notes", str(text_file.resolve())),
    ]


def test_file_loader_excludes_files_with_unmatched_extension_when_extensions_are_configured(tmp_path: Path) -> None:
    included_file = tmp_path / "included.txt"
    excluded_file = tmp_path / "excluded.yml"
    included_file.write_text("included", encoding="utf-8")
    excluded_file.write_text("excluded", encoding="utf-8")
    loader = FileLoader(tmp_path, extensions=[".txt"])

    result = loader.load()

    assert [(entry.text, entry.source) for entry in result] == [("included", str(included_file.resolve()))]


def test_file_loader_excludes_nested_files_when_recursion_is_disabled(tmp_path: Path) -> None:
    root_file = tmp_path / "root.txt"
    nested_directory = tmp_path / "nested"
    nested_file = nested_directory / "child.txt"
    root_file.write_text("root", encoding="utf-8")
    nested_directory.mkdir()
    nested_file.write_text("child", encoding="utf-8")
    loader = FileLoader(tmp_path, recursive=False)

    result = loader.load()

    assert [(entry.text, entry.source) for entry in result] == [("root", str(root_file.resolve()))]


def test_file_loader_returns_no_entries_when_path_does_not_exist(tmp_path: Path) -> None:
    loader = FileLoader(tmp_path / "missing.txt")

    result = loader.load()

    assert result == []
