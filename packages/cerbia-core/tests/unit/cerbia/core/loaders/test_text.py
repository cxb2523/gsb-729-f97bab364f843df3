import pytest
from cerbia.core.loaders.text import TextLoader

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("texts", "expected_entries"),
    [
        ("content", [("content", "inline[0]")]),
        (["first", "second"], [("first", "inline[0]"), ("second", "inline[1]")]),
        ([], []),
    ],
    ids=["single_text", "multiple_texts", "empty_list"],
)
def test_text_loader_creates_entry_for_each_text_when_loaded(
    texts: str | list[str], expected_entries: list[tuple[str, str]]
) -> None:
    loader = TextLoader(texts)

    result = loader.load()

    assert [(entry.text, entry.source) for entry in result] == expected_entries
