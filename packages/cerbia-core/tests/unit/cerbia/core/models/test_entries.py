import pytest
from cerbia.core.models.entries import Entry, EntryMetadata
from cerbia.core.types import ContentType

pytestmark = pytest.mark.unit


def test_entry_derive_creates_new_entry_with_updated_text_and_accumulated_lineage() -> None:
    entry = Entry(
        text="original",
        source="settings.yml",
        field_path="server.token",
        content_type=ContentType.TEXT,
    )

    result = entry.derive("normalized", "normalizer")

    assert result.text == "normalized"
    assert result.source == "settings.yml"
    assert result.field_path == "server.token"
    assert result.content_type is ContentType.TEXT
    assert result.metadata.original_text == "original"
    assert result.metadata.derived_from == ["normalizer"]


def test_entry_derive_accumulates_lineage_from_previous_derivations() -> None:
    entry = Entry(
        text="second form",
        source="stdin",
        metadata=EntryMetadata(original_text="original", derived_from=["decoder"]),
    )

    result = entry.derive("third form", "normalizer")

    assert result.metadata.original_text == "original"
    assert result.metadata.derived_from == ["decoder", "normalizer"]
