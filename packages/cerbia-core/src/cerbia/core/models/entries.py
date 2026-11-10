from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..types import ContentType

__all__ = ["Entry"]


class EntryMetadata(BaseModel):
    """Metadata for an Entry object.

    Attributes:
        original_text (str | None): The original text content before any preprocessing.
        derived_from (list[str]): List of preprocessor IDs that produced this entry.
    """

    original_text: str | None = None
    derived_from: list[str] = Field(default_factory=list)
    preprocessors: dict[str, Any] = Field(default_factory=dict)


class Entry(BaseModel):
    """A single text fragment to be processed.

    Attributes:
        text (str): The raw content to process.
        source (str): Origin identifier (file path, ``"stdin"``, ``"inline"``...).
        field_path (str | None): Dot-separated path within the source (e.g. ``"mcpServers.sentry.env.API_KEY"``).
        metadata (EntryMetadata): Metadata containing original text and derivation lineage.
    """

    text: str
    source: str
    field_path: str | None = None
    metadata: EntryMetadata = Field(default_factory=EntryMetadata)
    content_type: ContentType = ContentType.UNKNOWN

    def derive(self, text: str, preprocessor_id: str) -> Entry:
        """Create a derived entry preserving source lineage.

        Args:
            text (str): The derived text content.
            preprocessor_id (str): Identifier of the preprocessor that produced this text.

        Returns:
            Entry: A new entry with the same source and field_path, and
                ``original_text`` and ``derived_from`` added to metadata.
        """
        metadata = self.metadata.model_copy(deep=True)
        metadata.original_text = self.metadata.original_text or self.text
        metadata.derived_from.append(preprocessor_id)

        return Entry(
            text=text,
            source=self.source,
            field_path=self.field_path,
            metadata=metadata,
            content_type=self.content_type,
        )
