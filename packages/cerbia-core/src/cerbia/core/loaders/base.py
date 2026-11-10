from typing import Protocol, runtime_checkable

from ..models.entries import Entry


@runtime_checkable
class Loader(Protocol):
    """Contract for all input/source loaders.

    Implementations discover and parse their source material in ``__init__`` or lazily on first ``load()`` call, then
    return a flat list of :class:`Entry` objects ready for gate scanning.
    """

    def load(self) -> list[Entry]:
        """Discover and return entries from the underlying source.

        Returns:
            list[Entry]: Flat list of entries ready for gate scanning.
        """
        ...
