import re

from ..registries.i18n import i18n_registry as _registry
from . import en as en  # noqa: F401
from . import es as es  # noqa: F401
from . import gl as gl  # noqa: F401

__all__ = [
    "get_patterns",
]


def get_patterns(
    languages: list[str] | None = None,
    keys: list[str] | None = None,
) -> dict[str, list[re.Pattern[str]]]:
    """Retrieve compiled regex patterns for injection detection.

    Convenience wrapper around ``registry.get_patterns()``. Merges patterns
    from all requested languages, optionally filtered by category key.

    Args:
        languages (list[str] | None): ISO-639-1 language codes to include.
            Defaults to all registered languages when None.
        keys (list[str] | None): Category keys to include. Defaults to all
            registered keys when None.

    Returns:
        dict[str, list[re.Pattern[str]]]: Mapping of category key to compiled
            regex patterns.
    """
    return _registry.get_patterns(languages=languages, keys=keys)
