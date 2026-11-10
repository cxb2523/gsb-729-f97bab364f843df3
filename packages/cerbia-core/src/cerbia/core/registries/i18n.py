import re
from collections.abc import Callable


class I18nRegistry:
    """Multilingual regex pattern registry.

    Stores compiled patterns indexed by ``(language, pattern_type)`` and provides query/introspection methods.
    """

    def __init__(self) -> None:
        self._store: dict[str, dict[str, list[re.Pattern[str]]]] = {}

    def register(self, lang: str, pattern_type: str, patterns: list[re.Pattern[str]]) -> None:
        """Add compiled patterns for a language and category.

        Args:
            lang (str): ISO-639-1 language code.
            pattern_type (str): Category key (e.g. ``"instruction_override"``).
            patterns (list[re.Pattern[str]]): Pre-compiled regex patterns.
        """
        self._store.setdefault(lang, {}).setdefault(pattern_type, []).extend(patterns)

    def get_patterns(
        self,
        languages: list[str] | None = None,
        keys: list[str] | None = None,
    ) -> dict[str, list[re.Pattern[str]]]:
        """Retrieve compiled regex patterns, optionally filtered by language and category.

        Merges patterns from all requested languages. Results are grouped by pattern type (category key).

        Args:
            languages (list[str] | None): ISO-639-1 codes to include. Defaults to all registered languages when
                ``None``.
            keys (list[str] | None): Category keys to include. Defaults to all registered keys when ``None``.

        Returns:
            dict[str, list[re.Pattern[str]]]: Mapping of category key to compiled regex patterns.
        """
        if languages is None:
            languages = list(self._store.keys())

        merged: dict[str, list[re.Pattern[str]]] = {}

        for lang in languages:
            if lang not in self._store:
                continue

            for ptype, patterns in self._store[lang].items():
                if keys is not None and ptype not in keys:
                    continue
                merged.setdefault(ptype, []).extend(patterns)

        return merged

    def available_languages(self) -> set[str]:
        """Return language codes that have at least one registered pattern.

        Returns:
            set[str]: Registered language codes.
        """
        return set(self._store.keys())

    def available_keys(self) -> set[str]:
        """Return all pattern category keys registered across all languages.

        Returns:
            set[str]: Category keys (e.g. ``{"instruction_override", "exfiltration", ...}``).
        """
        keys: set[str] = set()
        for lang_patterns in self._store.values():
            keys.update(lang_patterns.keys())
        return keys

    def has_language(self, lang: str) -> bool:
        """Check whether a language has any registered patterns.

        Args:
            lang (str): ISO-639-1 language code.

        Returns:
            bool: ``True`` if at least one pattern is registered for this language.
        """
        return lang in self._store

    def has_key(self, key: str) -> bool:
        """Check whether a pattern category key exists in any language.

        Args:
            key (str): Category key to look up.

        Returns:
            bool: ``True`` if at least one language has this key registered.
        """
        return any(key in lang_patterns for lang_patterns in self._store.values())


i18n_registry = I18nRegistry()


def i18n_pattern(
    lang: str,
    pattern_type: str,
) -> Callable[[Callable[[], list[str]]], Callable[[], list[str]]]:
    """Decorator that registers injection-detection regex patterns.

    Decorated function must return a ``list[str]`` of raw regex strings. Patterns are compiled with ``re.IGNORECASE`` at
    registration time.

    Args:
        lang (str): ISO-639-1 language code.
        pattern_type (str): Category key.

    Returns:
        Callable: Decorator that registers the patterns and returns the original function unchanged.
    """

    def decorator(func: Callable[[], list[str]]) -> Callable[[], list[str]]:
        compiled = [re.compile(p, re.IGNORECASE) for p in func()]
        i18n_registry.register(lang, pattern_type, compiled)
        return func

    return decorator
