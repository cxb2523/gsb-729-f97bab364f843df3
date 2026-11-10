import re
from pathlib import Path

from ..._utils.url import normalize_for_matching
from ...exceptions import CerbIAConfigError
from ._normalization import compile_url_pattern, normalize_pattern_for_storage
from ._validation import pattern_covers


class UrlRegistry:
    """Store full-URL wildcard patterns.

    Shared by URL scanners, with separate allow and deny stores and explicit deny precedence.

    Args:
        entries (list[str] | None = None): Optional list of full-URL wildcard patterns to initialize the registry.
    """

    def __init__(self, entries: list[str] | None = None) -> None:
        self._patterns: list[tuple[str, re.Pattern[str]]] = []
        self._denied_patterns: list[tuple[str, re.Pattern[str]]] = []

        for entry in entries or []:
            self.register(entry)

    def register(self, entry: str, *, denied: bool = False) -> None:
        """Register a full-URL wildcard pattern.

        Args:
            entry (str): Full-URL wildcard pattern.
            denied (bool): Register in the deny store instead of the default allow store.
        """
        normalized = normalize_pattern_for_storage(entry)
        if not normalized:
            return

        compiled = compile_url_pattern(normalized)
        patterns = self._denied_patterns if denied else self._patterns
        for existing_pattern, _ in patterns:
            if pattern_covers(existing_pattern, normalized):
                return

        patterns[:] = [
            (existing_pattern, compiled_pattern)
            for existing_pattern, compiled_pattern in patterns
            if not pattern_covers(normalized, existing_pattern)
        ]
        patterns.append((normalized, compiled))

    def register_file(self, file: str | Path, *, denied: bool = False) -> None:
        """Register full-URL wildcard pattern from a .txt file.

        Strip surrounding whitespace and ignore blank lines and full-line # comments.

        Args:
            file (str | Path): Path to the .txt file containing full-URL wildcard patterns.
            denied (bool): Register rules in the deny store instead of the allow store.

        Raises:
            CerbIAConfigError: For invalid suffixes, read/decode errors (with path), or rules rejected by the existing
                compiler (with path and line).
        """
        path = Path(file)
        if path.suffix.lower() != ".txt":
            message = f"URL policy file {path}: expected a .txt suffix"
            raise CerbIAConfigError(message)

        try:
            text = path.read_text(encoding="utf-8")

        except (OSError, UnicodeError) as exc:
            message = f"Cannot read URL policy file {path}: {exc}"
            raise CerbIAConfigError(message) from exc

        for line_number, line in enumerate(text.splitlines(), start=1):
            rule = line.strip()
            if not rule or rule.startswith("#"):
                continue

            try:
                self.register(rule, denied=denied)

            except ValueError as exc:
                message = f"Invalid URL policy rule at {path}:{line_number}: {exc}"
                raise CerbIAConfigError(message) from exc

    def is_allowed(self, url: str) -> bool:
        """Check whether a URL is allowed without an explicit deny match.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True when an allow rule matches and no deny rule matches; otherwise, False.
        """
        normalized_url = normalize_for_matching(url)
        if normalized_url is None:
            return False

        return any(compiled_pattern.fullmatch(normalized_url) for _, compiled_pattern in self._patterns) and not any(
            compiled_pattern.fullmatch(normalized_url) for _, compiled_pattern in self._denied_patterns
        )

    def is_denied(self, url: str) -> bool:
        """Check only the deny store, regardless of matching allow rules.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True when a deny rule matches; otherwise, False.
        """
        normalized_url = normalize_for_matching(url)
        if normalized_url is None:
            return False
        return any(compiled_pattern.fullmatch(normalized_url) for _, compiled_pattern in self._denied_patterns)
