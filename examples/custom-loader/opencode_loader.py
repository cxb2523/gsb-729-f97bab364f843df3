from pathlib import Path

from cerbia.core.models.entries import Entry
from cerbia.core.types import ContentType


class OpenCodeLoader:
    """Illustrative, non-production loader for supported local OpenCode files.

    This example is intentionally small and is not prepared for production use. Do not use it as a complete OpenCode
    configuration parser or as a production security boundary.

    The project-root ``opencode.json`` or ``opencode.jsonc`` configuration is loaded alongside skill ``SKILL.md`` files
    and Markdown agent and command files below ``.opencode``.

    Args:
        root (Path | str): Project root containing the local ``.opencode`` directory.

    Attributes:
        root (Path | str): Project root containing the local ``.opencode`` directory.
    """

    def __init__(self, root: Path | str = ".") -> None:
        self.root = Path(root)

    def load(self) -> list[Entry]:
        """Load supported OpenCode files in deterministic category order.

        Returns:
            list[Entry]: Text entries for the project configuration and supported OpenCode files.
        """
        resolved_root = self.root.resolve()
        opencode_root = resolved_root / ".opencode"
        candidates = [
            resolved_root / "opencode.json",
            resolved_root / "opencode.jsonc",
            *sorted(opencode_root.glob("skills/**/SKILL.md")),
            *sorted(opencode_root.glob("agents/**/*.md")),
            *sorted(opencode_root.glob("commands/**/*.md")),
        ]
        return [
            self._load_file(candidate) for candidate in candidates if self._is_supported_file(candidate, resolved_root)
        ]

    @staticmethod
    def _is_supported_file(candidate: Path, resolved_root: Path) -> bool:
        if not candidate.is_file():
            return False

        try:
            candidate.resolve().relative_to(resolved_root)
        except ValueError:
            return False

        return True

    @staticmethod
    def _load_file(path: Path) -> Entry:
        resolved_path = path.resolve()
        return Entry(
            text=resolved_path.read_text(encoding="utf-8", errors="replace"),
            source=str(resolved_path),
            content_type=ContentType.TEXT,
        )
