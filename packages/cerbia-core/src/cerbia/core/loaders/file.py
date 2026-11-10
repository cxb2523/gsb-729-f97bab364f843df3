from logging import getLogger
from pathlib import Path

from ..models.entries import Entry

logger = getLogger(__name__)


class FileLoader:
    """Loads entries from files on disk.

    Supports two modes:

    * **File paths** — loads the contents of the provided file paths if they match the specified extensions (if any).
    * **Directory paths** — recursively scans the provided directory paths for files matching the specified extensions,
        loading their contents.

    Args:
        paths (Path | str | list[Path | str]): One or more file or directory paths to load.
        extensions (list[str] | None): File extensions to include. If ``None``, all files are included. Defaults to
            ``None``.
        recursive (bool): If ``True``, directory paths are scanned recursively. Defaults to ``True``.
    """

    def __init__(
        self,
        paths: Path | str | list[Path | str],
        extensions: list[str] | None = None,
        recursive: bool = True,
    ) -> None:
        if isinstance(paths, (str, Path)):
            paths = [paths]

        self.paths = [Path(p) for p in paths]
        self.extensions: set[str] = set(extensions or [])
        self.recursive = recursive

    def load(self) -> list[Entry]:
        """Load files as Entry objects.

        Returns:
            list[Entry]: One entry per discovered file.
        """
        entries: list[Entry] = []

        for path in self.paths:
            if path.is_file():
                if self._matches_extension(path):
                    entries.append(self._load_file(path))

                else:
                    logger.warning("Skipping %s due to unmatched extension", path)

            elif path.is_dir():
                entries.extend(self._load_directory(path))

        result_count = len(entries)
        logger.debug(
            "Loaded %d entries",
            result_count,
            extra={
                "operation": "load",
                "stage": "loading",
                "component_kind": "loader",
                "outcome": "completed",
                "result_count": result_count,
            },
        )
        return entries

    def _matches_extension(self, path: Path) -> bool:
        if not self.extensions:
            return True

        return path.suffix in self.extensions

    def _load_file(self, path: Path) -> Entry:
        return Entry(
            text=path.read_text(encoding="utf-8", errors="replace"),
            source=str(path.resolve()),
        )

    def _load_directory(self, path: Path) -> list[Entry]:
        pattern = "**/*" if self.recursive else "*"
        return [
            self._load_file(matched_path)
            for matched_path in sorted(path.glob(pattern))
            if matched_path.is_file() and self._matches_extension(matched_path)
        ]
