from ..exceptions import CerbIAError
from ._trace import FailureCode

__all__ = ["CascadeExecutionError"]


class CascadeExecutionError(CerbIAError):
    """Cascade fault identified by stage, category, and optional scanner.

    Args:
        stage_id (str): Configured stage identifier.
        category (FailureCode): Operational fault category.
        scanner_id (str | None): Configured scanner identifier, when applicable.

    Attributes:
        stage_id (str): Stage where the fault occurred.
        category (FailureCode): Operational fault category.
        scanner_id (str | None): Scanner involved in the fault, when applicable.
    """

    def __init__(self, stage_id: str, category: FailureCode, scanner_id: str | None = None) -> None:
        self.stage_id = stage_id
        self.category = category
        self.scanner_id = scanner_id
        super().__init__(
            f"Cascade stage {stage_id!r}: {category.value}"
            + (f" (scanner {scanner_id!r})" if scanner_id is not None else "")
        )
