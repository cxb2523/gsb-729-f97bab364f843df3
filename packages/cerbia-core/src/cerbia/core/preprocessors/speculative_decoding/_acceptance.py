from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from ._defaults import (
    DEFAULT_ACCEPTANCE_MAX_ENTROPY_BITS,
    DEFAULT_ACCEPTANCE_MIN_CHI_SQUARED_PVALUE,
    DEFAULT_ACCEPTANCE_MIN_PRINTABLE_RATIO,
    DEFAULT_ACCEPTANCE_MIN_TEXT_LENGTH,
)
from ._heuristics import byte_entropy, chi_squared_pvalue, printable_ratio
from ._types import DecodedBranch, RejectionReason


class AcceptanceFilter(BaseModel):
    """Fail-closed acceptance checks for terminal decoded branches.

    Attributes:
        min_chi_squared_pvalue (float): Minimum absolute language-fit p-value. Defaults to 0.10.
        min_text_length (int): Minimum length of the decoded string. Defaults to 16.
        min_printable_ratio (float): Minimum ratio of printable characters. Defaults to 0.85.
        max_entropy_bits (float): Maximum bits of entropy per byte. Defaults to 7.5.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    min_chi_squared_pvalue: float = DEFAULT_ACCEPTANCE_MIN_CHI_SQUARED_PVALUE
    min_text_length: int = DEFAULT_ACCEPTANCE_MIN_TEXT_LENGTH
    min_printable_ratio: float = DEFAULT_ACCEPTANCE_MIN_PRINTABLE_RATIO
    max_entropy_bits: float = DEFAULT_ACCEPTANCE_MAX_ENTROPY_BITS

    def evaluate(self, branch: DecodedBranch) -> tuple[bool, RejectionReason | None, str]:
        """Evaluate whether a decoded branch is acceptable.

        Args:
            branch (DecodedBranch): The decoded branch to evaluate.

        Returns:
            tuple[bool, RejectionReason | None, str]: Tuple of ``(is_accepted, rejection_reason, detail)``. If
                ``is_accepted`` is ``True``, the reason is ``None`` and the detail is empty.
        """
        text = branch.payload.text or ""

        if len(text) < self.min_text_length:
            return False, RejectionReason.ACCEPTANCE_FAILED, "too_short"

        if printable_ratio(text) < self.min_printable_ratio:
            return False, RejectionReason.ACCEPTANCE_FAILED, "low_printable"

        entropy = byte_entropy(branch.payload.raw)
        if entropy > self.max_entropy_bits:
            return False, RejectionReason.ACCEPTANCE_FAILED, "high_entropy"

        if chi_squared_pvalue(branch.payload.raw) < self.min_chi_squared_pvalue:
            return False, RejectionReason.ACCEPTANCE_FAILED, "low_pvalue"

        return True, None, ""
