from typing import Self

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

from .entries import Entry
from .scans import Finding, SkippedScanner
from .stages import StageResult, validate_stages

__all__ = ["EntryResult", "ScanResult", "StageResult"]


class EntryResult(BaseModel):
    """Scan results for a single :class:`Entry`.

    Attributes:
        entry (Entry): The input entry that was scanned.
        is_safe (bool): Whether the gate passed for this entry.
        aggregated_score (float): Simple gate's weighted BLOCK aggregate or cascade terminal score in [0.0, 1.0].
            Cascade operational blocks use 1.0 when the terminal stage has no score.
        rationale (str): Summary explanation of the gate verdict.
        findings (list[Finding]): Individual scanner results collected during the scan.
        skipped_scanners (list[SkippedScanner]): Scanners skipped due to content-type routing or the explicit
            ``"skip"`` on error policy in a simple gate; empty for a cascade.
        stages (tuple[StageResult, ...] | None): Ordered cascade summaries, including unreached stages; None for simple.
    """

    model_config = ConfigDict(extra="forbid")

    entry: Entry
    is_safe: bool = True
    aggregated_score: float = Field(ge=0.0, le=1.0, default=0.0)
    rationale: str = ""
    findings: list[Finding] = Field(default_factory=list)
    skipped_scanners: list[SkippedScanner] = Field(default_factory=list)
    stages: tuple[StageResult, ...] | None = None

    @model_validator(mode="after")
    def validate_stage_results(self) -> Self:
        """Check stage routing, scores, and finding ownership.

        Returns:
            Self: This validated entry result.

        Raises:
            PydanticCustomError: If stage routing, scores, finding ownership, or skipped scanners are inconsistent.
        """
        validate_stages(self, self.aggregated_score)
        return self


class ScanResult(BaseModel):
    """Top-level aggregation across all entries.

    Attributes:
        entry_results (list[EntryResult]): Per-entry scan outcomes.
        is_safe (bool): Whether all entries passed all gates.
        total_findings (int): Total number of findings across all entry results.
        unsafe_entries (int): Number of entry results where is_safe is False.
    """

    entry_results: list[EntryResult] = Field(default_factory=list)

    @computed_field
    @property
    def is_safe(self) -> bool:
        """Whether all entries passed all gates.

        Returns:
            bool: True if all entry results are safe, False otherwise.
        """
        return all(er.is_safe for er in self.entry_results)

    @computed_field
    @property
    def total_findings(self) -> int:
        """Total number of findings across all entry results.

        Returns:
            int: Sum of findings across all entry results.
        """
        return sum(len(er.findings) for er in self.entry_results)

    @computed_field
    @property
    def unsafe_entries(self) -> int:
        """Number of entry results where is_safe is False.

        Returns:
            int: Count of unsafe entry results.
        """
        return sum(1 for er in self.entry_results if not er.is_safe)
