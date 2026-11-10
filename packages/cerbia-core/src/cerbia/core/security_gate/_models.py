from typing import Self

from pydantic import BaseModel, ConfigDict, model_validator

from ..models.scans import Finding, SkippedScanner
from ..models.stages import StageResult, validate_stages


class GateVerdict(BaseModel):
    """Result from a simple or cascade gate scan.

    Attributes:
        is_safe (bool): Whether the gate passed or failed.
        score (float): Simple gate's weighted BLOCK aggregate or cascade terminal score. Cascade operational blocks
            use 1.0 when the terminal stage has no score.
        rationale (str): Human-readable explanation of the verdict.
        findings (list[Finding]): Findings from scanners that completed before execution stopped.
        skipped_scanners (list[SkippedScanner]): List of scanners that were skipped due to incompatible content types or
            errors under the simple gate's SKIP policy; empty for cascades.
        stages (tuple[StageResult, ...] | None): Ordered cascade stage summaries; None for a simple gate.
    """

    model_config = ConfigDict(extra="forbid")

    is_safe: bool
    score: float
    rationale: str
    findings: list[Finding]
    skipped_scanners: list[SkippedScanner]
    stages: tuple[StageResult, ...] | None = None

    @model_validator(mode="after")
    def validate_stage_results(self) -> Self:
        """Check stage routing, scores, and finding ownership.

        Returns:
            Self: This validated gate verdict.

        Raises:
            PydanticCustomError: If stage routing, scores, finding ownership, or skipped scanners are inconsistent.
        """
        validate_stages(self, self.score)
        return self
