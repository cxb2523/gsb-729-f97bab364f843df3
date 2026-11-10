from typing import Literal, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic_core import PydanticCustomError

from .scans import Finding, SkippedScanner

__all__ = ["StageResult"]


class StageResult(BaseModel):
    """Public summary of a cascade stage.

    Attributes:
        id (str): Configured stage identifier.
        result (Literal["allow", "block", "defer", "not_reached"]): Stage routing decision or unreached status.
        score (float | None): Finite aggregate in [0.0, 1.0]. Required for allow and defer, absent for not_reached,
            and optional for block because an operational fault has no score. Omitted from serialization when None.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    result: Literal["allow", "block", "defer", "not_reached"]
    score: float | None = Field(
        default=None, strict=True, ge=0.0, le=1.0, allow_inf_nan=False, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def check_score(self) -> Self:
        """Check that the score agrees with the stage status.

        Returns:
            Self: This validated stage summary.

        Raises:
            PydanticCustomError: If an unreached stage has a score or an allow/defer stage has none.
        """
        if self.result == "not_reached" and self.score is not None:
            raise PydanticCustomError("stage_score", "not_reached stage must omit score")

        if self.result in ("allow", "defer") and self.score is None:
            raise PydanticCustomError("stage_score", "allow/defer stage requires score")

        return self


class _StagedResult(Protocol):
    is_safe: bool
    findings: list[Finding]
    skipped_scanners: list[SkippedScanner]
    stages: tuple[StageResult, ...] | None


def validate_stages(result: _StagedResult, score: float) -> None:
    """Validate stage routing and ownership against the verdict.

    Args:
        result (_StagedResult): Scan result or gate verdict containing stage summaries.
        score (float): Verdict score, including the operational block sentinel.

    Raises:
        PydanticCustomError: If stage order, terminal verdict, score, or finding ownership is inconsistent.
    """
    if result.stages is None:
        if any(finding.stage is not None for finding in result.findings):
            raise PydanticCustomError("stage_ownership", "simple findings must omit stage")
        return

    if not result.stages:
        raise PydanticCustomError("stage_empty", "cascade requires stages")
    if result.skipped_scanners:
        raise PydanticCustomError("stage_skipped", "cascade faults block or fail; skipped scanners have no stage owner")

    positions, terminal = _validate_stage_order(result.stages)

    if terminal is None or result.is_safe != (terminal.result == "allow"):
        raise PydanticCustomError("stage_terminal", "stage terminal result must match verdict")

    expected_score = 1.0 if terminal.score is None else terminal.score
    if score != expected_score:
        raise PydanticCustomError(
            "stage_score", "verdict score must match terminal stage or operational block sentinel"
        )

    _validate_finding_ownership(result.findings, result.stages, positions)


def _validate_stage_order(stages: tuple[StageResult, ...]) -> tuple[dict[str, int], StageResult | None]:
    positions: dict[str, int] = {}
    terminal: StageResult | None = None
    for index, stage in enumerate(stages):
        if stage.id in positions:
            raise PydanticCustomError("stage_identity", "duplicate stage id")
        positions[stage.id] = index

        if stage.result == "not_reached":
            if terminal is None:
                raise PydanticCustomError("stage_order", "not_reached stage requires a preceding terminal result")
            continue

        if terminal is not None:
            raise PydanticCustomError("stage_order", "executed stage follows terminal result")
        if stage.result != "defer":
            terminal = stage

    return positions, terminal


def _validate_finding_ownership(
    findings: list[Finding], stages: tuple[StageResult, ...], positions: dict[str, int]
) -> None:
    previous = -1
    scanners: set[str] = set()
    for finding in findings:
        if finding.stage is None or finding.stage not in positions:
            raise PydanticCustomError("stage_ownership", "finding requires an executed stage owner")

        position = positions[finding.stage]
        if position < previous or stages[position].result == "not_reached":
            raise PydanticCustomError("stage_ownership", "findings must follow executed stage order")
        if finding.scanner_id in scanners:
            raise PydanticCustomError("stage_ownership", "cascade must contain each scanner finding only once")

        scanners.add(finding.scanner_id)
        previous = position
