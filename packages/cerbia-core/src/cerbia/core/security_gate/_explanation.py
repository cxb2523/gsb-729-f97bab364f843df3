from __future__ import annotations

import math
from collections.abc import Iterable
from enum import StrEnum, auto
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from ..types import Action, Severity

if TYPE_CHECKING:
    from ._models import GateVerdict

__all__ = [
    "CountedFinding",
    "ExcludedFinding",
    "ExclusionReason",
    "GateScoreExplanation",
    "explain_gate_score",
]

NEAR_ZERO_ABS_TOL = 1e-9
"""Absolute tolerance below which a risk score is treated as negligible by fail-fast."""

SCANNER_FAILURE_RATIONALE_PREFIX = "Scanner execution failed: "
"""Rationale prefix used by ``SimpleGate`` when scanner failures force an unsafe verdict."""


class ExclusionReason(StrEnum):
    """Why a finding was excluded from the gate's score aggregation.

    Attributes:
        ACTION_NOT_BLOCK: The finding's action is not ``BLOCK``.
        ZERO_RISK_SCORE: The finding's risk score is exactly ``0.0``. Positive scores within the
            near-zero tolerance are still aggregated by ``SimpleGate`` and therefore never excluded;
            they are flagged via ``CountedFinding.near_zero`` instead.
    """

    ACTION_NOT_BLOCK = auto()
    ZERO_RISK_SCORE = auto()


class CountedFinding(BaseModel):
    """A finding included in the gate's score aggregation.

    Attributes:
        scanner_id (str): Identifier of the scanner that produced the finding.
        risk_score (float): Original risk score reported by the scanner.
        severity (Severity): Severity level inherited from the scanner.
        weight (float): Severity weight applied to the risk score.
        weighted_score (float): ``risk_score * weight``, the value fed to the score aggregator.
        contribution (float): Share of the total weighted score across all counted findings; sums to
            ``1.0`` whenever at least one finding is counted.
        near_zero (bool): Whether the risk score is within the near-zero tolerance
            (``abs_tol=1e-9``). Such scores are tolerated by fail-fast but still aggregated.
    """

    model_config = ConfigDict(extra="forbid")

    scanner_id: str
    risk_score: float
    severity: Severity
    weight: float
    weighted_score: float
    contribution: float
    near_zero: bool


class ExcludedFinding(BaseModel):
    """A finding left out of the gate's score aggregation.

    Attributes:
        scanner_id (str): Identifier of the scanner that produced the finding.
        risk_score (float): Original risk score reported by the scanner.
        action (Action): Action attached to the finding.
        reason (ExclusionReason): Why the finding did not participate in the aggregation.
    """

    model_config = ConfigDict(extra="forbid")

    scanner_id: str
    risk_score: float
    action: Action
    reason: ExclusionReason


class GateScoreExplanation(BaseModel):
    """Structured explanation of a simple gate's score aggregation.

    Attributes:
        threshold (float): Gate threshold the aggregated score was compared against.
        total_score (float): Aggregated score; equal to the explained verdict's ``score``.
        is_safe (bool): Final safety decision; equal to the explained verdict's ``is_safe``.
        counted_findings (list[CountedFinding]): Findings that participated in the aggregation.
        excluded_findings (list[ExcludedFinding]): Findings left out of the aggregation, with reasons.
        scanner_failures (list[str]): Names of scanners whose execution failure forced an unsafe
            verdict; empty when no scanner failed.
        forced_unsafe (bool): Whether scanner failures forced the unsafe decision independently of
            the aggregated score.
    """

    model_config = ConfigDict(extra="forbid")

    threshold: float
    total_score: float
    is_safe: bool
    counted_findings: list[CountedFinding]
    excluded_findings: list[ExcludedFinding]
    scanner_failures: list[str]
    forced_unsafe: bool


def explain_gate_score(
    verdict: GateVerdict, threshold: float, *, scanner_failures: Iterable[str] | None = None
) -> GateScoreExplanation:
    """Explain how a simple gate verdict's score was aggregated.

    Pure function: mirrors ``SimpleGate``'s aggregation rule (only ``BLOCK`` findings with a positive
    risk score contribute, weighted by severity) without re-running scanners or altering the verdict.
    ``total_score`` and ``is_safe`` are taken from the verdict, so they are equal to
    ``verdict.score`` and ``verdict.is_safe`` by construction.

    Args:
        verdict (GateVerdict): Verdict produced by ``SimpleGate.scan``.
        threshold (float): Threshold configured on the gate that produced the verdict.
        scanner_failures (Iterable[str] | None): Names of scanners whose execution failure forced the
            unsafe verdict. When None, names are recovered from the verdict rationale if it records
            scanner failures. Defaults to None.

    Returns:
        GateScoreExplanation: Structured, serializable explanation. Contains no scanner exception
            text and no scanned input text.
    """
    counted: list[CountedFinding] = []
    excluded: list[ExcludedFinding] = []
    for finding in verdict.findings:
        if finding.action != Action.BLOCK:
            excluded.append(
                ExcludedFinding(
                    scanner_id=finding.scanner_id,
                    risk_score=finding.risk_score,
                    action=finding.action,
                    reason=ExclusionReason.ACTION_NOT_BLOCK,
                )
            )
        elif finding.risk_score == 0.0:
            excluded.append(
                ExcludedFinding(
                    scanner_id=finding.scanner_id,
                    risk_score=finding.risk_score,
                    action=finding.action,
                    reason=ExclusionReason.ZERO_RISK_SCORE,
                )
            )
        else:
            weight = finding.severity.weight
            counted.append(
                CountedFinding(
                    scanner_id=finding.scanner_id,
                    risk_score=finding.risk_score,
                    severity=finding.severity,
                    weight=weight,
                    weighted_score=finding.risk_score * weight,
                    contribution=0.0,
                    near_zero=math.isclose(finding.risk_score, 0.0, abs_tol=NEAR_ZERO_ABS_TOL),
                )
            )

    total_weighted = sum(item.weighted_score for item in counted)
    if total_weighted > 0.0:
        for item in counted:
            item.contribution = item.weighted_score / total_weighted

    failures = list(scanner_failures) if scanner_failures is not None else _infer_scanner_failures(verdict)
    return GateScoreExplanation(
        threshold=threshold,
        total_score=verdict.score,
        is_safe=verdict.is_safe,
        counted_findings=counted,
        excluded_findings=excluded,
        scanner_failures=failures,
        forced_unsafe=bool(failures),
    )


def _infer_scanner_failures(verdict: GateVerdict) -> list[str]:
    """Recover failed scanner names from a verdict rationale that records scanner failures.

    Args:
        verdict (GateVerdict): Verdict whose rationale may carry the scanner failure prefix.

    Returns:
        list[str]: Failed scanner names, or an empty list when the rationale records none.
    """
    if not verdict.rationale.startswith(SCANNER_FAILURE_RATIONALE_PREFIX):
        return []

    names = verdict.rationale.removeprefix(SCANNER_FAILURE_RATIONALE_PREFIX)
    return [name.strip() for name in names.split(",") if name.strip()]
