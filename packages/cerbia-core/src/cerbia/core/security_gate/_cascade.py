from typing import Literal, assert_never

from ..models.scans import Finding
from ..models.stages import StageResult
from ..scanners import Scanner
from ..types import ContentType, ScannerErrorPolicy
from ._errors import CascadeExecutionError
from ._execution import CompletedScan, FailedScan, UnsupportedScan, execute_scanner
from ._models import GateVerdict
from ._policy import OperationalFault, StageEvaluation, evaluate_stage
from ._stages import BuiltStage
from ._trace import FailureCode, StageDecision

__all__ = ["CascadeGate"]


class CascadeGate:
    """Run ordered stages using only each stage's own scanner scores.

    Args:
        name (str): Gate name.
        stages (tuple[BuiltStage, ...]): Constructed stages in execution order.
        on_scanner_error (Literal[ScannerErrorPolicy.FAIL, ScannerErrorPolicy.BLOCK]): Propagate operational faults
            or turn them into a terminal block.

    Attributes:
        name (str): Gate name.
        stages (tuple[BuiltStage, ...]): Constructed stages in execution order.
        on_scanner_error (Literal[ScannerErrorPolicy.FAIL, ScannerErrorPolicy.BLOCK]): Operational fault policy.
        scanners (tuple[Scanner, ...]): Flattened scanner view in stage order.
    """

    def __init__(
        self,
        name: str,
        stages: tuple[BuiltStage, ...],
        on_scanner_error: Literal[ScannerErrorPolicy.FAIL, ScannerErrorPolicy.BLOCK],
    ) -> None:
        self.name = name
        self.stages = stages
        self.on_scanner_error: Literal[ScannerErrorPolicy.FAIL, ScannerErrorPolicy.BLOCK] = on_scanner_error

    @property
    def scanners(self) -> tuple[Scanner, ...]:
        """Return the scanners in stage order.

        Returns:
            tuple[Scanner, ...]: Flattened view of the constructed scanners.
        """
        return tuple(scanner for stage in self.stages for scanner in stage.scanners)

    def scan(self, text: str, *, content_type: ContentType = ContentType.UNKNOWN) -> GateVerdict:
        """Run reached stages until an allow, block, or operational fault terminates the cascade.

        All scanners in a reached stage complete before score-based routing. A scanner fault stops that stage
        immediately. Under BLOCK, an operational fault produces a scoreless block stage and a verdict score of 1.0.

        Args:
            text (str): Text to scan.
            content_type (ContentType): Metadata used to check scanner compatibility.

        Returns:
            GateVerdict: Terminal verdict, completed findings, and summaries for reached and unreached stages.

        Raises:
            CascadeExecutionError: Under FAIL, if content is unsupported, an aggregator is missing, or its score is
                invalid. Also raised if no terminal decision is produced.
            Exception: If a scanner or aggregator raises under FAIL; the original exception is propagated.
        """
        findings: list[Finding] = []
        summaries: list[StageResult] = []
        terminal: StageResult | None = None
        rationale = ""
        own: list[CompletedScan] = []
        completed: CompletedScan | None = None

        try:
            for stage in self.stages:
                if terminal is not None:
                    summaries.append(StageResult(id=stage.config.id, result="not_reached"))
                    continue

                own.clear()
                completed = None
                fault: OperationalFault | None = None

                for scanner in stage.scanners:
                    match execute_scanner(scanner, text, content_type):
                        case CompletedScan() as completed:
                            own.append(completed)
                            completed.finding.stage = stage.config.id
                            findings.append(completed.finding)
                        case FailedScan(error=error):
                            fault = OperationalFault(error, FailureCode.SCANNER_ERROR)
                        case UnsupportedScan():
                            fault = OperationalFault(
                                CascadeExecutionError(
                                    stage.config.id, FailureCode.UNSUPPORTED_CONTENT, scanner.scanner_id
                                ),
                                FailureCode.UNSUPPORTED_CONTENT,
                            )
                        case unreachable:
                            assert_never(unreachable)

                    if fault is not None:
                        break

                if fault is not None:
                    evaluated: OperationalFault | StageEvaluation = fault
                else:
                    evaluated = evaluate_stage(stage, own, final=stage is self.stages[-1])

                own.clear()
                completed = None

                summary, rationale = self._summarize_stage(stage, evaluated)
                summaries.append(summary)
                if summary.result != StageDecision.DEFER:
                    terminal = summary

            if terminal is None:
                raise CascadeExecutionError(self.stages[-1].config.id, FailureCode.MISSING_EVIDENCE)

            return GateVerdict(
                is_safe=terminal.result == StageDecision.ALLOW,
                score=1.0 if terminal.score is None else terminal.score,
                rationale=rationale,
                findings=findings,
                skipped_scanners=[],
                stages=tuple(summaries),
            )
        finally:
            own.clear()
            completed = None

    def _summarize_stage(
        self, stage: BuiltStage, evaluated: OperationalFault | StageEvaluation
    ) -> tuple[StageResult, str]:
        match evaluated:
            case OperationalFault(error=error, category=category):
                match self.on_scanner_error:
                    case ScannerErrorPolicy.FAIL:
                        raise error
                    case ScannerErrorPolicy.BLOCK:
                        summary = StageResult(id=stage.config.id, result="block")
                        rationale = f"Cascade stage {stage.config.id}: {category.value}"
                    case unreachable:
                        assert_never(unreachable)
            case StageEvaluation() as decision:
                match decision.decision:
                    case StageDecision.ALLOW:
                        disposition = "allow"
                    case StageDecision.BLOCK:
                        disposition = "block"
                    case StageDecision.DEFER:
                        disposition = "defer"
                    case unreachable:
                        assert_never(unreachable)

                summary = StageResult(
                    id=stage.config.id,
                    result=disposition,
                    score=decision.score,
                )
                rationale = f"Cascade stage {stage.config.id}: {decision.rationale}"
            case unreachable:
                assert_never(unreachable)

        return summary, rationale
