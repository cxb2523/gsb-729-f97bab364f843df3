import logging
import math
from typing import assert_never

from ..models.scans import Finding, SkippedScanner
from ..scanners import Scanner
from ..score_aggregators import ScoreAggregator
from ..types import Action, ContentType, ScannerErrorPolicy
from ._execution import CompletedScan, FailedScan, UnsupportedScan, execute_scanner
from ._models import GateVerdict
from ._results import build_rationale

logger = logging.getLogger(__name__)


class SimpleGate:
    """Composes multiple scanners and aggregates their results into a single verdict.

    A gate runs each scanner sequentially against the input text, collects findings, and computes a severity-weighted
    aggregated score from positive-risk BLOCK findings. With no blocking scanner failures, the gate passes when no
    positive-risk BLOCK findings exist or when the aggregated score falls below the configured threshold.

    Args:
        name (str): Human-readable gate name (e.g. ``"config-scan"``).
        scanners (list[Scanner]): Ordered list of scanners to execute.
        score_aggregator (ScoreAggregator): Strategy that aggregates risk scores from blocked scanners.
        fail_fast (bool): Stop on a blocking scanner error or a non-negligible BLOCK finding whose weighted score
            meets the threshold. Defaults to True.
        threshold (float): Minimum aggregated score to trigger a block verdict. At ``0.0``, any positive-risk BLOCK
            finding blocks; zero-risk findings do not. Blocking scanner failures block independently of this threshold.
            Defaults to ``0.0``.
        on_scanner_error (ScannerErrorPolicy): How scanner execution errors are handled. Defaults to ``"block"``.

    Attributes:
        name (str): Human-readable gate name.
        scanners (list[Scanner]): Ordered list of scanners to execute.
        score_aggregator (ScoreAggregator): Strategy that aggregates risk scores from blocked scanners.
        fail_fast (bool): Whether blocking scanner errors or qualifying individual BLOCK findings stop execution.
        threshold (float): Minimum aggregated score to trigger a block verdict.
        on_scanner_error (ScannerErrorPolicy): Scanner execution error policy.
    """

    def __init__(
        self,
        name: str,
        scanners: list[Scanner],
        score_aggregator: ScoreAggregator,
        fail_fast: bool = True,
        threshold: float = 0.0,
        on_scanner_error: ScannerErrorPolicy = ScannerErrorPolicy.BLOCK,
    ) -> None:
        self.name = name
        self.scanners = scanners
        self.fail_fast = fail_fast
        self.score_aggregator = score_aggregator
        self.threshold = threshold
        self.on_scanner_error = on_scanner_error

    def scan(self, text: str, *, content_type: ContentType = ContentType.UNKNOWN) -> GateVerdict:
        """Run eligible scanners in order against the input text.

        FAIL re-raises the original scanner exception. BLOCK forces an unsafe verdict and stops only when fail_fast
        is enabled. SKIP records the failed scanner and continues. Fail-fast also stops on a BLOCK finding whose
        risk score is not close to zero (absolute tolerance 1e-9) and whose weighted score meets the threshold.
        Aggregation still includes every positive BLOCK score collected, including near-zero scores.

        Args:
            text (str): The text to scan.
            content_type (ContentType): Content type metadata used to skip incompatible scanners.

        Returns:
            GateVerdict: Aggregated verdict with individual findings.

        Raises:
            Exception: If a scanner raises under the FAIL policy or the score aggregator raises during aggregation;
                the original exception is propagated.
        """
        findings: list[Finding] = []
        skipped: list[SkippedScanner] = []
        scanner_failures: list[str] = []
        logger.debug(
            "Gate evaluation started",
            extra={
                "operation": "scan",
                "stage": "execution",
                "component_kind": "security_gate",
                "outcome": "started",
            },
        )
        for scanner in self.scanners:
            logger.debug(
                "Executing scanner %s (%s)",
                scanner.scanner_name,
                scanner.scanner_id,
                extra={
                    "operation": "scan",
                    "stage": "scanner",
                    "component_kind": "security_gate",
                },
            )
            finding: Finding | None = None
            scanner_failed = False

            match execute_scanner(scanner, text, content_type):
                case UnsupportedScan(skipped=skipped_entry):
                    logger.debug(
                        "Scanner skipped due to content type mismatch: %s (%s)",
                        scanner.scanner_name,
                        scanner.scanner_id,
                        extra={
                            "operation": "scan",
                            "stage": "scanner",
                            "component_kind": "security_gate",
                            "outcome": "skipped",
                        },
                    )
                    skipped.append(skipped_entry)
                    continue
                case CompletedScan(finding=finding):
                    findings.append(finding)
                case FailedScan(error=error):
                    match self.on_scanner_error:
                        case ScannerErrorPolicy.FAIL:
                            raise error
                        case ScannerErrorPolicy.BLOCK:
                            logger.error(
                                "Scanner execution failed: %s (%s). Blocking gate due to error policy.",
                                scanner.scanner_name,
                                scanner.scanner_id,
                                extra={
                                    "operation": "scan",
                                    "stage": "scanner",
                                    "outcome": "failure",
                                },
                            )
                            scanner_failures.append(scanner.scanner_name)
                            scanner_failed = True
                        case ScannerErrorPolicy.SKIP:
                            logger.error(
                                "Scanner execution failed: %s (%s). Skipping scanner due to error policy.",
                                scanner.scanner_name,
                                scanner.scanner_id,
                                extra={
                                    "operation": "scan",
                                    "stage": "scanner",
                                    "outcome": "failure",
                                },
                            )
                            skipped.append(
                                SkippedScanner(
                                    scanner_id=scanner.scanner_id,
                                    scanner_name=scanner.scanner_name,
                                    reason="scanner execution failed",
                                )
                            )
                        case unreachable:
                            assert_never(unreachable)
                case unreachable:
                    assert_never(unreachable)

            if self._should_fail_fast(finding, scanner_failed=scanner_failed):
                break

        verdict = self._build_verdict(findings, skipped, scanner_failures)
        skipped_count = len(skipped)
        result_count = len(findings)
        logger.debug(
            "Gate evaluation completed",
            extra={
                "operation": "scan",
                "stage": "execution",
                "component_kind": "security_gate",
                "outcome": "completed",
                "skipped_count": skipped_count,
                "result_count": result_count,
            },
        )
        return verdict

    def _should_fail_fast(self, finding: Finding | None = None, *, scanner_failed: bool = False) -> bool:
        if not self.fail_fast:
            return False

        if scanner_failed:
            return True

        if finding is None:
            return False

        if math.isclose(finding.risk_score, 0.0, abs_tol=1e-9):
            return False

        weighted = finding.risk_score * finding.severity.weight
        return finding.action == Action.BLOCK and weighted >= self.threshold

    def _build_verdict(
        self, findings: list[Finding], skipped: list[SkippedScanner], scanner_failures: list[str]
    ) -> GateVerdict:
        failed = [f for f in findings if f.risk_score > 0.0]
        blocked = [f for f in failed if f.action == Action.BLOCK]
        weighted_scores = [f.risk_score * f.severity.weight for f in blocked]
        aggregated_score = self.score_aggregator.compute(weighted_scores) if blocked else 0.0
        is_safe = not blocked or aggregated_score < self.threshold
        rationale = build_rationale(is_safe, failed, blocked)
        if scanner_failures:
            is_safe = False
            rationale = f"Scanner execution failed: {', '.join(scanner_failures)}"

        return GateVerdict(
            is_safe=is_safe,
            score=aggregated_score,
            rationale=rationale,
            findings=findings,
            skipped_scanners=skipped,
        )
