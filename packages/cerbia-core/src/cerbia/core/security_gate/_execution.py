from dataclasses import dataclass

from ..models.scans import Finding, ScanOutcome, SkippedScanner
from ..scanners import Scanner
from ..types import ContentType
from ._validation import check_content_type_skip


@dataclass(frozen=True, slots=True)
class CompletedScan:
    outcome: ScanOutcome
    finding: Finding


@dataclass(frozen=True, slots=True)
class UnsupportedScan:
    skipped: SkippedScanner


@dataclass(frozen=True, slots=True)
class FailedScan:
    error: Exception


def execute_scanner(
    scanner: Scanner, text: str, content_type: ContentType
) -> CompletedScan | UnsupportedScan | FailedScan:
    skipped = check_content_type_skip(scanner, content_type)
    if skipped is not None:
        return UnsupportedScan(skipped)

    try:
        outcome = scanner.scan(text)

        finding = Finding(
            scanner_id=scanner.scanner_id,
            scanner_name=scanner.scanner_name,
            risk_score=outcome.risk_score,
            severity=scanner.severity,
            action=scanner.action,
            rationale=outcome.rationale,
            matches=outcome.matches,
        )
    except Exception as error:
        return FailedScan(error)

    return CompletedScan(outcome, finding)
