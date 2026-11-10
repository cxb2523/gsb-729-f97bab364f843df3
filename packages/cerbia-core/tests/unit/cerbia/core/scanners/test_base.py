import pytest
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.scanners.base import Scanner
from cerbia.core.types import Action, ContentType, Severity

pytestmark = pytest.mark.unit


class _ScannerStub:
    scanner_id = "safe"
    scanner_name = "Safe Scanner"
    severity = Severity.LOW
    action = Action.PASS
    content_types: tuple[ContentType, ...] | None = None

    def scan(self, text: str) -> ScanOutcome:
        return ScanOutcome(risk_score=0.0, rationale="safe")


class _ScannerWithoutScanStub:
    scanner_id = "incomplete"
    scanner_name = "Incomplete Scanner"
    severity = Severity.LOW
    action = Action.PASS
    content_types: tuple[ContentType, ...] | None = None


def test_scanner_contract_is_satisfied_by_class_with_required_members() -> None:
    scanner = _ScannerStub()

    assert isinstance(scanner, Scanner)


def test_scanner_contract_is_not_satisfied_by_class_without_required_members() -> None:
    candidate = _ScannerWithoutScanStub()

    assert not isinstance(candidate, Scanner)
