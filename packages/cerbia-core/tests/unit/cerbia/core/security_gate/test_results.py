import pytest
from cerbia.core.models.scans import Finding
from cerbia.core.security_gate._results import build_rationale
from cerbia.core.types import Action, Severity

pytestmark = pytest.mark.unit


def test_build_rationale_returns_pass_message_when_no_scanners_flag_content() -> None:
    result = build_rationale(is_safe=True, failed=[], blocked=[])

    assert result == "All scanners passed"


def test_build_rationale_returns_warning_message_when_warn_scanners_flag_content() -> None:
    warning = _build_finding(scanner_name="Warning Scanner", action=Action.WARN)

    result = build_rationale(is_safe=True, failed=[warning], blocked=[])

    assert result == "Passed with warnings: Warning Scanner"


def test_build_rationale_returns_scanner_rationale_when_one_scanner_blocks() -> None:
    blocked = _build_finding(scanner_name="Blocking Scanner", action=Action.BLOCK, rationale="Threat detected")

    result = build_rationale(is_safe=False, failed=[blocked], blocked=[blocked])

    assert result == "Blocking Scanner: Threat detected"


def test_build_rationale_returns_blocked_scanner_summary_when_multiple_scanners_block() -> None:
    first_blocked = _build_finding(scanner_name="First Scanner", action=Action.BLOCK)
    second_blocked = _build_finding(scanner_name="Second Scanner", action=Action.BLOCK)

    result = build_rationale(
        is_safe=False,
        failed=[first_blocked, second_blocked],
        blocked=[first_blocked, second_blocked],
    )

    assert result == "2 scanners blocked: First Scanner, Second Scanner"


def _build_finding(
    scanner_name: str,
    action: Action,
    rationale: str = "Detected",
) -> Finding:
    return Finding(
        scanner_id=scanner_name.lower().replace(" ", "-"),
        scanner_name=scanner_name,
        risk_score=0.5,
        severity=Severity.MEDIUM,
        action=action,
        rationale=rationale,
    )
