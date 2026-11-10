import pytest
from cerbia.core.types import Severity

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("severity", "expected_weight"),
    [
        (Severity.CRITICAL, 1.0),
        (Severity.HIGH, 0.75),
        (Severity.MEDIUM, 0.5),
        (Severity.LOW, 0.25),
    ],
    ids=["critical", "high", "medium", "low"],
)
def test_severity_type_computes_weight_correctly(severity: Severity, expected_weight: float) -> None:
    result = severity.weight

    assert result == expected_weight
