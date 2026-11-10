import pytest
from cerbia.core.models.scans import MatchSpan, ScanOutcome

pytestmark = pytest.mark.unit


def test_scan_outcome_retains_legacy_wire_shape_without_provenance() -> None:
    outcome = ScanOutcome(risk_score=0.25, rationale="Synthetic café", matches=[MatchSpan(start=2, end=5)])

    assert (
        outcome.model_dump_json() == '{"risk_score":0.25,"rationale":"Synthetic café","matches":[{"start":2,"end":5}]}'
    )
