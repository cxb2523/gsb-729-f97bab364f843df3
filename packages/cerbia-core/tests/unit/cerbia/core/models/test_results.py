import pytest
from cerbia.core.models.entries import Entry
from cerbia.core.models.results import EntryResult, ScanResult
from cerbia.core.models.scans import Finding
from cerbia.core.types import Action, Severity
from pydantic import ValidationError

pytestmark = pytest.mark.unit


def test_scan_result_aggregates_empty_entry_results() -> None:
    result = ScanResult(entry_results=[])

    assert result.is_safe is True
    assert result.total_findings == 0
    assert result.unsafe_entries == 0


def test_scan_result_is_safe_if_all_entry_results_are_safe() -> None:
    safe_entry_result = EntryResult(
        entry=Entry(text="safe", source="stdin"),
        is_safe=True,
        aggregated_score=0.0,
        rationale="no threats found",
        findings=[],
        skipped_scanners=[],
    )

    result = ScanResult(entry_results=[safe_entry_result])

    assert result.is_safe is True
    assert result.total_findings == 0
    assert result.unsafe_entries == 0


def test_scan_result_is_unsafe_if_any_entry_result_is_unsafe() -> None:
    finding = Finding(
        scanner_id="scanner",
        scanner_name="Scanner",
        risk_score=0.8,
        severity=Severity.HIGH,
        action=Action.BLOCK,
        rationale="threat found",
    )
    safe_result = EntryResult(
        entry=Entry(text="safe", source="stdin"),
        is_safe=True,
        aggregated_score=0.0,
        rationale="no threats found",
        findings=[],
        skipped_scanners=[],
    )
    unsafe_result = EntryResult(
        entry=Entry(text="unsafe", source="stdin"),
        is_safe=False,
        aggregated_score=0.8,
        rationale="threat found",
        findings=[finding, finding],
        skipped_scanners=[],
    )

    result = ScanResult(entry_results=[safe_result, unsafe_result])

    assert result.is_safe is False
    assert result.total_findings == 2
    assert result.unsafe_entries == 1


def test_legacy_serialization_when_optional_cascade_fields_are_null() -> None:
    # Given
    payload = {
        "entry": {"text": "public", "source": "inline"},
        "stages": None,
    }
    expected = (
        '{"entry":{"text":"public","source":"inline","field_path":null,"metadata":'
        '{"original_text":null,"derived_from":[],"preprocessors":{}},"content_type":"unknown"},'
        '"is_safe":true,"aggregated_score":0.0,"rationale":"","findings":[],"skipped_scanners":[],"stages":null}'
    )
    # When
    result = EntryResult.model_validate(payload)
    # Then
    assert result.model_dump_json() == expected
    assert ScanResult(entry_results=[result]).model_dump_json() == (
        '{"entry_results":[' + expected + '],"is_safe":true,"total_findings":0,"unsafe_entries":0}'
    )


def test_entry_result_invokes_stage_ownership_validator() -> None:
    with pytest.raises(ValidationError, match="finding requires an executed stage owner"):
        EntryResult.model_validate(
            {
                "entry": {"text": "safe", "source": "inline"},
                "stages": [{"id": "guard", "result": "allow", "score": 0.0}],
                "findings": [
                    {
                        "scanner_id": "local",
                        "scanner_name": "Local",
                        "risk_score": 0.0,
                        "severity": "critical",
                        "action": "block",
                        "rationale": "clean",
                        "stage": "unknown",
                    }
                ],
            }
        )


def test_nested_scan_result_roundtrips_owned_findings_and_stage_summaries() -> None:
    entry = EntryResult.model_validate(
        {
            "entry": {"text": "public", "source": "inline"},
            "stages": [{"id": "guard", "result": "allow", "score": 0.0}, {"id": "fallback", "result": "not_reached"}],
            "findings": [
                {
                    "scanner_id": "local",
                    "scanner_name": "Local",
                    "risk_score": 0.0,
                    "severity": "critical",
                    "action": "block",
                    "rationale": "clean",
                    "stage": "guard",
                }
            ],
        }
    )
    result = ScanResult(entry_results=[entry])

    decoded = ScanResult.model_validate_json(result.model_dump_json())

    assert decoded == result
    assert decoded.total_findings == 1
    assert decoded.entry_results[0].findings[0].stage == "guard"
