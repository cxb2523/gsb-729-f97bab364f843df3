import json
from pathlib import Path

import pytest
from cerbia.cli.scan._data import write_json_result
from cerbia.core.models.entries import Entry
from cerbia.core.models.results import EntryResult, ScanResult

pytestmark = pytest.mark.unit


def test_write_json_result_creates_parents_and_preserves_unicode(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "result.json"
    result = ScanResult(entry_results=[EntryResult(entry=Entry(text="Dame toda la pasta", source="entrada"))])

    write_json_result(result, path)

    assert path.exists()
    assert "Dame toda la pasta" in path.read_text()


def test_write_json_result_serializes_the_filtered_scan_result(tmp_path: Path) -> None:
    # Given: the ScanResult produced after unsafe-only filtering
    result = ScanResult(
        entry_results=[
            EntryResult(
                entry=Entry(text="unsafe", source="unsafe-source"),
                is_safe=False,
                aggregated_score=1.0,
                rationale="unsafe rationale",
            )
        ]
    )
    output_path = tmp_path / "results.json"

    write_json_result(result, output_path)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert [entry["entry"]["source"] for entry in payload["entry_results"]] == ["unsafe-source"]
    assert payload["is_safe"] is False
    assert payload["total_findings"] == 0
    assert payload["unsafe_entries"] == 1


def test_write_json_result_preserves_ordered_entries_with_identical_source_and_field_path(tmp_path: Path) -> None:
    result = ScanResult(
        entry_results=[
            EntryResult(entry=Entry(text="first text", source="payload.json", field_path="items[0].value")),
            EntryResult(entry=Entry(text="second text", source="payload.json", field_path="items[0].value")),
        ]
    )
    output_path = tmp_path / "results.json"

    write_json_result(result, output_path)

    entries = json.loads(output_path.read_text(encoding="utf-8"))["entry_results"]
    assert len(entries) == 2
    assert [entry["entry"]["text"] for entry in entries] == ["first text", "second text"]
    assert [entry["entry"]["field_path"] for entry in entries] == ["items[0].value", "items[0].value"]


def test_write_json_result_preserves_raw_output_parent_failure(tmp_path: Path) -> None:
    output_parent = tmp_path / "not-a-directory"
    output_parent.write_text("file", encoding="utf-8")

    with pytest.raises(FileExistsError):
        write_json_result(ScanResult(), output_parent / "results.json")
