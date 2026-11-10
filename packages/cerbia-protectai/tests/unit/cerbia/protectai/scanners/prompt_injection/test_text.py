import pytest
from cerbia.protectai.scanners.prompt_injection._text import chunk_text

pytestmark = pytest.mark.unit


def test_chunk_text_returns_original_text_when_text_fits_in_chunk() -> None:
    result = chunk_text("short text", chunk_size=20, overlap=5)

    assert result == ["short text"]


@pytest.mark.parametrize(
    ("text", "chunk_size", "expected_chunks"),
    [
        ("abcd", 4, ["abcd"]),
        ("abcdefgh", 4, ["abcd", "efgh"]),
        ("abcdef", 4, ["abcd", "ef"]),
    ],
    ids=["exact_size", "zero_overlap_exact_multiple", "zero_overlap_partial_final_chunk"],
)
def test_chunk_text_preserves_chunk_boundaries_when_overlap_is_zero(
    text: str, chunk_size: int, expected_chunks: list[str]
) -> None:
    result = chunk_text(text, chunk_size=chunk_size, overlap=0)

    assert result == expected_chunks


def test_chunk_text_returns_overlapping_chunks_when_text_exceeds_chunk_size() -> None:
    result = chunk_text("abcdefghij", chunk_size=4, overlap=1)

    assert result == ["abcd", "defg", "ghij"]


@pytest.mark.parametrize("overlap", [4, 5])
def test_chunk_text_raises_value_error_when_overlap_is_not_less_than_chunk_size(overlap: int) -> None:
    with pytest.raises(ValueError, match=rf"overlap \({overlap}\) must be less than chunk_size \(4\)"):
        chunk_text("abcdefghij", chunk_size=4, overlap=overlap)
