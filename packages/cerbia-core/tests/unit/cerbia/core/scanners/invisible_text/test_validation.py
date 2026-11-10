import pytest
from cerbia.core.scanners.invisible_text import _validation
from cerbia.core.scanners.invisible_text._validation import classify_characters

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("character", "expected_counts", "expected_cleaned_text"),
    [
        ("\u200b", (1, 0, 0, 0, 0), ""),
        ("\u202e", (0, 1, 0, 0, 0), ""),
        ("\U000e0001", (0, 0, 0, 1, 0), ""),
        ("\u206a", (0, 0, 1, 0, 0), ""),
        ("\ue000", (0, 0, 0, 0, 1), ""),
        ("\u0378", (0, 0, 0, 0, 1), ""),
        ("visible", (0, 0, 0, 0, 0), "visible"),
    ],
    ids=["zero_width", "bidi_override", "tag_character", "format_control", "private_use", "unassigned", "visible_text"],
)
def test_classify_characters_returns_expected_category_counts_when_character_is_provided(
    character: str, expected_counts: tuple[int, int, int, int, int], expected_cleaned_text: str
) -> None:
    counts, found_characters, cleaned_characters = classify_characters(character)

    assert counts == expected_counts
    assert len(found_characters) == sum(expected_counts)
    assert "".join(cleaned_characters) == expected_cleaned_text


def test_classify_characters_limits_samples_and_excludes_detected_characters_from_cleaned_text() -> None:
    text = "a\u200bb\u202ec\u206ad\ue000e\u0378f\U000e0001g"

    counts, found_characters, cleaned_characters = classify_characters(text)

    assert counts == (1, 1, 1, 1, 2)
    assert len(found_characters) == 5
    assert found_characters[0] == "U+200B (ZERO WIDTH SPACE)"
    assert "".join(cleaned_characters) == "abcdefg"


@pytest.mark.parametrize(
    ("character", "codepoint", "expected_category"),
    [
        ("\u200b", 0x200B, "invisible"),
        ("\u202e", 0x202E, "bidi"),
        ("\U000e0001", 0xE0001, "tag"),
        ("\u206a", 0x206A, "cf"),
        ("\ue000", 0xE000, "co_cn"),
        ("A", 0x41, None),
    ],
    ids=[
        "explicit_invisible",
        "explicit_bidi",
        "tag_range",
        "format_control_fallback",
        "private_use_fallback",
        "visible_character",
    ],
)
def test_detect_char_type_returns_expected_category_when_character_is_provided(
    character: str, codepoint: int, expected_category: str | None
) -> None:
    result = _validation._detect_char_type(character, codepoint)

    assert result == expected_category
