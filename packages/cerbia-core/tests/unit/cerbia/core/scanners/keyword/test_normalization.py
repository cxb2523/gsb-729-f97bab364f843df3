import pytest
from cerbia.core.scanners.keyword._normalization import normalize_unicode

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("text", "expected_text"),
    [
        ("ｅｖａｌ", "eval"),
        ("éxécuté", "execute"),
        ("normal text", "normal text"),
    ],
    ids=["full_width_characters", "accented_characters", "plain_text"],
)
def test_normalize_unicode_returns_normalized_text_when_unicode_variant_is_provided(
    text: str, expected_text: str
) -> None:
    result = normalize_unicode(text)

    assert result == expected_text
