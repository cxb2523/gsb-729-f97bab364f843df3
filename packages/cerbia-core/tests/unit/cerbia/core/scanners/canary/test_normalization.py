import pytest
from cerbia.core.scanners.canary._normalization import normalize_for_detection

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("text", "expected_text"),
    [
        ("canary&amp;token", "canary&token"),
        ("canary%2Dtoken", "canary-token"),
        ("canary\u200b-token", "canary-token"),
        ("canary&amp;%E2%80%8Btoken", "canary&token"),
    ],
    ids=["html_entity", "url_encoded", "zero_width", "combined_encodings"],
)
def test_canary_normalization_returns_decoded_text_when_encoded_content_is_provided(
    text: str, expected_text: str
) -> None:
    result = normalize_for_detection(text)

    assert result == expected_text


def test_canary_normalization_returns_original_text_when_plain_content_is_provided() -> None:
    text = "plain canary token"

    result = normalize_for_detection(text)

    assert result == text
