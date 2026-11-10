import pytest
from cerbia.core.scanners.url_allow_list._format import format_url_finding

pytestmark = pytest.mark.unit


def test_url_allowlist_format_returns_normalized_url_when_valid_url_is_provided() -> None:
    result = format_url_finding("HTTPS://User:pass@EXAMPLE.COM/path/../docs?query=value#fragment")

    assert result == "https://example.com/docs"


def test_url_allowlist_format_returns_original_value_when_url_cannot_be_normalized() -> None:
    url = "not a valid URL"

    result = format_url_finding(url)

    assert result == url


@pytest.mark.parametrize(
    ("url", "display_limit", "expected_result"),
    [
        ("https://example.com/abc", 23, "https://example.com/abc"),
        ("https://example.com/abcdef", 23, "https://example.com/..."),
        ("https://example.com/abcdef", 10, "https:/..."),
    ],
    ids=["exact_limit", "default_truncation", "custom_limit"],
)
def test_url_allowlist_format_truncates_url_when_display_limit_is_exceeded(
    url: str, display_limit: int, expected_result: str
) -> None:
    result = format_url_finding(url, display_limit)

    assert result == expected_result
