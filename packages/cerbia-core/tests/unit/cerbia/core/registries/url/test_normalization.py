import pytest
from cerbia.core.registries.url._normalization import compile_url_pattern, normalize_pattern_for_storage

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("pattern", "expected_pattern"),
    [
        ("  HTTPS://User:pass@Example.COM/path?query=value#fragment  ", "https://example.com/path"),
        ("https://*.Example.COM/Path/*", "https://*.example.com/Path/*"),
        ("not a url", "not a url"),
        ("   ", ""),
    ],
    ids=["url_with_credentials", "wildcard_host", "non_url", "blank"],
)
def test_url_normalization_returns_storage_pattern_when_pattern_is_provided(
    pattern: str, expected_pattern: str
) -> None:
    result = normalize_pattern_for_storage(pattern)

    assert result == expected_pattern


@pytest.mark.parametrize(
    ("pattern", "matching_url", "non_matching_url"),
    [
        ("https://example.com/*", "https://example.com/path", "http://example.com/path"),
        ("https://example.com/file[1].txt", "https://example.com/file[1].txt", "https://example.com/file1.txt"),
        ("https://*.example.com/*", "https://api.example.com/path", "https://example.net/path"),
    ],
    ids=["wildcard_path", "literal_regex_metacharacter", "wildcard_subdomain"],
)
def test_url_normalization_compiles_anchored_wildcard_pattern_when_pattern_is_provided(
    pattern: str, matching_url: str, non_matching_url: str
) -> None:
    compiled_pattern = compile_url_pattern(pattern)

    assert compiled_pattern.fullmatch(matching_url) is not None
    assert compiled_pattern.fullmatch(non_matching_url) is None
