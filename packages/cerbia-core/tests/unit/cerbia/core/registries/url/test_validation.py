import pytest
from cerbia.core.registries.url._validation import pattern_covers

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("existing", "candidate"),
    [
        ("https://example.com/path", "https://example.com/path"),
        ("https://example.com/*", "https://example.com/path"),
        ("https://*.example.com/*", "https://api.example.com/path"),
        ("*", "https://example.com/path"),
        ("https://example.com/*/docs/*", "https://example.com/api/docs/index"),
    ],
    ids=["exact_match", "trailing_wildcard", "multiple_wildcards", "universal_wildcard", "intermediate_literals"],
)
def test_url_validation_returns_true_when_existing_pattern_covers_candidate(existing: str, candidate: str) -> None:
    assert pattern_covers(existing, candidate)


@pytest.mark.parametrize(
    ("existing", "candidate"),
    [
        ("https://example.com/path", "https://example.com/other"),
        ("https://example.com/*", "https://api.example.com/path"),
        ("https://example.com/*/docs", "https://example.com/api/docs/index"),
        ("https://example.com/*/docs/*", "https://example.com/docs/api/index"),
    ],
    ids=["different_exact_path", "different_host", "suffix_mismatch", "literal_order_mismatch"],
)
def test_url_validation_returns_false_when_existing_pattern_does_not_cover_candidate(
    existing: str, candidate: str
) -> None:
    assert not pattern_covers(existing, candidate)
