import pytest
from cerbia.core._utils import url as url_utils
from cerbia.core._utils.url import extract_urls, normalize_for_matching

pytestmark = pytest.mark.unit


def test_extract_urls_returns_supported_urls_when_text_contains_urls_with_punctuation() -> None:
    text = "Read https://example.com/docs, then ftp://files.example.org/archive. Ignore example.com without a scheme."

    result = extract_urls(text)

    assert [match.group() for match in result] == ["https://example.com/docs", "ftp://files.example.org/archive"]


def test_extract_urls_preserves_original_offsets_when_urls_repeat_with_unicode_and_punctuation() -> None:
    # Given
    url = "HTTPS://BÜCHER.example/é?q=1#frag"
    text = f"前🙂 ({url}), ftp://files.example/a; {url}!"
    # When
    matches = extract_urls(text)
    # Then
    assert [match.group() for match in matches] == [url, "ftp://files.example/a", url]
    assert [match.span() for match in matches] == [
        (text.index(url), text.index(url) + len(url)),
        (text.index("ftp://"), text.index("ftp://") + len("ftp://files.example/a")),
        (text.rindex(url), text.rindex(url) + len(url)),
    ]


def test_extract_urls_returns_empty_list_when_text_has_no_urls() -> None:
    assert extract_urls("no URLs here") == []


@pytest.mark.parametrize(
    ("url", "expected_url"),
    [
        ("HTTPS://user:pass@Example.COM/docs/section/../page?query=value#fragment", "https://example.com/docs/page"),
        ("https://example.com//docs///page/", "https://example.com/docs/page/"),
        ("https://b\u00fccher.example/path", "https://xn--bcher-kva.example/path"),
        ("https://192.0.2.1/path", "https://192.0.2.1/path"),
        ("https://[2001:DB8::1]/path", "https://[2001:db8::1]/path"),
        ("https://[fe80::1%25en0]:8443/path", "https://[fe80::1]:8443/path"),
        ("https://localhost", "https://localhost/"),
        ("https://example.com/relative", "https://example.com/relative"),
    ],
    ids=[
        "credentials_query_fragment",
        "duplicate_separators",
        "idna_host",
        "ipv4_host",
        "ipv6_host",
        "ipv6_zone",
        "localhost",
        "standard_path",
    ],
)
def test_normalize_for_matching_returns_canonical_url_when_valid_url_is_provided(url: str, expected_url: str) -> None:
    result = normalize_for_matching(url)

    assert result == expected_url


@pytest.mark.parametrize(
    "url",
    [
        "not a url",
        "https:///missing-host",
        "https://example.com:70000/path",
        "https://example.com:invalid/path",
        "https://-invalid.example/path",
        "https://invalid-.example/path",
        "https://[2001:db8::1/path",
        "https://2001:db8::1/path",
        "https://[not-an-ip]/path",
        "https://example%.com/path",
    ],
    ids=[
        "plain_text",
        "missing_host",
        "out_of_range_port",
        "non_numeric_port",
        "leading_hyphen_label",
        "trailing_hyphen_label",
        "unclosed_ipv6_bracket",
        "unbracketed_ipv6",
        "invalid_ipv6_literal",
        "percent_in_host",
    ],
)
def test_normalize_for_matching_returns_none_when_url_is_invalid(url: str) -> None:
    result = normalize_for_matching(url)

    assert result is None


@pytest.mark.parametrize(
    ("host_port", "expected_result"),
    [
        ("[2001:db8::1]", ("2001:db8::1", None, True)),
        ("[2001:db8::1]:443", ("2001:db8::1", "443", True)),
        ("[2001:db8::1", (None, None, False)),
        ("[2001:db8::1]suffix", (None, None, False)),
        ("[2001:db8::1]:", (None, None, False)),
        ("example.com:443", ("example.com", "443", False)),
        ("example.com", ("example.com", None, False)),
        (":443", (None, None, False)),
        ("example.com:", (None, None, False)),
        ("2001:db8::1", (None, None, False)),
    ],
    ids=[
        "ipv6_without_port",
        "ipv6_with_port",
        "unclosed_ipv6",
        "invalid_ipv6_suffix",
        "empty_ipv6_port",
        "host_with_port",
        "host_without_port",
        "empty_host",
        "empty_port",
        "unbracketed_ipv6",
    ],
)
def test_split_host_and_port_returns_expected_authority_parts_when_authority_is_provided(
    host_port: str, expected_result: tuple[str | None, str | None, bool]
) -> None:
    result = url_utils._split_host_and_port(host_port)

    assert result == expected_result


@pytest.mark.parametrize(
    ("host", "is_ipv6_literal", "expected_host"),
    [
        ("", False, None),
        ("example%.com", False, None),
        ("-invalid.example", False, None),
        ("a" * 64 + ".example", False, None),
        ("%zone", True, None),
        ("not-an-ip", True, None),
        ("2001:DB8::1", True, "[2001:db8::1]"),
    ],
    ids=[
        "empty_host",
        "percent_in_dns_host",
        "invalid_dns_label",
        "long_dns_label",
        "empty_ipv6_zone",
        "invalid_ipv6",
        "valid_ipv6",
    ],
)
def test_normalize_host_for_matching_returns_expected_host_when_host_is_provided(
    host: str, is_ipv6_literal: bool, expected_host: str | None
) -> None:
    result = url_utils._normalize_host_for_matching(host, is_ipv6_literal=is_ipv6_literal)

    assert result == expected_host


@pytest.mark.parametrize(
    ("port", "expected_port"),
    [
        (None, None),
        ("443", "443"),
        ("", None),
        ("invalid", None),
        ("70000", None),
    ],
    ids=["missing_port", "valid_port", "empty_port", "non_numeric_port", "out_of_range_port"],
)
def test_normalize_port_for_matching_returns_expected_port_when_port_is_provided(
    port: str | None, expected_port: str | None
) -> None:
    result = url_utils._normalize_port_for_matching(port)

    assert result == expected_port


@pytest.mark.parametrize(
    ("path", "expected_path"),
    [
        ("", "/"),
        ("relative/path", "/"),
        ("/", "/"),
        ("/docs/../page", "/page"),
        ("/docs/../page/", "/page/"),
    ],
    ids=["empty_path", "relative_path", "root_path", "dot_segment", "trailing_slash"],
)
def test_normalize_path_for_matching_returns_expected_path_when_path_is_provided(path: str, expected_path: str) -> None:
    result = url_utils._normalize_path_for_matching(path)

    assert result == expected_path
