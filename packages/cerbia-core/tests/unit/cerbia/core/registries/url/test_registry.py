from pathlib import Path
from unittest.mock import patch

import pytest
from cerbia.core.exceptions import CerbIAConfigError
from cerbia.core.registries.url import UrlRegistry

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("entry", "url"),
    [
        ("https://example.com/docs/*", "https://example.com/docs/start"),
        ("https://*.example.com/*", "https://api.example.com/path"),
        ("https://example.com:8443/*", "https://example.com:8443/path"),
        ("https://xn--bcher-kva.example/*", "https://bücher.example/path"),
        ("https://[2001:db8::1]/*", "https://[2001:DB8::1]/path"),
    ],
    ids=["path_wildcard", "subdomain_wildcard", "explicit_port", "internationalized_host", "ipv6_host"],
)
def test_url_registry_allows_url_when_registered_pattern_matches(entry: str, url: str) -> None:
    registry = UrlRegistry([entry])

    result = registry.is_allowed(url)

    assert result


@pytest.mark.parametrize(
    "url",
    [
        "not a URL",
        "https:///missing-host",
        "https://example.com:70000/path",
    ],
    ids=["plain_text", "missing_host", "invalid_port"],
)
def test_url_registry_rejects_url_when_url_cannot_be_normalized(url: str) -> None:
    registry = UrlRegistry(["https://example.com/*"])

    result = registry.is_allowed(url)

    assert not result


def test_url_registry_uses_normalized_url_when_credentials_query_and_fragment_are_provided() -> None:
    registry = UrlRegistry(["https://example.com/docs/page"])

    result = registry.is_allowed("HTTPS://user:pass@EXAMPLE.COM/docs/section/../page?query=value#fragment")

    assert result


def test_url_registry_ignores_entry_when_existing_pattern_covers_it() -> None:
    registry = UrlRegistry(["https://example.com/*"])
    registry.register("https://example.com/docs/*")

    assert len(registry._patterns) == 1
    assert registry.is_allowed("https://example.com/docs/page")


def test_url_registry_removes_existing_pattern_when_new_pattern_covers_it() -> None:
    registry = UrlRegistry(["https://example.com/docs/*"])
    registry.register("https://example.com/*")

    assert len(registry._patterns) == 1
    assert registry.is_allowed("https://example.com/other/page")


def test_url_registry_rejects_url_when_no_registered_pattern_matches() -> None:
    registry = UrlRegistry(["https://example.com/docs/*"])

    result = registry.is_allowed("https://example.com/other")

    assert not result


@pytest.mark.parametrize("denied", [False, True])
def test_invalid_rule_does_not_replace_existing_covered_policy(denied: bool) -> None:
    registry = UrlRegistry()
    registry.register("*", denied=denied)
    expected_patterns = registry._patterns.copy()
    expected_denied_patterns = registry._denied_patterns.copy()

    with pytest.raises(ValueError):
        registry.register("https://[invalid]/", denied=denied)

    assert registry._patterns == expected_patterns
    assert registry._denied_patterns == expected_denied_patterns


@pytest.mark.parametrize("deny_first", [False, True])
def test_deny_precedence_is_independent_of_registration_order(deny_first: bool) -> None:
    registry = UrlRegistry()
    for denied in [True, False] if deny_first else [False, True]:
        registry.register("https://example.com/private/*" if denied else "https://example.com/*", denied=denied)

    assert registry.is_denied("HTTPS://user@EXAMPLE.COM/a/../private/doc?q=1#frag")
    assert not registry.is_allowed("https://example.com/private/doc")
    assert registry.is_allowed("https://example.com/public/doc")


@pytest.mark.parametrize("denied", [False, True])
def test_file_error_preserves_earlier_valid_rules_and_reports_line(tmp_path: Path, denied: bool) -> None:
    path = tmp_path / "rules.txt"
    path.write_text("# policy\n*\nhttps://[invalid]/\n", encoding="utf-8")
    registry = UrlRegistry()

    with pytest.raises(CerbIAConfigError) as caught:
        registry.register_file(path, denied=denied)

    assert f"{path}:3:" in str(caught.value)
    assert isinstance(caught.value.__cause__, ValueError)
    assert registry.is_denied("https://example.com/") == denied
    assert registry.is_allowed("https://example.com/") == (not denied)


@pytest.mark.parametrize("failure", ["missing", "suffix", "decode", "directory", "permission"])
def test_registry_wraps_file_boundary_errors_with_path(failure: str, tmp_path: Path) -> None:
    path = tmp_path / ("rules.csv" if failure == "suffix" else "rules.txt")
    if failure == "directory":
        path.mkdir()
    elif failure != "missing":
        path.write_bytes(b"\xff" if failure == "decode" else b"https://example.com/*")
    registry = UrlRegistry()

    if failure == "permission":
        with (
            patch.object(Path, "read_text", side_effect=PermissionError("denied")),
            pytest.raises(CerbIAConfigError) as caught,
        ):
            registry.register_file(path)
    else:
        with pytest.raises(CerbIAConfigError) as caught:
            registry.register_file(path)

    assert str(path) in str(caught.value)


def test_file_reads_utf8_comments_once_and_targets_only_deny_store(tmp_path: Path) -> None:
    path = tmp_path / "rules.TXT"
    path.write_text("\n # comment\n https://bücher.example/* \n* # literal\n", encoding="utf-8")
    registry = UrlRegistry(["https://allowed.example/*"])

    with patch.object(Path, "read_text", autospec=True, side_effect=Path.read_text) as read:
        registry.register_file(path, denied=True)
        assert registry.is_denied("https://bücher.example/doc")
        assert not registry.is_denied("https://other.example/doc")

    read.assert_called_once_with(path, encoding="utf-8")
    assert registry.is_allowed("https://allowed.example/doc")
