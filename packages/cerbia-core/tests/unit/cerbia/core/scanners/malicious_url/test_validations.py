import pytest
from cerbia.core.scanners.malicious_url._validations import check_typosquatting, is_ip_url

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("hostname", "expected_result"),
    [
        ("192.0.2.1", True),
        ("2001:db8::1", True),
        ("example.com", False),
        ("not-an-ip", False),
    ],
    ids=["ipv4", "ipv6", "domain", "invalid_value"],
)
def test_malicious_url_validations_identifies_ip_host_when_hostname_is_provided(
    hostname: str, expected_result: bool
) -> None:
    result = is_ip_url(hostname)

    assert result is expected_result


@pytest.mark.parametrize(
    ("hostname", "popular_domains", "expected_result"),
    [
        ("gooogle.com", ["google.com"], "google.com"),
        ("google.com", ["google.com"], None),
        ("gooogle.net", ["google.com"], None),
        ("unrelated-domain.com", ["google.com"], None),
        ("localhost", ["google.com"], None),
    ],
    ids=["single_edit", "exact_popular_domain", "different_tld", "distance_exceeds_threshold", "no_registrable_domain"],
)
def test_malicious_url_validations_returns_popular_domain_when_hostname_is_typosquat(
    hostname: str, popular_domains: list[str], expected_result: str | None
) -> None:
    result = check_typosquatting(hostname, popular_domains)

    assert result == expected_result
