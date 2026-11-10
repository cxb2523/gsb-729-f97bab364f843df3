import ipaddress
from collections.abc import Iterable

from ._math import levenshtein


def _is_typosquat(candidate: str, target: str) -> bool:
    if abs(len(candidate) - len(target)) > 2:
        return False

    candidate_name = candidate.rsplit(".", 1)[0]
    target_name = target.rsplit(".", 1)[0]

    candidate_tld = candidate.rsplit(".", 1)[-1]
    target_tld = target.rsplit(".", 1)[-1]

    if candidate_tld != target_tld:
        return False

    if candidate_name == target_name:
        return False

    distance = levenshtein(candidate_name, target_name)
    return distance <= 2 and distance > 0


def check_typosquatting(hostname: str, popular_domains: Iterable[str]) -> str | None:
    """Check if the given hostname is a potential typosquatting of any popular domain.

    Args:
        hostname (str): The hostname to check.
        popular_domains (Iterable[str]): An iterable of popular domains to compare against.

    Returns:
        str | None: The popular domain that the hostname is a potential typosquatting of, or None if not found.
    """
    parts = hostname.split(".")
    if len(parts) < 2:
        return None

    registrable = ".".join(parts[-2:])
    if registrable in popular_domains:
        return None

    for popular in popular_domains:
        if _is_typosquat(registrable, popular):
            return popular

    return None


def is_ip_url(hostname: str) -> bool:
    """Check if the given hostname is an IP address.

    Args:
        hostname (str): The hostname to check.

    Returns:
        bool: True if the hostname is an IP address, False otherwise.
    """
    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False
