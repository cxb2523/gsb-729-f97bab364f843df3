import ipaddress
import posixpath
import re
from urllib.parse import urlsplit, urlunsplit

MULTI_SCHEME_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^\s\"'<>\)]+(?<![.,;:!?])", re.IGNORECASE)


def _split_ipv6_host_and_port(host_port: str) -> tuple[str | None, str | None, bool]:
    closing_bracket = host_port.find("]")
    if closing_bracket == -1:
        return None, None, False

    host = host_port[1:closing_bracket]
    remainder = host_port[closing_bracket + 1 :]
    if not remainder:
        return host, None, True
    if not remainder.startswith(":"):
        return None, None, False

    port = remainder[1:]
    if not port:
        return None, None, False
    return host, port, True


def _split_standard_host_and_port(host_port: str) -> tuple[str | None, str | None, bool]:
    host, separator, port = host_port.rpartition(":")
    if separator:
        if not host or not port:
            return None, None, False
        if ":" in host:
            return None, None, False
        return host, port, False
    if ":" in host_port:
        return None, None, False
    return host_port, None, False


def _split_host_and_port(netloc: str) -> tuple[str | None, str | None, bool]:
    host_port = netloc.rsplit("@", 1)[-1]
    if not host_port:
        return None, None, False

    if host_port.startswith("["):
        return _split_ipv6_host_and_port(host_port)

    return _split_standard_host_and_port(host_port)


def _is_valid_dns_label(label: str) -> bool:
    if not label or len(label) > 63:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return bool(re.fullmatch(r"[a-z0-9-]+", label))


def _is_valid_dns_name_or_ipv4(host: str) -> bool:
    host_to_validate = host.rstrip(".")
    if not host_to_validate:
        return False

    try:
        ipaddress.IPv4Address(host_to_validate)
    except ValueError:
        pass
    else:
        return True

    if host_to_validate == "localhost":
        return True

    labels = host_to_validate.split(".")
    return all(_is_valid_dns_label(label) for label in labels)


def _normalize_host_for_matching(host: str, *, is_ipv6_literal: bool) -> str | None:
    if not host:
        return None

    if is_ipv6_literal:
        zone_separator = host.find("%")
        if zone_separator != -1:
            host = host[:zone_separator]
            if not host:
                return None

        host = host.lower()
        try:
            _ = ipaddress.IPv6Address(host)
        except ValueError:
            return None

        return f"[{host}]"

    if "%" in host:
        return None

    host = host.lower()

    try:
        normalized_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        if not host.isascii():
            return None

        normalized_host = host

    if not _is_valid_dns_name_or_ipv4(normalized_host):
        return None

    return normalized_host


def _normalize_port_for_matching(port: str | None) -> str | None:
    if port is None:
        return None
    if not port.isascii() or not port.isdigit():
        return None

    port_number = int(port)
    if port_number < 0 or port_number > 65535:
        return None

    return port


def _normalize_path_for_matching(path: str) -> str:
    if not path:
        return "/"

    leading_slashes = len(path) - len(path.lstrip("/"))
    if leading_slashes == 0:
        return "/"

    preserve_trailing_slash = path.endswith("/") and path != "/"
    normalized = posixpath.normpath(path)
    normalized = re.sub(r"/+", "/", normalized)

    if normalized in {"", "."}:
        return "/"

    if not normalized.startswith("/"):
        normalized = f"/{normalized}"

    if preserve_trailing_slash and normalized != "/" and not normalized.endswith("/"):
        normalized = f"{normalized}/"

    return normalized


def extract_urls(text: str) -> list[re.Match[str]]:
    """Extract hierarchical URL matches with their original text offsets.

    Args:
        text (str): Input text to scan.

    Returns:
        list[re.Match[str]]: Matches containing extracted URLs and their spans.
    """
    return list(MULTI_SCHEME_URL_RE.finditer(text))


def normalize_for_matching(url: str) -> str | None:
    """Normalize a hierarchical URL for allowlist matching.

    Args:
        url: URL string to normalize.

    Returns:
        A normalized URL string with lowercase scheme and host, credentials
        removed, path normalized, and query/fragment dropped. Returns ``None``
        when the input cannot be parsed into a hierarchical URL with a host.
    """
    try:
        parsed = urlsplit(url)
    except Exception:
        return None

    if not parsed.scheme or not parsed.netloc:
        return None

    scheme = parsed.scheme.lower()
    host, port, is_ipv6_literal = _split_host_and_port(parsed.netloc)
    if host is None:
        return None

    normalized_host = _normalize_host_for_matching(host, is_ipv6_literal=is_ipv6_literal)
    if not normalized_host:
        return None

    normalized_port = _normalize_port_for_matching(port)
    if port is not None and normalized_port is None:
        return None

    authority = normalized_host
    if normalized_port is not None:
        authority = f"{authority}:{normalized_port}"

    path = _normalize_path_for_matching(parsed.path)
    return urlunsplit((scheme, authority, path, "", ""))
