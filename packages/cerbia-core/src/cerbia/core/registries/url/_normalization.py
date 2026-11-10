import re
from functools import lru_cache
from urllib.parse import urlparse, urlsplit, urlunsplit


def _normalize_pattern_label(label: str) -> str:
    if not label:
        return ""

    if "*" in label:
        return label.lower()

    lowered = label.lower()
    try:
        return lowered.encode("idna").decode("ascii")
    except UnicodeError:
        return lowered


def _normalize_pattern_host(host: str) -> str:
    if not host:
        return ""

    labels = host.split(".")
    return ".".join(_normalize_pattern_label(label) for label in labels)


def _normalize_pattern_netloc(netloc: str) -> str:
    authority = netloc.rsplit("@", 1)[-1]
    if not authority:
        return ""

    if authority.startswith("["):
        closing_bracket = authority.find("]")
        if closing_bracket == -1:
            return authority.lower()

        host = authority[1:closing_bracket]
        zone_separator = host.find("%")

        if zone_separator != -1:
            host = host[:zone_separator]

        return f"[{host.lower()}]{authority[closing_bracket + 1 :]}"

    host, separator, port = authority.rpartition(":")
    if separator and host and ":" not in host:
        return f"{_normalize_pattern_host(host)}:{port}"

    return _normalize_pattern_host(authority)


def _normalize_url_pattern(pattern: str) -> str:
    if "://" not in pattern:
        return pattern

    parsed = urlsplit(pattern)
    if not parsed.scheme:
        return pattern

    scheme = parsed.scheme.lower()
    authority = _normalize_pattern_netloc(parsed.netloc)

    return urlunsplit((scheme, authority, parsed.path, "", ""))


@lru_cache(maxsize=256)
def compile_url_pattern(pattern: str) -> re.Pattern[str]:
    """Compile a user URL wildcard pattern into an anchored regex.

    Only ``*`` is treated as a wildcard. All other regex metacharacters are
    escaped and matched literally.

    Args:
        pattern (str): User-supplied wildcard pattern.

    Returns:
        re.Pattern[str]: Compiled regular expression anchored to the full normalized URL string.
    """
    normalized_pattern = _normalize_url_pattern(pattern)
    escaped_pattern = "".join(".*" if char == "*" else re.escape(char) for char in normalized_pattern)

    return re.compile(f"^{escaped_pattern}$", re.DOTALL)


def normalize_pattern_for_storage(pattern: str) -> str:
    """Normalize a user URL wildcard pattern for storage in the registry.

    Args:
        pattern (str): User-supplied wildcard pattern.

    Returns:
        str: Normalized pattern suitable for storage in the registry.
    """
    normalized = pattern.strip()
    if not normalized or "://" not in normalized:
        return normalized

    try:
        parsed = urlparse(normalized)
    except Exception:
        return normalized

    if not parsed.scheme:
        return normalized

    authority = parsed.netloc.rsplit("@", 1)[-1].lower()
    path = parsed.path or ""

    return f"{parsed.scheme.lower()}://{authority}{path}"
