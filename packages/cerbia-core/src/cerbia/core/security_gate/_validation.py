from ..models.scans import SkippedScanner
from ..scanners import Scanner
from ..types import ContentType


def _supports_content_type(scanner_types: tuple[ContentType, ...] | None, content_type: ContentType) -> bool:
    if scanner_types is None:
        return True

    if content_type == ContentType.UNKNOWN:
        return True

    return content_type in scanner_types


def check_content_type_skip(scanner: Scanner, content_type: ContentType) -> SkippedScanner | None:
    """Return a SkippedScanner if the scanner doesn't support the given content type.

    Args:
        scanner (Scanner): The scanner to check.
        content_type (ContentType): The entry's content type.

    Returns:
        SkippedScanner | None: A skip record if incompatible, ``None`` otherwise.
    """
    scanner_types = scanner.content_types
    if _supports_content_type(scanner_types, content_type):
        return None

    supported = ", ".join(str(t) for t in scanner_types) if scanner_types else ""
    reason = f"content_type '{content_type.value}' not supported (accepts: {supported})"

    return SkippedScanner(
        scanner_id=scanner.scanner_id,
        scanner_name=scanner.scanner_name,
        reason=reason,
    )
