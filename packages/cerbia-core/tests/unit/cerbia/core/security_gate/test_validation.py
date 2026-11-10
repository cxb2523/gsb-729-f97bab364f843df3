import pytest
from cerbia.core.models.scans import SkippedScanner
from cerbia.core.security_gate._validation import check_content_type_skip
from cerbia.core.types import Action, ContentType, Severity

pytestmark = pytest.mark.unit


class _ScannerStub:
    scanner_id = "scanner-id"
    scanner_name = "Scanner Name"
    severity = Severity.LOW
    action = Action.PASS

    def __init__(self, content_types: tuple[ContentType, ...] | None) -> None:
        self.content_types = content_types


@pytest.mark.parametrize(
    ("scanner_content_types", "content_type"),
    [
        (None, ContentType.TEXT),
        ((ContentType.TEXT,), ContentType.TEXT),
        ((ContentType.TEXT,), ContentType.UNKNOWN),
    ],
    ids=["unrestricted_scanner", "supported_content_type", "unknown_content_type"],
)
def test_content_type_skip_returns_none_when_scanner_accepts_content_type(
    scanner_content_types: tuple[ContentType, ...] | None, content_type: ContentType
) -> None:
    scanner = _ScannerStub(scanner_content_types)

    result = check_content_type_skip(scanner, content_type)

    assert result is None


def test_content_type_skip_returns_skip_record_when_scanner_rejects_content_type() -> None:
    scanner = _ScannerStub((ContentType.TEXT, ContentType.CODE))

    result = check_content_type_skip(scanner, ContentType.URL)

    assert result == SkippedScanner(
        scanner_id="scanner-id",
        scanner_name="Scanner Name",
        reason="content_type 'url' not supported (accepts: text, code)",
    )
