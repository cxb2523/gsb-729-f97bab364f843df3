import pytest
from cerbia.core.config import ScannerConfig
from cerbia.core.factories.scanner import ScannerFactory
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.scanners import (
    CanaryLeakScanner,
    InvisibleTextScanner,
    KeywordScanner,
    MaliciousUrlScanner,
    PiiScanner,
    PromptInjectionScanner,
    Scanner,
    SecretScanner,
    UrlAllowListScanner,
    XssScanner,
)
from cerbia.core.types import Action, ContentType, Severity

pytestmark = pytest.mark.unit


class _ScannerStub:
    scanner_id = "stub"
    scanner_name = "Stub"
    severity = Severity.LOW
    action = Action.PASS
    content_types: tuple[ContentType, ...] | None = None

    def __init__(self, threshold: float) -> None:
        self.threshold = threshold

    def scan(self, text: str) -> ScanOutcome:
        raise NotImplementedError


def test_scanner_factory_builds_configured_scanner() -> None:
    config = ScannerConfig(scanner=f"{__name__}._ScannerStub", init_args={"threshold": 0.8})

    result = ScannerFactory.build(config)

    assert isinstance(result, Scanner)
    assert isinstance(result, _ScannerStub)
    assert result.threshold == 0.8


@pytest.mark.parametrize(
    ("scanner", "init_args", "expected_type"),
    [
        ("cerbia.core.scanners.canary.CanaryLeakScanner", {}, CanaryLeakScanner),
        ("cerbia.core.scanners.invisible_text.InvisibleTextScanner", {}, InvisibleTextScanner),
        ("cerbia.core.scanners.keyword.KeywordScanner", {}, KeywordScanner),
        ("cerbia.core.scanners.malicious_url.MaliciousUrlScanner", {}, MaliciousUrlScanner),
        ("cerbia.core.scanners.pii.PiiScanner", {}, PiiScanner),
        ("cerbia.core.scanners.prompt_injection.PromptInjectionScanner", {}, PromptInjectionScanner),
        ("cerbia.core.scanners.secret.SecretScanner", {}, SecretScanner),
        (
            "cerbia.core.scanners.url_allow_list.UrlAllowListScanner",
            {"allowed_domains": ["https://example.com/*"]},
            UrlAllowListScanner,
        ),
        ("cerbia.core.scanners.xss.XssScanner", {}, XssScanner),
    ],
    ids=[
        "canary",
        "invisible_text",
        "keyword",
        "malicious_url",
        "pii",
        "prompt_injection",
        "secret",
        "url_allowlist",
        "xss",
    ],
)
def test_scanner_factory_builds_public_scanner_when_configured(
    scanner: str, init_args: dict[str, list[str]], expected_type: type[Scanner]
) -> None:
    config = ScannerConfig(scanner=scanner, init_args=init_args)

    result = ScannerFactory.build(config)

    assert isinstance(result, expected_type)
