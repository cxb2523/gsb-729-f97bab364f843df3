from pathlib import Path

import pytest
from cerbia.core.models.scans import MatchSpan
from cerbia.core.registries.url import UrlRegistry
from cerbia.core.scanners import UrlDenyListScanner
from cerbia.core.types import Action, Severity

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("source", ["inline", "string", "path"])
def test_denylist_routes_supported_rule_sources_and_only_blocks_matching_urls(source: str, tmp_path: Path) -> None:
    path = tmp_path / "rules.txt"
    path.write_text("https://blocked.example/*\n", encoding="utf-8")

    if source == "inline":
        rules = ["https://blocked.example/*"]
    elif source == "string":
        rules = str(path)
    else:
        rules = path

    scanner = UrlDenyListScanner(rules)

    result = scanner.scan("https://blocked.example/doc https://other.example/doc")

    assert result.risk_score == 0.95
    assert result.matches == [MatchSpan(start=0, end=len("https://blocked.example/doc"))]


def test_denylist_preserves_spans_for_normalized_repeated_unicode_urls() -> None:
    scanner = UrlDenyListScanner(["https://xn--bcher-kva.example/docs"])
    url = "HTTPS://user:pass@BÜCHER.example/a/../docs?q=é#frag"
    text = f"前🙂 ({url}), https://safe.example/; {url}!"

    result = scanner.scan(text)

    assert [text[span.start : span.end] for span in result.matches] == [url, url]
    assert result.risk_score == 0.95
    assert "allowlist" not in result.rationale


def test_denylist_uses_injected_registry_and_configured_positional_arguments() -> None:
    registry = UrlRegistry(["*"])
    scanner = UrlDenyListScanner(["https://blocked.example/*"], Severity.LOW, Action.WARN, registry, None)

    result = scanner.scan("https://blocked.example/doc")

    assert result.risk_score == 0.95
    assert scanner._url_registry is registry
    assert (scanner.severity, scanner.action, scanner.content_types) == (Severity.LOW, Action.WARN, None)


def test_denylist_retains_all_spans_while_limiting_finding_details() -> None:
    scanner = UrlDenyListScanner(["https://blocked.example/*"])
    urls = [f"https://blocked.example/{index}" for index in range(6)]
    text = " ".join(urls)

    result = scanner.scan(text)

    assert [text[span.start : span.end] for span in result.matches] == urls
    assert urls[-1] not in result.rationale


@pytest.mark.parametrize("text", ["no links", "https://other.example/"])
def test_empty_deny_policy_is_safe(text: str) -> None:
    result = UrlDenyListScanner([]).scan(text)

    assert result.risk_score == 0.0
    assert result.matches == []
