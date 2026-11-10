import pytest
import spacy.cli
from cerbia.core.models.scans import MatchSpan
from cerbia.presidio.scanners.pii import PresidioPiiScanner

pytestmark = pytest.mark.integration


def test_scanner_uses_installed_small_english_model(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_download(*args: str, **kwargs: str) -> None:
        raise AssertionError("runtime download attempted")

    monkeypatch.setattr(spacy.cli, "download", fail_download)

    scanner = PresidioPiiScanner(entities=["EMAIL_ADDRESS"])

    outcome = scanner.scan("Contact jane@example.com from 192.0.2.1")

    assert outcome.risk_score > 0.0
    assert outcome.matches == [MatchSpan(start=8, end=24)]
    assert outcome.rationale == "PII detected (1 entity/ies): EMAIL_ADDRESS (1)"
