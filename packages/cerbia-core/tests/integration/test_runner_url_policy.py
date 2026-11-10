from pathlib import Path

import pytest
from cerbia.core.config import LoaderConfig, ScannerConfig, ScoreAggregatorConfig, SimpleGateConfig
from cerbia.core.runner import Runner
from cerbia.core.scanners import MaliciousUrlScanner, UrlAllowListScanner, UrlDenyListScanner

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("allow_source,deny_source", [("inline", "file"), ("file", "inline")])
@pytest.mark.parametrize("deny_first", [False, True])
@pytest.mark.parametrize("fail_fast", [False, True])
def test_runner_blocks_allowlisted_url_when_denylisted_in_either_order(
    allow_source: str, deny_source: str, deny_first: bool, fail_fast: bool, tmp_path: Path
) -> None:
    # Given
    path = tmp_path / "rules.txt"
    path.write_text("https://blocked.xyz/*\n", encoding="utf-8")
    configs = []
    for kind, source, key in (
        ("AllowList", allow_source, "allowed_domains"),
        ("DenyList", deny_source, "blocked_domains"),
    ):
        args = {key: ["https://blocked.xyz/*"] if source == "inline" else str(path)}
        configs.append(ScannerConfig(scanner=f"cerbia.core.scanners.Url{kind}Scanner", init_args=args))
    if deny_first:
        configs.reverse()
    configs.append(ScannerConfig(scanner="cerbia.core.scanners.MaliciousUrlScanner"))
    config = SimpleGateConfig(
        name="url-policy",
        loaders=[
            LoaderConfig(loader="cerbia.core.loaders.TextLoader", init_args={"texts": "https://blocked.xyz/docs"})
        ],
        scanners=configs,
        fail_fast=fail_fast,
        score_aggregator=ScoreAggregatorConfig(score_aggregator="cerbia.core.score_aggregators.MaxScoreAggregator"),
    )
    # When
    runner = Runner(config)
    result = runner.scan()
    # Then
    assert result.is_safe is False
    findings = {finding.scanner_id: finding for finding in result.entry_results[0].findings}
    assert findings["url_denylist" if deny_first else "url_allowlist"].risk_score == 0.95
    if not fail_fast:
        assert findings["url_denylist"].risk_score == 0.95
        assert findings["url_allowlist"].risk_score == 0.95
        assert findings["url_malicious"].risk_score > 0.0
    blocking = findings["url_denylist" if deny_first else "url_allowlist"]
    assert [(span.start, span.end) for span in blocking.matches] == [(0, 24)]
    registries = [
        scanner._url_registry
        for scanner in runner.scanners
        if isinstance(scanner, (UrlAllowListScanner, UrlDenyListScanner, MaliciousUrlScanner))
    ]
    assert len(registries) == 3
    assert all(registry is registries[0] for registry in registries)


def test_runner_keeps_policies_isolated_when_another_runner_is_built() -> None:
    # Given
    config = SimpleGateConfig(
        name="isolated-policy",
        loaders=[LoaderConfig(loader="cerbia.core.loaders.TextLoader", init_args={"texts": "https://example.com/"})],
        scanners=[
            ScannerConfig(scanner="cerbia.core.scanners.UrlAllowListScanner", init_args={"allowed_domains": ["*"]}),
            ScannerConfig(scanner="cerbia.core.scanners.UrlDenyListScanner", init_args={"blocked_domains": []}),
        ],
        score_aggregator=ScoreAggregatorConfig(score_aggregator="cerbia.core.score_aggregators.MaxScoreAggregator"),
    )
    first = Runner(config)
    config.scanners[1].init_args["blocked_domains"] = ["*"]
    # When
    second = Runner(config)
    # Then
    assert first.scan().is_safe
    assert not second.scan().is_safe
