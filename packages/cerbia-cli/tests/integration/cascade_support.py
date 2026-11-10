from pathlib import Path

import yaml
from cerbia.core.config import CascadeGateConfig, parse_config


def write_cascade(path: Path, *, policy: str = "fail") -> Path:
    path.write_text(
        f"""name: cli-cascade
loaders:
  - loader: cerbia.core.loaders.text.TextLoader
    init_args:
      texts: [configured text]
type: cascade
on_scanner_error: {policy}
stages:
    - id: guard
      scanners:
        - scanner: cerbia.core.scanners.CanaryLeakScanner
          init_args:
            canary_tokens: [CASCADE_TOKEN]
      threshold: 0.5
      defer_above: 0.2
      score_aggregator:
        score_aggregator: cerbia.core.score_aggregators.MaxScoreAggregator
    - id: final
      scanners:
        - scanner: cerbia.core.scanners.KeywordScanner
      score_aggregator:
        score_aggregator: cerbia.core.score_aggregators.MaxScoreAggregator
      threshold: 0.9
""",
        encoding="utf-8",
    )
    return path


def read_cascade(path: Path) -> CascadeGateConfig:
    config = parse_config(yaml.safe_load(path.read_text(encoding="utf-8")))
    assert isinstance(config, CascadeGateConfig)
    return config
