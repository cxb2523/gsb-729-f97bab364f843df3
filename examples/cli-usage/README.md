# CLI usage

These configurations use the same built-in loaders, preprocessors, scanner
order, and scanner options. Install the CLI extra before running these commands.

- [simple.cerbia.yaml](simple.cerbia.yaml) is the original configuration,
  renamed without changing its contents. It runs all six scanners with
  `fail_fast: false` and the default simple-gate threshold.
- [cascade.cerbia.yaml](cascade.cerbia.yaml) splits those scanners into `text`
  (invisible text, keywords, prompt injection) and `secrets-and-urls`
  (secrets, malicious URLs, URL allowlist). Each stage uses `MaxScoreAggregator`;
  inputs, preprocessing, and `on_scanner_error: block` are configured at the root.
  Its first input intentionally differs from the simple example to demonstrate
  a defer followed by a second-stage block; the second input is unchanged.

From this directory:

```bash
# Validate either configuration.
uv run --no-sync cerbia validate simple.cerbia.yaml
uv run --no-sync cerbia validate cascade.cerbia.yaml

# Scan the configured inputs (includes an unsafe value).
uv run --no-sync cerbia scan --config simple.cerbia.yaml
uv run --no-sync cerbia scan --config cascade.cerbia.yaml

# Replace the configured loaders with safe inline text.
uv run --no-sync cerbia scan --config simple.cerbia.yaml --text "A short message"
uv run --no-sync cerbia scan --config cascade.cerbia.yaml --text "A short message"
```

Both validations and safe inline scans exit `0`; both configured-input scans
exit `1` because the fixture includes an unsafe value. These built-in components
run locally without API or model calls.

The first cascade input contains one YAML-escaped zero-width space (`\u200b`)
and the synthetic URL `http://outside.example.invalid/telemetry`. The real
`InvisibleTextScanner` produces a text-stage score of `0.20`, so the entry
defers. The URL is outside the configured allowlist: `UrlAllowListScanner`
then produces a severity-weighted second-stage score of `0.7125` and blocks.
No URL is fetched. The second input blocks in `text` and does not reach
`secrets-and-urls`. The safe inline override still allows at text score `0.00`.

The cascade's root `threshold: 0.5` and first-stage `defer_above: 0.1` are
illustrative, **not calibrated security thresholds**. Both stages inherit `0.5`.
The `text` stage blocks above `0.5`, defers to `secrets-and-urls` when its score
is above `0.1` and at most `0.5`, and allows at or below `0.1`. The final stage
has no `defer_above`: it blocks above `0.5`, otherwise allows. Each stage scores
only its own findings, not earlier stages' findings.

**Early allow skips the second-stage secret and URL checks.** A URL-only or
secret-only input with a low text-stage score can therefore be allowed by the
cascade even when the simple configuration blocks it. An early text-stage block
also prevents the second stage from running. This demonstrates cascade routing,
not equivalent protection to the simple configuration.

See the [CLI reference](https://inditextech.github.io/cerbia/latest/main/cli/)
and [configuration guide](https://inditextech.github.io/cerbia/latest/main/configuration/) for general options.
