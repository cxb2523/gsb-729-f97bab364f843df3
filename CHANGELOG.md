<!--
SPDX-FileCopyrightText: INDUSTRIA DE DISEÑO TEXTIL S.A. (INDITEX S.A.)

SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-11-09

### Added

- Added configurable cascade gates, where ordered scanner stages can allow,
  block, or defer to the next stage, with stage-specific thresholds and results
  (`type: cascade`) (#50).

### Changed

- **Breaking for Python API users:** `CerbIAConfig` is now a union and
  `SecurityGate` is a protocol. Replace direct construction with
  `SimpleGateConfig` or `CascadeGateConfig`, and use `Runner` to build the gate.
  Existing flat YAML remains compatible and defaults to a simple gate; cascade
  YAML uses `type: cascade` and `stages` (#50).
- Upgraded documentation tooling from Docouture 1.1.1 to 1.3.1, using native
  `/cerbia` search URLs instead of a local index fixer and removing the external
  link check (#57).
- Updated documentation workflow path filters to include build inputs and
  limited release previews to same-repository pull requests (#57).
- Reorganized the documentation sidebar into Overview, Getting started, Guides,
  and Reference, with Custom components under Guides (#57).

### Fixed

- Aligned product-triggered docs releases with the product tag version and
  immutable commit, protected automatic releases from conflicting docs tags,
  and prepared the docs target for 0.6.0 (#57).

## [0.5.0] - 2026-11-04

### Added

- Decisions/SystemOne text scanner with configurable questions and answer evaluation (#42).
- Optional `email_domains` filtering for `PiiScanner`, with exact,
  case-insensitive matching for standard and supported obfuscated emails (#40).
  Omitting the option preserves unrestricted email detection; an empty list
  disables built-in email detection without affecting other PII checks.
- `UrlDenyListScanner` with explicit deny rules taking precedence over allow
  rules in the shared URL registry (#37).
- File-backed URL allowlist and denylist policies: pass an inline list or a
  UTF-8 `.txt` file path to `allowed_domains` or `blocked_domains` (#37).
- Original-text match spans for URL policy and malicious-URL findings (#37).

### Changed

- **Breaking:** renamed `UrlAllowlistScanner` to `UrlAllowListScanner` and its
  module from `url_allowlist` to `url_allow_list`; update imports and scanner
  configuration paths. The scanner ID remains `url_allowlist` (#37).
- Internal `extract_urls()` now returns regex matches instead of URL strings
  to preserve match positions (#37).

### Fixed

- Prevented `SecretScanner` extra patterns from leaking into other scanner
  instances through shared defaults (#35) (thanks @Lostmanu).
- Rejected invalid IPv6 candidates and prevented MAC addresses from being
  misclassified as IPv6 (#44).
- Removed redundant contained entropy findings while retaining distinct
  overlapping findings (#44).
- Recognized encrypted private-key PEM headers at the existing risk level
  (#44).

## [0.4.0] - 2026-10-21

### Added

- Optional checksum validation and custom validators for `PiiScanner`, disabled
  by default (#25) (thanks @jmcaamanog).
- FastAPI BIM guardrail example with input and output security gates (#24) (thanks @jmcaamanog).
- LangChain agent guardrail example with middleware and callbacks for prompts,
  responses, and tool inputs and outputs (#26) (thanks @jmcaamanog).
- Third-party dependency notices and license texts (#28).

### Fixed

- Restored the `code-uv_python-release-core` workflow to its golden bytes after
  a release attempt clobbered it (#13).
- Hardened the `docouture-*` workflows to least-privilege tokens, resolving
  the Scorecard Token-Permissions alerts on `main` (#20).
- Corrected CLI errors when a configuration path is a directory on Windows (#23) (thanks @jmcaamanog).
- Matched IBANs using country-specific formats without consuming following
  text (#25) (thanks @jmcaamanog).

### Security

- Updated locked `urllib3` to 2.8.0 for HTTPS proxy TLS and streaming security
  fixes (#14).
- Updated locked `virtualenv` to 21.7.13 for activation command-injection
  fixes (#21).
- Updated documentation dependency `handlebars` to 4.7.10 for upstream security
  fixes (#29).
- Updated locked `certifi` to 2026.10.19 and repository `uv` pins to 0.13.4 to
  mitigate the eMudhra CA compromise (#31).

## [0.3.0] - 2026-09-30

### Fixed

- Restored the golden bytes of `.tool-versions` clobbered by a failed release
  attempt (#12).

## [0.2.0] - 2026-09-30

### Changed

- Release alignment only: bumped package versions to 0.2.0; no functional
  changes.

## [0.1.0] - 2026-09-30

### Added

- Initial release of the modular security-scanning library for AI/LLM
  pipelines: the `cerbia` metapackage plus `cerbia-core`, `cerbia-cli`,
  `cerbia-ml`, `cerbia-presidio` and `cerbia-protectai`.

### Changed

- Adopted centrally governed CI workflows.
- Migrated documentation to Docouture (#9).

### Fixed

- Normalized the trailing newline when reading `.tool-versions` inside release
  heredocs (#11).

[Unreleased]: https://github.com/InditexTech/cerbia/compare/v0.6.0...HEAD

[0.6.0]: https://github.com/InditexTech/cerbia/compare/v0.5.0...v0.6.0

[0.5.0]: https://github.com/InditexTech/cerbia/compare/v0.4.0...v0.5.0

[0.4.0]: https://github.com/InditexTech/cerbia/compare/v0.3.0...v0.4.0

[0.3.0]: https://github.com/InditexTech/cerbia/compare/v0.2.0...v0.3.0

[0.2.0]: https://github.com/InditexTech/cerbia/compare/v0.1.0...v0.2.0

[0.1.0]: https://github.com/InditexTech/cerbia/releases/tag/v0.1.0
