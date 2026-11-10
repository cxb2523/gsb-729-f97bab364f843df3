<!--
SPDX-FileCopyrightText: 2026 INDUSTRIA DE DISEÑO TEXTIL S.A. (INDITEX S.A.)

SPDX-License-Identifier: Apache-2.0
-->

# Contributing

Thank you for your interest in contributing to this project! We value and appreciate any contributions you can make.
To maintain a collaborative and respectful environment, please consider the following guidelines when contributing to this project.

## Prerequisites

- Before starting to contribute to the code, you must first sign the
  Contributor License Agreement (CLA).
  Detailed instructions on how to proceed can be found [here](https://github.com/InditexTech/foss/blob/main/CONTRIBUTING.md).

## How to Contribute

1. Open an issue to discuss and gather feedback on the feature or fix you wish to address.
2. Fork the repository and clone it to your local machine.
3. Create a new branch to work on your contribution: `git checkout -b your-branch-name`.
4. Make the necessary changes in your local branch.
5. Ensure that your code follows the established project style and formatting guidelines.
6. Perform testing to ensure your changes do not introduce errors.
7. Make clear and descriptive commits that explain your changes.
8. Push your branch to the remote repository: `git push origin your-branch-name`.
9. Open a pull request describing your changes and linking the corresponding issue.
10. Await comments and discussions on your pull request. Make any necessary modifications based on the received feedback.
11. Once your pull request is approved, your contribution will be merged into the main branch.

## Contribution Guidelines

- All contributors are expected to follow the project's [code of conduct](CODE_OF_CONDUCT.md). Please be respectful and
considerate towards other contributors.
- Before starting work on a new feature or fix, check existing [issues](../../issues) and [pull requests](../../pulls)
to avoid duplications and unnecessary discussions.
- If you wish to work on an existing issue, comment on the issue to inform other contributors that you are working on it.
This will help coordinate efforts and prevent conflicts.
- It is always advisable to discuss and gather feedback from the community before making significant changes to the
project's structure or architecture.
- Ensure a clean and organized commit history. Divide your changes into logical and descriptive commits. We recommend to use the [Conventional Commits Specification](https://www.conventionalcommits.org/en/v1.0.0/)
- Document any new changes or features you add. This will help other contributors and project users understand your work
and its purpose.
- Be sure to link the corresponding issue in your pull request to maintain proper tracking of contributions.
- Remember to add license and copyright information following the [REUSE Specification](https://reuse.software/spec/#copyright-and-licensing-information).

## Development

Bootstrap the locked development environment and install the commit hook:

```bash
make install
```

Use `make format` to apply Ruff formatting in place. `make lint` is
non-mutating: it runs Ruff, ty, and a formatting check. `make verify` runs the
non-mutating lint-and-test gate.

```bash
make format
make lint
make test
make build
make verify

make test cerbia-ml
make verify cerbia-ml
make build cerbia-ml
```

Accepted package names are `cerbia`, `cerbia-core`, `cerbia-ml`,
`cerbia-presidio`, and `cerbia-protectai`. `make install` synchronizes the
complete locked workspace. The metadata-only `cerbia` package is handled
automatically without source coverage.

To prepare a release, use a canonical PEP 440 version:

```bash
make bump-version 1.2.3
```

This updates every package version and internal CerbIA dependency pin, then
refreshes `uv.lock` and synchronizes the workspace environment.

CI runs each package pipeline in parallel. The local hooks run Ruff and ty
through uv, so no globally installed Python tooling is required.

### Documentation

Documentation uses Docouture and Antora. Install Node.js 24 or later, npm, and
Docker with a running daemon. The site renders Mermaid diagrams through a local
Kroki service; the Antora extension starts it with Docker Compose when needed.
From the repository root, install locked dependencies, build the site with
persistent output, or start the live development server:

```bash
make docs-install
make docs-build
make docs-serve
```

The equivalent commands from `docs/` are:

```bash
npm ci
npm run build
npm run dev
```

`make docs-build` uses the production playbook (`main` and `docs/v*`) and leaves
`docs/build/site` for the gh-pages publisher.
Stop `npm run dev` before building: the live server owns that output while running.

For HEAD-only QA without touching the live output, run from `docs/`:

```bash
output=$(mktemp -d)
trap 'rm -rf "$output"' EXIT
npx antora --fetch --log-failure-level warn --to-dir "$output" antora-playbook.local.yml
SITE_DIR="$output" node --test scripts/search-index.test.mjs
```

The read-only search regression checks native URL prefixes, local page/anchor
targets, and the latest copy when present. For production QA, use a disposable
full-history repository copy, check out `main` there, then overlay the candidate
working tree before building with `npm run build -- --to-dir "$output"`. Otherwise
the production playbook can silently read the old `main` commit instead of your
candidate. Keep the original repository's refs and live output untouched.

Docouture uses full-history versioning: `main` stays `version: prerelease` with
`prerelease: true` in `docs/src/antora.yml`, while `docs/vX.Y.Z` tags supply numbered
documentation versions. With no release tags, the site contains only prerelease.

Product GitHub Releases align docs with the product: `v0.6.0` selects
`docs/v0.6.0` from the release event's immutable product commit, not current
`main` or `docs/.release-version`. The product tag must have a leading `v`
followed by strict SemVer. The product snapshot must contain the current docs
tooling (including Docouture 1.3.1); historical backfills are a separate operation.
For the planned 0.6.0 release, use the explicit `release-type/minor` PR label.
When a PR also has `docs/release`, that label defers docs tagging until the
product GitHub Release is published unless `skip-release` is present. The product
release preview, not the docs descriptor, determines the coupled version.

For a docs-only release, merge a PR into `main` with `docs/release` and the target
SemVer in `docs/.release-version`, without a pending product release (or with
`skip-release`). Alternatively, run `docouture-release` manually against `main`
and supply the desired version instead of its standalone default `stable`.
SemVer prerelease and build-metadata suffixes are supported. The workflow builds
the exact release descriptor before tagging, then calls the gh-pages publisher
using current `main` tooling and all docs tags. Do not change
`docs/src/antora.yml` on `main` to release.

After a new version, the workflow refreshes `main` and commits the next patch
target only if `docs/.release-version` still equals the version just released.
A different planned target is preserved. Set that file explicitly in a reviewed
PR when planning a different next target, such as a new minor (currently 0.6.0).
Automatic releases accept an existing docs tag only if its full tree matches;
conflicting content fails without overwriting it. To republish an existing
version, manually supply its version: the workflow **force-recreates and pushes
the existing `docs/v…` tag**, and skips the next-target bump. These tags are not
guaranteed immutable; a republish changes the documentation at that numbered URL.

Run the local workflow regression checks (no remote writes) from `docs/`:

```bash
node --test scripts/release-workflows.test.mjs
```

Production enables `duplicate_latest_version` on the Antora extension. Once a
non-prerelease release exists, `/cerbia/latest/` serves an independent copy of
Antora's latest released pages, images, and attachments, not redirects or
symlinks. Numbered versions remain available. The copy retains the source
version's canonical URLs and shared search index; search results go to numbered
`/cerbia/<version>/` URLs, not `/latest/`. No `ROOT-latest.json` is generated, and
prerelease-only builds have no latest copy. HEAD-only QA uses the local playbook
without this duplication option.

The build does not check diagram count or SVG accessibility. Kroki failures may
fall back to raw Mermaid without failing Antora; a successful build is not proof
that diagrams rendered. Check a representative page's embedded Mermaid SVG for
rendered shapes as well as running the read-only search regression.
