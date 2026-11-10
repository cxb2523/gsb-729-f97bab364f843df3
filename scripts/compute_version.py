#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 INDUSTRIA DE DISEÑO TEXTIL S.A. (INDITEX S.A.)
# SPDX-License-Identifier: Apache-2.0

import os
import re
import subprocess
from typing import Literal

import typer

TAG_PATTERN = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def _latest_tag() -> str:
    result = subprocess.run(["git", "tag"], check=True, capture_output=True, text=True)
    versions: list[tuple[tuple[int, int, int], str]] = []

    for tag in result.stdout.splitlines():
        match = TAG_PATTERN.fullmatch(tag)
        if match is not None:
            versions.append(((int(match[1]), int(match[2]), int(match[3])), tag))

    return max(versions, default=((0, 0, 0), "v0.0.0"))[1]


def _calculate_version(base_tag: str, bump: Literal["major", "minor", "patch"]) -> str:
    match = TAG_PATTERN.fullmatch(base_tag)
    if match is None:
        raise ValueError(f"Invalid version tag: {base_tag}")

    major, minor, patch = (int(value) for value in match.groups())
    match bump:
        case "major":
            return f"{major + 1}.0.0"
        case "minor":
            return f"{major}.{minor + 1}.0"
        case "patch":
            return f"{major}.{minor}.{patch + 1}"


def main(
    bump: Literal["major", "minor", "patch"] = typer.Option("patch", help="Base semantic-version bump."),
    next_release: bool = typer.Option(False, help="Calculate the next minor development version."),
) -> None:
    """Print the requested release version and optionally write it to GitHub Actions output."""
    latest_tag = _latest_tag()
    version = (
        f"{_calculate_version(latest_tag, 'minor')}.dev1" if next_release else _calculate_version(latest_tag, bump)
    )
    print(version)

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as output:
            output.write(f"new_version={version}\n")


if __name__ == "__main__":
    typer.run(main)
