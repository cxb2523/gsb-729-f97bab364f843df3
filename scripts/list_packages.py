import json
import os
from pathlib import Path

import typer


def list_packages() -> list[str]:
    """Return the names of packages with a Python project manifest."""
    packages_folder = Path(__file__).parent.parent / "packages"
    packages = sorted(
        manifest.parent.name for manifest in packages_folder.glob("*/pyproject.toml") if manifest.is_file()
    )

    return packages


def main(
    gh_output_key: str | None = typer.Option(
        None, help="The GitHub Actions output key to set. Only applied if value is provided."
    ),
    gh_env_key: str | None = typer.Option(
        None, help="The GitHub Actions environment key to set. Only applied if value is provided."
    ),
) -> None:
    """Retrieves the names of packages with a Python project manifest."""
    packages = list_packages()

    if not packages:
        print("No package manifests found under packages/*/pyproject.toml")
        raise typer.Exit(code=1)

    serialized_packages = json.dumps(packages, separators=(",", ":"))
    print(serialized_packages)

    if gh_output_key:
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"{gh_output_key}={serialized_packages}\n")

    if gh_env_key:
        with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as env:
            env.write(f"{gh_env_key}={serialized_packages}\n")


if __name__ == "__main__":
    typer.run(main)
