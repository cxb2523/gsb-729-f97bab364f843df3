import re
import subprocess
from pathlib import Path

import typer
from list_packages import list_packages


def main(
    version: str = typer.Argument(..., help="The version to set for all packages."),
    sync: bool = typer.Option(False, help="Whether to update the workspace lockfile."),
) -> None:
    """Bump package versions and optionally update the workspace lockfile."""
    packages = list_packages()
    pyprojects = {
        package: Path(__file__).parent.parent / "packages" / package / "pyproject.toml" for package in packages
    }

    version_regex = re.compile(r'version\s*=\s*"[^"]+"')

    package_names = "|".join(re.escape(package) for package in packages)
    dependencies_regex = re.compile(rf'(?P<package>{package_names})==(?P<version>[^"\]]+)')

    for package, pyproject_path in pyprojects.items():
        print(f"Processing {package}")

        pyproject_text = pyproject_path.read_text(encoding="utf-8")
        pyproject_text = version_regex.sub(
            f'version = "{version}"',
            pyproject_text,
        )
        pyproject_text = dependencies_regex.sub(
            lambda match: f"{match.group('package')}=={version}",
            pyproject_text,
        )
        pyproject_path.write_text(pyproject_text, encoding="utf-8")

    if sync:
        subprocess.run(["uv", "sync", "--all-extras", "--all-groups", "--all-packages"], check=True)
        subprocess.run(["uv", "lock"], check=True)
        subprocess.run(["uv", "lock", "--check"], check=True)


if __name__ == "__main__":
    typer.run(main)
