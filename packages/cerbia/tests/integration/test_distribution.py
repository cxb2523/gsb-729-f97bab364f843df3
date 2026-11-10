import re
import tomllib
from collections.abc import Sequence
from importlib.metadata import distribution
from pathlib import Path

import pytest

INTERNAL_REQUIREMENT = re.compile(r"cerbia(?:-[A-Za-z0-9_.-]+)?==(?P<version>[0-9][A-Za-z0-9.!+_-]*)")

pytestmark = pytest.mark.integration


def test_workspace_packages_share_a_version_and_internal_pins() -> None:
    workspace = Path(__file__).parents[4]
    manifests = sorted(workspace.glob("packages/*/pyproject.toml"))
    _assert_workspace_version_policy(manifests)


def _assert_workspace_version_policy(manifests: Sequence[Path]) -> None:
    documents = [tomllib.loads(manifest.read_text()) for manifest in manifests]
    versions = {document["project"]["version"] for document in documents}

    assert len(versions) == 1

    version = versions.pop()
    internal_pin_versions: set[str] = set()
    for document in documents:
        project = document["project"]
        requirements = [*project.get("dependencies", [])]
        for optional_requirements in project.get("optional-dependencies", {}).values():
            requirements.extend(optional_requirements)

        for requirement in requirements:
            name = requirement.partition("==")[0]
            match = INTERNAL_REQUIREMENT.fullmatch(requirement)
            if name == "cerbia" or name.startswith("cerbia-"):
                assert match is not None
                internal_pin_versions.add(match["version"])

    assert len(internal_pin_versions) == 1
    if ".dev" not in version:
        assert internal_pin_versions == {version}


@pytest.mark.parametrize(
    ("version", "pin"),
    [
        pytest.param("1.2.1.dev0", "1.2.0", id="development-with-previous-stable-pins"),
        pytest.param("1.2.1.dev0", "1.2.1.dev0", id="development-with-full-development-pins"),
        pytest.param("1.2.1", "1.2.1", id="stable-with-matching-pins"),
    ],
)
def test_version_policy_accepts_consistent_pins(version: str, pin: str, tmp_path: Path) -> None:
    # Given shared versions and pins in normal and optional dependencies.
    manifests = [tmp_path / "core.toml", tmp_path / "cli.toml"]
    manifests[0].write_text(f'[project]\nversion = "{version}"\ndependencies = ["cerbia-core=={pin}"]\n')
    manifests[1].write_text(
        f'[project]\nversion = "{version}"\n[project.optional-dependencies]\ncli = ["cerbia-cli=={pin}"]\n'
    )

    # When checking the workspace, then the policy accepts it.
    _assert_workspace_version_policy(manifests)


@pytest.mark.parametrize(
    ("versions", "requirements"),
    [
        pytest.param(
            ("1.2.1.dev0", "1.2.1.dev0"),
            ("cerbia-core==1.2.0", "cerbia-cli==1.2.1.dev0"),
            id="mixed-development-pins",
        ),
        pytest.param(
            ("1.2.1", "1.2.1"),
            ("cerbia-core==1.2.0", "cerbia-cli==1.2.0"),
            id="stable-version-mismatch",
        ),
        pytest.param(
            ("1.2.1.dev0", "1.2.1.dev0"),
            ("cerbia-core>=1.2.0", "cerbia-cli==1.2.0"),
            id="malformed-normal-pin",
        ),
        pytest.param(
            ("1.2.1.dev0", "1.2.1.dev0"),
            ("cerbia-core==1.2.0", "cerbia-cli>=1.2.0"),
            id="malformed-optional-pin",
        ),
        pytest.param(
            ("1.2.1.dev0", "1.2.1.dev0"),
            ("cerbia-core==1.2.*", "cerbia-cli==1.2.*"),
            id="shared-wildcard-pins",
        ),
        pytest.param(
            ("1.2.1.dev0", "1.2.1.dev0"),
            ("cerbia-core==1.2.0,!=1.2.1", "cerbia-cli==1.2.0,!=1.2.1"),
            id="shared-compound-pins",
        ),
        pytest.param(
            ("1.2.1.dev0", "1.2.2.dev0"),
            ("cerbia-core==1.2.0", "cerbia-cli==1.2.0"),
            id="mixed-workspace-versions",
        ),
    ],
)
def test_version_policy_rejects_inconsistent_manifests(
    versions: tuple[str, str], requirements: tuple[str, str], tmp_path: Path
) -> None:
    # Given inconsistent versions, pins, or pin formats.
    manifests = [tmp_path / "core.toml", tmp_path / "cli.toml"]
    manifests[0].write_text(f'[project]\nversion = "{versions[0]}"\ndependencies = ["{requirements[0]}"]\n')
    manifests[1].write_text(
        f'[project]\nversion = "{versions[1]}"\n[project.optional-dependencies]\ncli = ["{requirements[1]}"]\n'
    )

    # When checking the workspace, then the policy rejects it.
    with pytest.raises(AssertionError):
        _assert_workspace_version_policy(manifests)


def test_distribution_declares_supported_extras() -> None:
    metadata = distribution("cerbia").metadata

    assert metadata["Name"] == "cerbia"
    assert set(metadata.get_all("Provides-Extra", [])) == {
        "all",
        "cli",
        "ml",
        "presidio",
        "protectai",
    }
