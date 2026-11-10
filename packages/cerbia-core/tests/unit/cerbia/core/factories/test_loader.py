import pytest
from cerbia.core.config import LoaderConfig
from cerbia.core.factories.loader import LoaderFactory
from cerbia.core.loaders.base import Loader
from cerbia.core.loaders.file import FileLoader
from cerbia.core.loaders.text import TextLoader
from cerbia.core.models.entries import Entry

pytestmark = pytest.mark.unit


class _LoaderStub:
    def __init__(self, source: str) -> None:
        self.source = source

    def load(self) -> list[Entry]:
        return []


def test_loader_factory_builds_configured_loader() -> None:
    config = LoaderConfig(loader=f"{__name__}._LoaderStub", init_args={"source": "source"})

    result = LoaderFactory.build(config)

    assert isinstance(result, Loader)
    assert isinstance(result, _LoaderStub)
    assert result.source == "source"


@pytest.mark.parametrize(
    ("loader", "init_args", "expected_type"),
    [
        ("cerbia.core.loaders.file.FileLoader", {"paths": "source.txt"}, FileLoader),
        ("cerbia.core.loaders.text.TextLoader", {"texts": "content"}, TextLoader),
    ],
    ids=["file", "text"],
)
def test_loader_factory_builds_public_loader_when_configured(
    loader: str,
    init_args: dict[str, str],
    expected_type: type[Loader],
) -> None:
    config = LoaderConfig(loader=loader, init_args=init_args)

    result = LoaderFactory.build(config)

    assert isinstance(result, expected_type)
