import pytest
from cerbia.core.loaders.base import Loader
from cerbia.core.models.entries import Entry

pytestmark = pytest.mark.unit


class _LoaderStub:
    def load(self) -> list[Entry]:
        return [Entry(text="content", source="stdin")]


class _LoaderWithoutLoadStub:
    source = "stdin"


def test_base_loader_contract_is_satisfied_by_class_with_load_method() -> None:
    loader = _LoaderStub()

    assert isinstance(loader, Loader)


def test_base_loader_contract_is_not_satisfied_by_class_without_load_method() -> None:
    candidate = _LoaderWithoutLoadStub()

    assert not isinstance(candidate, Loader)
