import pytest
from cerbia.core.models.entries import Entry
from cerbia.core.preprocessors.base import Preprocessor

pytestmark = pytest.mark.unit


class _PreprocessorStub:
    preprocessor_id = "stub-preprocessor"
    preprocessor_name = "Stub Preprocessor"

    def process(self, entries: list[Entry]) -> list[Entry]:
        return entries


class _PreprocessorWithoutProcessStub:
    preprocessor_id = "incomplete-preprocessor"
    preprocessor_name = "Incomplete Preprocessor"


def test_preprocessor_contract_is_satisfied_by_class_with_required_members() -> None:
    preprocessor = _PreprocessorStub()

    assert isinstance(preprocessor, Preprocessor)


def test_preprocessor_contract_is_not_satisfied_by_class_without_required_members() -> None:
    candidate = _PreprocessorWithoutProcessStub()

    assert not isinstance(candidate, Preprocessor)
