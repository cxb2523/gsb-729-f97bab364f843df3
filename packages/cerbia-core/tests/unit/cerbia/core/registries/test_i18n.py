import re

import pytest
from cerbia.core.registries.i18n import I18nRegistry, i18n_pattern

pytestmark = pytest.mark.unit


def test_i18n_registry_appends_patterns_when_same_language_and_key_are_registered() -> None:
    registry = I18nRegistry()
    first_pattern = re.compile(r"first")
    second_pattern = re.compile(r"second")

    registry.register("en", "instruction_override", [first_pattern])
    registry.register("en", "instruction_override", [second_pattern])

    assert registry.get_patterns() == {"instruction_override": [first_pattern, second_pattern]}


def test_i18n_registry_merges_patterns_when_multiple_languages_share_key() -> None:
    registry = I18nRegistry()
    english_pattern = re.compile(r"ignore")
    spanish_pattern = re.compile(r"ignora")
    exfiltration_pattern = re.compile(r"export")

    registry.register("en", "instruction_override", [english_pattern])
    registry.register("es", "instruction_override", [spanish_pattern])
    registry.register("en", "exfiltration", [exfiltration_pattern])

    assert registry.get_patterns() == {
        "instruction_override": [english_pattern, spanish_pattern],
        "exfiltration": [exfiltration_pattern],
    }


def test_i18n_registry_filters_patterns_when_languages_and_keys_are_provided() -> None:
    registry = I18nRegistry()
    english_pattern = re.compile(r"ignore")
    spanish_pattern = re.compile(r"ignora")
    exfiltration_pattern = re.compile(r"export")

    registry.register("en", "instruction_override", [english_pattern])
    registry.register("es", "instruction_override", [spanish_pattern])
    registry.register("es", "exfiltration", [exfiltration_pattern])

    result = registry.get_patterns(languages=["es", "unknown"], keys=["instruction_override"])

    assert result == {"instruction_override": [spanish_pattern]}


def test_i18n_registry_returns_empty_patterns_when_filters_do_not_match_registered_entries() -> None:
    registry = I18nRegistry()
    registry.register("en", "instruction_override", [re.compile(r"ignore")])

    result = registry.get_patterns(languages=["unknown"], keys=["exfiltration"])

    assert result == {}


@pytest.mark.parametrize(
    ("method_name", "value", "expected_result"),
    [
        ("has_language", "en", True),
        ("has_language", "es", False),
        ("has_key", "instruction_override", True),
        ("has_key", "exfiltration", False),
    ],
    ids=["registered_language", "unknown_language", "registered_key", "unknown_key"],
)
def test_i18n_registry_returns_expected_membership_when_value_is_queried(
    method_name: str, value: str, expected_result: bool
) -> None:
    registry = I18nRegistry()
    registry.register("en", "instruction_override", [re.compile(r"ignore")])

    result = getattr(registry, method_name)(value)

    assert result is expected_result


def test_i18n_registry_returns_available_languages_and_keys_when_patterns_are_registered() -> None:
    registry = I18nRegistry()
    registry.register("en", "instruction_override", [re.compile(r"ignore")])
    registry.register("es", "instruction_override", [re.compile(r"ignora")])
    registry.register("es", "exfiltration", [re.compile(r"exporta")])

    assert registry.available_languages() == {"en", "es"}
    assert registry.available_keys() == {"instruction_override", "exfiltration"}


def test_i18n_pattern_registers_case_insensitive_compiled_patterns_and_preserves_function(mocker) -> None:
    registry = I18nRegistry()
    mocker.patch("cerbia.core.registries.i18n.i18n_registry", registry)

    @i18n_pattern("en", "instruction_override")
    def patterns() -> list[str]:
        return [r"ignore previous instructions"]

    result = patterns()
    registered_pattern = registry.get_patterns()["instruction_override"][0]

    assert result == [r"ignore previous instructions"]
    assert registered_pattern.pattern == r"ignore previous instructions"
    assert registered_pattern.flags & re.IGNORECASE
    assert registered_pattern.search("IGNORE PREVIOUS INSTRUCTIONS")
