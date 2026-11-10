import math

import pytest
from cerbia.core.preprocessors.speculative_decoding import _heuristics
from cerbia.core.preprocessors.speculative_decoding.exceptions import ChiSquaredError

pytestmark = pytest.mark.unit


def test_byte_entropy_returns_zero_for_empty_and_uniform_data() -> None:
    assert _heuristics.byte_entropy(b"") == 0.0
    assert _heuristics.byte_entropy(b"a" * 16) == 0.0


def test_byte_entropy_returns_eight_bits_for_uniform_byte_distribution() -> None:
    assert _heuristics.byte_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_printable_ratio_counts_ascii_whitespace_as_printable() -> None:
    assert _heuristics.printable_ratio("A\n\r\t\x00") == pytest.approx(0.8)
    assert _heuristics.printable_ratio("") == 0.0


def test_looks_like_text_requires_strict_utf8_and_high_printability() -> None:
    assert _heuristics._looks_like_text(b"readable text") is True
    assert _heuristics._looks_like_text(b"text\x00") is False
    assert _heuristics._looks_like_text(b"\xff") is False


def test_chi_squared_pvalue_returns_zero_for_short_data_and_math_failures(mocker) -> None:
    mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._heuristics._regularized_lower_incomplete_gamma",
        side_effect=ChiSquaredError("failed"),
    )

    assert _heuristics.chi_squared_pvalue(b"short") == 0.0
    assert _heuristics.chi_squared_pvalue(b"long enough input") == 0.0


def test_chi_squared_pvalue_selects_text_or_binary_statistic(mocker) -> None:
    profile = [1 / 256] * 256
    text_statistic = mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._heuristics._text_chi_squared", return_value=1.0
    )
    binary_statistic = mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._heuristics._count_chi_squared", return_value=1.0
    )
    mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._heuristics._regularized_lower_incomplete_gamma",
        return_value=0.25,
    )

    assert _heuristics.chi_squared_pvalue(b"readable text data", {"test": profile}) == pytest.approx(0.75)
    assert _heuristics.chi_squared_pvalue(b"\xff" * 16, {"test": profile}) == pytest.approx(0.75)
    assert text_statistic.called
    assert binary_statistic.called


@pytest.mark.parametrize(
    ("s", "x"), [(0.0, 1.0), (1.0, -1.0), (math.inf, 1.0)], ids=["zero_shape", "negative_bound", "infinite_shape"]
)
def test_regularized_gamma_rejects_invalid_parameters(s: float, x: float) -> None:
    with pytest.raises(ChiSquaredError):
        _heuristics._regularized_lower_incomplete_gamma(s, x)


def test_regularized_gamma_matches_known_exponential_case() -> None:
    assert _heuristics._regularized_lower_incomplete_gamma(1.0, 2.0) == pytest.approx(1 - math.exp(-2.0))


def test_byte_entropy_two_values_is_one_bit() -> None:
    assert _heuristics.byte_entropy(b"\x00\x01" * 50) == pytest.approx(1.0)


def test_byte_entropy_english_text_is_mid_range() -> None:
    entropy = _heuristics.byte_entropy(b"the quick brown fox jumps over the lazy dog")

    assert 3.0 < entropy < 5.0


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("hello world", 1.0),
        ("\t\n\r", 1.0),
        ("ab\x00\x01", 0.5),
        ("\x7f", 0.0),
    ],
    ids=["ascii", "whitespace", "controls", "del"],
)
def test_printable_ratio_handles_legacy_character_edges(text: str, expected: float) -> None:
    assert _heuristics.printable_ratio(text) == pytest.approx(expected)


def test_chi_squared_pvalue_accepts_english_text() -> None:
    text = ("the quick brown fox jumps over the lazy dog. " * 50).encode()

    assert _heuristics.chi_squared_pvalue(text) > 0.5


def test_chi_squared_pvalue_rejects_fixed_binary_distribution() -> None:
    assert _heuristics.chi_squared_pvalue(bytes(range(256)) * 8) < 0.01


@pytest.mark.parametrize("data", [b"", b"hi"], ids=["empty", "short"])
def test_chi_squared_pvalue_returns_zero_below_minimum_length(data: bytes) -> None:
    assert _heuristics.chi_squared_pvalue(data) == 0.0


@pytest.mark.parametrize(
    "data",
    [b"a" * 100, bytes(range(16)), b"https://github.com/owner/repo/pull/789"],
    ids=["repeated_text", "binary", "url"],
)
def test_chi_squared_pvalue_stays_in_unit_interval(data: bytes) -> None:
    pvalue = _heuristics.chi_squared_pvalue(data)

    assert 0.0 <= pvalue <= 1.0


def test_chi_squared_pvalue_handles_extreme_chi_squared_input() -> None:
    assert _heuristics.chi_squared_pvalue(b"\x00" * 1024) == 0.0


def test_chi_squared_pvalue_keeps_url_like_text_below_language_threshold() -> None:
    assert _heuristics.chi_squared_pvalue(b"https://github.com/owner/repo/pull/789") < 0.05
