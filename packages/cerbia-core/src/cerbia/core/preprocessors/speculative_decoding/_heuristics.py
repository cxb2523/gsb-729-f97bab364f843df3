import math
from collections.abc import Mapping, Sequence

from ..._utils.math import shannon_entropy
from ...i18n.language_profiles import LANGUAGE_PROFILES
from .exceptions import ChiSquaredError

_GAMMA_MAX_ITERATIONS = 200
_GAMMA_TOLERANCE = 1e-12
_GAMMA_TINY = 1e-300


def byte_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte.

    Args:
        data (bytes): Raw bytes to analyze.

    Returns:
        float: Entropy estimate used to distinguish readable text from compressed or highly random payloads.
    """
    if not data:
        return 0.0

    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    return shannon_entropy(freq.values(), len(data))


def printable_ratio(text: str) -> float:
    """Compute the ratio of printable characters in text.

    Args:
        text (str): Text to evaluate.

    Returns:
        float: Fraction of characters that look printable enough for human-readable text.
    """
    if not text:
        return 0.0
    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t")
    return printable / len(text)


def chi_squared_pvalue(data: bytes, profiles: Mapping[str, Sequence[float]] = LANGUAGE_PROFILES) -> float:
    """Best language-fit score in ``[0, 1]`` against the known byte-language profiles.

    For binary or non-text payloads, this function uses a count-based Pearson chi-squared statistic and converts it to
    an upper-tail score via the chi-square CDF. For printable UTF-8 text, it uses the CyberChef-compatible
    normalized-frequency statistic already tuned to the speculative-decoding thresholds in this repository.

    This is the primary language-fit gate for speculative decoding acceptance. A score near zero suggests the data does
    not resemble any supported language profile closely enough to keep exploring.

    Args:
        data (bytes): Raw bytes to compare against the known language profiles.
        profiles (Mapping[str, Sequence[float]]): Language profiles used to compute the best language-fit score.

    Returns:
        float: Best language-fit score in the inclusive ``[0.0, 1.0]`` range.
    """
    if len(data) < 16:
        return 0.0

    try:
        length = len(data)
        observed = [0] * 256
        for byte in data:
            observed[byte] += 1

        text_like = _looks_like_text(data)
        best_pvalue = 0.0

        for profile in profiles.values():
            chi2 = (
                _text_chi_squared(observed, length, profile)
                if text_like
                else _count_chi_squared(observed, length, profile)
            )

            pvalue = 1.0 - _regularized_lower_incomplete_gamma(255.0 / 2.0, chi2 / 2.0)
            if not math.isfinite(pvalue):
                raise ChiSquaredError(f"non-finite p-value for s={255.0 / 2.0}, x={chi2 / 2.0}, iterations=0")

            best_pvalue = max(best_pvalue, pvalue)

    except ChiSquaredError:
        return 0.0

    return min(1.0, max(0.0, best_pvalue))


def _looks_like_text(data: bytes) -> bool:
    """Check whether bytes decode to mostly printable UTF-8 text.

    Args:
        data (bytes): Raw bytes to inspect.

    Returns:
        bool: ``True`` when the bytes decode as UTF-8 text with high printability.
    """
    try:
        text = data.decode("utf-8", errors="strict")

    except UnicodeDecodeError:
        return False

    return printable_ratio(text) >= 0.95


def _count_chi_squared(observed: Sequence[int], length: int, profile: Sequence[float]) -> float:
    """Compute chi-squared distance using raw observed counts.

    Args:
        observed (Sequence[int]): Observed byte counts.
        length (int): Total sample length.
        profile (Sequence[float]): Expected byte-frequency profile.

    Returns:
        float: Chi-squared statistic against the provided profile.
    """
    chi2 = 0.0
    for i in range(256):
        expected = max(profile[i] * length, 0.5)
        diff = observed[i] - expected
        chi2 += diff * diff / expected

    return chi2


def _text_chi_squared(observed: Sequence[int], length: int, profile: Sequence[float]) -> float:
    """Compute CyberChef-compatible chi-squared distance using normalized text percentages.

    Args:
        observed (Sequence[int]): Observed byte counts.
        length (int): Total sample length.
        profile (Sequence[float]): Expected byte-frequency profile.

    Returns:
        float: Normalized-frequency compatibility statistic used for printable UTF-8 text.
    """
    chi2 = 0.0
    for i in range(256):
        observed_percent = observed[i] * 100.0 / length
        expected_percent = max(profile[i] * 100.0, 0.5)
        diff = observed_percent - expected_percent
        chi2 += diff * diff / expected_percent

    return chi2


def _regularized_lower_incomplete_gamma(s: float, x: float) -> float:
    """Compute P(s, x) to solve for the chi-squared cumulative distribution function.

    The branch split follows the standard Numerical Recipes approach to maintain precision across the entire range:
    evaluate the lower gamma series when x < s + 1, otherwise evaluate the upper gamma continued fraction and return
    1 - Q(s, x).

    Args:
        s (float): Shape parameter of the regularized gamma function.
        x (float): Upper integration bound expressed in chi-squared space.

    Returns:
        float: Regularized lower incomplete gamma value ``P(s, x)``.

    Raises:
        ChiSquaredError: If the inputs are invalid or the computation cannot be performed safely.
    """
    if s <= 0.0 or x < 0.0 or not math.isfinite(s) or not math.isfinite(x):
        raise ChiSquaredError(f"invalid gamma parameters for s={s}, x={x}, iterations=0")

    if math.isclose(x, 0.0, rel_tol=0.0, abs_tol=_GAMMA_TINY):
        return 0.0

    if x < s + 1.0:
        return _regularized_lower_incomplete_gamma_series(s, x)

    return 1.0 - _regularized_upper_incomplete_gamma_continued_fraction(s, x)


def _regularized_lower_incomplete_gamma_series(s: float, x: float) -> float:
    """Compute the lower incomplete gamma P(s, x) using its power series representation.

    Used when x < s + 1 to ensure rapid convergence and numerical stability. This formula is the standard choice for
    small values of x relative to the degrees of freedom.

    Args:
        s (float): Shape parameter of the regularized gamma function.
        x (float): Upper integration bound expressed in chi-squared space.

    Returns:
        float: Regularized lower incomplete gamma value ``P(s, x)`` computed by series expansion.

    Raises:
        ChiSquaredError: If the series fails to converge or produces a non-finite result.
    """
    iteration = 0
    try:
        log_term = (s * math.log(x)) - x - math.lgamma(s)
        gamma_sum = 1.0 / s
        term = gamma_sum
        value = s

        for _ in range(1, _GAMMA_MAX_ITERATIONS + 1):
            iteration += 1
            value += 1.0
            term *= x / value
            gamma_sum += term

            if abs(term) < abs(gamma_sum) * _GAMMA_TOLERANCE:
                result = gamma_sum * math.exp(log_term)

                if not math.isfinite(result):
                    raise ValueError("non-finite gamma series result")

                return min(1.0, max(0.0, result))

    except (OverflowError, ValueError) as exc:
        raise ChiSquaredError(f"gamma series failed for s={s}, x={x}, iterations={iteration}") from exc

    raise ChiSquaredError(f"gamma series did not converge for s={s}, x={x}, iterations={_GAMMA_MAX_ITERATIONS}")


def _regularized_upper_incomplete_gamma_continued_fraction(s: float, x: float) -> float:
    """Compute the upper incomplete gamma Q(s, x) using Lentz's method for continued fractions.

    Used when x >= s + 1 to avoid the slow convergence or precision loss that the power series would suffer at larger
    values of x.

    Args:
        s (float): Shape parameter of the regularized gamma function.
        x (float): Upper integration bound expressed in chi-squared space.

    Returns:
        float: Regularized upper incomplete gamma value ``Q(s, x)`` computed by continued fraction.

    Raises:
        ChiSquaredError: If the continued fraction fails to converge or produces a non-finite result.
    """
    iteration = 0
    try:
        log_term = (s * math.log(x)) - x - math.lgamma(s)
        denominator = x + 1.0 - s

        if abs(denominator) < _GAMMA_TINY:
            denominator = _GAMMA_TINY

        fraction_c = 1.0 / _GAMMA_TINY
        fraction_d = 1.0 / denominator
        fraction_h = fraction_d

        for iteration in range(1, _GAMMA_MAX_ITERATIONS + 1):
            numerator = -iteration * (iteration - s)
            denominator += 2.0
            fraction_d = (numerator * fraction_d) + denominator

            if abs(fraction_d) < _GAMMA_TINY:
                fraction_d = _GAMMA_TINY

            fraction_c = denominator + (numerator / fraction_c)
            if abs(fraction_c) < _GAMMA_TINY:
                fraction_c = _GAMMA_TINY

            fraction_d = 1.0 / fraction_d
            delta = fraction_c * fraction_d
            fraction_h *= delta

            if abs(delta - 1.0) < _GAMMA_TOLERANCE:
                result = math.exp(log_term) * fraction_h

                if not math.isfinite(result):
                    raise ValueError("non-finite gamma continued-fraction result")

                return min(1.0, max(0.0, result))

    except (OverflowError, ValueError) as exc:
        raise ChiSquaredError(f"gamma continued fraction failed for s={s}, x={x}, iterations={iteration}") from exc

    raise ChiSquaredError(
        f"gamma continued fraction did not converge for s={s}, x={x}, iterations={_GAMMA_MAX_ITERATIONS}"
    )
