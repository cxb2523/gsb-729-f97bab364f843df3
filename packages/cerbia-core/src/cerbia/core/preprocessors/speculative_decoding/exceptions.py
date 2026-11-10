from ..exceptions import PreprocessorError


class ChiSquaredError(PreprocessorError):
    """Raised when chi-squared p-value math cannot be computed safely."""


class ExcessiveEncodingError(PreprocessorError):
    """Content exceeds the maximum decoding rounds.

    Indicates a deliberate attempt to evade detection through deeply nested encoding layers.
    """
