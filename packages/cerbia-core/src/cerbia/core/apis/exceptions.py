from ..exceptions import CerbIAConfigError, CerbIAError


class APIError(CerbIAError):
    """Report an API request or response failure with a fixed message that redacts external details."""

    def __init__(self) -> None:
        super().__init__("API request failed")


class APIConfigError(CerbIAConfigError):
    """Report invalid API client configuration with a fixed message that redacts external details."""

    def __init__(self) -> None:
        super().__init__("Invalid API configuration")
