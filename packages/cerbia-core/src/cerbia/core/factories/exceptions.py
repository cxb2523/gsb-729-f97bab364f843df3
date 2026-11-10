from ..exceptions import CerbIAError

__all__ = ["FactoryError"]


class FactoryError(CerbIAError):
    """Failed to create a component from the factory."""
