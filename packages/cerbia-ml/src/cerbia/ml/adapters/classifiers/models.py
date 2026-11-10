from pydantic import BaseModel, ConfigDict

__all__ = ["ClassificationResult"]


class ClassificationResult(BaseModel):
    """Boundary model for a single classifier label score."""

    model_config = ConfigDict(frozen=True)

    label: str
    score: float
