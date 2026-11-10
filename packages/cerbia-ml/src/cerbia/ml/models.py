from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = ["ArtifactCoords"]


class ArtifactCoords(BaseModel):
    """Coordinates for an ML artifact stored in a repository.

    Attributes:
        ref (str): Repository reference or path identifying the artifact source.
        revision (str): Exact Git revision pinned to a 40-character lowercase hex SHA.
        subfolder (str | None): Optional subfolder within the artifact repository.
        filename (str | None): Optional filename within the artifact repository.
    """

    model_config = ConfigDict(frozen=True)

    ref: str = Field(min_length=1)
    revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    subfolder: str | None = None
    filename: str | None = None

    @field_validator("ref")
    @classmethod
    def _strip_non_blank_ref(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("ref must not be blank")
        return stripped
