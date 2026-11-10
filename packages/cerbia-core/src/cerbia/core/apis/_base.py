from collections.abc import Iterable
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StrictStr


class APIModel(BaseModel):
    """Base model for closed, frozen API question and response schemas.

    Attributes:
        model_config (ConfigDict): Shared configuration that prevents field reassignment, forbids extra fields and
            non-finite numbers, and hides input values in validation error messages.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False, hide_input_in_errors=True)


Number = Annotated[float, Field(strict=True, allow_inf_nan=False)]
Identifier = Annotated[StrictStr, Field(min_length=1)]


def unique(values: Iterable[str | bool | int]) -> None:
    """Reject duplicate scalar values.

    Args:
        values (Iterable[str | bool | int]): Scalar values to compare using Python equality and hashing.

    Returns:
        None: The values contain no duplicates.

    Raises:
        ValueError: If duplicate values are present.
    """
    entries = list(values)

    if len(set(entries)) != len(entries):
        raise ValueError("Duplicate entries")


def unique_json_pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    """Build a JSON object without silently overwriting duplicate keys.

    Args:
        pairs (list[tuple[str, JsonValue]]): JSON object key-value pairs in their original order.

    Returns:
        dict[str, JsonValue]: JSON object containing each supplied key-value pair.

    Raises:
        ValueError: If a JSON object key occurs more than once.
    """
    result: dict[str, JsonValue] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")

        result[key] = value

    return result
