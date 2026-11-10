from typing import Annotated, Literal

from pydantic import Field, StrictStr

from .._base import APIModel, Identifier


class NoulCriteria(APIModel):
    """Describe the true and false outcomes of a System One question.

    Attributes:
        true (str | None): Optional description of the true outcome. Defaults to ``None``.
        false (str | None): Optional description of the false outcome. Defaults to ``None``.
    """

    true: StrictStr | None = None
    false: StrictStr | None = None


class NoulQuestion(APIModel):
    """Request System One probability-of-true evidence.

    Attributes:
        type (Literal["noul"]): Wire discriminator. Defaults to ``"noul"``.
        instructions (str | None): Optional question instructions. Defaults to ``None``.
        criteria (NoulCriteria | None): Optional true and false outcome descriptions. Defaults to ``None``.
    """

    type: Literal["noul"] = "noul"
    instructions: StrictStr | None = None
    criteria: NoulCriteria | None = None


class SystemOneChoiceQuestion(APIModel):
    """Request a choice from named System One criteria.

    Attributes:
        type (Literal["choice"]): Wire discriminator. Defaults to ``"choice"``.
        instructions (str | None): Optional question instructions. Defaults to ``None``.
        criteria (dict[str, str | None]): Between 1 and 255 choices with non-empty string IDs and optional descriptions.
    """

    type: Literal["choice"] = "choice"
    instructions: StrictStr | None = None
    criteria: Annotated[dict[Identifier, StrictStr | None], Field(min_length=1, max_length=255)]


class SystemOneScoreQuestion(APIModel):
    """Request a score over an ordered System One rubric.

    Attributes:
        type (Literal["score"]): Wire discriminator. Defaults to ``"score"``.
        instructions (str | None): Optional question instructions. Defaults to ``None``.
        criteria (tuple[str, ...]): Between 2 and 10 ordered rubric descriptions, indexed from zero.
    """

    type: Literal["score"] = "score"
    instructions: StrictStr | None = None
    criteria: Annotated[tuple[StrictStr, ...], Field(min_length=2, max_length=10)]


SystemOneQuestion = Annotated[
    NoulQuestion | SystemOneChoiceQuestion | SystemOneScoreQuestion, Field(discriminator="type")
]
