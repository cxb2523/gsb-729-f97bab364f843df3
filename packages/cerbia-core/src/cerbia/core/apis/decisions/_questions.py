from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictStr, model_validator

from .._base import APIModel, Identifier, unique

ChoiceValue = StrictStr | StrictBool


class ChoiceOption(APIModel):
    """Typed choice value, keeping booleans and strings distinct.

    Attributes:
        value (ChoiceValue): Strict string or boolean identifying the option.
        description (StrictStr | None): Optional explanation of the option.
    """

    value: ChoiceValue
    description: StrictStr | None = None


class ScoreLevel(APIModel):
    """Ordered Decisions score rubric entry.

    Attributes:
        label (StrictStr): Label for the score level, whose value is its zero-based position in the rubric.
        description (StrictStr | None): Optional explanation of the level.
    """

    label: StrictStr
    description: StrictStr | None = None


class PredicateQuestion(APIModel):
    """Named Decisions predicate.

    Attributes:
        type (Literal["predicate"]): Question discriminator. Defaults to ``"predicate"``.
        name (Identifier): Nonempty question identifier used to correlate the answer.
        instructions (StrictStr): Instructions defining the predicate to assess.
    """

    type: Literal["predicate"] = "predicate"
    name: Identifier
    instructions: StrictStr


class ChoiceQuestion(APIModel):
    """Named Decisions choice question.

    Attributes:
        type (Literal["choice"]): Question discriminator. Defaults to ``"choice"``.
        name (Identifier): Nonempty question identifier used to correlate the answer.
        instructions (StrictStr): Instructions for selecting an option.
        choices (tuple[ChoiceOption, ...]): Two to 255 options with unique values.
    """

    type: Literal["choice"] = "choice"
    name: Identifier
    instructions: StrictStr
    choices: Annotated[tuple[ChoiceOption, ...], Field(min_length=2, max_length=255)]

    @model_validator(mode="after")
    def distinct_choices(self) -> Self:
        """Require unique option values.

        Returns:
            Self: Question with distinct option values.

        Raises:
            ValueError: If option values are duplicated.
        """
        unique(option.value for option in self.choices)

        return self


class ScoreQuestion(APIModel):
    """Named Decisions score question.

    Attributes:
        type (Literal["score"]): Question discriminator. Defaults to ``"score"``.
        name (Identifier): Nonempty question identifier used to correlate the answer.
        instructions (StrictStr): Instructions for assessing the score.
        levels (tuple[ScoreLevel, ...]): Two to ten ordered levels with zero-based score values.
    """

    type: Literal["score"] = "score"
    name: Identifier
    instructions: StrictStr
    levels: Annotated[tuple[ScoreLevel, ...], Field(min_length=2, max_length=10)]


DecisionQuestion = Annotated[PredicateQuestion | ChoiceQuestion | ScoreQuestion, Field(discriminator="type")]
