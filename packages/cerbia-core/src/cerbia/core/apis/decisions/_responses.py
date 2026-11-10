from typing import Annotated, Literal

from pydantic import Field, StrictInt, StrictStr

from .._base import APIModel, Number
from ._questions import ChoiceValue

Probability = Annotated[float, Field(ge=0, le=1, strict=True, allow_inf_nan=False)]
TokenCount = Annotated[int, Field(strict=True, ge=0)]


class PredicateAnswer(APIModel):
    """Decisions predicate probability.

    Attributes:
        type (Literal["predicate"]): Answer discriminator.
        name (StrictStr | None): Question identifier, or null in an uncorrelated wire response.
        probability (Probability): Probability that the requested predicate holds, from zero to one.
    """

    type: Literal["predicate"]
    name: StrictStr | None
    probability: Probability


class ChoiceProbability(APIModel):
    """Probability mass associated with a typed choice value.

    Attributes:
        value (ChoiceValue): Strict string or boolean identifying the option.
        probability (Probability): Probability mass assigned to the option, from zero to one.
    """

    value: ChoiceValue
    probability: Probability


class ChoiceAnswer(APIModel):
    """Decisions choice evidence.

    Attributes:
        type (Literal["choice"]): Answer discriminator.
        name (StrictStr | None): Question identifier, or null in an uncorrelated wire response.
        choice (ChoiceValue): Selected option value.
        probabilities (tuple[ChoiceProbability, ...]): Probability distribution over the requested options.
        confidence (Probability): Reported confidence in the choice, from zero to one; not a violation probability.
    """

    type: Literal["choice"]
    name: StrictStr | None
    choice: ChoiceValue
    probabilities: tuple[ChoiceProbability, ...]
    confidence: Probability


class ScoreProbability(APIModel):
    """Probability and label for a discrete score level.

    Attributes:
        value (StrictInt): Zero-based score level index.
        label (StrictStr): Label of the corresponding requested rubric level.
        probability (Probability): Probability mass assigned to the level, from zero to one.
    """

    value: StrictInt
    label: StrictStr
    probability: Probability


class ScoreAnswer(APIModel):
    """Decisions expected score with its full rubric distribution.

    Attributes:
        type (Literal["score"]): Answer discriminator.
        name (StrictStr | None): Question identifier, or null in an uncorrelated wire response.
        score (Number): Expected value of the zero-based rubric level distribution.
        probabilities (tuple[ScoreProbability, ...]): Probability distribution over the requested rubric levels.
        confidence (Probability): Reported confidence in the score, from zero to one; not a violation probability.
    """

    type: Literal["score"]
    name: StrictStr | None
    score: Number
    probabilities: tuple[ScoreProbability, ...]
    confidence: Probability


class RefusalAnswer(APIModel):
    """Per-question Decisions refusal evidence.

    Attributes:
        type (Literal["refusal"]): Answer discriminator indicating that assessment was refused.
        name (StrictStr | None): Question identifier, or null in an uncorrelated wire response.
    """

    type: Literal["refusal"]
    name: StrictStr | None


DecisionAnswer = Annotated[PredicateAnswer | ChoiceAnswer | ScoreAnswer | RefusalAnswer, Field(discriminator="type")]


class InputTokenDetails(APIModel):
    """Decisions cache token accounting.

    Attributes:
        cached_tokens (TokenCount): Nonnegative number of input tokens served from cache.
        cache_write_tokens (TokenCount): Nonnegative number of input tokens written to cache.
    """

    cached_tokens: TokenCount
    cache_write_tokens: TokenCount


class OutputTokenDetails(APIModel):
    """Decisions reasoning token accounting.

    Attributes:
        reasoning_tokens (TokenCount): Nonnegative number of output tokens used for reasoning.
    """

    reasoning_tokens: TokenCount


class DecisionsUsage(APIModel):
    """Full Decisions token accounting.

    Attributes:
        input_tokens (TokenCount): Nonnegative input token count.
        output_tokens (TokenCount): Nonnegative output token count.
        input_tokens_details (InputTokenDetails): Input cache token counts.
        output_tokens_details (OutputTokenDetails): Output reasoning token count.
        total_tokens (TokenCount): Reported nonnegative total token count.
    """

    input_tokens: TokenCount
    output_tokens: TokenCount
    input_tokens_details: InputTokenDetails
    output_tokens_details: OutputTokenDetails
    total_tokens: TokenCount


class DecisionsResponse(APIModel):
    """Typed Decisions wire response, which may contain refusals before request validation.

    Attributes:
        model (StrictStr): Model identifier reported by the service.
        answers (tuple[DecisionAnswer, ...]): Predicate, choice, score, or refusal answers.
        usage (DecisionsUsage): Token accounting reported by the service.
    """

    model: StrictStr
    answers: tuple[DecisionAnswer, ...]
    usage: DecisionsUsage
