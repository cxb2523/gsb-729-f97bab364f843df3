from typing import Annotated, Literal

from pydantic import Field, StrictStr

from .._base import APIModel, Number

Probability = Annotated[float, Field(ge=0, le=1, strict=True, allow_inf_nan=False)]
TokenCount = Annotated[int, Field(strict=True, ge=0)]


class NoulAnswer(APIModel):
    """System One probability-of-true evidence.

    Attributes:
        type (Literal["noul"]): Wire discriminator.
        noul (float): Finite probability that the criterion is true, from zero to one inclusive.
    """

    type: Literal["noul"]
    noul: Probability


class SystemOneChoiceAnswer(APIModel):
    """System One choice evidence.

    Attributes:
        type (Literal["choice"]): Wire discriminator.
        choice (str): Selected criterion ID, checked against the requested choices by the client.
        confidence (float): API-reported confidence from zero to one inclusive; not cross-checked against probabilities.
        probabilities (dict[str, float]): Criterion IDs mapped to finite probabilities from zero to one inclusive.
            The client requires the requested domain, a sum within ``1e-4`` of one, and a maximal selected choice.
    """

    type: Literal["choice"]
    choice: StrictStr
    confidence: Probability
    probabilities: dict[StrictStr, Probability]


class SystemOneScoreAnswer(APIModel):
    """System One score evidence with its text rubric legend.

    Attributes:
        type (Literal["score"]): Wire discriminator.
        score (float): Finite score, checked by the client against the rubric range and distribution's expected value.
        confidence (float): API-reported confidence from zero to one inclusive; not cross-checked against probabilities.
        legend (dict[str, str]): Stringified zero-based rubric indices mapped to the requested criterion descriptions.
        probabilities (dict[str, float]): Rubric index strings mapped to finite probabilities in ``[0, 1]``.
            The client requires the legend's domain and a sum within ``1e-4`` of one.
    """

    type: Literal["score"]
    score: Number
    confidence: Probability
    legend: dict[StrictStr, StrictStr]
    probabilities: dict[StrictStr, Probability]


SystemOneAnswer = Annotated[NoulAnswer | SystemOneChoiceAnswer | SystemOneScoreAnswer, Field(discriminator="type")]


class Usage(APIModel):
    """System One token usage.

    Attributes:
        input_tokens (int): Non-negative input token count.
        output_tokens (int): Non-negative output token count.
    """

    input_tokens: TokenCount
    output_tokens: TokenCount


class SystemOneResponse(APIModel):
    """Typed System One response containing answers and token usage.

    Attributes:
        model (str): Model identifier reported by the API.
        answers (dict[str, SystemOneAnswer]): Question IDs mapped to noul, choice, or score evidence.
        usage (Usage): Input and output token counts reported by the API.
    """

    model: StrictStr
    answers: dict[StrictStr, SystemOneAnswer]
    usage: Usage
