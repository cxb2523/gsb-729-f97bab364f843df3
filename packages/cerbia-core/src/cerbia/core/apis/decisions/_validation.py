from collections.abc import Iterable, Mapping, Sequence
from math import isclose

from .._base import unique
from ._questions import (
    ChoiceQuestion,
    ChoiceValue,
    DecisionQuestion,
    PredicateQuestion,
    ScoreQuestion,
)
from ._responses import (
    ChoiceAnswer,
    DecisionsResponse,
    PredicateAnswer,
    RefusalAnswer,
    ScoreAnswer,
)


def distribution(values: Iterable[float]) -> None:
    """Require a complete normalized distribution, allowing rounding to 1e-4.

    Args:
        values (Iterable[float]): Probability masses to sum.

    Raises:
        ValueError: If the sum differs from one by more than 1e-4.
    """
    if not isclose(sum(values), 1.0, rel_tol=0, abs_tol=1e-4):
        raise ValueError("Invalid probability distribution")


def validate_choice[T: ChoiceValue](probabilities: Mapping[T, float], choice: T) -> None:
    """Require normalized probabilities and a maximal selected choice.

    Args:
        probabilities (Mapping[T, float]): Probability mass for each choice value.
        choice (T): Selected string or boolean choice value.

    Raises:
        ValueError: If probabilities are not normalized, the choice is absent, or its probability is not maximal.
    """
    distribution(probabilities.values())

    if choice not in probabilities or probabilities[choice] < max(probabilities.values()):
        raise ValueError("Inconsistent choice")


def validate_score(probabilities: Mapping[int, float], score: float) -> None:
    """Require a score consistent with the distribution's expected value.

    Args:
        probabilities (Mapping[int, float]): Probability mass for each zero-based rubric level.
        score (float): Reported expected score.

    Raises:
        ValueError: If probabilities are not normalized, the score is out of bounds, or it differs from the
            expected value by more than 1e-4.
    """
    distribution(probabilities.values())

    expected = sum(level * probability for level, probability in probabilities.items())

    if not 0 <= score <= len(probabilities) - 1 or not isclose(score, expected, rel_tol=0, abs_tol=1e-4):
        raise ValueError("Inconsistent score")


def validate_decisions(questions: Sequence[DecisionQuestion], response: DecisionsResponse) -> None:
    """Require every requested ID, answer type and domain exactly once.

    Args:
        questions (Sequence[DecisionQuestion]): Requested questions defining the expected names, types, and domains.
        response (DecisionsResponse): Parsed wire response to correlate with the questions.

    Raises:
        ValueError: If answer names are duplicated or do not match, answer types or domains differ, distributions
            or selected values are inconsistent, rubric labels differ, or an assessment is refused.
    """
    unique(answer.name for answer in response.answers if answer.name is not None)
    answers = {answer.name: answer for answer in response.answers}

    if set(answers) != {question.name for question in questions}:
        raise ValueError("Answer IDs do not match")

    for question in questions:
        answer = answers[question.name]
        match question, answer:
            case PredicateQuestion(), PredicateAnswer():
                continue

            case ChoiceQuestion(), ChoiceAnswer():
                unique(entry.value for entry in answer.probabilities)
                probabilities = {entry.value: entry.probability for entry in answer.probabilities}

                if probabilities.keys() != {option.value for option in question.choices}:
                    raise ValueError("Choice domain mismatch")

                validate_choice(probabilities, answer.choice)

            case ScoreQuestion(), ScoreAnswer():
                unique(entry.value for entry in answer.probabilities)
                scores = {entry.value: entry.probability for entry in answer.probabilities}

                if scores.keys() != set(range(len(question.levels))):
                    raise ValueError("Score domain mismatch")

                for entry in answer.probabilities:
                    if entry.label != question.levels[entry.value].label:
                        raise ValueError("Score rubric mismatch")

                validate_score(scores, answer.score)

            case _, RefusalAnswer():
                raise ValueError("Assessment refused")

            case _:
                raise ValueError("Answer type mismatch")
