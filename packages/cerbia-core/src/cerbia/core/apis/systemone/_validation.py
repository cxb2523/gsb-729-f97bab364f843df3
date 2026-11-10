from collections.abc import Iterable, Mapping
from math import isclose

from ._questions import NoulQuestion, SystemOneChoiceQuestion, SystemOneQuestion, SystemOneScoreQuestion
from ._responses import NoulAnswer, SystemOneChoiceAnswer, SystemOneResponse, SystemOneScoreAnswer


def distribution(values: Iterable[float]) -> None:
    """Require probabilities to sum to one within an absolute tolerance of ``1e-4``.

    Args:
        values (Iterable[float]): Probabilities whose individual bounds are checked by the response models.

    Returns:
        None: The sum is within tolerance.

    Raises:
        ValueError: If the sum differs from one by more than ``1e-4``.
    """
    if not isclose(sum(values), 1.0, rel_tol=0, abs_tol=1e-4):
        raise ValueError("Invalid probability distribution")


def validate_choice(probabilities: Mapping[str, float], choice: str) -> None:
    """Require normalized probabilities and a maximal selected string choice.

    Args:
        probabilities (Mapping[str, float]): Choice IDs mapped to probabilities.
        choice (str): Selected choice ID; ties for the highest probability are accepted.

    Returns:
        None: The distribution and selected choice are consistent.

    Raises:
        ValueError: If probabilities do not sum to one within ``1e-4``, or the choice is absent or not maximal.
    """
    distribution(probabilities.values())

    if choice not in probabilities or probabilities[choice] < max(probabilities.values()):
        raise ValueError("Inconsistent choice")


def validate_score(probabilities: Mapping[int, float], score: float) -> None:
    """Require a score consistent with the distribution's expected value.

    Args:
        probabilities (Mapping[int, float]): Zero-based rubric indices mapped to probabilities.
        score (float): Score to check against the rubric range and expected value.

    Returns:
        None: The distribution and score are consistent.

    Raises:
        ValueError: If probabilities do not sum to one within ``1e-4``, the score is outside zero through
            ``len(probabilities) - 1``, or it differs from the expected value by more than ``1e-4``.
    """
    distribution(probabilities.values())

    expected = sum(level * probability for level, probability in probabilities.items())
    if not 0 <= score <= len(probabilities) - 1 or not isclose(score, expected, rel_tol=0, abs_tol=1e-4):
        raise ValueError("Inconsistent score")


def validate_systemone(questions: Mapping[str, SystemOneQuestion], response: SystemOneResponse) -> None:
    """Require exact System One IDs, answer types, domains, and rubric legend.

    Args:
        questions (Mapping[str, SystemOneQuestion]): Requested questions keyed by ID.
        response (SystemOneResponse): Parsed response to check against the request.

    Returns:
        None: Every answer matches its question and satisfies the applicable consistency checks.

    Raises:
        ValueError: If answer IDs or types mismatch, choice or score domains differ, the score legend differs from
            the requested rubric, or a choice distribution or score is inconsistent.
    """
    if response.answers.keys() != questions.keys():
        raise ValueError("Answer IDs do not match")

    for key, question in questions.items():
        answer = response.answers[key]
        match question, answer:
            case NoulQuestion(), NoulAnswer():
                continue

            case SystemOneChoiceQuestion(), SystemOneChoiceAnswer():
                if answer.probabilities.keys() != question.criteria.keys():
                    raise ValueError("Choice domain mismatch")

                validate_choice(answer.probabilities, answer.choice)

            case SystemOneScoreQuestion(), SystemOneScoreAnswer():
                legend = {str(index): criterion for index, criterion in enumerate(question.criteria)}
                if answer.legend != legend or answer.probabilities.keys() != legend.keys():
                    raise ValueError("Score domain or legend mismatch")

                scores = {int(index): probability for index, probability in answer.probabilities.items()}
                validate_score(scores, answer.score)

            case _:
                raise ValueError("Answer type mismatch")
