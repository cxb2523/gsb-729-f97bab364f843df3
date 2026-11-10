import importlib
from collections.abc import Sequence
from typing import Annotated

from pydantic import ConfigDict, Field, JsonValue, TypeAdapter

from ...apis._base import unique
from ...apis.decisions import DecisionQuestion, DecisionsClient
from ...exceptions import CerbIAConfigError, CerbIAError
from ...models.scans import ScanOutcome
from ...types import Action, ContentType, Severity
from ._evaluator import DecisionsEvaluator


class DecisionsScanner:
    """Ask fixed questions and pass the typed response to an application evaluator.

    The scanner sends Decisions questions to its API client and delegates risk interpretation to the evaluator.

    Args:
        questions (Sequence[DecisionQuestion | JsonValue]): Typed questions or YAML mappings to parse into a tuple.
        evaluator (str): The dotted path to the evaluator function.
        model (str): The model to use for the API client.
        base_url (str | None): The base URL for the API client.
        timeout (float): The timeout for API requests.
        api_key_provider (str | None): The API key provider for the client.
        severity (Severity): The severity level of the scan outcome.
        action (Action): The action to take based on the scan outcome.
        content_types (tuple[ContentType, ...] | list[str] | None): The content types to scan.

    Attributes:
        scanner_id (str): The ID of the scanner.
        scanner_name (str): The name of the scanner.
        severity (Severity): The severity level of the scan outcome.
        action (Action): The action to take based on the scan outcome.
        content_types (tuple[ContentType, ...] | None): The content types to scan.

    Raises:
        CerbIAConfigError: If questions, evaluator path, import, or callability are invalid.
        APIConfigError: If API client or credential-provider configuration is invalid; propagates unchanged.
    """

    _evaluator: DecisionsEvaluator
    _questions: tuple[DecisionQuestion, ...]

    def __init__(
        self,
        questions: Sequence[DecisionQuestion | JsonValue],
        evaluator: str,
        model: str,
        base_url: str | None = None,
        timeout: float = 30.0,
        api_key_provider: str | None = None,
        severity: Severity = Severity.HIGH,
        action: Action = Action.BLOCK,
        content_types: tuple[ContentType, ...] | list[str] | None = (ContentType.TEXT,),
    ) -> None:
        self.scanner_id = "decisions"
        self.scanner_name = "Decisions"
        self.severity = severity
        self.action = action
        self.content_types = tuple(content_types) if content_types is not None else None

        try:
            self._questions = TypeAdapter(
                Annotated[tuple[DecisionQuestion, ...], Field(min_length=1, max_length=400)],
                config=ConfigDict(hide_input_in_errors=True),
            ).validate_python(questions)
            unique(question.name for question in self._questions)

        except (ValueError, TypeError) as exc:
            raise CerbIAConfigError("Invalid Decisions scanner questions") from exc

        try:
            module_path, _, name = evaluator.rpartition(".")
        except (AttributeError, TypeError) as exc:
            raise CerbIAConfigError("Evaluator must be a dotted import path (module.function)") from exc

        if not module_path or not name:
            raise CerbIAConfigError("Evaluator must be a dotted import path (module.function)")

        try:
            evaluator_function: DecisionsEvaluator = getattr(importlib.import_module(module_path), name)
        except Exception as exc:
            raise CerbIAConfigError("Could not import evaluator") from exc

        if not callable(evaluator_function):
            raise CerbIAConfigError("Evaluator must be callable")

        self._evaluator = evaluator_function

        self._api = DecisionsClient(
            model=model,
            base_url=base_url,
            timeout=timeout,
            api_key_provider=api_key_provider,
        )

    def scan(self, text: str) -> ScanOutcome:
        """Ask about text and return the evaluator's standard scanner outcome.

        Args:
            text (str): The text to scan.

        Returns:
            ScanOutcome: The outcome of the scan.

        Raises:
            APIError: If the API request or response fails; propagates unchanged.
            APIConfigError: If credential resolution fails; propagates unchanged.
            CerbIAError: If the evaluator raises or its result is not ScanOutcome.
        """
        response = self._api.ask(text, self._questions)

        try:
            outcome = self._evaluator(response)
        except Exception as exc:
            raise CerbIAError("Decision evaluator raised an exception") from exc

        if not isinstance(outcome, ScanOutcome):
            raise CerbIAError("Evaluator must return ScanOutcome")

        return outcome
