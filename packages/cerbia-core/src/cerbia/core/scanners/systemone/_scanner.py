import importlib
from collections.abc import Mapping
from typing import Annotated

from pydantic import ConfigDict, Field, JsonValue, TypeAdapter

from ...apis._base import Identifier
from ...apis.systemone import SystemOneClient, SystemOneQuestion
from ...exceptions import CerbIAConfigError, CerbIAError
from ...models.scans import ScanOutcome
from ...types import Action, ContentType, Severity
from ._evaluator import SystemOneEvaluator


class SystemOneScanner:
    """Ask fixed System One questions and delegate risk interpretation to an application evaluator.

    Args:
        questions (Mapping[str, SystemOneQuestion | JsonValue]): Typed questions or YAML mappings keyed by question ID.
        evaluator (str): The dotted path to the evaluator function.
        model (str): The model to use for the API client.
        base_url (str | None): The base URL for the API client.
        timeout (float): The timeout for API requests.
        api_key_provider (str | None): The dotted path to the API key provider.
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

    _evaluator: SystemOneEvaluator
    _questions: dict[Identifier, SystemOneQuestion]

    def __init__(
        self,
        questions: Mapping[str, SystemOneQuestion | JsonValue],
        evaluator: str,
        model: str,
        base_url: str | None = None,
        timeout: float = 30.0,
        api_key_provider: str | None = None,
        severity: Severity = Severity.HIGH,
        action: Action = Action.BLOCK,
        content_types: tuple[ContentType, ...] | list[str] | None = (ContentType.TEXT,),
    ) -> None:
        self.scanner_id = "systemone"
        self.scanner_name = "System One"
        self.severity = severity
        self.action = action
        self.content_types = tuple(content_types) if content_types is not None else None

        try:
            self._questions = TypeAdapter(
                Annotated[dict[Identifier, SystemOneQuestion], Field(min_length=1)],
                config=ConfigDict(hide_input_in_errors=True),
            ).validate_python(questions)

        except (ValueError, TypeError) as exc:
            raise CerbIAConfigError("Invalid System One scanner questions") from exc

        try:
            module_path, _, name = evaluator.rpartition(".")
        except (AttributeError, TypeError) as exc:
            raise CerbIAConfigError("Evaluator must be a dotted import path (module.function)") from exc

        if not module_path or not name:
            raise CerbIAConfigError("Evaluator must be a dotted import path (module.function)")

        try:
            evaluator_function: SystemOneEvaluator = getattr(importlib.import_module(module_path), name)
        except Exception as exc:
            raise CerbIAConfigError("Could not import evaluator") from exc

        if not callable(evaluator_function):
            raise CerbIAConfigError("Evaluator must be callable")

        self._evaluator = evaluator_function

        self._api = SystemOneClient(
            model=model,
            base_url=base_url,
            timeout=timeout,
            api_key_provider=api_key_provider,
        )

    def scan(self, text: str) -> ScanOutcome:
        """Ask about text and return the evaluator's standard scanner outcome.

        Args:
            text (str): The text to scan as System One state.

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
            raise CerbIAError("System One evaluator raised an exception") from exc

        if not isinstance(outcome, ScanOutcome):
            raise CerbIAError("Evaluator must return ScanOutcome")

        return outcome
