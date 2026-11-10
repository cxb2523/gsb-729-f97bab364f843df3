import json
from collections.abc import Sequence

from pydantic import TypeAdapter

from .._base import unique, unique_json_pairs
from .._http import HTTPClient
from ..exceptions import APIConfigError, APIError
from ._questions import DecisionQuestion
from ._responses import DecisionsResponse
from ._validation import validate_decisions


class DecisionsClient:
    """Send Decisions text requests and parse typed protocol responses.

    Args:
        model (str): Nonempty model identifier sent with each request.
        base_url (str | None): HTTP(S) base URL, including any path prefix. The fixed
            ``/v1/decisions`` endpoint is appended after removing trailing slashes.
            If omitted, requests fail with APIError.
        timeout (float): Positive finite request timeout in seconds. Defaults to 30.0.
        api_key_provider (str | None): Optional dotted import path to a zero-argument callable returning
            a bearer token. If omitted, no authorization header is added.

    Attributes:
        _model (str): Validated model identifier.
        _http (HTTPClient): Transport configured for the fixed Decisions endpoint.

    Raises:
        APIConfigError: If the model, base URL, timeout, or credential-provider configuration is invalid.
    """

    def __init__(
        self,
        *,
        model: str,
        base_url: str | None = None,
        timeout: float = 30.0,
        api_key_provider: str | None = None,
    ) -> None:
        if not isinstance(model, str) or len(model) == 0:
            raise APIConfigError() from None

        self._model = model

        self._http = HTTPClient(
            base_url=base_url,
            endpoint_path="/v1/decisions",
            timeout=timeout,
            api_key_provider=api_key_provider,
        )

    def ask(self, text: str, questions: Sequence[DecisionQuestion]) -> DecisionsResponse:
        """Send text and fixed questions once and validate the response against them.

        Args:
            text (str): Text to assess.
            questions (Sequence[DecisionQuestion]): One to 400 questions with unique names.

        Returns:
            DecisionsResponse: Typed response with matching answer names, types, and domains.

        Raises:
            APIError: If input is invalid, the endpoint is unconfigured, credential resolution or HTTP fails,
                or the response is malformed, inconsistent, or contains a refusal.
        """
        if not isinstance(text, str):
            raise APIError() from None

        try:
            parsed = TypeAdapter(tuple[DecisionQuestion, ...]).validate_python(questions)

            if not 1 <= len(parsed) <= 400:
                raise ValueError("Invalid question count")
            unique(question.name for question in parsed)

            body = {
                "model": self._model,
                "input": text,
                "questions": [q.model_dump(mode="json", exclude_none=True) for q in parsed],
            }

            raw = self._http.request(json.dumps(body, allow_nan=False))

            response = DecisionsResponse.model_validate(json.loads(raw, object_pairs_hook=unique_json_pairs))

            validate_decisions(parsed, response)

            return response
        except (ValueError, TypeError):
            raise APIError() from None
