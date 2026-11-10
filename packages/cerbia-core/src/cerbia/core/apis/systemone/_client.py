import json
from collections.abc import Mapping

from pydantic import TypeAdapter

from .._base import Identifier, unique_json_pairs
from .._http import HTTPClient
from ..exceptions import APIConfigError, APIError
from ._questions import SystemOneQuestion
from ._responses import SystemOneResponse
from ._validation import validate_systemone


class SystemOneClient:
    """Send System One text requests and parse typed responses without scanner policy.

    Args:
        model (str): Non-empty model identifier sent with each request.
        base_url (str | None): HTTP(S) base URL to which the fixed ``/v1/systemone`` path is appended.
            Defaults to ``None``, which allows construction but prevents requests.
        timeout (float): Finite, positive HTTP timeout in seconds. Defaults to ``30.0``.
        api_key_provider (str | None): Optional dotted import path to a zero-argument callable returning a bearer key.
            Defaults to ``None``, which sends no authorization header.

    Raises:
        APIConfigError: If the model, base URL, timeout, or credential-provider import or callability is invalid.
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
            endpoint_path="/v1/systemone",
            timeout=timeout,
            api_key_provider=api_key_provider,
        )

    def ask(self, text: str, questions: Mapping[str, SystemOneQuestion]) -> SystemOneResponse:
        """Send text and fixed questions once, rejecting malformed or inconsistent responses.

        Args:
            text (str): Text sent as the request's ``state`` without coercion.
            questions (Mapping[str, SystemOneQuestion]): Non-empty mapping of non-empty question IDs to typed questions.

        Returns:
            SystemOneResponse: Parsed response matching every requested question ID, answer type, and domain.

        Raises:
            APIError: If input validation or serialization fails, the base URL is missing, credentials fail at runtime,
                or the HTTP request fails. Also raised for malformed responses, including duplicate JSON keys, missing
                or extra answers, mismatched answer types or domains, invalid distributions, or inconsistent scores.
        """
        if not isinstance(text, str):
            raise APIError() from None

        try:
            keyed = TypeAdapter(dict[Identifier, SystemOneQuestion]).validate_python(questions)
            if not keyed:
                raise ValueError("Missing questions")

            body = {
                "model": self._model,
                "state": text,
                "questions": {
                    key: {**q.model_dump(mode="json", exclude_unset=True), "type": q.type} for key, q in keyed.items()
                },
            }

            raw = self._http.request(json.dumps(body, allow_nan=False))
            response = SystemOneResponse.model_validate(json.loads(raw, object_pairs_hook=unique_json_pairs))
            validate_systemone(keyed, response)

            return response

        except (ValueError, TypeError):
            raise APIError() from None
