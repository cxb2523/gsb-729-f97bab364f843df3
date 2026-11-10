import hashlib

import pytest
from cerbia.core.scanners.canary import CanaryTokenGenerator, _generator

pytestmark = pytest.mark.unit


def test_canary_token_generator_returns_configured_hash_when_token_is_generated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entropy = "a" * 32
    timestamp = 123456789
    expected_hash = hashlib.sha256(f"unit:{entropy}:{timestamp}".encode()).hexdigest()[:12]
    monkeypatch.setattr(_generator.secrets, "token_hex", lambda _: entropy)
    monkeypatch.setattr(_generator.time, "time_ns", lambda: timestamp)
    generator = CanaryTokenGenerator(token_prefix="TEST-", token_length=12, namespace="unit")

    result = generator.generate()

    assert result == f"TEST-{expected_hash}"


@pytest.mark.parametrize(
    ("inject_format", "expected_header"),
    [
        ("<-@!-- {canary} --@!->", "<-@!-- CANARY-token --@!->"),
        ("[secret:{canary}]", "[secret:CANARY-token]"),
    ],
    ids=["default_format", "custom_format"],
)
def test_canary_token_generator_prepends_formatted_token_when_prompt_is_injected(
    monkeypatch: pytest.MonkeyPatch, inject_format: str, expected_header: str
) -> None:
    monkeypatch.setattr(CanaryTokenGenerator, "generate", lambda _: "CANARY-token")
    generator = CanaryTokenGenerator(inject_format=inject_format)

    result, token = generator.inject("Follow the system instructions.")

    assert result == f"{expected_header}\nFollow the system instructions."
    assert token == "CANARY-token"
