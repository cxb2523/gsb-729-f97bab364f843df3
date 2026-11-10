import pytest
from cerbia.core.preprocessors.speculative_decoding._types import (
    DecoderSpec,
    OutputPolicy,
    Payload,
)

pytestmark = pytest.mark.unit


def test_payload_from_text_preserves_utf8_text_and_raw_bytes() -> None:
    payload = Payload.from_text("decoded text")

    assert payload.raw == b"decoded text"
    assert payload.text == "decoded text"


@pytest.mark.parametrize("raw,text", [(b"\xff\xfe", None), ("café".encode(), "café"), (b"", "")])
def test_payload_from_bytes_preserves_binary_data_and_utf8_view(raw: bytes, text: str | None) -> None:
    payload = Payload.from_bytes(raw)

    assert payload.raw == raw
    assert payload.text == text


def test_decoder_spec_uses_default_behaviors_when_optional_fields_are_omitted() -> None:
    decoder = DecoderSpec(decoder_id="test")

    assert decoder.extract_patterns == ()
    assert decoder.chain_only is False
    assert decoder.input_gate("candidate") is True
    assert decoder.accepts(Payload.from_text("candidate")) is True
    assert decoder.decode(Payload.from_text("candidate")) == []
    assert decoder.output_policy == OutputPolicy()


def test_output_policy_inert_defaults() -> None:
    policy = OutputPolicy()

    assert policy.min_printable_ratio == 0.70
    assert policy.min_text_length == 4
    assert policy.entropy_range is None
    assert policy.expected_pattern is None
    assert policy.require_utf8 is False
    assert policy.min_chi_squared_pvalue == 0.0
