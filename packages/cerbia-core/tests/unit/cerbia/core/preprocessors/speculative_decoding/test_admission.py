import re

import pytest
from cerbia.core.preprocessors.speculative_decoding._admission import (
    runtime_input_gate_candidate,
    should_try_decoder,
)
from cerbia.core.preprocessors.speculative_decoding._observability import capture_rejections
from cerbia.core.preprocessors.speculative_decoding._types import DecoderSpec, Payload, RejectionReason

pytestmark = pytest.mark.unit


def test_runtime_input_gate_candidate_returns_extracted_match_when_gate_passes() -> None:
    decoder = DecoderSpec(
        decoder_id="test", extract_patterns=(re.compile(r"value=(\w+)"),), input_gate=lambda text: text == "encoded"
    )

    candidate, detail = runtime_input_gate_candidate(decoder, Payload.from_text("value=encoded"))

    assert candidate == "encoded"
    assert detail is None


@pytest.mark.parametrize(
    ("decoder", "payload", "expected_detail"),
    [
        (DecoderSpec(decoder_id="test"), Payload.from_bytes(b"\xff"), None),
        (
            DecoderSpec(decoder_id="test", input_gate=lambda _text: False),
            Payload.from_text("text"),
            "input_gate_failed_for_payload_text",
        ),
        (
            DecoderSpec(decoder_id="test", extract_patterns=(re.compile(r"encoded"),), input_gate=lambda _text: False),
            Payload.from_text("encoded"),
            "input_gate_failed_for_extracted_candidate",
        ),
        (
            DecoderSpec(decoder_id="test", extract_patterns=(re.compile(r"encoded"),)),
            Payload.from_text("clean"),
            "no_extracted_candidate",
        ),
    ],
    ids=["binary_payload", "payload_gate_failure", "extracted_gate_failure", "no_extracted_candidate"],
)
def test_runtime_input_gate_candidate_returns_detail_when_no_candidate_is_available(
    decoder, payload: Payload, expected_detail: str | None
) -> None:
    candidate, detail = runtime_input_gate_candidate(decoder, payload)

    assert candidate is None
    assert detail == expected_detail


@pytest.mark.parametrize(
    ("decoder", "chain", "hints", "depth", "intensive_mode", "expected", "reason"),
    [
        (DecoderSpec(decoder_id="base64"), (), frozenset({"base64"}), 0, False, True, None),
        (
            DecoderSpec(decoder_id="base64"),
            ("base64",),
            frozenset({"base64"}),
            1,
            False,
            False,
            RejectionReason.EXCESSIVE_DEPTH,
        ),
        (
            DecoderSpec(decoder_id="gzip", chain_only=True),
            (),
            frozenset({"gzip"}),
            0,
            False,
            False,
            RejectionReason.INPUT_GATE_FAILED,
        ),
        (DecoderSpec(decoder_id="base64"), (), frozenset(), 0, False, False, RejectionReason.INPUT_GATE_FAILED),
        (DecoderSpec(decoder_id="rot13"), (), frozenset(), 0, False, False, RejectionReason.INPUT_GATE_FAILED),
        (DecoderSpec(decoder_id="rot13"), (), frozenset(), 0, True, True, None),
        (DecoderSpec(decoder_id="base64"), (), frozenset(), 1, False, True, None),
    ],
    ids=["hinted", "repeated", "chain_only_root", "not_hinted", "intensive_disabled", "intensive_enabled", "nested"],
)
def test_should_try_decoder_applies_admission_rules(
    decoder,
    chain: tuple[str, ...],
    hints: frozenset[str],
    depth: int,
    intensive_mode: bool,
    expected: bool,
    reason: RejectionReason | None,
) -> None:
    with capture_rejections() as rejections:
        result, actual_reason = should_try_decoder(decoder, chain, hints, depth, intensive_mode=intensive_mode)

    assert result is expected
    assert actual_reason is reason
    assert sum(rejections.values()) == (0 if expected else 1)
