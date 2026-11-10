import re

import pytest
from cerbia.core.preprocessors.speculative_decoding._observability import capture_rejections
from cerbia.core.preprocessors.speculative_decoding._search import _expansion
from cerbia.core.preprocessors.speculative_decoding._types import DecoderSpec, OutputPolicy, Payload, RejectionReason

pytestmark = pytest.mark.unit


def test_expand_node_returns_children_only_for_admissible_gate_and_accepting_decoder(mocker) -> None:
    payload = Payload.from_text("encoded")
    result = Payload.from_text("decoded")
    decoder = DecoderSpec(decoder_id="base64", decode=lambda _payload: [result])
    mocker.patch.object(_expansion, "should_try_decoder", return_value=(True, None))
    mocker.patch.object(_expansion, "runtime_input_gate_candidate", return_value=("encoded", None))
    mocker.patch.object(_expansion, "passes_output_policy_with_profiles", return_value=(True, None, None))

    children = _expansion.expand_node(payload, (), frozenset({"base64"}), 0, (decoder,), intensive_mode=False)

    assert children == [(result, ("base64",), OutputPolicy())]


@pytest.mark.parametrize(
    "stage", ["admission", "gate", "accepts", "policy"], ids=["admission", "gate", "accepts", "policy"]
)
def test_expand_node_rejects_decoder_when_any_validation_stage_fails(mocker, stage: str) -> None:
    payload = Payload.from_text("encoded")
    decoder = DecoderSpec(decoder_id="base64", decode=lambda _payload: [Payload.from_text("decoded")])
    mocker.patch.object(
        _expansion, "should_try_decoder", return_value=((stage != "admission"), RejectionReason.INPUT_GATE_FAILED)
    )
    mocker.patch.object(
        _expansion, "runtime_input_gate_candidate", return_value=("encoded", None if stage != "gate" else "failed")
    )
    mocker.patch.object(
        _expansion,
        "passes_output_policy_with_profiles",
        return_value=((stage != "policy"), RejectionReason.OUTPUT_POLICY_FAILED, "failed"),
    )
    decoder = decoder.model_copy(update={"accepts": lambda _payload: stage != "accepts"})

    children = _expansion.expand_node(payload, (), frozenset({"base64"}), 0, (decoder,), intensive_mode=False)

    assert children == []


def test_expansion_rejects_runtime_gate_without_decoding() -> None:
    decoder = DecoderSpec(
        decoder_id="runtime-gated",
        extract_patterns=(re.compile(r"token=([A-Z]+)"),),
        input_gate=lambda text: text == "allowed",
        decode=lambda payload: pytest.fail("rejected candidate decoded"),
    )

    with capture_rejections() as rejections:
        children = _expansion.expand_node(
            Payload.from_text("token=blocked"), (), frozenset({"runtime-gated"}), 0, (decoder,), intensive_mode=False
        )

    assert children == []
    assert rejections == {RejectionReason.INPUT_GATE_FAILED: 1}
