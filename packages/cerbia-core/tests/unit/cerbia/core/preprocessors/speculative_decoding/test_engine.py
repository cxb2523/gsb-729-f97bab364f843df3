import re

import pytest
from cerbia.core.preprocessors.speculative_decoding._acceptance import AcceptanceFilter
from cerbia.core.preprocessors.speculative_decoding._engine import (
    _budget_exhausted,
    _intensive_decoders,
    decode_segment,
    decode_text,
)
from cerbia.core.preprocessors.speculative_decoding._observability import capture_rejections
from cerbia.core.preprocessors.speculative_decoding._types import (
    DecodedBranch,
    DecoderSpec,
    OutputPolicy,
    Payload,
    RejectionReason,
    SegmentCandidate,
)
from cerbia.core.preprocessors.speculative_decoding.exceptions import ExcessiveEncodingError

pytestmark = pytest.mark.unit


def _decoder(decoder_id: str, *, chain_only: bool = False) -> DecoderSpec:
    return DecoderSpec(decoder_id=decoder_id, chain_only=chain_only, extract_patterns=(re.compile(r"encoded"),))


_PERMISSIVE_ACCEPTANCE = AcceptanceFilter(
    min_chi_squared_pvalue=0.0,
    min_text_length=1,
    min_printable_ratio=0.0,
    max_entropy_bits=8.0,
)


def test_intensive_decoders_returns_only_configured_intensive_decoder_ids() -> None:
    result = _intensive_decoders(
        (_decoder("base64"), _decoder("rot13", chain_only=True), _decoder("gzip", chain_only=True))
    )

    assert [decoder.decoder_id for decoder in result] == ["rot13"]


def test_budget_exhausted_records_rejection_only_after_limit_is_exceeded() -> None:
    with capture_rejections() as rejections:
        at_limit = _budget_exhausted(2, 2)
        exceeded = _budget_exhausted(3, 2)

    assert at_limit is False
    assert exceeded is True
    assert rejections == {RejectionReason.BUDGET_EXHAUSTED: 1}


def test_decode_text_records_no_segment_rejections_when_extraction_finds_nothing(mocker) -> None:
    decoder = _decoder("base64")
    mocker.patch("cerbia.core.preprocessors.speculative_decoding._engine.extract_segments", return_value=[])

    with capture_rejections() as rejections:
        result = decode_text("clean", decoders=(decoder,))

    assert result == []
    assert rejections == {RejectionReason.INPUT_GATE_FAILED: 1}


def test_decode_text_returns_best_branch_for_each_extracted_segment(mocker) -> None:
    first = SegmentCandidate(start=0, end=7, text="encoded", hinted_decoders=("base64",))
    second = SegmentCandidate(start=8, end=15, text="encoded", hinted_decoders=("base64",))
    first_branch = DecodedBranch(payload=Payload.from_text("first"), chain=("base64",), depth=1, score=60.0)
    second_branch = DecodedBranch(payload=Payload.from_text("second"), chain=("base64",), depth=1, score=70.0)
    mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._engine.extract_segments", return_value=[first, second]
    )
    decode_segment = mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._engine.decode_segment",
        side_effect=[[first_branch], [second_branch]],
    )

    result = decode_text("encoded encoded", decoders=(_decoder("base64"),))

    assert result == [(first, first_branch), (second, second_branch)]
    assert decode_segment.call_count == 2


def test_decode_text_uses_intensive_whole_text_fallback_when_no_segments_exist(mocker) -> None:
    branch = DecodedBranch(payload=Payload.from_text("decoded"), chain=("rot13",), depth=1, score=80.0)
    decoder = _decoder("rot13", chain_only=True)
    mocker.patch("cerbia.core.preprocessors.speculative_decoding._engine.extract_segments", return_value=[])
    decode_segment = mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._engine.decode_segment", return_value=[branch]
    )

    result = decode_text("encoded", decoders=(decoder,), intensive_mode=True)

    assert result[0][0] == SegmentCandidate(
        start=0, end=7, text="encoded", hinted_decoders=("leetspeak", "reversed", "rot13", "rot47")
    )
    assert result[0][1] == branch
    assert decode_segment.call_args.kwargs["intensive_mode"] is True


def test_decode_text_uses_intensive_whole_text_fallback_when_extracted_segments_have_no_results(mocker) -> None:
    segment = SegmentCandidate(start=0, end=7, text="encoded", hinted_decoders=("base64",))
    branch = DecodedBranch(payload=Payload.from_text("decoded"), chain=("rot13",), depth=1, score=80.0)
    decoder = _decoder("rot13", chain_only=True)
    mocker.patch("cerbia.core.preprocessors.speculative_decoding._engine.extract_segments", return_value=[segment])
    decode_segment = mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._engine.decode_segment", side_effect=[[], [branch]]
    )

    result = decode_text("encoded", decoders=(decoder,), intensive_mode=True)

    assert result[0][1] == branch
    assert decode_segment.call_count == 2
    assert decode_segment.call_args.kwargs["intensive_mode"] is True


def test_decode_text_skips_intensive_fallback_when_text_is_empty(mocker) -> None:
    mocker.patch("cerbia.core.preprocessors.speculative_decoding._engine.extract_segments", return_value=[])
    decode_segment = mocker.patch("cerbia.core.preprocessors.speculative_decoding._engine.decode_segment")

    result = decode_text("", decoders=(_decoder("rot13", chain_only=True),), intensive_mode=True)

    assert result == []
    decode_segment.assert_not_called()


def test_decode_segment_decodes_hex_then_base64_with_current_follow_up_admission() -> None:
    decoded_text = "This is a deterministic decoded instruction with sufficient readable English text."
    base64_text = (
        "VGhpcyBpcyBhIGRldGVybWluaXN0aWMgZGVjb2RlZCBpbnN0cnVjdGlvbiB3aXRoIHN1ZmZpY2llbnQg"
        "cmVhZGFibGUgRW5nbGlzaCB0ZXh0Lg=="
    )
    hex_text = base64_text.encode().hex()
    hex_decoder = DecoderSpec(
        decoder_id="hex",
        extract_patterns=(re.compile(re.escape(hex_text)),),
        decode=lambda _payload: [Payload.from_text(base64_text)],
    )
    base64_decoder = DecoderSpec(
        decoder_id="base64",
        extract_patterns=(re.compile(re.escape(base64_text)),),
        decode=lambda _payload: [Payload.from_text(decoded_text)],
    )
    segment = SegmentCandidate(start=0, end=len(hex_text), text=hex_text, hinted_decoders=("hex",))

    branches = decode_segment(
        segment,
        decoders=(hex_decoder, base64_decoder),
        max_depth=2,
        acceptance_filter=_PERMISSIVE_ACCEPTANCE,
        improvement_min_delta=-1.0,
        improvement_min_pvalue=0.0,
    )

    assert [(branch.chain, branch.payload.text) for branch in branches] == [
        (("hex", "base64"), decoded_text),
        (("hex",), base64_text),
    ]


def test_decode_segment_raises_when_a_depth_limited_branch_remains_viable() -> None:
    first = DecoderSpec(
        decoder_id="first",
        extract_patterns=(re.compile(r"root"),),
        decode=lambda _payload: [Payload.from_text("follow-up")],
    )
    second = DecoderSpec(
        decoder_id="second",
        extract_patterns=(re.compile(r"follow-up"),),
        decode=lambda _payload: [Payload.from_text("still viable")],
    )
    segment = SegmentCandidate(start=0, end=4, text="root", hinted_decoders=("first",))

    with pytest.raises(ExcessiveEncodingError, match="depth 1"):
        decode_segment(
            segment,
            decoders=(first, second),
            max_depth=1,
            acceptance_filter=_PERMISSIVE_ACCEPTANCE,
            improvement_min_delta=-1.0,
            improvement_min_pvalue=0.0,
        )


def test_decode_segment_records_terminal_output_policy_rejection_without_raising() -> None:
    decoder = DecoderSpec(
        decoder_id="short-output",
        extract_patterns=(re.compile(r"encoded"),),
        decode=lambda _payload: [Payload.from_text("short")],
        output_policy=OutputPolicy(min_text_length=10),
    )
    segment = SegmentCandidate(start=0, end=7, text="encoded", hinted_decoders=("short-output",))

    with capture_rejections() as rejections:
        branches = decode_segment(
            segment,
            decoders=(decoder,),
            acceptance_filter=_PERMISSIVE_ACCEPTANCE,
            improvement_min_delta=-1.0,
            improvement_min_pvalue=0.0,
        )

    assert branches == []
    assert rejections == {RejectionReason.OUTPUT_POLICY_FAILED: 1}


def test_decode_text_uses_intensive_rot13_fallback_with_custom_decoder() -> None:
    decoder = DecoderSpec(
        decoder_id="rot13",
        chain_only=True,
        decode=lambda _payload: [Payload.from_text("This fallback produces readable decoded English content.")],
    )

    result = decode_text(
        "Guvf vf ebg13 rapbqrq grkg.",
        decoders=(decoder,),
        intensive_mode=True,
        acceptance_filter=_PERMISSIVE_ACCEPTANCE,
        improvement_min_delta=-1.0,
        improvement_min_pvalue=0.0,
    )

    assert len(result) == 1
    assert result[0][1].chain == ("rot13",)
