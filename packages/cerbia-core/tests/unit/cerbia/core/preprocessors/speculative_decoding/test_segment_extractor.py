import re

import pytest
from cerbia.core.preprocessors.speculative_decoding._segment_extractor import extract_segments
from cerbia.core.preprocessors.speculative_decoding._types import DecoderSpec

pytestmark = pytest.mark.unit


def test_extract_segments_returns_empty_list_when_no_decoder_matches() -> None:
    decoder = DecoderSpec(decoder_id="base64", extract_patterns=(re.compile(r"[A-Z]{4}"),))

    result = extract_segments("clean content", decoders=(decoder,))

    assert result == []


def test_extract_segments_ignores_chain_only_decoders() -> None:
    decoder = DecoderSpec(decoder_id="gzip", chain_only=True, extract_patterns=(re.compile(r"encoded"),))

    result = extract_segments("encoded", decoders=(decoder,))

    assert result == []


def test_extract_segments_merges_overlapping_matches_and_collects_unique_hints() -> None:
    wide_decoder = DecoderSpec(decoder_id="wide", extract_patterns=(re.compile(r"ABCDEFGH"),))
    narrow_decoder = DecoderSpec(decoder_id="narrow", extract_patterns=(re.compile(r"CDEF"),))
    duplicate_decoder = DecoderSpec(decoder_id="wide", extract_patterns=(re.compile(r"BCDE"),))

    result = extract_segments("before ABCDEFGH after", decoders=(wide_decoder, narrow_decoder, duplicate_decoder))

    assert [segment.model_dump() for segment in result] == [
        {
            "start": 7,
            "end": 15,
            "text": "ABCDEFGH",
            "hinted_decoders": ("wide", "narrow"),
        }
    ]


def test_extract_segments_extends_partially_overlapping_matches() -> None:
    first_decoder = DecoderSpec(decoder_id="first", extract_patterns=(re.compile(r"ABCD"),))
    second_decoder = DecoderSpec(decoder_id="second", extract_patterns=(re.compile(r"CDEF"),))

    result = extract_segments("ABCDEF", decoders=(first_decoder, second_decoder))

    assert [segment.model_dump() for segment in result] == [
        {
            "start": 0,
            "end": 6,
            "text": "ABCDEF",
            "hinted_decoders": ("first", "second"),
        }
    ]


def test_extract_segments_unions_transitive_overlaps_and_deduplicates_hints() -> None:
    first_decoder = DecoderSpec(decoder_id="first", extract_patterns=(re.compile(r"ABCD"),))
    bridge_decoder = DecoderSpec(decoder_id="bridge", extract_patterns=(re.compile(r"CDEFGH"),))
    final_decoder = DecoderSpec(decoder_id="final", extract_patterns=(re.compile(r"EFGHIJ"),))
    duplicate_decoder = DecoderSpec(decoder_id="bridge", extract_patterns=(re.compile(r"DEFG"),))

    result = extract_segments(
        "ABCDEFGHIJ",
        decoders=(first_decoder, bridge_decoder, final_decoder, duplicate_decoder),
    )

    assert [segment.model_dump() for segment in result] == [
        {
            "start": 0,
            "end": 10,
            "text": "ABCDEFGHIJ",
            "hinted_decoders": ("first", "bridge", "final"),
        }
    ]


def test_extract_segments_preserves_contained_span_and_deduplicates_hints() -> None:
    outer_decoder = DecoderSpec(decoder_id="outer", extract_patterns=(re.compile(r"ABCDEFGH"),))
    inner_decoder = DecoderSpec(decoder_id="inner", extract_patterns=(re.compile(r"CDEF"),))
    duplicate_decoder = DecoderSpec(decoder_id="outer", extract_patterns=(re.compile(r"BCDE"),))

    result = extract_segments("ABCDEFGH", decoders=(outer_decoder, inner_decoder, duplicate_decoder))

    assert [segment.model_dump() for segment in result] == [
        {
            "start": 0,
            "end": 8,
            "text": "ABCDEFGH",
            "hinted_decoders": ("outer", "inner"),
        }
    ]


def test_extract_segments_orders_candidates_and_applies_segment_limit() -> None:
    decoder = DecoderSpec(decoder_id="token", extract_patterns=(re.compile(r"[A-Z]{4}"),))

    result = extract_segments("ZZZZ AAAA MMMM", decoders=(decoder,), max_segments=2)

    assert [(segment.start, segment.text) for segment in result] == [(0, "ZZZZ"), (5, "AAAA")]
