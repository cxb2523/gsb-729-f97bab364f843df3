import pytest
from cerbia.core.preprocessors.speculative_decoding._decoders._registry import DECODERS, INTENSIVE_DECODER_IDS
from cerbia.core.preprocessors.speculative_decoding._types import DecoderSpec

from .._corpus import MUST_DECODE, CorpusEntry

pytestmark = pytest.mark.unit


def accepted_decoder_ids(text: str) -> set[str]:
    """Return non-chain decoder IDs whose extracted candidates pass their gates."""
    accepted: set[str] = set()
    decoder: DecoderSpec
    for decoder in DECODERS:
        if decoder.chain_only:
            continue
        for pattern in decoder.extract_patterns:
            for match in pattern.finditer(text):
                candidate = match.group(1) if match.lastindex else match.group()
                if decoder.input_gate(candidate):
                    accepted.add(decoder.decoder_id)
                    break
            if decoder.decoder_id in accepted:
                break
    return accepted


def test_decoder_registry_has_exact_ids_in_priority_order() -> None:
    assert [decoder.decoder_id for decoder in DECODERS] == [
        "base64",
        "hex",
        "base32",
        "url_encoding",
        "html_entities",
        "unicode_escapes",
        "rot13",
        "rot47",
        "leetspeak",
        "reversed",
        "gzip",
        "zlib",
    ]


def test_decoder_registry_has_exact_chain_only_flags() -> None:
    assert [decoder.chain_only for decoder in DECODERS] == [
        False,
        False,
        False,
        False,
        False,
        False,
        True,
        True,
        True,
        True,
        True,
        True,
    ]


def test_intensive_decoder_ids_are_registry_owned_non_chain_only_decoders() -> None:
    registry_ids = {decoder.decoder_id for decoder in DECODERS}
    chain_only_ids = {decoder.decoder_id for decoder in DECODERS if decoder.chain_only}

    assert frozenset({"rot13", "rot47", "leetspeak", "reversed"}) == INTENSIVE_DECODER_IDS
    assert registry_ids >= INTENSIVE_DECODER_IDS
    assert chain_only_ids >= INTENSIVE_DECODER_IDS
    assert INTENSIVE_DECODER_IDS.isdisjoint({"gzip", "zlib"})


@pytest.mark.parametrize("entry", MUST_DECODE, ids=lambda entry: entry.id)
def test_decoder_registry_accepts_every_positive_corpus_candidate(entry: CorpusEntry) -> None:
    assert accepted_decoder_ids(entry.text)
