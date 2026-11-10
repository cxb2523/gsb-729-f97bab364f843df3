from ._decoders._registry import INTENSIVE_DECODER_IDS
from ._observability import record_rejection
from ._types import DecoderSpec, Payload, RejectionReason


def _first_matching_extract_candidate(decoder: DecoderSpec, text: str) -> tuple[str | None, bool]:
    """Return the first extractor candidate that passes a decoder input gate.

    Args:
        decoder (DecoderSpec): Decoder whose extraction patterns and input gate are evaluated.
        text (str): Source text to scan for extractor matches.

    Returns:
        tuple[str | None, bool]: Tuple containing the first accepted candidate, if any, and whether any extractor
            matched at all.
    """
    matched_candidate = False
    for pattern in decoder.extract_patterns:
        for match in pattern.finditer(text):
            matched_candidate = True
            candidate = match.group(1) if match.lastindex else match.group()

            if decoder.input_gate(candidate):
                return candidate, True

    return None, matched_candidate


def runtime_input_gate_candidate(decoder: DecoderSpec, payload: Payload) -> tuple[str | None, str | None]:
    """Resolve the runtime input-gate candidate for a decoder.

    Args:
        decoder (DecoderSpec): Decoder being considered for the current payload.
        payload (Payload): Current payload under evaluation.

    Returns:
        tuple[str | None, str | None]: Tuple of ``(candidate, detail)`` where ``candidate`` is the accepted input-gate
            text and ``detail`` explains why no candidate was available.
    """
    if payload.text is None:
        return None, None

    if decoder.extract_patterns:
        candidate, matched_candidate = _first_matching_extract_candidate(decoder, payload.text)
        if candidate is not None:
            return candidate, None

        if matched_candidate:
            return None, "input_gate_failed_for_extracted_candidate"

        return None, "no_extracted_candidate"

    if decoder.input_gate(payload.text):
        return payload.text, None

    return None, "input_gate_failed_for_payload_text"


def should_try_decoder(
    decoder: DecoderSpec,
    chain: tuple[str, ...],
    hinted_decoder_ids: frozenset[str],
    depth: int,
    *,
    intensive_mode: bool,
) -> tuple[bool, RejectionReason | None]:
    """Decide whether a decoder is admissible for the current branch.

    Args:
        decoder (DecoderSpec): Decoder being considered.
        chain (tuple[str, ...]): Decoder chain already applied to the current payload.
        hinted_decoder_ids (frozenset[str]): Decoder IDs hinted by segment extraction at depth 0.
        depth (int): Current search depth.
        intensive_mode (bool): Whether intensive-only decoders may run at depth 0.

    Returns:
        tuple[bool, RejectionReason | None]: Tuple of ``(should_try, reason)`` where ``reason`` is populated when a
            rejection was recorded.
    """
    if decoder.decoder_id in chain:
        record_rejection(
            reason=RejectionReason.EXCESSIVE_DEPTH,
        )

        return False, RejectionReason.EXCESSIVE_DEPTH

    if depth == 0:
        if decoder.decoder_id in INTENSIVE_DECODER_IDS:
            if not intensive_mode:
                record_rejection(
                    reason=RejectionReason.INPUT_GATE_FAILED,
                )

                return False, RejectionReason.INPUT_GATE_FAILED

            return True, None

        if decoder.chain_only:
            record_rejection(
                reason=RejectionReason.INPUT_GATE_FAILED,
            )

            return False, RejectionReason.INPUT_GATE_FAILED

        if decoder.decoder_id not in hinted_decoder_ids:
            record_rejection(
                reason=RejectionReason.INPUT_GATE_FAILED,
            )

            return False, RejectionReason.INPUT_GATE_FAILED

        return True, None

    return True, None
