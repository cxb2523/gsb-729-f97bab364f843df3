from collections.abc import Mapping, Sequence

from .._admission import runtime_input_gate_candidate, should_try_decoder
from .._observability import record_rejection
from .._scoring import passes_output_policy_with_profiles
from .._types import DecoderSpec, OutputPolicy, Payload, RejectionReason


def _record_decoder_rejection(
    *,
    reason: RejectionReason,
) -> None:
    """Record a rejection tied to a specific decoder decision.

    Args:
        reason (RejectionReason): High-level rejection reason.
    """
    record_rejection(
        reason=reason,
    )


def _result_passes_output_policy(
    result: Payload,
    decoder: DecoderSpec,
    chain: tuple[str, ...],
    depth: int,
    *,
    language_profiles: Mapping[str, Sequence[float]] | None,
) -> bool:
    """Validate one decoder result against its output policy.

    Args:
        result (Payload): Decoder output to validate.
        decoder (DecoderSpec): Decoder that produced the result.
        chain (tuple[str, ...]): Decoder chain active before applying the decoder.
        depth (int): Current search depth.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.

    Returns:
        bool: ``True`` when the result passes non-leaf output-policy validation.
    """
    accepted, reason, _ = passes_output_policy_with_profiles(
        result,
        decoder.output_policy,
        is_leaf=False,
        language_profiles=language_profiles,
    )

    if accepted:
        return True

    _record_decoder_rejection(
        reason=reason or RejectionReason.OUTPUT_POLICY_FAILED,
    )

    return False


def _decoder_children(
    payload: Payload,
    chain: tuple[str, ...],
    depth: int,
    decoder: DecoderSpec,
    *,
    language_profiles: Mapping[str, Sequence[float]] | None,
) -> list[tuple[Payload, tuple[str, ...], OutputPolicy]]:
    """Decode one payload with a specific decoder and keep policy-valid children.

    Args:
        payload (Payload): Current payload being expanded.
        chain (tuple[str, ...]): Decoder chain applied so far.
        depth (int): Current search depth.
        decoder (DecoderSpec): Decoder to apply.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.

    Returns:
        list[tuple[Payload, tuple[str, ...], OutputPolicy]]: Children that passed decoder output-policy validation.
    """
    children: list[tuple[Payload, tuple[str, ...], OutputPolicy]] = []
    for result in decoder.decode(payload):
        if _result_passes_output_policy(result, decoder, chain, depth, language_profiles=language_profiles):
            children.append((result, (*chain, decoder.decoder_id), decoder.output_policy))

    return children


def _decoder_accepts_payload(payload: Payload, decoder: DecoderSpec, chain: tuple[str, ...], depth: int) -> bool:
    """Check whether a decoder accepts the current payload.

    Args:
        payload (Payload): Current payload being evaluated.
        decoder (DecoderSpec): Decoder to test.
        chain (tuple[str, ...]): Decoder chain applied so far.
        depth (int): Current search depth.

    Returns:
        bool: ``True`` when the decoder accepts the payload.
    """
    if decoder.accepts(payload):
        return True

    _record_decoder_rejection(
        reason=RejectionReason.ACCEPTS_FAILED,
    )

    return False


def _runtime_gate_allows_payload(payload: Payload, decoder: DecoderSpec, chain: tuple[str, ...], depth: int) -> bool:
    """Check whether a decoder's runtime input gate allows the payload.

    Args:
        payload (Payload): Current payload being evaluated.
        decoder (DecoderSpec): Decoder to test.
        chain (tuple[str, ...]): Decoder chain applied so far.
        depth (int): Current search depth.

    Returns:
        bool: ``True`` when the runtime input gate allows this payload.
    """
    _, gate_detail = runtime_input_gate_candidate(decoder, payload)
    if gate_detail is None:
        return True

    _record_decoder_rejection(
        reason=RejectionReason.INPUT_GATE_FAILED,
    )

    return False


def expand_node(
    payload: Payload,
    chain: tuple[str, ...],
    hinted_decoder_ids: frozenset[str],
    depth: int,
    decoders: tuple[DecoderSpec, ...],
    *,
    intensive_mode: bool,
    language_profiles: Mapping[str, Sequence[float]] | None = None,
) -> list[tuple[Payload, tuple[str, ...], OutputPolicy]]:
    """Expand one search node across all admissible decoders.

    Args:
        payload (Payload): Current payload being expanded.
        chain (tuple[str, ...]): Decoder chain applied so far.
        hinted_decoder_ids (frozenset[str]): Decoder IDs hinted by initial extraction.
        depth (int): Current search depth.
        decoders (tuple[DecoderSpec, ...]): Decoder suite to consider.
        intensive_mode (bool): Whether intensive-only decoders may run at depth 0.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.

    Returns:
        list[tuple[Payload, tuple[str, ...], OutputPolicy]]: Child payloads that survived admission and non-leaf
            output-policy checks.
    """
    children: list[tuple[Payload, tuple[str, ...], OutputPolicy]] = []
    for decoder in decoders:
        should_try, _ = should_try_decoder(
            decoder,
            chain,
            hinted_decoder_ids,
            depth,
            intensive_mode=intensive_mode,
        )
        if not should_try:
            continue

        if not _runtime_gate_allows_payload(payload, decoder, chain, depth):
            continue

        if not _decoder_accepts_payload(payload, decoder, chain, depth):
            continue

        children.extend(_decoder_children(payload, chain, depth, decoder, language_profiles=language_profiles))

    return children
