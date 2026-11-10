from collections import deque
from collections.abc import Mapping, Sequence

from .._acceptance import AcceptanceFilter
from .._admission import runtime_input_gate_candidate, should_try_decoder
from .._decoders._registry import INTENSIVE_DECODER_IDS
from .._observability import record_rejection
from .._scoring import passes_output_policy_with_profiles, score_branch_with_profiles
from .._types import DecodedBranch, DecoderSpec, OutputPolicy, Payload, RejectionReason


def _record_child_rejection(
    *,
    reason: RejectionReason | None,
) -> None:
    """Record a rejection reason for a child branch.

    Args:
        reason (RejectionReason | None): High-level rejection reason.
    """
    record_rejection(
        reason=reason,
    )


def _append_followup_candidate(
    child_payload: Payload,
    child_chain: tuple[str, ...],
    depth: int,
    queue: deque[tuple[Payload, tuple[str, ...], int]],
) -> bool:
    """Queue a child that still needs text decoding before scoring.

    Args:
        child_payload (Payload): Child payload produced by a decoder.
        child_chain (tuple[str, ...]): Decoder chain for the child payload.
        depth (int): Current search depth.
        queue (deque[tuple[Payload, tuple[str, ...], int]]): BFS work queue.

    Returns:
        bool: ``True`` when the child was queued instead of scored immediately.
    """
    if child_payload.text is not None:
        return False

    queue.append((child_payload, child_chain, depth + 1))

    return True


def _score_child_candidate(
    original_bytes: bytes,
    child_payload: Payload,
    child_chain: tuple[str, ...],
    depth: int,
    acceptance_filter: AcceptanceFilter,
    language_profiles: Mapping[str, Sequence[float]] | None,
    improvement_min_delta: float,
    improvement_min_pvalue: float,
) -> tuple[float, RejectionReason | None, str | None]:
    """Score a child candidate for beam consideration.

    Args:
        original_bytes (bytes): Original input bytes for the explored segment.
        child_payload (Payload): Child payload produced by a decoder.
        child_chain (tuple[str, ...]): Decoder chain for the child payload.
        depth (int): Current search depth.
        acceptance_filter (AcceptanceFilter): Acceptance filter for terminal branches.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.
        improvement_min_delta (float): Minimum p-value improvement required to score a branch.
        improvement_min_pvalue (float): Minimum absolute p-value required to score a branch.

    Returns:
        tuple[float, RejectionReason | None, str | None]: Tuple of ``(score, reason, detail)`` for the child candidate.
    """
    branch = DecodedBranch(payload=child_payload, chain=child_chain, depth=depth + 1, score=0.0)
    return score_branch_with_profiles(
        original_bytes,
        branch,
        is_leaf=False,
        acceptance=acceptance_filter,
        language_profiles=language_profiles,
        improvement_min_delta=improvement_min_delta,
        improvement_min_pvalue=improvement_min_pvalue,
    )


def _queue_viable_followup(
    child_payload: Payload,
    child_chain: tuple[str, ...],
    depth: int,
    queue: deque[tuple[Payload, tuple[str, ...], int]],
    decoders: tuple[DecoderSpec, ...],
    *,
    language_profiles: Mapping[str, Sequence[float]] | None,
) -> bool:
    """Queue an unscored child when a follow-up decoder still looks viable.

    Args:
        child_payload (Payload): Child payload produced by a decoder.
        child_chain (tuple[str, ...]): Decoder chain for the child payload.
        depth (int): Current search depth.
        queue (deque[tuple[Payload, tuple[str, ...], int]]): BFS work queue.
        decoders (tuple[DecoderSpec, ...]): Decoder suite to consider for the follow-up step.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.

    Returns:
        bool: ``True`` when a viable follow-up decoder exists and the child was queued.
    """
    if not _has_viable_followup_decoder(
        child_payload,
        child_chain,
        depth + 1,
        decoders,
        language_profiles=language_profiles,
    ):
        return False

    queue.append((child_payload, child_chain, depth + 1))

    return True


def _store_accepted_leaf_result(
    original_text: str,
    original_bytes: bytes,
    child_payload: Payload,
    child_chain: tuple[str, ...],
    depth: int,
    score: float,
    results_by_chain: dict[tuple[str, ...], DecodedBranch],
    acceptance_filter: AcceptanceFilter,
    language_profiles: Mapping[str, Sequence[float]] | None,
    improvement_min_delta: float,
    improvement_min_pvalue: float,
) -> tuple[RejectionReason | None, str | None]:
    """Store an accepted leaf result after final scoring and acceptance.

    Args:
        original_text (str): Original input text for the explored segment.
        original_bytes (bytes): Original input bytes for the explored segment.
        child_payload (Payload): Accepted child payload.
        child_chain (tuple[str, ...]): Decoder chain for the accepted child.
        depth (int): Current search depth.
        score (float): Beam score already assigned to the child.
        results_by_chain (dict[tuple[str, ...], DecodedBranch]): Accepted results indexed by chain.
        acceptance_filter (AcceptanceFilter): Acceptance filter for terminal branches.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.
        improvement_min_delta (float): Minimum p-value improvement required to score a branch.
        improvement_min_pvalue (float): Minimum absolute p-value required to score a branch.

    Returns:
        tuple[RejectionReason | None, str | None]: Optional rejection reason and detail when final leaf validation
            fails.
    """
    branch = DecodedBranch(payload=child_payload, chain=child_chain, depth=depth + 1, score=score)
    leaf_score, reason, detail = score_branch_with_profiles(
        original_bytes,
        branch,
        is_leaf=True,
        acceptance=acceptance_filter,
        language_profiles=language_profiles,
        improvement_min_delta=improvement_min_delta,
        improvement_min_pvalue=improvement_min_pvalue,
    )

    if reason is not None:
        return reason, detail

    results_by_chain[child_chain] = branch.model_copy(update={"score": leaf_score})
    parent_chain = child_chain[:-1]
    if parent_chain and parent_chain not in results_by_chain:
        results_by_chain[parent_chain] = DecodedBranch(
            payload=Payload(raw=original_bytes, text=original_text),
            chain=parent_chain,
            depth=depth,
            score=0.0,
        )

    return None, None


def _score_child_for_beam(
    original_bytes: bytes,
    child_payload: Payload,
    child_chain: tuple[str, ...],
    output_policy: OutputPolicy,
    depth: int,
    queue: deque[tuple[Payload, tuple[str, ...], int]],
    acceptance_filter: AcceptanceFilter,
    language_profiles: Mapping[str, Sequence[float]] | None,
    improvement_min_delta: float,
    improvement_min_pvalue: float,
    decoders: tuple[DecoderSpec, ...],
) -> tuple[float, Payload, tuple[str, ...], OutputPolicy] | None:
    """Score one child and decide whether it should enter the beam.

    Args:
        original_bytes (bytes): Original input bytes for the explored segment.
        child_payload (Payload): Child payload produced by a decoder.
        child_chain (tuple[str, ...]): Decoder chain for the child payload.
        output_policy (OutputPolicy): Output policy associated with the decoder.
        depth (int): Current search depth.
        queue (deque[tuple[Payload, tuple[str, ...], int]]): BFS work queue.
        acceptance_filter (AcceptanceFilter): Acceptance filter for terminal branches.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.
        improvement_min_delta (float): Minimum p-value improvement required to score a branch.
        improvement_min_pvalue (float): Minimum absolute p-value required to score a branch.
        decoders (tuple[DecoderSpec, ...]): Decoder suite to consider for follow-up exploration.

    Returns:
        tuple[float, Payload, tuple[str, ...], OutputPolicy] | None: Scored child tuple for beam ranking, or ``None``
            when the child was rejected or queued.
    """
    if _append_followup_candidate(child_payload, child_chain, depth, queue):
        return None

    score, reason, _ = _score_child_candidate(
        original_bytes,
        child_payload,
        child_chain,
        depth,
        acceptance_filter,
        language_profiles,
        improvement_min_delta,
        improvement_min_pvalue,
    )
    if reason is not None:
        if reason is RejectionReason.NO_IMPROVEMENT and _queue_viable_followup(
            child_payload,
            child_chain,
            depth,
            queue,
            decoders,
            language_profiles=language_profiles,
        ):
            return None

        _record_child_rejection(
            reason=reason,
        )

        return None

    return score, child_payload, child_chain, output_policy


def _accept_scored_child(
    original_text: str,
    original_bytes: bytes,
    scored_child: tuple[float, Payload, tuple[str, ...], OutputPolicy],
    depth: int,
    results_by_chain: dict[tuple[str, ...], DecodedBranch],
    acceptance_filter: AcceptanceFilter,
    language_profiles: Mapping[str, Sequence[float]] | None,
    improvement_min_delta: float,
    improvement_min_pvalue: float,
) -> None:
    """Accept one scored child into the results map when terminal checks pass.

    Args:
        original_text (str): Original input text for the explored segment.
        original_bytes (bytes): Original input bytes for the explored segment.
        scored_child (tuple[float, Payload, tuple[str, ...], OutputPolicy]): Beam-scored child tuple to validate as a
            leaf.
        depth (int): Current search depth.
        results_by_chain (dict[tuple[str, ...], DecodedBranch]): Accepted results indexed by chain.
        acceptance_filter (AcceptanceFilter): Acceptance filter for terminal branches.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.
        improvement_min_delta (float): Minimum p-value improvement required to score a branch.
        improvement_min_pvalue (float): Minimum absolute p-value required to score a branch.
    """
    score, child_payload, child_chain, output_policy = scored_child
    accepted, reason, _ = passes_output_policy_with_profiles(
        child_payload,
        output_policy,
        is_leaf=True,
        language_profiles=language_profiles,
    )

    if not accepted:
        _record_child_rejection(
            reason=reason,
        )

    if accepted:
        reason, _ = _store_accepted_leaf_result(
            original_text,
            original_bytes,
            child_payload,
            child_chain,
            depth,
            score,
            results_by_chain,
            acceptance_filter,
            language_profiles,
            improvement_min_delta,
            improvement_min_pvalue,
        )

        if reason is not None:
            _record_child_rejection(
                reason=reason,
            )


def process_children(
    original_text: str,
    original_bytes: bytes,
    children: list[tuple[Payload, tuple[str, ...], OutputPolicy]],
    depth: int,
    queue: deque[tuple[Payload, tuple[str, ...], int]],
    results_by_chain: dict[tuple[str, ...], DecodedBranch],
    beam_width: int,
    acceptance_filter: AcceptanceFilter,
    language_profiles: Mapping[str, Sequence[float]] | None,
    improvement_min_delta: float,
    improvement_min_pvalue: float,
    decoders: tuple[DecoderSpec, ...],
) -> None:
    """Score, rank, accept, and queue expanded children for the next beam layer.

    Args:
        original_text (str): Original input text for the explored segment.
        original_bytes (bytes): Original input bytes for the explored segment.
        children (list[tuple[Payload, tuple[str, ...], OutputPolicy]]): Expanded children produced at the current node.
        depth (int): Current search depth.
        queue (deque[tuple[Payload, tuple[str, ...], int]]): BFS work queue.
        results_by_chain (dict[tuple[str, ...], DecodedBranch]): Accepted results indexed by chain.
        beam_width (int): Number of scored children to keep for the next layer.
        acceptance_filter (AcceptanceFilter): Acceptance filter for terminal branches.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.
        improvement_min_delta (float): Minimum p-value improvement required to score a branch.
        improvement_min_pvalue (float): Minimum absolute p-value required to score a branch.
        decoders (tuple[DecoderSpec, ...]): Decoder suite to consider for follow-up exploration.
    """
    scored_children: list[tuple[float, Payload, tuple[str, ...], OutputPolicy]] = []
    for child_payload, child_chain, output_policy in children:
        if scored_child := _score_child_for_beam(
            original_bytes,
            child_payload,
            child_chain,
            output_policy,
            depth,
            queue,
            acceptance_filter,
            language_profiles,
            improvement_min_delta,
            improvement_min_pvalue,
            decoders,
        ):
            scored_children.append(scored_child)

    scored_children.sort(key=lambda x: x[0], reverse=True)
    for scored_child in scored_children[:beam_width]:
        _accept_scored_child(
            original_text,
            original_bytes,
            scored_child,
            depth,
            results_by_chain,
            acceptance_filter,
            language_profiles,
            improvement_min_delta,
            improvement_min_pvalue,
        )
        _, child_payload, child_chain, _ = scored_child
        queue.append((child_payload, child_chain, depth + 1))


def has_scored_children(
    original_bytes: bytes,
    children: list[tuple[Payload, tuple[str, ...], OutputPolicy]],
    depth: int,
    acceptance_filter: AcceptanceFilter,
    language_profiles: Mapping[str, Sequence[float]] | None,
    improvement_min_delta: float,
    improvement_min_pvalue: float,
) -> bool:
    """Check whether any child could still produce a scored result.

    Args:
        original_bytes (bytes): Original input bytes for the explored segment.
        children (list[tuple[Payload, tuple[str, ...], OutputPolicy]]): Expanded children produced at the current node.
        depth (int): Current search depth.
        acceptance_filter (AcceptanceFilter): Acceptance filter for terminal branches.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.
        improvement_min_delta (float): Minimum p-value improvement required to score a branch.
        improvement_min_pvalue (float): Minimum absolute p-value required to score a branch.

    Returns:
        bool: ``True`` when at least one child remains viable for scoring or follow-up exploration.
    """
    for child_payload, child_chain, _ in children:
        if child_payload.text is None:
            return True

        branch = DecodedBranch(payload=child_payload, chain=child_chain, depth=depth + 1, score=0.0)
        _, reason, _ = score_branch_with_profiles(
            original_bytes,
            branch,
            is_leaf=False,
            acceptance=acceptance_filter,
            language_profiles=language_profiles,
            improvement_min_delta=improvement_min_delta,
            improvement_min_pvalue=improvement_min_pvalue,
        )

        if reason is None:
            return True

        _record_child_rejection(
            reason=reason,
        )

    return False


def _has_viable_followup_decoder(
    payload: Payload,
    chain: tuple[str, ...],
    depth: int,
    decoders: tuple[DecoderSpec, ...],
    *,
    language_profiles: Mapping[str, Sequence[float]] | None,
) -> bool:
    """Check whether a child payload still has at least one viable follow-up decoder.

    Args:
        payload (Payload): Child payload being considered for deeper exploration.
        chain (tuple[str, ...]): Decoder chain for the child payload.
        depth (int): Search depth the follow-up decoder would run at.
        decoders (tuple[DecoderSpec, ...]): Decoder suite to consider.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.

    Returns:
        bool: ``True`` when at least one follow-up decoder can still produce policy-valid output.
    """
    for decoder in decoders:
        if decoder.decoder_id in INTENSIVE_DECODER_IDS:
            continue

        if not decoder.extract_patterns:
            continue

        should_try, _ = should_try_decoder(
            decoder,
            chain,
            frozenset(),
            depth,
            intensive_mode=False,
        )
        if not should_try:
            continue

        gate_candidate, gate_detail = runtime_input_gate_candidate(decoder, payload)
        if gate_detail is not None or gate_candidate is None or not decoder.accepts(payload):
            continue

        for result in decoder.decode(payload):
            accepted, _, _ = passes_output_policy_with_profiles(
                result,
                decoder.output_policy,
                is_leaf=False,
                language_profiles=language_profiles,
            )

            if accepted:
                return True

    return False
