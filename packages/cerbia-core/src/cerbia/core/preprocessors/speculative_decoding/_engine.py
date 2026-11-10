from collections import deque
from collections.abc import Mapping, Sequence

from ._acceptance import AcceptanceFilter
from ._decoders import DECODERS
from ._decoders._registry import INTENSIVE_DECODER_IDS
from ._defaults import (
    DEFAULT_BEAM_WIDTH,
    DEFAULT_IMPROVEMENT_MIN_DELTA,
    DEFAULT_IMPROVEMENT_MIN_PVALUE,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_NODES,
    DEFAULT_MAX_SEGMENTS,
)
from ._observability import record_rejection
from ._scoring import prune_terminal_branch
from ._search import expand_node, has_scored_children, process_children
from ._segment_extractor import extract_segments
from ._types import DecodedBranch, DecoderSpec, OutputPolicy, Payload, RejectionReason, SegmentCandidate
from .exceptions import ExcessiveEncodingError


def _intensive_decoders(decoders: tuple[DecoderSpec, ...]) -> tuple[DecoderSpec, ...]:
    """Return only decoders that are allowed in intensive whole-text mode.

    Args:
        decoders (tuple[DecoderSpec, ...]): Decoder suite configured for the search.

    Returns:
        tuple[DecoderSpec, ...]: Tuple containing only intensive-only decoders.
    """
    return tuple(decoder for decoder in decoders if decoder.decoder_id in INTENSIVE_DECODER_IDS)


def _record_no_segment_rejections(decoders: tuple[DecoderSpec, ...]) -> None:
    """Record extraction rejections when no decoder found any initial segment.

    Args:
        decoders (tuple[DecoderSpec, ...]): Decoder suite considered during segment extraction.
    """
    for decoder in decoders:
        if decoder.chain_only:
            continue

        record_rejection(
            reason=RejectionReason.INPUT_GATE_FAILED,
        )


def _budget_exhausted(
    nodes_explored: int,
    max_nodes: int,
) -> bool:
    """Check whether the current segment search has exceeded its node budget.

    Args:
        nodes_explored (int): Number of nodes explored so far.
        max_nodes (int): Configured maximum node budget.

    Returns:
        bool: ``True`` when the budget was exceeded and a rejection was recorded.
    """
    if nodes_explored <= max_nodes:
        return False

    record_rejection(
        reason=RejectionReason.BUDGET_EXHAUSTED,
    )
    return True


def _depth_limited_results_exist(
    root_payload: Payload,
    children: list[tuple[Payload, tuple[str, ...], OutputPolicy]],
    depth: int,
    acceptance_filter: AcceptanceFilter,
    language_profiles: Mapping[str, Sequence[float]] | None,
    improvement_min_delta: float,
    improvement_min_pvalue: float,
) -> bool:
    """Check whether a max-depth node still has score-worthy children.

    Args:
        root_payload (Payload): Original segment payload used as the scoring baseline.
        children (list[tuple[Payload, tuple[str, ...], OutputPolicy]]): Children expanded from the depth-limited node.
        depth (int): Current search depth.
        acceptance_filter (AcceptanceFilter): Acceptance filter used for scoring.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.
        improvement_min_delta (float): Minimum p-value improvement required to score a branch.
        improvement_min_pvalue (float): Minimum absolute p-value required to score a branch.

    Returns:
        bool: ``True`` when at least one child still looks score-worthy.
    """
    return has_scored_children(
        root_payload.raw,
        children,
        depth,
        acceptance_filter,
        language_profiles,
        improvement_min_delta,
        improvement_min_pvalue,
    )


def _handle_depth_limited_node(
    root_payload: Payload,
    chain: tuple[str, ...],
    depth: int,
    children: list[tuple[Payload, tuple[str, ...], OutputPolicy]],
    results_by_chain: dict[tuple[str, ...], DecodedBranch],
    acceptance_filter: AcceptanceFilter,
    language_profiles: Mapping[str, Sequence[float]] | None,
    improvement_min_delta: float,
    improvement_min_pvalue: float,
    max_depth: int,
) -> bool:
    """Handle a node that has reached the configured maximum depth.

    Args:
        root_payload (Payload): Original segment payload used as the scoring baseline.
        chain (tuple[str, ...]): Decoder chain active at the limited node.
        depth (int): Current search depth.
        children (list[tuple[Payload, tuple[str, ...], OutputPolicy]]): Children expanded from the limited node.
        results_by_chain (dict[tuple[str, ...], DecodedBranch]): Accepted results indexed by decoder chain.
        acceptance_filter (AcceptanceFilter): Acceptance filter used for terminal pruning.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.
        improvement_min_delta (float): Minimum p-value improvement required to score a branch.
        improvement_min_pvalue (float): Minimum absolute p-value required to score a branch.
        max_depth (int): Configured maximum depth.

    Returns:
        bool: ``True`` when the node was fully handled and should not continue expansion.

    Raises:
        ExcessiveEncodingError: If a depth-limited branch is still producing viable children.
    """
    if depth < max_depth:
        return False

    if _depth_limited_results_exist(
        root_payload,
        children,
        depth,
        acceptance_filter,
        language_profiles,
        improvement_min_delta,
        improvement_min_pvalue,
    ):
        raise ExcessiveEncodingError(
            f"Decoded content still producing results at depth {max_depth} (chain: {' → '.join(chain or ('root',))})"
        )

    prune_terminal_branch(chain, results_by_chain, acceptance_filter, language_profiles)
    return True


def decode_segment(
    segment: SegmentCandidate,
    decoders: tuple[DecoderSpec, ...] = DECODERS,
    max_depth: int = DEFAULT_MAX_DEPTH,
    beam_width: int = DEFAULT_BEAM_WIDTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    *,
    intensive_mode: bool = False,
    acceptance_filter: AcceptanceFilter | None = None,
    language_profiles: Mapping[str, Sequence[float]] | None = None,
    improvement_min_delta: float = DEFAULT_IMPROVEMENT_MIN_DELTA,
    improvement_min_pvalue: float = DEFAULT_IMPROVEMENT_MIN_PVALUE,
) -> list[DecodedBranch]:
    """Run beam search over the decode tree for one suspicious segment.

    Args:
        segment (SegmentCandidate): Suspicious text span selected for speculative decoding.
        decoders (tuple[DecoderSpec, ...]): Decoder suite to consider while expanding the branch tree.
        max_depth (int): Maximum recursive decode depth allowed for this segment.
        beam_width (int): Number of scored children to retain per layer.
        max_nodes (int): Hard limit on explored nodes for this segment.
        intensive_mode (bool): Whether depth-0 intensive decoders are allowed.
        acceptance_filter (AcceptanceFilter | None): Optional override for terminal acceptance checks.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override for chi-squared
            scoring.
        improvement_min_delta (float): Minimum p-value improvement required to score a branch.
        improvement_min_pvalue (float): Minimum absolute p-value required to score a branch.

    Returns:
        list[DecodedBranch]: Accepted decoded branches sorted by descending score.

    Raises:
        ExcessiveEncodingError: If a branch is still productive after reaching ``max_depth``.
    """
    root_payload = Payload.from_text(segment.text)
    leaf_acceptance = acceptance_filter or AcceptanceFilter()
    queue: deque[tuple[Payload, tuple[str, ...], int]] = deque()
    queue.append((root_payload, (), 0))

    results_by_chain: dict[tuple[str, ...], DecodedBranch] = {}
    nodes_explored = 0

    while queue:
        payload, chain, depth = queue.popleft()
        nodes_explored += 1

        if _budget_exhausted(nodes_explored, max_nodes):
            break

        hinted: frozenset[str] = frozenset(segment.hinted_decoders) if depth == 0 else frozenset()
        children = expand_node(
            payload,
            chain,
            hinted,
            depth,
            decoders,
            intensive_mode=intensive_mode,
            language_profiles=language_profiles,
        )

        if _handle_depth_limited_node(
            root_payload,
            chain,
            depth,
            children,
            results_by_chain,
            leaf_acceptance,
            language_profiles,
            improvement_min_delta,
            improvement_min_pvalue,
            max_depth,
        ):
            continue

        if not children:
            prune_terminal_branch(chain, results_by_chain, leaf_acceptance, language_profiles)
            continue

        process_children(
            root_payload.text or "",
            root_payload.raw,
            children,
            depth,
            queue,
            results_by_chain,
            beam_width,
            leaf_acceptance,
            language_profiles,
            improvement_min_delta,
            improvement_min_pvalue,
            decoders,
        )

    results = list(results_by_chain.values())
    results.sort(key=lambda b: b.score, reverse=True)

    return results


def decode_text(
    text: str,
    decoders: tuple[DecoderSpec, ...] = DECODERS,
    max_depth: int = DEFAULT_MAX_DEPTH,
    beam_width: int = DEFAULT_BEAM_WIDTH,
    max_nodes_per_segment: int = DEFAULT_MAX_NODES,
    max_segments: int = DEFAULT_MAX_SEGMENTS,
    *,
    intensive_mode: bool = False,
    acceptance_filter: AcceptanceFilter | None = None,
    language_profiles: Mapping[str, Sequence[float]] | None = None,
    improvement_min_delta: float = DEFAULT_IMPROVEMENT_MIN_DELTA,
    improvement_min_pvalue: float = DEFAULT_IMPROVEMENT_MIN_PVALUE,
) -> list[tuple[SegmentCandidate, DecodedBranch]]:
    """Decode suspicious segments within a text string.

    Args:
        text (str): Input text to analyze.
        decoders (tuple[DecoderSpec, ...]): Decoder suite to use for segment extraction and search.
        max_depth (int): Maximum recursive decode depth per segment.
        beam_width (int): Number of scored children to retain per layer.
        max_nodes_per_segment (int): Hard node budget per extracted segment.
        max_segments (int): Maximum extracted segments to explore.
        intensive_mode (bool): Whether to run the whole-text intensive fallback.
        acceptance_filter (AcceptanceFilter | None): Optional override for terminal acceptance checks.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override for chi-squared
            scoring.
        improvement_min_delta (float): Minimum p-value improvement required to score a branch.
        improvement_min_pvalue (float): Minimum absolute p-value required to score a branch.

    Returns:
        list[tuple[SegmentCandidate, DecodedBranch]]: Best accepted branch per extracted
            segment, preserving segment metadata.

    Raises:
        ExcessiveEncodingError: If any segment exceeds the configured depth while still producing results.
    """
    segments = extract_segments(text, decoders=decoders, max_segments=max_segments)
    if not segments:
        _record_no_segment_rejections(decoders)

    results: list[tuple[SegmentCandidate, DecodedBranch]] = []

    for segment in segments:
        branches = decode_segment(
            segment,
            decoders=decoders,
            max_depth=max_depth,
            beam_width=beam_width,
            max_nodes=max_nodes_per_segment,
            intensive_mode=intensive_mode,
            acceptance_filter=acceptance_filter,
            language_profiles=language_profiles,
            improvement_min_delta=improvement_min_delta,
            improvement_min_pvalue=improvement_min_pvalue,
        )
        if branches:
            results.append((segment, branches[0]))

    if intensive_mode and text and not results:
        whole_segment = SegmentCandidate(
            start=0,
            end=len(text),
            text=text,
            hinted_decoders=tuple(sorted(INTENSIVE_DECODER_IDS)),
        )
        whole_branches = decode_segment(
            whole_segment,
            decoders=_intensive_decoders(decoders),
            max_depth=max_depth,
            beam_width=beam_width,
            max_nodes=max_nodes_per_segment,
            intensive_mode=True,
            acceptance_filter=acceptance_filter,
            language_profiles=language_profiles,
            improvement_min_delta=improvement_min_delta,
            improvement_min_pvalue=improvement_min_pvalue,
        )
        if whole_branches:
            return [(whole_segment, whole_branches[0])]

    return results
