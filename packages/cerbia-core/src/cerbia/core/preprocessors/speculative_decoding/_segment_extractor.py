from ._decoders import DECODERS
from ._types import DecoderSpec, SegmentCandidate


def _collect_raw_matches(
    text: str,
    decoders: tuple[DecoderSpec, ...],
) -> list[tuple[int, int, str, str]]:
    """Collect raw extractor matches for all non-chain-only decoders.

    Args:
        text (str): Source text to scan.
        decoders (tuple[DecoderSpec, ...]): Decoder specifications whose extraction patterns should run.

    Returns:
        list[tuple[int, int, str, str]]: Tuples of ``(start, end, matched_text, decoder_id)`` for every match.
    """
    raw_matches: list[tuple[int, int, str, str]] = []
    for decoder in decoders:
        if decoder.chain_only:
            continue

        for pattern in decoder.extract_patterns:
            for match in pattern.finditer(text):
                start, end = match.start(), match.end()
                matched_text = match.group(1) if match.lastindex else match.group()
                raw_matches.append((start, end, matched_text, decoder.decoder_id))

    return raw_matches


def _try_merge_with_existing(
    merged: list[SegmentCandidate],
    text: str,
    start: int,
    end: int,
    decoder_id: str,
) -> bool:
    """Merge a raw match into an existing segment when spans overlap.

    Args:
        merged (list[SegmentCandidate]): Current merged segment candidates.
        text (str): Original source text.
        start (int): Start offset of the new match.
        end (int): End offset of the new match.
        decoder_id (str): Decoder that produced the new match.

    Returns:
        bool: ``True`` when the match was merged into an existing segment.
    """
    for i, existing in enumerate(merged):
        replacement = _merged_segment_candidate(existing, text, start, end, decoder_id)

        if replacement is None:
            continue

        if replacement != existing:
            merged[i] = replacement

        return True

    return False


def _merged_segment_candidate(
    existing: SegmentCandidate,
    text: str,
    start: int,
    end: int,
    decoder_id: str,
) -> SegmentCandidate | None:
    """Build a merged segment candidate when two spans overlap.

    Args:
        existing (SegmentCandidate): Existing merged segment.
        text (str): Original source text.
        start (int): Start offset of the new match.
        end (int): End offset of the new match.
        decoder_id (str): Decoder that produced the new match.

    Returns:
        SegmentCandidate | None: Replacement segment candidate when the spans overlap; otherwise, ``None``.
    """
    is_contained = start >= existing.start and end <= existing.end
    overlaps = start < existing.end and end > existing.start

    if not (is_contained or overlaps):
        return None

    merged_start = existing.start if is_contained else min(start, existing.start)
    merged_end = existing.end if is_contained else max(end, existing.end)
    merged_text = existing.text if is_contained else text[merged_start:merged_end]
    hinted_decoders = existing.hinted_decoders

    if decoder_id not in hinted_decoders:
        hinted_decoders = (*hinted_decoders, decoder_id)

    return SegmentCandidate(
        start=merged_start,
        end=merged_end,
        text=merged_text,
        hinted_decoders=hinted_decoders,
    )


def extract_segments(
    text: str,
    decoders: tuple[DecoderSpec, ...] = DECODERS,
    max_segments: int = 20,
) -> list[SegmentCandidate]:
    """Return merged suspicious spans so search explores each encoded region once.

    Args:
        text (str): Input text to analyze.
        decoders (tuple[DecoderSpec, ...]): Decoder specifications whose extractors hint plausible encodings.
        max_segments (int): Upper bound on extracted regions to keep search bounded.

    Returns:
        list[SegmentCandidate]: Ordered segment candidates with overlapping hints merged onto one span.
    """
    raw_matches = _collect_raw_matches(text, decoders)

    if not raw_matches:
        return []

    raw_matches.sort(key=lambda m: (m[0], -(m[1] - m[0])))

    merged: list[SegmentCandidate] = []
    for start, end, matched_text, decoder_id in raw_matches:
        if not _try_merge_with_existing(merged, text, start, end, decoder_id):
            merged.append(SegmentCandidate(start=start, end=end, text=matched_text, hinted_decoders=(decoder_id,)))

    merged.sort(key=lambda s: s.start)

    return merged[:max_segments]
