import logging
from collections.abc import Mapping, Sequence
from typing import TypedDict

from ...i18n.language_profiles import LANGUAGE_PROFILES
from ...models.entries import Entry
from ._acceptance import AcceptanceFilter
from ._decoders import DECODERS
from ._defaults import (
    DEFAULT_BEAM_WIDTH,
    DEFAULT_IMPROVEMENT_MIN_DELTA,
    DEFAULT_IMPROVEMENT_MIN_PVALUE,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_NODES,
    DEFAULT_MAX_SEGMENTS,
)
from ._engine import decode_text
from ._observability import capture_rejections
from ._types import DecoderSpec, RejectionReason

logger = logging.getLogger(__name__)


class _DecodedSegmentMetadata(TypedDict):
    """Metadata stored for one accepted decoded segment.

    Attributes:
        decoder_chain (list[str]): Ordered decoder IDs that produced the accepted payload.
        span (list[int]): Start and end offsets of the original suspicious segment.
        original_segment (str): Raw segment text extracted from the input entry.
        decoded_segment (str): Replacement text written back into the derived entry.
    """

    decoder_chain: list[str]
    span: list[int]
    original_segment: str
    decoded_segment: str


class SpeculativeDecodingPreprocessor:
    """Detects and decodes obfuscated payloads hidden inside text entries.

    Uses a BFS beam-search engine to extract encoded segments (Base64, hex, URL-encoding, etc.), recursively decode them
    through chained decoders, and produce derived ``Entry`` objects with the decoded content spliced back into the
    original text.

    Attributes:
        preprocessor_id (str): Unique identifier for this preprocessor instance.
        preprocessor_name (str): Human-readable name used for logging and reporting.

    Args:
        max_depth (int): Maximum recursive decoding depth per segment.
        beam_width (int): Number of candidate branches to keep per BFS level.
        max_nodes_per_segment (int): Hard cap on total nodes explored per segment.
        max_segments_per_entry (int): Maximum suspicious segments to analyze per entry.
        decoders (Sequence[DecoderSpec] | None): Custom decoder specifications. Defaults to the built-in suite.
        intensive_mode (bool): Enables depth-0 intensive decoders such as ROT13.
        language_profiles (Mapping[str, Sequence[float]] | None): Language profiles used by chi-squared scoring.
        acceptance (AcceptanceFilter | None): Acceptance filter applied to terminal decoded branches.
        improvement_min_delta (float): Minimum p-value improvement required to score a branch.
        improvement_min_pvalue (float): Minimum absolute p-value required to score a branch.

    Raises:
        ValueError: If any numeric threshold is outside its valid range.
    """

    def __init__(
        self,
        *,
        max_depth: int = DEFAULT_MAX_DEPTH,
        beam_width: int = DEFAULT_BEAM_WIDTH,
        max_nodes_per_segment: int = DEFAULT_MAX_NODES,
        max_segments_per_entry: int = DEFAULT_MAX_SEGMENTS,
        decoders: Sequence[DecoderSpec] | None = None,
        intensive_mode: bool = False,
        language_profiles: Mapping[str, Sequence[float]] | None = None,
        acceptance: AcceptanceFilter | None = None,
        improvement_min_delta: float = DEFAULT_IMPROVEMENT_MIN_DELTA,
        improvement_min_pvalue: float = DEFAULT_IMPROVEMENT_MIN_PVALUE,
    ) -> None:
        _validate_minimum(name="max_depth", value=max_depth, minimum=1)
        _validate_minimum(name="beam_width", value=beam_width, minimum=1)
        _validate_probability(name="improvement_min_delta", value=improvement_min_delta)
        _validate_probability(name="improvement_min_pvalue", value=improvement_min_pvalue)

        self.preprocessor_id: str = "speculative_decoding"
        self.preprocessor_name: str = "Speculative Decoding"
        self._max_depth: int = max_depth
        self._beam_width: int = beam_width
        self._max_nodes_per_segment: int = max_nodes_per_segment
        self._max_segments_per_entry: int = max_segments_per_entry
        self._decoders: tuple[DecoderSpec, ...] = tuple(decoders) if decoders is not None else DECODERS
        self._intensive_mode: bool = intensive_mode
        self._language_profiles: dict[str, tuple[float, ...]] = {
            language: tuple(profile) for language, profile in (language_profiles or LANGUAGE_PROFILES).items()
        }
        self._acceptance: AcceptanceFilter = acceptance if acceptance is not None else AcceptanceFilter()
        self._improvement_min_delta: float = improvement_min_delta
        self._improvement_min_pvalue: float = improvement_min_pvalue

    @property
    def _acceptance_filter(self) -> AcceptanceFilter:
        """Return the effective acceptance filter used during search.

        Returns:
            AcceptanceFilter: Effective acceptance filter for terminal branch validation.
        """
        return self._acceptance

    def process(self, entries: list[Entry]) -> list[Entry]:
        """Preserve entry count while rewriting only spans with accepted better decodes.

        Args:
            entries (list[Entry]): Input entries to process.

        Returns:
            list[Entry]: One entry per input, with clean entries returned unchanged and changed entries carrying
                rejection metadata under ``speculative_decoding.rejections`` plus decoded-span metadata when
                speculative search finds an accepted improvement.
        """
        output: list[Entry] = []

        for entry in entries:
            with capture_rejections() as rejections:
                results = decode_text(
                    entry.text,
                    decoders=self._decoders,
                    max_depth=self._max_depth,
                    beam_width=self._beam_width,
                    max_nodes_per_segment=self._max_nodes_per_segment,
                    max_segments=self._max_segments_per_entry,
                    intensive_mode=self._intensive_mode,
                    acceptance_filter=self._acceptance_filter,
                    language_profiles=self._language_profiles,
                    improvement_min_delta=self._improvement_min_delta,
                    improvement_min_pvalue=self._improvement_min_pvalue,
                )

            decoded_segments: list[_DecodedSegmentMetadata] = [
                {
                    "decoder_chain": list(branch.chain),
                    "span": [segment.start, segment.end],
                    "original_segment": segment.text,
                    "decoded_segment": branch.payload.text,
                }
                for segment, branch in results
                if branch.payload.text is not None
            ]

            rewritten: str = entry.text
            for segment in reversed(decoded_segments):
                start = segment["span"][0]
                end = segment["span"][1]
                rewritten = rewritten[:start] + segment["decoded_segment"] + rewritten[end:]

            if rewritten == entry.text:
                output.append(entry)
                continue

            processed_entry = entry.derive(rewritten, self.preprocessor_id)
            metadata_updates = _build_metadata_updates(
                processed_entry=processed_entry,
                decoded_segments=decoded_segments,
                rejections=rejections,
            )

            processed_entry.metadata.preprocessors[self.preprocessor_id] = metadata_updates
            output.append(processed_entry)

        processed_count = len(entries)
        result_count = len(output)
        logger.debug(
            "%s entries decoded",
            processed_count,
            extra={
                "operation": "process",
                "stage": "decoding",
                "component_kind": "preprocessor",
                "outcome": "completed",
                "processed_count": processed_count,
                "result_count": result_count,
            },
        )
        return output


def _build_metadata_updates(
    *,
    processed_entry: Entry,
    decoded_segments: list[_DecodedSegmentMetadata],
    rejections: Mapping[RejectionReason, int],
) -> dict[str, object]:
    """Build metadata updates for a processed entry.

    Args:
        processed_entry (Entry): Entry after optional text rewriting.
        decoded_segments (list[_DecodedSegmentMetadata]): Accepted decoded segments to expose in metadata.
        rejections (Mapping[RejectionReason, int]): Aggregated rejection counters captured during processing.

    Returns:
        dict[str, object]: Canonical speculative-decoding metadata mapping.
    """
    speculative_metadata = processed_entry.metadata.preprocessors.get("speculative_decoding", {}).copy()
    speculative_metadata["rejections"] = {
        reason.value: count for reason, count in sorted(rejections.items(), key=lambda item: item[0].value)
    }

    if decoded_segments:
        speculative_metadata["decoded_segments"] = decoded_segments

    return speculative_metadata


def _validate_minimum(*, name: str, value: int, minimum: int) -> None:
    """Validate that an integer configuration value meets its minimum.

    Args:
        name (str): Human-readable parameter name for error reporting.
        value (int): Value provided by the caller.
        minimum (int): Inclusive lower bound.

    Raises:
        ValueError: If ``value`` is lower than ``minimum``.
    """
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")


def _validate_probability(*, name: str, value: float) -> None:
    """Validate that a probability-like configuration value is in ``[0.0, 1.0]``.

    Args:
        name (str): Human-readable parameter name for error reporting.
        value (float): Value provided by the caller.

    Raises:
        ValueError: If ``value`` falls outside the inclusive probability range.
    """
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0.0 and 1.0")
