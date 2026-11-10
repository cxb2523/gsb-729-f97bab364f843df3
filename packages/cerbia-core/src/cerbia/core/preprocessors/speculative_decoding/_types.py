from __future__ import annotations

import re
from collections.abc import Callable
from enum import StrEnum
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field


class Payload(BaseModel, frozen=True):
    """Immutable container for decoded content in both raw and text form.

    Decoders that operate on bytes (e.g. gzip) produce payloads where ``text`` may be ``None`` if the raw bytes are not
    valid UTF-8.

    Attributes:
        raw (bytes): Decoded bytes preserved exactly as produced by the decoder chain.
        text (str | None): UTF-8 text view of ``raw`` when strict decoding succeeds.
    """

    raw: bytes
    text: str | None

    @classmethod
    def from_text(cls, text: str) -> Payload:
        """Build a payload from UTF-8 text.

        Args:
            text (str): Text to store in both string and byte form.

        Returns:
            Payload: Payload with ``raw`` encoded as UTF-8 and ``text`` preserved.
        """
        return cls(raw=text.encode("utf-8"), text=text)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Payload:
        """Build a payload from bytes while preserving an optional UTF-8 view.

        Args:
            raw (bytes): Raw bytes produced by a decoder.

        Returns:
            Payload: Payload with ``text`` populated only when strict UTF-8 decoding succeeds.
        """
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = None

        return cls(raw=raw, text=text)


class OutputPolicy(BaseModel, frozen=True):
    """Validation rules applied to decoder output before further exploration.

    Attributes:
        min_printable_ratio (float): Minimum printable-character ratio accepted for text output.
        min_text_length (int): Minimum text length required for accepted output.
        entropy_range (tuple[float, float] | None): Optional inclusive entropy range allowed for raw bytes.
        expected_pattern (re.Pattern[str] | None): Optional full-match regex that accepted text must satisfy.
        require_utf8 (bool): Whether terminal output must decode as strict UTF-8 text.
        min_chi_squared_pvalue (float): Minimum language-fit p-value required by the policy.
    """

    min_printable_ratio: float = 0.70
    min_text_length: int = 4
    entropy_range: tuple[float, float] | None = None
    expected_pattern: re.Pattern[str] | None = None
    require_utf8: bool = False
    min_chi_squared_pvalue: float = 0.0


class DecoderSpec(BaseModel):
    """Descriptor for a single encoding/decoding operation.

    Attributes:
        decoder_id (str): Unique identifier (e.g. ``"base64"``, ``"rot13"``).
        extract_patterns (tuple[re.Pattern[str], ...]): Regexes used to find candidate segments in raw text. Empty for
            ``chain_only`` decoders.
        chain_only (bool): If ``True``, this decoder only applies to already-extracted segments.
        input_gate (Callable[[str], bool]): Predicate that checks raw candidate textbefore payload decoding.
        accepts (Callable[[Payload], bool]): Predicate that checks whether this decoder can handle the given payload
            (e.g. entropy range check, pattern match).
        decode (Callable[[Payload], list[Payload]]): Function that attempts to decode the payload. Returns a list of
            successfully decoded payloads (may be empty).
        output_policy (OutputPolicy): Validation criteria for decoded output.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    decoder_id: str
    extract_patterns: tuple[re.Pattern[str], ...] = ()
    chain_only: bool = False
    input_gate: Callable[[str], bool] = Field(default=lambda _s: True)
    accepts: Callable[[Payload], bool] = Field(default=lambda _p: True)
    decode: Callable[[Payload], list[Payload]] = Field(default=lambda _p: [])
    output_policy: OutputPolicy = Field(default_factory=OutputPolicy)


class SegmentCandidate(BaseModel, frozen=True):
    """Suspicious text span selected for speculative decoding.

    Attributes:
        start (int): Start offset of the candidate span in the original text.
        end (int): End offset of the candidate span in the original text.
        text (str): Text content extracted for decoder exploration.
        hinted_decoders (tuple[str, ...]): Decoder IDs whose extraction patterns matched the span.
    """

    start: int
    end: int
    text: str
    hinted_decoders: tuple[str, ...]


class DecodedBranch(BaseModel, frozen=True):
    """State for one explored decode path.

    Attributes:
        payload (Payload): Current decoded payload at this branch.
        chain (tuple[str, ...]): Ordered decoder IDs applied to reach the payload.
        depth (int): Recursive search depth of the branch.
        score (float): Weighted branch score used for beam ranking and selection.
    """

    payload: Payload
    chain: tuple[str, ...]
    depth: int
    score: float


class RejectionReason(StrEnum):
    """Reason codes for branch rejection in the speculative engine.

    Attributes:
        INPUT_GATE_FAILED (str): Segment failed the decoder's raw text input gate.
        ACCEPTS_FAILED (str): Segment failed the decoder's ``accepts`` predicate.
        OUTPUT_POLICY_FAILED (str): Decoded output failed the decoder's ``output_policy``.
        ACCEPTANCE_FAILED (str): Terminal branch failed the global ``AcceptanceFilter``.
        NO_IMPROVEMENT (str): Branch p-value did not improve enough over the parent.
        EXCESSIVE_DEPTH (str): Branch reached the maximum configured search depth.
        BUDGET_EXHAUSTED (str): Search reached the maximum configured node count.
    """

    INPUT_GATE_FAILED = "INPUT_GATE_FAILED"
    ACCEPTS_FAILED = "ACCEPTS_FAILED"
    OUTPUT_POLICY_FAILED = "OUTPUT_POLICY_FAILED"
    ACCEPTANCE_FAILED = "ACCEPTANCE_FAILED"
    NO_IMPROVEMENT = "NO_IMPROVEMENT"
    EXCESSIVE_DEPTH = "EXCESSIVE_DEPTH"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
