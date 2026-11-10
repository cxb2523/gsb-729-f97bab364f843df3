from collections.abc import Mapping, Sequence

from ...i18n.language_profiles import LANGUAGE_PROFILES
from ._acceptance import AcceptanceFilter
from ._defaults import DEFAULT_IMPROVEMENT_MIN_DELTA, DEFAULT_IMPROVEMENT_MIN_PVALUE
from ._heuristics import byte_entropy, chi_squared_pvalue, printable_ratio
from ._observability import record_rejection
from ._types import DecodedBranch, OutputPolicy, Payload, RejectionReason

CHAIN_DEPTH_BONUS_DEPTH_1 = 1.0
CHAIN_DEPTH_BONUS_DEPTH_2 = 0.7
CHAIN_DEPTH_BONUS_DEPTH_3 = 0.4
CHAIN_DEPTH_BONUS_DEFAULT = 0.1
RAW_BYTE_ENTROPY_MAX_BITS = 8.0
IMPROVEMENT_BONUS_CAP = 0.20
OUTPUT_SCORE_WEIGHT_PVALUE = 0.45
OUTPUT_SCORE_WEIGHT_PRINTABLE_RATIO = 0.20
OUTPUT_SCORE_WEIGHT_INVERTED_ENTROPY = 0.15
OUTPUT_SCORE_WEIGHT_IMPROVEMENT = 0.10
OUTPUT_SCORE_WEIGHT_CHAIN_DEPTH = 0.10
SCORE_PERCENT_MAX = 100.0
SCORE_PERCENT_MIN = 0.0


def _chain_depth_bonus(depth: int) -> float:
    """Return the score bonus associated with a decode-chain depth.

    Args:
        depth (int): Number of decoders applied in the current chain.

    Returns:
        float: Depth bonus used by branch scoring.
    """
    if depth == 1:
        return CHAIN_DEPTH_BONUS_DEPTH_1

    if depth == 2:
        return CHAIN_DEPTH_BONUS_DEPTH_2

    if depth == 3:
        return CHAIN_DEPTH_BONUS_DEPTH_3

    return CHAIN_DEPTH_BONUS_DEFAULT


def _chi_squared_pvalue_with_profiles(
    data: bytes,
    language_profiles: Mapping[str, Sequence[float]] | None,
) -> float:
    """Compute chi-squared p-value with an optional profile override.

    Args:
        data (bytes): Raw bytes to score.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional override for language profiles.

    Returns:
        float: Best chi-squared p-value across the selected language profiles.
    """
    return chi_squared_pvalue(data, language_profiles if language_profiles is not None else LANGUAGE_PROFILES)


def _evaluate_acceptance(
    branch: DecodedBranch,
    acceptance: AcceptanceFilter,
    *,
    language_profiles: Mapping[str, Sequence[float]] | None = None,
) -> tuple[bool, RejectionReason | None, str]:
    """Evaluate terminal branch acceptance.

    Args:
        branch (DecodedBranch): Branch being considered as an accepted result.
        acceptance (AcceptanceFilter): Acceptance filter configuration.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.

    Returns:
        tuple[bool, RejectionReason | None, str]: Tuple of ``(accepted, reason, detail)`` describing the acceptance
            outcome.
    """
    if language_profiles is None:
        return acceptance.evaluate(branch)

    text = branch.payload.text or ""

    if len(text) < acceptance.min_text_length:
        return False, RejectionReason.ACCEPTANCE_FAILED, "too_short"

    if printable_ratio(text) < acceptance.min_printable_ratio:
        return False, RejectionReason.ACCEPTANCE_FAILED, "low_printable"

    entropy = byte_entropy(branch.payload.raw)
    if entropy > acceptance.max_entropy_bits:
        return False, RejectionReason.ACCEPTANCE_FAILED, "high_entropy"

    if _chi_squared_pvalue_with_profiles(branch.payload.raw, language_profiles) < acceptance.min_chi_squared_pvalue:
        return False, RejectionReason.ACCEPTANCE_FAILED, "low_pvalue"

    return True, None, ""


def _basic_output_policy_failure(
    payload: Payload,
    policy: OutputPolicy,
    *,
    is_leaf: bool,
) -> str | None:
    """Check non-statistical output-policy constraints.

    Args:
        payload (Payload): Candidate decoded payload.
        policy (OutputPolicy): Output policy associated with the decoder.
        is_leaf (bool): Whether the payload is being validated as a terminal result.

    Returns:
        str | None: Failure detail when a constraint is violated; otherwise, ``None``.
    """
    text = payload.text or ""

    if len(text) < policy.min_text_length:
        return "text_too_short"

    if printable_ratio(text) < policy.min_printable_ratio:
        return "printable_ratio_too_low"

    if _entropy_out_of_range(payload, policy):
        return "entropy_out_of_range"

    if not _matches_expected_pattern(payload, policy):
        return "pattern_mismatch"

    if is_leaf and policy.require_utf8 and payload.text is None:
        return "utf8_required"

    return None


def _entropy_out_of_range(payload: Payload, policy: OutputPolicy) -> bool:
    """Check whether payload entropy falls outside the allowed policy range.

    Args:
        payload (Payload): Candidate decoded payload.
        policy (OutputPolicy): Output policy associated with the decoder.

    Returns:
        bool: ``True`` when the payload entropy is outside the configured range.
    """
    if policy.entropy_range is None:
        return False

    entropy = byte_entropy(payload.raw)
    lo, hi = policy.entropy_range

    return entropy < lo or entropy > hi


def _matches_expected_pattern(payload: Payload, policy: OutputPolicy) -> bool:
    """Check whether payload text satisfies the policy's expected regex.

    Args:
        payload (Payload): Candidate decoded payload.
        policy (OutputPolicy): Output policy associated with the decoder.

    Returns:
        bool: ``True`` when the payload text matches the expected pattern.
    """
    if policy.expected_pattern is None:
        return True

    if payload.text is None:
        return False

    return policy.expected_pattern.fullmatch(payload.text) is not None


def _chi_squared_output_policy_failure(
    payload: Payload,
    policy: OutputPolicy,
    language_profiles: Mapping[str, Sequence[float]] | None,
) -> str | None:
    """Check chi-squared-specific output-policy constraints.

    Args:
        payload (Payload): Candidate decoded payload.
        policy (OutputPolicy): Output policy associated with the decoder.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.

    Returns:
        str | None: Failure detail when the p-value gate is not met; otherwise, ``None``.
    """
    if policy.min_chi_squared_pvalue <= 0.0:
        return None

    pvalue = _chi_squared_pvalue_with_profiles(payload.raw, language_profiles)
    if pvalue < policy.min_chi_squared_pvalue:
        return f"chi2_pvalue={pvalue:.4f}"

    return None


def passes_output_policy_with_profiles(
    payload: Payload,
    policy: OutputPolicy,
    *,
    is_leaf: bool,
    language_profiles: Mapping[str, Sequence[float]] | None = None,
) -> tuple[bool, RejectionReason | None, str | None]:
    """Evaluate whether a payload passes its output policy.

    Args:
        payload (Payload): Candidate decoded payload.
        policy (OutputPolicy): Output policy associated with the decoder.
        is_leaf (bool): Whether the payload is being validated as a terminal result.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.

    Returns:
        tuple[bool, RejectionReason | None, str | None]: Tuple of ``(accepted, reason, detail)`` describing the policy
            outcome.
    """
    failure = _basic_output_policy_failure(payload, policy, is_leaf=is_leaf)
    if failure is not None:
        return False, RejectionReason.OUTPUT_POLICY_FAILED, failure

    chi_squared_failure = _chi_squared_output_policy_failure(payload, policy, language_profiles)
    if chi_squared_failure is not None:
        return False, RejectionReason.OUTPUT_POLICY_FAILED, chi_squared_failure

    return True, None, None


def score_branch_with_profiles(
    original_bytes: bytes,
    branch: DecodedBranch,
    *,
    is_leaf: bool,
    acceptance: AcceptanceFilter,
    language_profiles: Mapping[str, Sequence[float]] | None = None,
    improvement_min_delta: float = DEFAULT_IMPROVEMENT_MIN_DELTA,
    improvement_min_pvalue: float = DEFAULT_IMPROVEMENT_MIN_PVALUE,
) -> tuple[float, RejectionReason | None, str | None]:
    """Score a decoded branch with optional profile overrides.

    Args:
        original_bytes (bytes): Original input bytes for the explored segment.
        branch (DecodedBranch): Candidate decoded branch to score.
        is_leaf (bool): Whether the branch is being evaluated as a terminal result.
        acceptance (AcceptanceFilter): Acceptance filter for terminal branches.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.
        improvement_min_delta (float): Minimum p-value improvement required to score a branch.
        improvement_min_pvalue (float): Minimum absolute p-value required to score a branch.

    Returns:
        tuple[float, RejectionReason | None, str | None]: Tuple of ``(score, reason, detail)`` describing either the
            score or the rejection.
    """
    p_in = _chi_squared_pvalue_with_profiles(original_bytes, language_profiles)
    p_out = _chi_squared_pvalue_with_profiles(branch.payload.raw, language_profiles)

    if p_out < p_in + improvement_min_delta or p_out < improvement_min_pvalue:
        return 0.0, RejectionReason.NO_IMPROVEMENT, f"p_in={p_in:.3f} p_out={p_out:.3f}"

    if is_leaf:
        accepted, reason, detail = _evaluate_acceptance(
            branch,
            acceptance,
            language_profiles=language_profiles,
        )
        if not accepted:
            return 0.0, reason, detail

    normalized_entropy = min(1.0, max(0.0, byte_entropy(branch.payload.raw) / RAW_BYTE_ENTROPY_MAX_BITS))
    improvement_bonus = min(p_out - p_in, IMPROVEMENT_BONUS_CAP)
    score = (
        (OUTPUT_SCORE_WEIGHT_PVALUE * p_out)
        + (OUTPUT_SCORE_WEIGHT_PRINTABLE_RATIO * printable_ratio(branch.payload.text or ""))
        + (OUTPUT_SCORE_WEIGHT_INVERTED_ENTROPY * (1.0 - normalized_entropy))
        + (OUTPUT_SCORE_WEIGHT_IMPROVEMENT * improvement_bonus)
        + (OUTPUT_SCORE_WEIGHT_CHAIN_DEPTH * _chain_depth_bonus(len(branch.chain)))
    )

    return min(SCORE_PERCENT_MAX, max(SCORE_PERCENT_MIN, score * SCORE_PERCENT_MAX)), None, None


def prune_terminal_branch(
    chain: tuple[str, ...],
    results_by_chain: dict[tuple[str, ...], DecodedBranch],
    acceptance_filter: AcceptanceFilter,
    language_profiles: Mapping[str, Sequence[float]] | None,
) -> None:
    """Remove a terminal branch result if it fails final acceptance.

    Args:
        chain (tuple[str, ...]): Decoder chain for the terminal branch.
        results_by_chain (dict[tuple[str, ...], DecodedBranch]): Accepted results indexed by chain.
        acceptance_filter (AcceptanceFilter): Acceptance filter for terminal branches.
        language_profiles (Mapping[str, Sequence[float]] | None): Optional language profiles override.
    """
    if not chain:
        return

    branch = results_by_chain.get(chain)
    if branch is None:
        return

    accepted, reason, _ = _evaluate_acceptance(
        branch,
        acceptance_filter,
        language_profiles=language_profiles,
    )

    if not accepted:
        record_rejection(
            reason=reason,
        )
        results_by_chain.pop(chain, None)
