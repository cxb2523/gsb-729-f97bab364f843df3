import re

import pytest
from cerbia.core.preprocessors.speculative_decoding._acceptance import AcceptanceFilter
from cerbia.core.preprocessors.speculative_decoding._scoring import (
    passes_output_policy_with_profiles,
    prune_terminal_branch,
    score_branch_with_profiles,
)
from cerbia.core.preprocessors.speculative_decoding._types import DecodedBranch, OutputPolicy, Payload, RejectionReason

pytestmark = pytest.mark.unit


def _branch(text: str = "decoded text") -> DecodedBranch:
    return DecodedBranch(payload=Payload.from_text(text), chain=("base64",), depth=1, score=0.0)


@pytest.mark.parametrize(
    ("payload", "policy", "is_leaf", "detail"),
    [
        (Payload.from_text("x"), OutputPolicy(min_text_length=2), False, "text_too_short"),
        (Payload.from_text("text"), OutputPolicy(min_printable_ratio=1.1), False, "printable_ratio_too_low"),
        (Payload.from_text("text"), OutputPolicy(entropy_range=(9.0, 10.0)), False, "entropy_out_of_range"),
        (Payload.from_text("text"), OutputPolicy(expected_pattern=re.compile(r"digits")), False, "pattern_mismatch"),
        (
            Payload.from_bytes(b"\xff"),
            OutputPolicy(min_text_length=0, min_printable_ratio=0.0, require_utf8=True),
            True,
            "utf8_required",
        ),
    ],
    ids=["short", "non_printable", "entropy", "pattern", "utf8"],
)
def test_passes_output_policy_returns_rejection_detail_when_basic_policy_fails(
    payload, policy, is_leaf: bool, detail: str
) -> None:
    accepted, reason, actual_detail = passes_output_policy_with_profiles(payload, policy, is_leaf=is_leaf)

    assert accepted is False
    assert reason is RejectionReason.OUTPUT_POLICY_FAILED
    assert actual_detail == detail


def test_passes_output_policy_accepts_payload_when_fixed_chi_squared_floor_is_met(mocker) -> None:
    payload = Payload.from_text("decoded payload")
    policy = OutputPolicy(min_chi_squared_pvalue=0.5)
    mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._scoring._chi_squared_pvalue_with_profiles",
        return_value=0.5,
    )

    accepted, reason, detail = passes_output_policy_with_profiles(payload, policy, is_leaf=True)

    assert accepted is True
    assert reason is None
    assert detail is None


def test_passes_output_policy_rejects_payload_below_fixed_chi_squared_floor(mocker) -> None:
    payload = Payload.from_text("decoded payload")
    policy = OutputPolicy(min_chi_squared_pvalue=0.5)
    mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._scoring._chi_squared_pvalue_with_profiles",
        return_value=0.49,
    )

    accepted, reason, detail = passes_output_policy_with_profiles(payload, policy, is_leaf=True)

    assert accepted is False
    assert reason is RejectionReason.OUTPUT_POLICY_FAILED
    assert detail == "chi2_pvalue=0.4900"


def test_passes_output_policy_applies_utf8_requirement_only_to_terminal_leaves() -> None:
    payload = Payload.from_bytes(b"\xff")
    policy = OutputPolicy(min_text_length=0, min_printable_ratio=0.0, require_utf8=True)

    intermediate = passes_output_policy_with_profiles(payload, policy, is_leaf=False)
    terminal = passes_output_policy_with_profiles(payload, policy, is_leaf=True)

    assert intermediate == (True, None, None)
    assert terminal == (False, RejectionReason.OUTPUT_POLICY_FAILED, "utf8_required")


def test_score_branch_returns_no_improvement_when_pvalue_threshold_is_not_met(mocker) -> None:
    mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._scoring._chi_squared_pvalue_with_profiles",
        side_effect=[0.4, 0.42],
    )

    score, reason, detail = score_branch_with_profiles(
        b"original", _branch(), is_leaf=False, acceptance=AcceptanceFilter()
    )

    assert score == 0.0
    assert reason is RejectionReason.NO_IMPROVEMENT
    assert detail == "p_in=0.400 p_out=0.420"


def test_score_branch_returns_score_when_improvement_and_acceptance_pass(mocker) -> None:
    mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._scoring._chi_squared_pvalue_with_profiles",
        side_effect=[0.1, 0.8],
    )
    mocker.patch("cerbia.core.preprocessors.speculative_decoding._scoring.byte_entropy", return_value=1.0)
    mocker.patch("cerbia.core.preprocessors.speculative_decoding._scoring.printable_ratio", return_value=1.0)
    acceptance = mocker.Mock(spec=AcceptanceFilter)
    acceptance.evaluate.return_value = (True, None, "")

    score, reason, detail = score_branch_with_profiles(b"original", _branch(), is_leaf=True, acceptance=acceptance)

    assert score > 0.0
    assert reason is None
    assert detail is None
    acceptance.evaluate.assert_called_once()


def test_score_branch_only_applies_acceptance_filter_to_terminal_leaf(mocker) -> None:
    mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._scoring._chi_squared_pvalue_with_profiles",
        side_effect=[0.1, 0.8],
    )
    mocker.patch("cerbia.core.preprocessors.speculative_decoding._scoring.byte_entropy", return_value=1.0)
    mocker.patch("cerbia.core.preprocessors.speculative_decoding._scoring.printable_ratio", return_value=1.0)
    acceptance = mocker.Mock(spec=AcceptanceFilter)
    acceptance.evaluate.return_value = (False, RejectionReason.ACCEPTANCE_FAILED, "too_short")

    score, reason, detail = score_branch_with_profiles(b"original", _branch(), is_leaf=False, acceptance=acceptance)

    assert score > 0.0
    assert reason is None
    assert detail is None
    acceptance.evaluate.assert_not_called()


def test_score_branch_ranks_larger_fixed_pvalue_improvement_higher(mocker) -> None:
    mocker.patch(
        "cerbia.core.preprocessors.speculative_decoding._scoring._chi_squared_pvalue_with_profiles",
        side_effect=[0.1, 0.7, 0.1, 0.9],
    )
    mocker.patch("cerbia.core.preprocessors.speculative_decoding._scoring.byte_entropy", return_value=1.0)
    mocker.patch("cerbia.core.preprocessors.speculative_decoding._scoring.printable_ratio", return_value=1.0)
    acceptance = AcceptanceFilter()

    lower_score, _, _ = score_branch_with_profiles(b"original", _branch(), is_leaf=False, acceptance=acceptance)
    higher_score, _, _ = score_branch_with_profiles(b"original", _branch(), is_leaf=False, acceptance=acceptance)

    assert 0.0 <= lower_score < higher_score <= 100.0


def test_prune_terminal_branch_removes_rejected_result(mocker) -> None:
    branch = _branch()
    results = {branch.chain: branch}
    acceptance = mocker.Mock(spec=AcceptanceFilter)
    acceptance.evaluate.return_value = (False, RejectionReason.ACCEPTANCE_FAILED, "too_short")

    prune_terminal_branch(branch.chain, results, acceptance, language_profiles=None)

    assert results == {}
