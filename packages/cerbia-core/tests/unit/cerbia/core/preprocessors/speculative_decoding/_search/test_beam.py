from collections import deque

import pytest
from cerbia.core.preprocessors.speculative_decoding._acceptance import AcceptanceFilter
from cerbia.core.preprocessors.speculative_decoding._search import _beam
from cerbia.core.preprocessors.speculative_decoding._types import OutputPolicy, Payload, RejectionReason

pytestmark = pytest.mark.unit


def test_process_children_keeps_highest_scored_candidates_within_beam_width(mocker) -> None:
    first, second = Payload.from_text("first"), Payload.from_text("second")
    children: list[tuple[Payload, tuple[str, ...], OutputPolicy]] = [
        (first, ("first",), OutputPolicy()),
        (second, ("second",), OutputPolicy()),
    ]
    queue = deque()
    mocker.patch.object(
        _beam,
        "_score_child_for_beam",
        side_effect=[(10.0, first, ("first",), OutputPolicy()), (20.0, second, ("second",), OutputPolicy())],
    )
    accepted = mocker.patch.object(_beam, "_accept_scored_child")

    _beam.process_children("original", b"original", children, 0, queue, {}, 1, AcceptanceFilter(), None, 0.05, 0.05, ())

    accepted.assert_called_once()
    assert list(queue) == [(second, ("second",), 1)]


def test_process_children_does_not_accept_or_queue_scored_children_when_beam_width_is_zero(mocker) -> None:
    payload = Payload.from_text("decoded")
    children: list[tuple[Payload, tuple[str, ...], OutputPolicy]] = [(payload, ("base64",), OutputPolicy())]
    queue = deque()
    mocker.patch.object(_beam, "_score_child_for_beam", return_value=(10.0, payload, ("base64",), OutputPolicy()))
    accepted = mocker.patch.object(_beam, "_accept_scored_child")

    _beam.process_children("original", b"original", children, 0, queue, {}, 0, AcceptanceFilter(), None, 0.05, 0.05, ())

    accepted.assert_not_called()
    assert list(queue) == []


def test_score_child_for_beam_queues_no_improvement_when_followup_is_viable(mocker) -> None:
    payload = Payload.from_text("intermediate")
    queue = deque()
    mocker.patch.object(
        _beam,
        "_score_child_candidate",
        return_value=(0.0, RejectionReason.NO_IMPROVEMENT, "p_in=0.800 p_out=0.800"),
    )
    mocker.patch.object(_beam, "_queue_viable_followup", return_value=True)
    rejected = mocker.patch.object(_beam, "_record_child_rejection")

    scored_child = _beam._score_child_for_beam(
        b"original",
        payload,
        ("base64",),
        OutputPolicy(),
        1,
        queue,
        AcceptanceFilter(),
        None,
        0.05,
        0.05,
        (),
    )

    assert scored_child is None
    rejected.assert_not_called()


def test_score_child_for_beam_records_hard_rejection_when_no_followup_is_viable(mocker) -> None:
    payload = Payload.from_text("intermediate")
    queue = deque()
    mocker.patch.object(
        _beam,
        "_score_child_candidate",
        return_value=(0.0, RejectionReason.NO_IMPROVEMENT, "p_in=0.800 p_out=0.800"),
    )
    mocker.patch.object(_beam, "_queue_viable_followup", return_value=False)
    rejected = mocker.patch.object(_beam, "_record_child_rejection")

    scored_child = _beam._score_child_for_beam(
        b"original",
        payload,
        ("base64",),
        OutputPolicy(),
        1,
        queue,
        AcceptanceFilter(),
        None,
        0.05,
        0.05,
        (),
    )

    assert scored_child is None
    assert list(queue) == []
    rejected.assert_called_once_with(
        reason=RejectionReason.NO_IMPROVEMENT,
    )


def test_has_scored_children_returns_true_for_binary_child_without_scoring() -> None:
    result = _beam.has_scored_children(
        b"original", [(Payload.from_bytes(b"\xff"), ("gzip",), OutputPolicy())], 0, AcceptanceFilter(), None, 0.05, 0.05
    )

    assert result is True


def test_has_scored_children_returns_false_when_all_text_children_are_rejected(mocker) -> None:
    mocker.patch.object(
        _beam,
        "score_branch_with_profiles",
        return_value=(0.0, RejectionReason.NO_IMPROVEMENT, "p_in=0.800 p_out=0.800"),
    )
    rejected = mocker.patch.object(_beam, "_record_child_rejection")

    result = _beam.has_scored_children(
        b"original", [(Payload.from_text("text"), ("base64",), OutputPolicy())], 0, AcceptanceFilter(), None, 0.05, 0.05
    )

    assert result is False
    rejected.assert_called_once()
