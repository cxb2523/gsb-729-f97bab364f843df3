import pytest
from cerbia.core.preprocessors.speculative_decoding._observability import capture_rejections, record_rejection
from cerbia.core.preprocessors.speculative_decoding._types import (
    RejectionReason,
)

pytestmark = pytest.mark.unit


def test_capture_rejections_counts_only_non_null_reasons() -> None:
    with capture_rejections() as rejections:
        record_rejection(reason=None)
        record_rejection(reason=RejectionReason.NO_IMPROVEMENT)

    assert rejections == {RejectionReason.NO_IMPROVEMENT: 1}


def test_record_rejection_increments_counter_for_concrete_reason() -> None:
    with capture_rejections() as rejections:
        record_rejection(
            reason=RejectionReason.OUTPUT_POLICY_FAILED,
        )

    assert rejections == {RejectionReason.OUTPUT_POLICY_FAILED: 1}
