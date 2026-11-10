import gc
import weakref

import pytest
from cerbia.core.models.scans import ScanOutcome
from cerbia.core.security_gate import CascadeExecutionError
from cerbia.core.types import ContentType

from .cascade_support import Aggregate, Leaf, leaf, numerical, runner, veto

pytestmark = pytest.mark.unit


def test_terminal_block_completes_own_scanners_and_skips_later_stages() -> None:
    gate = runner(
        [
            veto([leaf("a", 0.2, severity="low"), leaf("b", 0.9, action="warn"), leaf("c")]),
            numerical("last", [leaf("later")]),
        ]
    ).gate

    result = gate.scan("sample")

    assert not result.is_safe
    assert result.score == 0.05
    assert Leaf.calls == ["a", "b", "c"]
    assert [finding.stage for finding in result.findings] == ["guard"] * 3
    assert result.stages is not None
    assert result.stages[1].result == "not_reached"


@pytest.mark.parametrize("risk", [0.0, 0.2, 0.20001, 0.9, 0.90001])
def test_score_bands_preserve_exact_equality_and_route_fallback(risk: float) -> None:
    gate = runner(
        [numerical("primary", [leaf("primary", risk)], final=False), numerical("fallback", [leaf("fallback")])]
    ).gate

    result = gate.scan("sample")

    deferred = 0.2 < risk <= 0.9
    assert result.is_safe is (risk <= 0.9)
    assert Leaf.calls == (["primary", "fallback"] if deferred else ["primary"])
    assert result.stages is not None
    assert [stage.result for stage in result.stages] == (
        ["defer", "allow"] if deferred else ["allow" if risk <= 0.2 else "block", "not_reached"]
    )
    assert result.score == (0.0 if deferred else risk)


def test_three_stages_aggregate_only_current_outcomes_and_retain_owned_findings() -> None:
    gate = runner(
        [
            numerical("a", [leaf("a", 0.6, severity="high")], final=False),
            numerical("b", [leaf("b", 0.4, severity="low")], final=False, defer_above=0.0),
            numerical("c", [leaf("c", 0.2)], aggregator="Local"),
        ]
    ).gate

    result = gate.scan("sample")

    assert Aggregate.inputs == [[0.2]]
    assert Leaf.calls == ["a", "b", "c"]
    assert [finding.stage for finding in result.findings] == ["a", "b", "c"]
    assert result.stages is not None
    assert [stage.result for stage in result.stages] == ["defer", "defer", "allow"]


def test_prior_deferred_score_does_not_prevent_current_stage_allow() -> None:
    gate = runner(
        [
            numerical("prior", [leaf("prior", 0.6)], final=False),
            numerical("primary", [leaf("primary")], final=False),
            numerical("fallback", [leaf("fallback")]),
        ]
    ).gate

    result = gate.scan("sample")

    assert result.is_safe
    assert result.score == 0.0
    assert Leaf.calls == ["prior", "primary"]
    assert [finding.stage for finding in result.findings] == ["prior", "primary"]


def test_unknown_content_executes_required_typed_scanner() -> None:
    gate = runner([numerical("last", [leaf("text", content_types=["text"])])]).gate

    result = gate.scan("sample", content_type=ContentType.UNKNOWN)

    assert result.is_safe
    assert Leaf.calls == ["text"]


@pytest.mark.parametrize("unsupported", [False, True])
def test_required_scanner_fault_blocks_without_fabricating_findings(unsupported: bool) -> None:
    second = leaf("b", content_types=["url"]) if unsupported else leaf("b")
    gate = runner(
        [numerical("first", [leaf("a", 0.2), second, leaf("c")], final=False), numerical("last", [leaf("d")])],
        policy="block",
    ).gate
    if not unsupported:
        Leaf.failures["b"] = RuntimeError("private failure")

    result = gate.scan("sample", content_type=ContentType.TEXT)

    assert not result.is_safe
    assert result.score == 1.0
    assert [finding.scanner_id for finding in result.findings] == ["a"]
    assert result.stages is not None
    assert result.stages[0].result == "block"
    assert result.stages[0].score is None
    assert result.stages[1].result == "not_reached"
    assert result.rationale == f"Cascade stage first: {'unsupported_content' if unsupported else 'scanner_error'}"
    assert Leaf.calls == (["a"] if unsupported else ["a", "b"])
    assert "private failure" not in result.model_dump_json()


def test_scanner_fail_preserves_exception_and_cause_identity() -> None:
    gate = runner([numerical("last", [leaf("a"), leaf("b")])]).gate
    cause = OSError("private cause")
    error = RuntimeError("private detail")
    error.__cause__ = cause
    Leaf.failures["a"] = error

    with pytest.raises(RuntimeError) as caught:
        gate.scan("sample")

    assert caught.value is error
    assert caught.value.__cause__ is cause
    assert Leaf.calls == ["a"]


def test_required_content_failure_raises_owned_fault_without_scanning() -> None:
    gate = runner([numerical("last", [leaf("url", content_types=["url"])])]).gate

    with pytest.raises(CascadeExecutionError) as caught:
        gate.scan("sample", content_type=ContentType.TEXT)

    assert caught.value.category == "unsupported_content"
    assert Leaf.calls == []


@pytest.mark.parametrize("policy", ["fail", "block"])
def test_aggregator_failure_preserves_identity_or_sanitizes_operational_block(
    policy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = runner([numerical("last", [leaf("a", 0.5)], aggregator="Local")], policy=policy).gate
    error = RuntimeError("private aggregate")
    monkeypatch.setattr(Aggregate, "error", error)

    if policy == "fail":
        with pytest.raises(RuntimeError) as caught:
            gate.scan("sample")
        assert caught.value is error
    else:
        result = gate.scan("sample")
        assert result.score == 1.0
        assert not result.is_safe
        assert result.rationale == "Cascade stage last: aggregator_error"
        assert len(result.findings) == 1
        assert "private aggregate" not in result.model_dump_json()


@pytest.mark.parametrize("policy", ["fail", "block"])
def test_invalid_plugin_score_uses_operational_error_policy(policy: str, monkeypatch: pytest.MonkeyPatch) -> None:
    gate = runner([numerical("last", [leaf("a", 0.5)], aggregator="Local")], policy=policy).gate
    monkeypatch.setattr(Aggregate, "result", float("nan"))

    if policy == "fail":
        with pytest.raises(CascadeExecutionError) as caught:
            gate.scan("sample")
        assert caught.value.category == "invalid_aggregate"
    else:
        result = gate.scan("sample")
        assert not result.is_safe
        assert result.score == 1.0
        assert result.stages is not None
        assert result.stages[0].score is None
        assert [finding.risk_score for finding in result.findings] == [0.5]


def test_next_stage_releases_previous_raw_outcomes(monkeypatch: pytest.MonkeyPatch) -> None:
    gate = runner([numerical("first", [leaf("first", 0.6)], final=False), numerical("last", [leaf("last")])]).gate
    prior: list[weakref.ReferenceType[ScanOutcome]] = []
    original = Leaf.scan

    def scan(scanner: Leaf, text: str) -> ScanOutcome:
        if scanner.scanner_id == "last":
            assert prior
            assert all(reference() is None for reference in prior)
        outcome = original(scanner, text)
        if scanner.scanner_id == "first":
            prior.append(weakref.ref(outcome))
        return outcome

    monkeypatch.setattr(Leaf, "scan", scan)

    assert gate.scan("sample").is_safe


@pytest.mark.parametrize("aggregate_error", [False, True])
def test_retained_exception_traceback_releases_raw_outcomes(
    aggregate_error: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = runner([numerical("last", [leaf("a", 0.5), leaf("b")], aggregator="Local")]).gate
    references: list[weakref.ReferenceType[ScanOutcome]] = []
    original = Leaf.scan

    def scan(scanner: Leaf, text: str) -> ScanOutcome:
        outcome = original(scanner, text)
        references.append(weakref.ref(outcome))
        return outcome

    monkeypatch.setattr(Leaf, "scan", scan)
    error = RuntimeError("held traceback")
    if aggregate_error:
        monkeypatch.setattr(Aggregate, "error", error)
    else:
        Leaf.failures["b"] = error

    with pytest.raises(RuntimeError) as caught:
        gate.scan("sample")
    gc.collect()

    assert caught.value is error
    assert references
    assert all(reference() is None for reference in references)


@pytest.mark.parametrize("interrupt", [RuntimeError("failure"), KeyboardInterrupt(), SystemExit(4)])
def test_interrupted_entry_releases_outcomes_and_gate_recovers(
    interrupt: BaseException, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = runner([numerical("a", [leaf("a", 0.19), leaf("tail")], final=False), numerical("b", [leaf("b")])]).gate
    references: list[weakref.ReferenceType[ScanOutcome]] = []
    original = Leaf.scan

    def scan(scanner: Leaf, text: str) -> ScanOutcome:
        outcome = original(scanner, text)
        references.append(weakref.ref(outcome))
        return outcome

    monkeypatch.setattr(Leaf, "scan", scan)
    Leaf.failures["tail"] = interrupt

    with pytest.raises(type(interrupt)) as caught:
        gate.scan("sample")
    gc.collect()
    assert caught.value is interrupt
    assert all(reference() is None for reference in references)

    result = gate.scan("clean")
    assert result.is_safe
    assert result.score == 0.0
    assert Leaf.calls == ["a", "tail", "a", "tail"]
