"""Accuracy scoring is pure set comparison against an analyst answer key."""

from __future__ import annotations

from sift_sentinel.accuracy import GroundTruth, _score, evaluate
from sift_sentinel.agent import CaseState, Finding, Hypothesis


def test_score_perfect_match():
    score = _score({"a", "b"}, {"a", "b"})
    assert score.precision == 1.0
    assert score.recall == 1.0
    assert score.f1 == 1.0
    assert score.missed == ()
    assert score.spurious == ()


def test_score_with_miss_and_false_positive():
    score = _score({"a", "b", "c"}, {"a", "b", "x"})
    assert score.true_positives == 2
    assert score.false_negatives == 1
    assert score.false_positives == 1
    assert score.missed == ("c",)
    assert score.spurious == ("x",)


def test_score_empty_sets_are_perfect():
    score = _score(set(), set())
    assert score.precision == 1.0
    assert score.recall == 1.0


def _compromised_state() -> CaseState:
    state = CaseState(case_id="DEMO-CASE")
    state.findings.append(
        Finding(
            phase="memory_process",
            title="Imposter svchost",
            detail="wrong parent",
            severity="critical",
            confidence=0.9,
            mitre=("T1036.005",),
            iocs=("C:\\Temp\\svchost.exe",),
        )
    )
    state.hypothesis = Hypothesis(
        statement="The host is compromised.", confidence=0.9, status="confirmed"
    )
    return state


def test_evaluate_scores_verdict_and_iocs():
    state = _compromised_state()
    truth = GroundTruth(
        case_id="DEMO-CASE",
        verdict="compromised",
        expected_iocs=("c:\\temp\\svchost.exe", "1.2.3.4"),
        expected_techniques=("T1036.005",),
    )
    report = evaluate(state, truth)
    assert report.verdict_correct is True
    # One of two expected IOCs found (case-insensitive), so recall is 0.5.
    assert report.iocs.recall == 0.5
    assert report.iocs.missed == ("1.2.3.4",)
    assert report.techniques.recall == 1.0


def test_evaluate_flags_wrong_verdict():
    state = CaseState(case_id="C")  # default hypothesis is "open" -> clean
    truth = GroundTruth(case_id="C", verdict="compromised")
    report = evaluate(state, truth)
    assert report.verdict_actual == "clean"
    assert report.verdict_correct is False
