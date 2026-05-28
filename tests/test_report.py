"""Reports are pure functions of computed state, tested without a model."""

from __future__ import annotations

from sift_sentinel.accuracy import GroundTruth, evaluate
from sift_sentinel.agent import CaseState, Finding, Hypothesis
from sift_sentinel.report import render_accuracy_report, render_ir_report


def _state() -> CaseState:
    state = CaseState(case_id="DEMO-CASE")
    state.completed_phases = ["triage", "memory_process", "report"]
    state.denied_calls = 2
    state.findings.append(
        Finding(
            phase="memory_process",
            title="Imposter svchost.exe",
            detail="Wrong parent and path.",
            severity="critical",
            confidence=0.9,
            mitre=("T1036.005", "T1055"),
            iocs=("C:\\Temp\\svchost.exe", "185.220.101.47:443"),
            tool="volatility3",
            artifact="memory.mem",
        )
    )
    state.hypothesis = Hypothesis(
        statement="The host is compromised by an active intrusion.",
        confidence=0.9,
        status="confirmed",
    )
    return state


def test_ir_report_has_verdict_iocs_mitre_and_hashes():
    state = _state()
    md = render_ir_report(state, evidence_hashes={"/evidence/disk.raw": "abc123"})
    assert "COMPROMISED" in md
    assert "Imposter svchost.exe" in md
    assert "185.220.101.47:443" in md
    assert "T1036.005" in md
    assert "abc123" in md
    assert "2 tool call(s) denied" in md


def test_ir_report_handles_clean_case():
    md = render_ir_report(CaseState(case_id="CLEAN"))
    assert "NO CONFIRMED COMPROMISE" in md
    assert "No findings recorded." in md


def test_accuracy_report_renders_metrics():
    state = _state()
    truth = GroundTruth(
        case_id="DEMO-CASE",
        verdict="compromised",
        expected_iocs=("c:\\temp\\svchost.exe", "185.220.101.47:443"),
        expected_techniques=("T1036.005", "T1055"),
    )
    md = render_accuracy_report(evaluate(state, truth))
    assert "Accuracy Report" in md
    assert "Precision: 1.00" in md
    assert "correct" in md
