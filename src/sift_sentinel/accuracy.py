"""Self-scored accuracy: grade a run against analyst ground truth.

The FIND EVIL! rubric rewards an agent that knows how right it was. After a run
we compare the agent's discovered IOCs and ATT&CK techniques - and its overall
verdict - against a ground-truth file an analyst prepared for the case, and emit
precision / recall / F1 plus an explicit list of false positives and missed
artifacts. Nothing here is graded by the agent's own narrative; it is pure set
comparison against a fixed answer key.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from .agent import CaseState

Verdict = str  # "compromised" | "clean"; kept loose to match analyst files.


class GroundTruth(BaseModel):
    case_id: str
    verdict: Verdict
    expected_iocs: tuple[str, ...] = ()
    expected_techniques: tuple[str, ...] = ()
    notes: str = ""

    @classmethod
    def load(cls, path: str | Path) -> "GroundTruth":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)


class MetricScore(BaseModel):
    precision: float
    recall: float
    f1: float
    true_positives: int
    false_positives: int
    false_negatives: int
    missed: tuple[str, ...] = ()
    spurious: tuple[str, ...] = ()


class AccuracyReport(BaseModel):
    case_id: str
    verdict_expected: Verdict
    verdict_actual: Verdict
    verdict_correct: bool
    iocs: MetricScore
    techniques: MetricScore
    findings_count: int
    confidence: float


def _normalize(value: str) -> str:
    # IOCs (Windows paths, hosts, hashes) compare case-insensitively.
    return value.strip().lower()


def _score(expected: set[str], found: set[str]) -> MetricScore:
    tp = len(expected & found)
    fp = len(found - expected)
    fn = len(expected - found)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return MetricScore(
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        missed=tuple(sorted(expected - found)),
        spurious=tuple(sorted(found - expected)),
    )


def _verdict_from_state(state: CaseState) -> Verdict:
    return "compromised" if state.hypothesis.status == "confirmed" else "clean"


def evaluate(state: CaseState, truth: GroundTruth) -> AccuracyReport:
    """Score a finished case against its ground-truth answer key."""
    found_iocs = {
        _normalize(ioc) for finding in state.findings for ioc in finding.iocs
    }
    found_techniques = {
        _normalize(tech) for finding in state.findings for tech in finding.mitre
    }
    expected_iocs = {_normalize(ioc) for ioc in truth.expected_iocs}
    expected_techniques = {_normalize(tech) for tech in truth.expected_techniques}

    actual_verdict = _verdict_from_state(state)
    return AccuracyReport(
        case_id=truth.case_id,
        verdict_expected=truth.verdict,
        verdict_actual=actual_verdict,
        verdict_correct=_normalize(actual_verdict) == _normalize(truth.verdict),
        iocs=_score(expected_iocs, found_iocs),
        techniques=_score(expected_techniques, found_techniques),
        findings_count=len(state.findings),
        confidence=round(state.hypothesis.confidence, 4),
    )
