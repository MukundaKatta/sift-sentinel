"""Render a case into an incident-response report and an accuracy report.

The IR report is a graded deliverable: a SOC-ready Markdown document with an
executive summary, an attack timeline, an IOC table, a MITRE ATT&CK mapping, and
the evidence-integrity hashes that anchor chain of custody. The accuracy report
renders the self-scored metrics from ``accuracy.py``. Both are pure functions of
already-computed state so they can be unit-tested without a model or a backend.
"""

from __future__ import annotations

from .accuracy import AccuracyReport, MetricScore
from .agent import CaseState, Finding

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _dedupe(findings: list[Finding]) -> list[Finding]:
    # The same artifact can surface from a tool re-run in a later phase (e.g.
    # volatility3 in both the memory and network phases). The audit trail keeps
    # every call, but the IR report shows each distinct finding once.
    seen: set[tuple] = set()
    distinct: list[Finding] = []
    for finding in findings:
        key = (finding.title, finding.detail, finding.severity, finding.iocs)
        if key not in seen:
            seen.add(key)
            distinct.append(finding)
    return distinct


def distinct_findings(findings: list[Finding]) -> list[Finding]:
    """Public view of the deduplicated findings used in the IR report."""
    return _dedupe(findings)


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    # Most severe first; stable by phase order within a severity is preserved by
    # the original append order, so use a stable sort on severity only.
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 5))


def _ioc_rows(findings: list[Finding]) -> list[str]:
    seen: dict[str, str] = {}
    for finding in findings:
        for ioc in finding.iocs:
            seen.setdefault(ioc, finding.title)
    return [f"| `{ioc}` | {title} |" for ioc, title in seen.items()]


def _mitre_rows(findings: list[Finding]) -> list[str]:
    seen: dict[str, str] = {}
    for finding in findings:
        for technique in finding.mitre:
            seen.setdefault(technique, finding.title)
    return [f"| {technique} | {title} |" for technique, title in sorted(seen.items())]


def render_ir_report(
    state: CaseState, evidence_hashes: dict[str, str] | None = None
) -> str:
    """Produce a Markdown incident-response report for the case."""
    distinct = _dedupe(state.findings)
    findings = _sorted_findings(distinct)
    hypothesis = state.hypothesis
    verdict = "COMPROMISED" if hypothesis.status == "confirmed" else "NO CONFIRMED COMPROMISE"

    lines: list[str] = []
    lines.append(f"# Incident Response Report - case {state.case_id}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Verdict: **{verdict}**")
    lines.append(
        f"- Confidence: {hypothesis.confidence:.2f} ({hypothesis.status})"
    )
    lines.append(f"- Assessment: {hypothesis.statement}")
    lines.append(f"- Findings: {len(findings)} across "
                 f"{len(state.completed_phases)} triage phases")
    if state.denied_calls:
        lines.append(
            f"- Guardrail: {state.denied_calls} tool call(s) denied before execution"
        )
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if findings:
        for finding in findings:
            lines.append(f"### [{finding.severity.upper()}] {finding.title}")
            lines.append(f"- Phase: {finding.phase}")
            if finding.tool:
                lines.append(f"- Tool: `{finding.tool}`")
            lines.append(f"- Confidence: {finding.confidence:.2f}")
            if finding.artifact:
                lines.append(f"- Artifact: {finding.artifact}")
            lines.append(f"- Detail: {finding.detail}")
            lines.append("")
    else:
        lines.append("No findings recorded.")
        lines.append("")

    lines.append("## Indicators of Compromise")
    lines.append("")
    ioc_rows = _ioc_rows(state.findings)
    if ioc_rows:
        lines.append("| Indicator | Source finding |")
        lines.append("| --- | --- |")
        lines.extend(ioc_rows)
    else:
        lines.append("No indicators of compromise extracted.")
    lines.append("")

    lines.append("## MITRE ATT&CK Mapping")
    lines.append("")
    mitre_rows = _mitre_rows(state.findings)
    if mitre_rows:
        lines.append("| Technique | Observed via |")
        lines.append("| --- | --- |")
        lines.extend(mitre_rows)
    else:
        lines.append("No techniques mapped.")
    lines.append("")

    lines.append("## Evidence Integrity")
    lines.append("")
    if evidence_hashes:
        lines.append("| Evidence | SHA-256 (case open) |")
        lines.append("| --- | --- |")
        for path, digest in sorted(evidence_hashes.items()):
            lines.append(f"| `{path}` | `{digest}` |")
    else:
        lines.append("No evidence baseline recorded.")
    lines.append("")

    return "\n".join(lines)


def _metric_block(title: str, score: MetricScore) -> list[str]:
    out = [
        f"### {title}",
        "",
        f"- Precision: {score.precision:.2f}",
        f"- Recall: {score.recall:.2f}",
        f"- F1: {score.f1:.2f}",
        f"- TP / FP / FN: {score.true_positives} / "
        f"{score.false_positives} / {score.false_negatives}",
    ]
    if score.missed:
        out.append(f"- Missed: {', '.join(score.missed)}")
    if score.spurious:
        out.append(f"- False positives: {', '.join(score.spurious)}")
    out.append("")
    return out


def render_accuracy_report(report: AccuracyReport) -> str:
    """Produce a Markdown accuracy report from self-scored metrics."""
    lines: list[str] = []
    lines.append(f"# Accuracy Report - case {report.case_id}")
    lines.append("")
    mark = "correct" if report.verdict_correct else "INCORRECT"
    lines.append(
        f"- Verdict: expected `{report.verdict_expected}`, "
        f"got `{report.verdict_actual}` ({mark})"
    )
    lines.append(f"- Findings recorded: {report.findings_count}")
    lines.append(f"- Final confidence: {report.confidence:.2f}")
    lines.append("")
    lines.extend(_metric_block("Indicators of Compromise", report.iocs))
    lines.extend(_metric_block("MITRE ATT&CK Techniques", report.techniques))
    return "\n".join(lines)
