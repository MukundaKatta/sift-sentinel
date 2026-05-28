"""End-to-end proof the guarded loop runs offline with no API key or VM.

The simulated backend plus scripted planner exercise the full
plan -> guardrail -> tool -> integrity-check -> finding -> hypothesis pipeline,
so this is the closest thing to a live run that can be asserted deterministically.
"""

from __future__ import annotations

import asyncio
import json

from sift_sentinel.agent import (
    PlannedCall,
    PlannerDecision,
    ScriptedPlanner,
    SentinelAgent,
)
from sift_sentinel.audit import AuditLog
from sift_sentinel.config import DENIED_TOOLS, READONLY_TOOLS, Settings
from sift_sentinel.guardrails import Guardrail
from sift_sentinel.mcp_client import SimulatedSiftBackend


def _guard(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    return (
        Guardrail(
            allowlist=READONLY_TOOLS.keys(),
            denied=DENIED_TOOLS,
            evidence_root=str(evidence),
            workspace_root=str(workspace),
        ),
        evidence,
        workspace,
    )


def _run_agent(tmp_path, planner):
    guard, evidence, _ = _guard(tmp_path)
    backend = SimulatedSiftBackend()
    audit_path = tmp_path / "audit.jsonl"
    with AuditLog(audit_path) as audit:
        agent = SentinelAgent(
            settings=Settings(),
            guardrail=guard,
            backend=backend,
            planner=planner,
            audit=audit,
            case_id="T-CASE",
        )
        state = asyncio.run(agent.run())
        summary = audit.summary()
    return state, summary, audit_path


def test_offline_run_confirms_compromise(tmp_path):
    evidence = tmp_path / "evidence"
    state, summary, audit_path = _run_agent(
        tmp_path, ScriptedPlanner(str(tmp_path / "evidence"))
    )
    assert state.hypothesis.status == "confirmed"
    assert "report" in state.completed_phases
    assert summary["tool_calls"] > 0

    iocs = {ioc for finding in state.findings for ioc in finding.iocs}
    assert any("svchost.exe" in ioc for ioc in iocs)
    assert "185.220.101.47:443" in iocs

    techniques = {t for finding in state.findings for t in finding.mitre}
    assert "T1071.001" in techniques  # C2 over web protocol

    # A hypothesis revision must be recorded as a visible belief update.
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    actions = [json.loads(line)["action"] for line in lines]
    assert "revision" in actions
    assert "report" in actions


def test_denied_tool_is_blocked_before_execution(tmp_path):
    class DenyingPlanner:
        async def plan(self, *, phase, state, available):
            if phase.id == "triage":
                return PlannerDecision(
                    calls=(PlannedCall(tool="dd", args={}, rationale="image it"),)
                )
            return PlannerDecision(calls=())

        async def interpret(self, *, phase, call, result, state):
            return ()

        def pop_usage(self):
            return (0, 0)

    state, summary, _ = _run_agent(tmp_path, DenyingPlanner())
    assert state.denied_calls == 1
    assert summary["denied_calls"] == 1
    assert "tool_explicitly_denied" in summary["denials_by_code"]


def test_evidence_baseline_holds_across_a_run(tmp_path):
    guard, evidence, _ = _guard(tmp_path)
    artifact = evidence / "disk.raw"
    artifact.write_bytes(b"acquired image bytes")
    guard.ledger.baseline([str(artifact)])

    backend = SimulatedSiftBackend()
    with AuditLog(tmp_path / "audit.jsonl") as audit:
        agent = SentinelAgent(
            settings=Settings(),
            guardrail=guard,
            backend=backend,
            planner=ScriptedPlanner(str(evidence)),
            audit=audit,
            case_id="T-INTEGRITY",
        )
        asyncio.run(agent.run())

    # The simulated tools are read-only, so the baseline must still verify.
    assert guard.verify_evidence().decision == "allow"
