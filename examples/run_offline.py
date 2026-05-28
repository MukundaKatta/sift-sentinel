"""Offline demo: run the full guarded Find Evil loop with no API key and no VM.

    python examples/run_offline.py

Runs the simulated intrusion through the scripted planner, prints the
incident-response report and the self-scored accuracy report to stdout, and
writes the audit trail to ./sift-workspace/analysis/forensic_audit.jsonl.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "src"))

from sift_sentinel.accuracy import GroundTruth, evaluate  # noqa: E402
from sift_sentinel.agent import ScriptedPlanner, SentinelAgent  # noqa: E402
from sift_sentinel.audit import AuditLog  # noqa: E402
from sift_sentinel.config import DENIED_TOOLS, READONLY_TOOLS, Settings  # noqa: E402
from sift_sentinel.guardrails import Guardrail  # noqa: E402
from sift_sentinel.mcp_client import SimulatedSiftBackend  # noqa: E402
from sift_sentinel.report import render_accuracy_report, render_ir_report  # noqa: E402


async def main() -> None:
    workspace = _REPO / "sift-workspace"
    workspace.mkdir(exist_ok=True)
    evidence_root = _REPO / "evidence"
    guardrail = Guardrail(
        allowlist=READONLY_TOOLS.keys(),
        denied=DENIED_TOOLS,
        evidence_root=str(evidence_root),
        workspace_root=str(workspace),
    )
    # Lock in the chain-of-custody hash baseline before any tool runs.
    guardrail.ledger.baseline(
        [str(p) for p in sorted(evidence_root.rglob("*")) if p.is_file()]
    )
    backend = SimulatedSiftBackend()
    planner = ScriptedPlanner(str(evidence_root))

    with AuditLog(workspace / "analysis" / "forensic_audit.jsonl") as audit:
        agent = SentinelAgent(
            settings=Settings(),
            guardrail=guardrail,
            backend=backend,
            planner=planner,
            audit=audit,
            case_id="DEMO-CASE",
        )
        state = await agent.run()
        summary = audit.summary()

    print(render_ir_report(state, evidence_hashes=guardrail.ledger.tracked))
    print()

    truth = GroundTruth.load(_REPO / "datasets" / "simulated-intrusion.groundtruth.json")
    print(render_accuracy_report(evaluate(state, truth)))
    print()
    print(f"audit summary: {summary}")


if __name__ == "__main__":
    asyncio.run(main())
