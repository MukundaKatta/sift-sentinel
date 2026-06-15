"""Command-line entrypoint for sift-sentinel.

Runs the guarded Find Evil triage loop end to end and writes the graded
deliverables: a JSONL audit trail, a Markdown incident-response report, the raw
case state as JSON, and (when a ground-truth key is supplied) a self-scored
accuracy report.

By default it runs fully offline: simulated backend, scripted planner, no API
key, no SIFT workstation. So `sift-sentinel` produces a complete example case
with one command. Point `--backend protocol-sift` and `--planner claude` at a
real Protocol SIFT MCP server and a Claude model for a live run.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from .accuracy import GroundTruth, evaluate
from .agent import ClaudePlanner, ScriptedPlanner, SentinelAgent, to_json
from .audit import AuditLog
from .config import DENIED_TOOLS, READONLY_TOOLS, Settings
from .guardrails import Guardrail
from .mcp_client import ProtocolSiftBackend, SimulatedSiftBackend
from .playbook import PHASES
from .report import distinct_findings, render_accuracy_report, render_ir_report


def _build_backend(name: str, settings: Settings):
    if name == "simulated":
        return SimulatedSiftBackend()
    return ProtocolSiftBackend(settings.mcp_command)


def _build_planner(name: str, settings: Settings, evidence_root: str):
    if name == "claude":
        if not settings.api_key:
            raise SystemExit(
                "ANTHROPIC_API_KEY is required for --planner claude "
                "(set it in the environment or a .env file)."
            )
        return ClaudePlanner(settings)
    return ScriptedPlanner(evidence_root)


def _baseline_paths(evidence_root: Path) -> list[str]:
    """Every regular file under the evidence root, to hash at case open."""
    if not evidence_root.exists():
        return []
    if evidence_root.is_file():
        return [str(evidence_root)]
    return [str(p) for p in sorted(evidence_root.rglob("*")) if p.is_file()]


def _print_summary(
    *,
    case_id: str,
    backend: str,
    planner: str,
    state,
    summary: dict,
    audit_path: Path,
    ir_path: Path,
    state_path: Path,
    accuracy_path: Path | None,
) -> None:
    hyp = state.hypothesis
    verdict = "COMPROMISED" if hyp.status == "confirmed" else "NO CONFIRMED COMPROMISE"
    print()
    print(f"  sift-sentinel  case {case_id}")
    print(f"  backend={backend}  planner={planner}")
    print("  " + "-" * 56)
    print(f"  verdict        : {verdict}")
    print(f"  confidence     : {hyp.confidence:.2f} ({hyp.status})")
    distinct = len(distinct_findings(state.findings))
    print(f"  findings       : {distinct} distinct ({len(state.findings)} recorded)")
    print(f"  phases done    : {len(state.completed_phases)}/{len(PHASES)}")
    print(f"  tool calls     : {summary['tool_calls']}")
    print(f"  denied calls   : {summary['denied_calls']} {summary['denials_by_code'] or ''}")
    print(f"  tokens (in/out): {summary['tokens_in']}/{summary['tokens_out']}")
    print("  " + "-" * 56)
    print(f"  audit trail    : {audit_path}")
    print(f"  IR report      : {ir_path}")
    print(f"  case state     : {state_path}")
    if accuracy_path is not None:
        print(f"  accuracy report: {accuracy_path}")
    print()


async def _run(args: argparse.Namespace, settings: Settings) -> int:
    evidence_root = Path(args.evidence_root).expanduser()
    workspace = Path(args.workspace).expanduser()
    workspace.mkdir(parents=True, exist_ok=True)
    reports_dir = workspace / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    guardrail = Guardrail(
        allowlist=READONLY_TOOLS.keys(),
        denied=DENIED_TOOLS,
        evidence_root=str(evidence_root),
        workspace_root=str(workspace),
    )
    # Lock in the chain-of-custody hash baseline before any tool runs.
    guardrail.ledger.baseline(_baseline_paths(evidence_root))

    backend = _build_backend(args.backend, settings)
    planner = _build_planner(args.planner, settings, str(evidence_root))

    audit_path = (
        Path(args.audit_log).expanduser()
        if args.audit_log
        else workspace / "analysis" / "forensic_audit.jsonl"
    )

    with AuditLog(audit_path) as audit:
        agent = SentinelAgent(
            settings=settings,
            guardrail=guardrail,
            backend=backend,
            planner=planner,
            audit=audit,
            case_id=args.case_id,
        )
        try:
            state = await agent.run()
        finally:
            await backend.aclose()
        summary = audit.summary()

    ir_path = reports_dir / f"{args.case_id}-ir-report.md"
    ir_path.write_text(
        render_ir_report(state, evidence_hashes=guardrail.ledger.tracked),
        encoding="utf-8",
    )

    state_path = reports_dir / f"{args.case_id}-state.json"
    state_path.write_text(to_json(state), encoding="utf-8")

    accuracy_path: Path | None = None
    if args.ground_truth:
        truth = GroundTruth.load(args.ground_truth)
        report = evaluate(state, truth)
        accuracy_path = reports_dir / f"{args.case_id}-accuracy.md"
        accuracy_path.write_text(render_accuracy_report(report), encoding="utf-8")

    _print_summary(
        case_id=args.case_id,
        backend=args.backend,
        planner=args.planner,
        state=state,
        summary=summary,
        audit_path=audit_path,
        ir_path=ir_path,
        state_path=state_path,
        accuracy_path=accuracy_path,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sift-sentinel",
        description="Autonomous, guardrailed DFIR triage agent for Protocol SIFT.",
    )
    parser.add_argument(
        "--backend",
        choices=("simulated", "protocol-sift"),
        default="simulated",
        help="Tool backend. 'simulated' replays a fixed intrusion offline (default).",
    )
    parser.add_argument(
        "--planner",
        choices=("scripted", "claude"),
        default="scripted",
        help="'scripted' walks the playbook offline (default); 'claude' uses a model.",
    )
    parser.add_argument("--case-id", default="DEMO-CASE", help="Case identifier.")
    parser.add_argument(
        "--evidence-root",
        default="./evidence",
        help="Read-only evidence directory; every file is hashed at case open.",
    )
    parser.add_argument(
        "--workspace",
        default="./sift-workspace",
        help="Writable workspace for analysis output and reports.",
    )
    parser.add_argument(
        "--audit-log",
        default=None,
        help="Audit JSONL path (default: <workspace>/analysis/forensic_audit.jsonl).",
    )
    parser.add_argument(
        "--ground-truth",
        default=None,
        help="Optional ground-truth JSON key to score accuracy against.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override the Claude model id (only used with --planner claude).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings.from_env()
    if args.model:
        settings = Settings(
            model=args.model,
            max_iterations=settings.max_iterations,
            mcp_command=settings.mcp_command,
            api_key=settings.api_key,
            allowlist=settings.allowlist,
        )
    return asyncio.run(_run(args, settings))


if __name__ == "__main__":
    raise SystemExit(main())
