"""The plan-act-validate agent loop.

The agent is a deterministic state machine that walks the SANS Find Evil
``playbook`` one phase at a time. For each phase it asks a ``Planner`` which
read-only tools to run, routes every proposed call through the architectural
``Guardrail`` before execution, runs the survivors against a ``SiftBackend``,
re-verifies evidence integrity after each call, and folds the results into a
``CaseState`` while updating a running compromise hypothesis. Every transition
is written to the ``AuditLog``.

Two planners implement one protocol:

* ``ScriptedPlanner`` walks the playbook's suggested tools deterministically and
  derives findings from structured tool ``Signal``s. It needs no API key, so the
  whole loop runs offline for ``--dry-run``, tests, and demos.
* ``ClaudePlanner`` drives the same loop with a real Claude model, using prompt
  caching and a single stable tool definition for cache-prefix stability.

Self-correction is explicit: as findings accumulate, the agent raises its
compromise confidence and, when a threshold is crossed, transitions the
hypothesis state and records a ``revision`` - a visible belief update rather
than a hidden one.
"""

from __future__ import annotations

import json
from typing import Literal, Protocol

from pydantic import BaseModel, Field

from .audit import AuditLog
from .config import Settings
from .guardrails import Guardrail
from .mcp_client import Severity, SiftBackend, ToolResult, ToolSpec
from .playbook import PHASES, Phase

# Confidence a single finding carries, by severity.
_FINDING_CONFIDENCE: dict[Severity, float] = {
    "info": 0.25,
    "low": 0.40,
    "medium": 0.55,
    "high": 0.75,
    "critical": 0.90,
}

# How much each finding moves the overall compromise hypothesis.
_HYPOTHESIS_WEIGHT: dict[Severity, float] = {
    "info": 0.00,
    "low": 0.05,
    "medium": 0.10,
    "high": 0.20,
    "critical": 0.30,
}

# Confidence at which the standing hypothesis flips open -> confirmed.
_CONFIRM_THRESHOLD = 0.70


class Finding(BaseModel):
    phase: str
    title: str
    detail: str
    severity: Severity
    confidence: float
    mitre: tuple[str, ...] = ()
    iocs: tuple[str, ...] = ()
    artifact: str | None = None
    tool: str | None = None
    # True if this finding triggered a hypothesis state change (self-correction).
    revised: bool = False


class Hypothesis(BaseModel):
    statement: str
    confidence: float = 0.10
    status: Literal["open", "confirmed", "rejected"] = "open"
    supporting: tuple[str, ...] = ()


class CaseState(BaseModel):
    case_id: str
    findings: list[Finding] = Field(default_factory=list)
    hypothesis: Hypothesis = Field(
        default_factory=lambda: Hypothesis(
            statement="The host shows no evidence of compromise."
        )
    )
    completed_phases: list[str] = Field(default_factory=list)
    denied_calls: int = 0


class PlannedCall(BaseModel):
    tool: str
    args: dict = Field(default_factory=dict)
    rationale: str = ""


class PlannerDecision(BaseModel):
    calls: tuple[PlannedCall, ...] = ()
    # Whether the phase objective is met after these calls run.
    advance: bool = True
    notes: str = ""


class Planner(Protocol):
    """Decides which tools to run and turns their output into findings."""

    async def plan(
        self, *, phase: Phase, state: CaseState, available: tuple[ToolSpec, ...]
    ) -> PlannerDecision: ...

    async def interpret(
        self, *, phase: Phase, call: PlannedCall, result: ToolResult, state: CaseState
    ) -> tuple[Finding, ...]: ...

    def pop_usage(self) -> tuple[int, int]:
        """Return and reset (tokens_in, tokens_out) accrued since the last call."""
        ...


# --------------------------------------------------------------------------- #
# Scripted planner (offline, deterministic)
# --------------------------------------------------------------------------- #


class ScriptedPlanner:
    """Walks the playbook deterministically; findings come from tool signals."""

    def __init__(self, evidence_root: str) -> None:
        self._evidence_root = evidence_root

    async def plan(
        self, *, phase: Phase, state: CaseState, available: tuple[ToolSpec, ...]
    ) -> PlannerDecision:
        names = {spec.name for spec in available}
        calls = tuple(
            PlannedCall(
                tool=tool,
                args={"target": self._evidence_root},
                rationale=f"{phase.name}: run {tool} per Find Evil heuristics.",
            )
            for tool in phase.suggested_tools
            if tool in names
        )
        return PlannerDecision(calls=calls, advance=True)

    async def interpret(
        self, *, phase: Phase, call: PlannedCall, result: ToolResult, state: CaseState
    ) -> tuple[Finding, ...]:
        if not result.ok:
            return ()
        return tuple(
            Finding(
                phase=phase.id,
                title=signal.title,
                detail=signal.detail,
                severity=signal.severity,
                confidence=_FINDING_CONFIDENCE[signal.severity],
                mitre=signal.mitre,
                iocs=signal.iocs,
                artifact=signal.artifact,
                tool=result.tool,
            )
            for signal in result.signals
        )

    def pop_usage(self) -> tuple[int, int]:
        return (0, 0)


# --------------------------------------------------------------------------- #
# Claude planner (real model, prompt-cache friendly)
# --------------------------------------------------------------------------- #

_SYSTEM_PREAMBLE = (
    "You are SIFT-Sentinel, an autonomous DFIR triage analyst working a case on "
    "a SANS SIFT Workstation. You follow the SANS Find Evil methodology and only "
    "ever request read-only forensic tools. You never attempt to modify evidence. "
    "When a phase objective is satisfied, stop requesting tools for it."
)


def _catalog_block(available: tuple[ToolSpec, ...]) -> str:
    lines = [f"- {spec.name}: {spec.description}" for spec in available]
    return "Available read-only tools:\n" + "\n".join(lines)


def _phases_block() -> str:
    out = ["Investigation methodology (fixed phase order):"]
    for phase in PHASES:
        out.append(f"\n## {phase.name} ({phase.id})\nObjective: {phase.objective}")
        for heuristic in phase.heuristics:
            out.append(f"  - {heuristic}")
    return "\n".join(out)


class ClaudePlanner:
    """Real planner backed by Claude, with prompt caching for the static prefix.

    Each SIFT tool is exposed to the model through a single stable ``run_sift_tool``
    tool (an enum of allowlisted names plus a free-form args object). Keeping one
    tool definition - rather than one per SIFT command - keeps the cached prompt
    prefix byte-identical across turns and across phases.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._tokens_in = 0
        self._tokens_out = 0
        self._client = None  # anthropic.AsyncAnthropic, created lazily

    def _ensure_client(self):
        if self._client is None:
            from anthropic import AsyncAnthropic

            self._client = AsyncAnthropic(api_key=self._settings.api_key)
        return self._client

    def _system(self, available: tuple[ToolSpec, ...]) -> list[dict]:
        # Static, cache-eligible system content. Ordered deterministically so the
        # cached prefix stays stable turn to turn.
        static = "\n\n".join(
            [_SYSTEM_PREAMBLE, _phases_block(), _catalog_block(available)]
        )
        return [
            {
                "type": "text",
                "text": static,
                "cache_control": {"type": "ephemeral"},
            }
        ]

    @staticmethod
    def _run_tool_schema(available: tuple[ToolSpec, ...]) -> list[dict]:
        return [
            {
                "name": "run_sift_tool",
                "description": "Run one read-only SIFT forensic tool against the evidence.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "tool": {
                            "type": "string",
                            "enum": [spec.name for spec in available],
                        },
                        "args": {"type": "object"},
                        "rationale": {"type": "string"},
                    },
                    "required": ["tool", "rationale"],
                },
            }
        ]

    @staticmethod
    def _record_findings_schema() -> list[dict]:
        return [
            {
                "name": "record_findings",
                "description": "Record forensic findings extracted from a tool's output.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "title": {"type": "string"},
                                    "detail": {"type": "string"},
                                    "severity": {
                                        "type": "string",
                                        "enum": [
                                            "info",
                                            "low",
                                            "medium",
                                            "high",
                                            "critical",
                                        ],
                                    },
                                    "mitre": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                    "iocs": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                    "artifact": {"type": "string"},
                                },
                                "required": ["title", "detail", "severity"],
                            },
                        }
                    },
                    "required": ["findings"],
                },
            }
        ]

    def _account(self, response) -> None:
        usage = getattr(response, "usage", None)
        if usage is not None:
            self._tokens_in += getattr(usage, "input_tokens", 0) or 0
            self._tokens_out += getattr(usage, "output_tokens", 0) or 0

    async def plan(
        self, *, phase: Phase, state: CaseState, available: tuple[ToolSpec, ...]
    ) -> PlannerDecision:
        client = self._ensure_client()
        user = (
            f"Current phase: {phase.name} ({phase.id}).\n"
            f"Objective: {phase.objective}\n"
            f"Findings so far: {len(state.findings)}. "
            f"Hypothesis: {state.hypothesis.statement} "
            f"(confidence {state.hypothesis.confidence:.2f}).\n"
            "Request the next read-only tool(s) for this phase via run_sift_tool. "
            "If the objective is already satisfied, respond with text and call no tool."
        )
        response = await client.messages.create(
            model=self._settings.model,
            max_tokens=1024,
            system=self._system(available),
            tools=self._run_tool_schema(available),
            messages=[{"role": "user", "content": user}],
        )
        self._account(response)
        calls: list[PlannedCall] = []
        for block in response.content:
            if getattr(block, "type", None) == "tool_use" and block.name == "run_sift_tool":
                data = block.input or {}
                calls.append(
                    PlannedCall(
                        tool=str(data.get("tool", "")),
                        args=dict(data.get("args", {}) or {}),
                        rationale=str(data.get("rationale", "")),
                    )
                )
        return PlannerDecision(calls=tuple(calls), advance=not calls)

    async def interpret(
        self, *, phase: Phase, call: PlannedCall, result: ToolResult, state: CaseState
    ) -> tuple[Finding, ...]:
        if not result.ok:
            return ()
        client = self._ensure_client()
        user = (
            f"Phase: {phase.name}. Tool: {result.tool}.\n"
            f"Heuristics:\n" + "\n".join(f"- {h}" for h in phase.heuristics) + "\n\n"
            f"Tool output:\n{result.output}\n\n"
            "Extract only well-supported findings via record_findings. "
            "If nothing in the output is evil, record an empty list."
        )
        response = await client.messages.create(
            model=self._settings.model,
            max_tokens=1024,
            system=self._system(await _noop_specs(state)),
            tools=self._record_findings_schema(),
            tool_choice={"type": "tool", "name": "record_findings"},
            messages=[{"role": "user", "content": user}],
        )
        self._account(response)
        findings: list[Finding] = []
        for block in response.content:
            if getattr(block, "type", None) == "tool_use" and block.name == "record_findings":
                data = block.input or {}
                for raw in data.get("findings", []) or []:
                    severity: Severity = raw.get("severity", "info")
                    findings.append(
                        Finding(
                            phase=phase.id,
                            title=str(raw.get("title", "")),
                            detail=str(raw.get("detail", "")),
                            severity=severity,
                            confidence=_FINDING_CONFIDENCE.get(severity, 0.25),
                            mitre=tuple(raw.get("mitre", []) or []),
                            iocs=tuple(raw.get("iocs", []) or []),
                            artifact=raw.get("artifact"),
                            tool=result.tool,
                        )
                    )
        return tuple(findings)

    def pop_usage(self) -> tuple[int, int]:
        usage = (self._tokens_in, self._tokens_out)
        self._tokens_in = 0
        self._tokens_out = 0
        return usage


async def _noop_specs(state: CaseState) -> tuple[ToolSpec, ...]:
    # interpret() does not re-list tools; reuse the static catalog for a stable
    # cached system prefix without another backend round-trip.
    from .mcp_client import _allowlist_specs

    return _allowlist_specs()


# --------------------------------------------------------------------------- #
# The agent
# --------------------------------------------------------------------------- #


class SentinelAgent:
    """Runs the guarded plan-act-validate loop over the Find Evil playbook."""

    def __init__(
        self,
        *,
        settings: Settings,
        guardrail: Guardrail,
        backend: SiftBackend,
        planner: Planner,
        audit: AuditLog,
        case_id: str,
    ) -> None:
        self._settings = settings
        self._guardrail = guardrail
        self._backend = backend
        self._planner = planner
        self._audit = audit
        self._state = CaseState(case_id=case_id)
        self._iterations = 0

    @property
    def state(self) -> CaseState:
        return self._state

    async def run(self) -> CaseState:
        available = await self._backend.list_tools()
        for phase in PHASES:
            if self._iterations >= self._settings.max_iterations:
                self._audit.record(
                    phase=phase.id,
                    action="stop",
                    result_summary="Iteration budget exhausted before phase start.",
                )
                break
            await self._run_phase(phase, available)
            self._state.completed_phases.append(phase.id)

        # Final integrity gate: evidence must still match its case-open baseline.
        verdict = self._guardrail.verify_evidence()
        self._audit.record(
            phase="report",
            action="validation",
            verdict=verdict.decision,
            result_summary=(
                "Evidence integrity verified."
                if verdict.decision == "allow"
                else getattr(verdict, "detail", "Integrity check failed.")
            ),
        )
        self._audit.record(
            phase="report",
            action="report",
            result_summary=(
                f"{len(self._state.findings)} findings; hypothesis "
                f"'{self._state.hypothesis.statement}' "
                f"({self._state.hypothesis.status}, "
                f"{self._state.hypothesis.confidence:.2f})."
            ),
        )
        return self._state

    async def _run_phase(self, phase: Phase, available: tuple[ToolSpec, ...]) -> None:
        decision = await self._planner.plan(
            phase=phase, state=self._state, available=available
        )
        in_, out = self._planner.pop_usage()
        self._audit.record(
            phase=phase.id,
            action="plan",
            result_summary=f"Planned {len(decision.calls)} call(s). {decision.notes}".strip(),
            tokens_in=in_,
            tokens_out=out,
        )

        for call in decision.calls:
            if self._iterations >= self._settings.max_iterations:
                self._audit.record(
                    phase=phase.id,
                    action="stop",
                    result_summary="Iteration budget exhausted mid-phase.",
                )
                return
            self._iterations += 1
            await self._execute(phase, call)

    async def _execute(self, phase: Phase, call: PlannedCall) -> None:
        # Architectural guardrail: allowlist + explicit-deny + path jail.
        verdict = self._guardrail.check_call(call.tool, call.args)
        if verdict.decision == "deny":
            self._state.denied_calls += 1
            self._audit.record(
                phase=phase.id,
                action="tool_call",
                tool=call.tool,
                args=call.args,
                verdict=verdict.code,
                result_summary=verdict.detail,
            )
            return

        result = await self._backend.call_tool(call.tool, call.args)
        self._audit.record(
            phase=phase.id,
            action="tool_call",
            tool=call.tool,
            args=call.args,
            verdict="allow",
            result_summary=_summarize(result),
        )

        # Post-execution integrity check: a tool must never mutate evidence.
        integrity = self._guardrail.verify_evidence()
        if integrity.decision == "deny":
            self._audit.record(
                phase=phase.id,
                action="validation",
                tool=call.tool,
                verdict=integrity.code,
                result_summary=integrity.detail,
            )
            return

        findings = await self._planner.interpret(
            phase=phase, call=call, result=result, state=self._state
        )
        in_, out = self._planner.pop_usage()
        for finding in findings:
            self._integrate(finding)
            self._audit.record(
                phase=phase.id,
                action="validation",
                tool=call.tool,
                verdict="allow",
                result_summary=f"[{finding.severity}] {finding.title}",
                confidence=finding.confidence,
                hypothesis=self._state.hypothesis.statement,
                revised=finding.revised,
                tokens_in=in_,
                tokens_out=out,
            )
            in_, out = 0, 0  # only attribute usage to the first record

    def _integrate(self, finding: Finding) -> None:
        """Add a finding and update the standing hypothesis (self-correction)."""
        self._state.findings.append(finding)
        hypothesis = self._state.hypothesis
        new_confidence = min(
            1.0, hypothesis.confidence + _HYPOTHESIS_WEIGHT[finding.severity]
        )
        supporting = (*hypothesis.supporting, finding.title)
        status = hypothesis.status
        statement = hypothesis.statement

        crossed = status == "open" and new_confidence >= _CONFIRM_THRESHOLD
        if crossed:
            status = "confirmed"
            statement = "The host is compromised by an active intrusion."
            finding.revised = True

        self._state.hypothesis = Hypothesis(
            statement=statement,
            confidence=new_confidence,
            status=status,
            supporting=supporting,
        )
        if crossed:
            self._audit.record(
                phase=finding.phase,
                action="revision",
                result_summary=(
                    f"Hypothesis confirmed at confidence {new_confidence:.2f} "
                    f"after '{finding.title}'."
                ),
                confidence=new_confidence,
                hypothesis=statement,
                revised=True,
            )


def _summarize(result: ToolResult, limit: int = 240) -> str:
    if not result.ok:
        return f"ERROR: {result.error or 'tool failed'}"
    head = result.output.strip().replace("\n", " ")
    if len(head) > limit:
        head = head[:limit] + "..."
    return head or "(no output)"


def to_json(state: CaseState) -> str:
    """Serialize case state for persistence or inspection."""
    return json.dumps(state.model_dump(), indent=2, sort_keys=True)
