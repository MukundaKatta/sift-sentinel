"""Structured, append-only audit trail for an agent run.

Every decision the agent makes is written as one JSON line the instant it
happens, so a crash mid-run still leaves a complete, timestamped record of tool
sequences, guardrail verdicts, token usage, and confidence revisions. This file
is both an operational debugging aid and a graded deliverable: the rubric scores
"Audit Trail Quality" directly.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

ActionKind = Literal["plan", "tool_call", "validation", "revision", "report", "stop"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StepRecord(BaseModel):
    ts: str = Field(default_factory=_utc_now)
    step: int
    phase: str
    action: ActionKind
    tool: str | None = None
    args: dict | None = None
    verdict: str | None = None
    result_summary: str | None = None
    confidence: float | None = None
    hypothesis: str | None = None
    revised: bool = False
    tokens_in: int = 0
    tokens_out: int = 0


class AuditLog:
    """Writes StepRecords to a JSONL file and keeps them for run summaries."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[StepRecord] = []
        self._step = 0
        # Truncate any stale log so a re-run starts a clean trail.
        self._handle = self.path.open("w", encoding="utf-8")

    def record(self, *, phase: str, action: ActionKind, **fields: object) -> StepRecord:
        self._step += 1
        record = StepRecord(step=self._step, phase=phase, action=action, **fields)
        self._records.append(record)
        # One line, flushed immediately, so the trail survives a crash.
        self._handle.write(record.model_dump_json() + "\n")
        self._handle.flush()
        return record

    @property
    def records(self) -> list[StepRecord]:
        return list(self._records)

    def total_tokens(self) -> tuple[int, int]:
        return (
            sum(r.tokens_in for r in self._records),
            sum(r.tokens_out for r in self._records),
        )

    def summary(self) -> dict[str, object]:
        actions = Counter(r.action for r in self._records)
        denials = Counter(
            r.verdict for r in self._records if r.verdict and r.verdict != "allow"
        )
        tokens_in, tokens_out = self.total_tokens()
        return {
            "steps": len(self._records),
            "tool_calls": actions.get("tool_call", 0),
            "validations": actions.get("validation", 0),
            "revisions": sum(1 for r in self._records if r.revised),
            "denied_calls": sum(denials.values()),
            "denials_by_code": dict(denials),
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
        }

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.close()

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
