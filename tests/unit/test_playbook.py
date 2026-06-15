"""Standard-library unittest coverage for the Find Evil playbook.

Like ``test_config`` here, this runs with only the standard library so the
methodology data and its load-bearing invariants are verifiable in an
environment with no third-party packages installed. It imports and exercises the
real ``sift_sentinel.playbook`` module.

Run with:  python3 -m unittest discover -s tests/unit
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from sift_sentinel.config import READONLY_TOOLS  # noqa: E402
from sift_sentinel.playbook import (  # noqa: E402
    PHASES,
    PHASES_BY_ID,
    Phase,
    phase_index,
)


class PlaybookInvariantTests(unittest.TestCase):
    def test_every_suggested_tool_is_allowlisted(self) -> None:
        # The playbook docstring promises this invariant: a phase must never
        # suggest a tool the guardrail's allowlist would deny at runtime.
        for phase in PHASES:
            for tool in phase.suggested_tools:
                self.assertIn(
                    tool,
                    READONLY_TOOLS,
                    f"phase '{phase.id}' suggests '{tool}', which is not in the "
                    f"read-only allowlist and would be denied at runtime.",
                )

    def test_phase_order_starts_with_triage_ends_with_report(self) -> None:
        self.assertEqual(PHASES[0].id, "triage")
        self.assertEqual(PHASES[-1].id, "report")

    def test_report_phase_runs_no_tools(self) -> None:
        # Synthesis is reasoning only; it must not request any further tools.
        report = PHASES_BY_ID["report"]
        self.assertEqual(report.suggested_tools, ())

    def test_phase_ids_are_unique(self) -> None:
        ids = [phase.id for phase in PHASES]
        self.assertEqual(len(ids), len(set(ids)), "phase ids must be unique")

    def test_phases_by_id_matches_phases(self) -> None:
        self.assertEqual(len(PHASES_BY_ID), len(PHASES))
        for phase in PHASES:
            self.assertIs(PHASES_BY_ID[phase.id], phase)

    def test_every_phase_carries_objective_and_heuristics(self) -> None:
        for phase in PHASES:
            self.assertTrue(phase.name.strip())
            self.assertTrue(phase.objective.strip())
            self.assertGreater(
                len(phase.heuristics),
                0,
                f"phase '{phase.id}' must state at least one heuristic",
            )

    def test_phase_is_immutable(self) -> None:
        # Phase is a frozen dataclass; the methodology must not be mutable at run
        # time. This keeps the planner prompt prefix byte-stable across turns.
        with self.assertRaises(Exception):
            PHASES[0].id = "tampered"  # type: ignore[misc]


class PhaseIndexTests(unittest.TestCase):
    def test_phase_index_returns_ordinal(self) -> None:
        for ordinal, phase in enumerate(PHASES):
            self.assertEqual(phase_index(phase.id), ordinal)

    def test_phase_index_is_monotonic_in_declared_order(self) -> None:
        self.assertLess(phase_index("triage"), phase_index("report"))
        self.assertLess(
            phase_index("memory_process"), phase_index("persistence")
        )

    def test_phase_index_unknown_is_minus_one(self) -> None:
        self.assertEqual(phase_index("does-not-exist"), -1)

    def test_construct_phase_dataclass(self) -> None:
        phase = Phase(
            id="x",
            name="X",
            objective="o",
            heuristics=("h",),
            suggested_tools=(),
        )
        self.assertEqual(phase.id, "x")
        self.assertEqual(phase.heuristics, ("h",))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
