"""The playbook docstring promises a test enforcing that no phase can suggest a
tool the guardrail would deny. This is that test, plus phase-order invariants."""

from __future__ import annotations

from sift_sentinel.config import READONLY_TOOLS
from sift_sentinel.playbook import PHASES, PHASES_BY_ID, phase_index


def test_every_suggested_tool_is_allowlisted():
    for phase in PHASES:
        for tool in phase.suggested_tools:
            assert tool in READONLY_TOOLS, (
                f"phase '{phase.id}' suggests '{tool}', which is not in the "
                f"read-only allowlist and would be denied at runtime."
            )


def test_phase_order_starts_with_triage_ends_with_report():
    assert PHASES[0].id == "triage"
    assert PHASES[-1].id == "report"


def test_phase_ids_are_unique():
    ids = [phase.id for phase in PHASES]
    assert len(ids) == len(set(ids))


def test_phases_by_id_is_complete():
    assert set(PHASES_BY_ID) == {phase.id for phase in PHASES}


def test_phase_index_round_trips():
    for index, phase in enumerate(PHASES):
        assert phase_index(phase.id) == index
    assert phase_index("does-not-exist") == -1


def test_report_phase_runs_no_tools():
    assert PHASES_BY_ID["report"].suggested_tools == ()
