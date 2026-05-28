"""The audit trail is a graded deliverable: prove every record lands as one
flushed JSON line and that the run summary counts tool calls and denials."""

from __future__ import annotations

import json

from sift_sentinel.audit import AuditLog


def test_records_written_as_one_json_line_each(tmp_path):
    path = tmp_path / "audit.jsonl"
    with AuditLog(path) as log:
        log.record(phase="triage", action="plan", result_summary="planned 2 calls")
        log.record(phase="triage", action="tool_call", tool="fls", verdict="allow")
        log.record(
            phase="triage",
            action="tool_call",
            tool="dd",
            verdict="tool_explicitly_denied",
        )
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3
    records = [json.loads(line) for line in lines]
    assert [r["step"] for r in records] == [1, 2, 3]
    assert all("ts" in r for r in records)


def test_lines_flush_immediately_for_crash_survival(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record(phase="triage", action="plan")
    # Read the file while the log is still open: the line must already be there.
    assert len(path.read_text(encoding="utf-8").strip().splitlines()) == 1
    log.close()


def test_summary_counts_calls_denials_and_tokens(tmp_path):
    path = tmp_path / "audit.jsonl"
    with AuditLog(path) as log:
        log.record(phase="p", action="plan", tokens_in=100, tokens_out=20)
        log.record(phase="p", action="tool_call", tool="fls", verdict="allow")
        log.record(phase="p", action="tool_call", tool="volatility3", verdict="allow")
        log.record(
            phase="p", action="tool_call", tool="dd", verdict="tool_explicitly_denied"
        )
        log.record(phase="p", action="validation", revised=True)
    summary = log.summary()
    assert summary["tool_calls"] == 3
    assert summary["denied_calls"] == 1
    assert summary["denials_by_code"] == {"tool_explicitly_denied": 1}
    assert summary["revisions"] == 1
    assert summary["tokens_in"] == 100
    assert summary["tokens_out"] == 20
