"""The architectural guardrail is the core differentiator, so it is the most
heavily tested unit: every deny path, the path jail, and evidence integrity."""

from __future__ import annotations

from sift_sentinel.guardrails import Deny, EvidenceLedger, Guardrail


def _guard(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    guard = Guardrail(
        allowlist={"fls", "sha256sum", "volatility3"},
        denied={"dd": "Can overwrite evidence."},
        evidence_root=str(evidence),
        workspace_root=str(workspace),
    )
    return guard, evidence, workspace


def test_allows_allowlisted_tool_with_in_jail_path(tmp_path):
    guard, evidence, _ = _guard(tmp_path)
    verdict = guard.check_call("fls", {"image": str(evidence / "disk.raw")})
    assert verdict.decision == "allow"


def test_allows_write_into_workspace(tmp_path):
    guard, _, workspace = _guard(tmp_path)
    verdict = guard.check_call("fls", {"out": str(workspace / "analysis" / "x.csv")})
    assert verdict.decision == "allow"


def test_allows_non_path_string_args(tmp_path):
    guard, _, _ = _guard(tmp_path)
    verdict = guard.check_call("volatility3", {"plugin": "windows.pslist", "flag": "-r"})
    assert verdict.decision == "allow"


def test_denies_missing_tool_name(tmp_path):
    guard, _, _ = _guard(tmp_path)
    verdict = guard.check_call("", {})
    assert isinstance(verdict, Deny)
    assert verdict.code == "missing_tool_name"


def test_denies_explicitly_denied_tool(tmp_path):
    guard, _, _ = _guard(tmp_path)
    verdict = guard.check_call("dd", {})
    assert isinstance(verdict, Deny)
    assert verdict.code == "tool_explicitly_denied"


def test_denies_tool_not_on_allowlist(tmp_path):
    guard, _, _ = _guard(tmp_path)
    verdict = guard.check_call("nmap", {})
    assert isinstance(verdict, Deny)
    assert verdict.code == "tool_not_allowlisted"


def test_denies_path_outside_jail(tmp_path):
    guard, _, _ = _guard(tmp_path)
    verdict = guard.check_call("fls", {"image": "/etc/passwd"})
    assert isinstance(verdict, Deny)
    assert verdict.code == "path_outside_jail"


def test_denies_path_traversal_escape(tmp_path):
    guard, evidence, _ = _guard(tmp_path)
    escape = str(evidence / ".." / ".." / "etc" / "shadow")
    verdict = guard.check_call("fls", {"image": escape})
    assert isinstance(verdict, Deny)
    assert verdict.code == "path_outside_jail"


def test_ledger_baseline_then_clean_verify(tmp_path):
    target = tmp_path / "evidence" / "disk.raw"
    target.parent.mkdir()
    target.write_bytes(b"original evidence bytes")
    ledger = EvidenceLedger()
    baseline = ledger.baseline([str(target)])
    assert str(target) in {str(k) for k in baseline}
    assert ledger.verify() == []


def test_ledger_detects_mutation(tmp_path):
    target = tmp_path / "evidence" / "disk.raw"
    target.parent.mkdir()
    target.write_bytes(b"original evidence bytes")
    ledger = EvidenceLedger()
    ledger.baseline([str(target)])
    target.write_bytes(b"tampered")
    changed = ledger.verify()
    assert len(changed) == 1


def test_ledger_detects_deletion(tmp_path):
    target = tmp_path / "evidence" / "disk.raw"
    target.parent.mkdir()
    target.write_bytes(b"original evidence bytes")
    ledger = EvidenceLedger()
    ledger.baseline([str(target)])
    target.unlink()
    assert len(ledger.verify()) == 1


def test_verify_evidence_verdict_flips_on_tamper(tmp_path):
    guard, evidence, _ = _guard(tmp_path)
    target = evidence / "disk.raw"
    target.write_bytes(b"clean")
    guard.ledger.baseline([str(target)])
    assert guard.verify_evidence().decision == "allow"
    target.write_bytes(b"dirty")
    verdict = guard.verify_evidence()
    assert isinstance(verdict, Deny)
    assert verdict.code == "evidence_hash_mismatch"
