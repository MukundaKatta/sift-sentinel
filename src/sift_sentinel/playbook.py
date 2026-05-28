"""The SANS "Find Evil" triage methodology, encoded as an ordered playbook.

The agent does not improvise an investigation from a blank prompt. It walks a
fixed sequence of forensic phases, each carrying the concrete known-good /
known-bad heuristics a SANS analyst would apply by hand. This serves three
goals the FIND EVIL! rubric cares about:

* Methodology - the phases mirror the SANS "Hunt Evil / Know Normal" flow, so
  the agent's reasoning is auditable against an industry-standard reference.
* Determinism - a fixed phase order and a fixed suggested-tool order per phase
  keep the model's prompt prefix byte-stable across turns, which preserves the
  Anthropic prompt cache and makes runs reproducible.
* Grounding - heuristics are stated as data, not buried in a system prompt, so
  the planner (real or scripted) reads from the same source of truth.

Every tool named in ``suggested_tools`` must exist in the read-only allowlist in
``config.READONLY_TOOLS``; a unit test enforces that invariant so the playbook
can never silently suggest a tool the guardrail will deny.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Phase:
    """One stage of the triage, with the heuristics that define "evil" in it."""

    id: str
    name: str
    objective: str
    # Known-good vs known-bad signals an analyst checks in this phase. Stated
    # plainly so they can be injected into the planner prompt verbatim.
    heuristics: tuple[str, ...]
    # Allowlisted tools relevant here, in deterministic priority order.
    suggested_tools: tuple[str, ...]


# The ordered methodology. Order is load-bearing: acquisition integrity first,
# live process anomalies next (where most intrusions are caught), then the
# persistence / timeline / network / lateral sweeps, and finally synthesis.
PHASES: tuple[Phase, ...] = (
    Phase(
        id="triage",
        name="Acquisition & Triage",
        objective=(
            "Establish the evidence layout and lock in an integrity baseline "
            "before touching anything else."
        ),
        heuristics=(
            "Hash every evidence file at case open; this is the chain-of-custody anchor.",
            "Map the partition and filesystem layout so later inode references are unambiguous.",
            "Note image type (disk vs memory vs pcap) to route the right specialist tools.",
            "Never mutate evidence; only derived artifacts may be written to the workspace.",
        ),
        suggested_tools=("sha256sum", "hashdeep", "mmls", "fsstat"),
    ),
    Phase(
        id="memory_process",
        name="Memory & Process Anomalies",
        objective=(
            "Find malicious processes by deviation from a known-good Windows "
            "process tree - the heart of the SANS Find Evil method."
        ),
        heuristics=(
            "Wrong parent: svchost.exe must descend from services.exe; never from explorer.exe or a browser.",
            "Wrong path: system binaries (svchost, lsass, csrss) live in System32; copies elsewhere are suspect.",
            "Wrong count: exactly one lsass.exe and one wininit.exe; multiple is a red flag.",
            "Imposter names: scvhost.exe, lsass.exe with a trailing space, csrsss.exe - typosquatted system names.",
            "Orphans: System32 binaries with no parent or an exited parent warrant a second look.",
            "Injected/packed code: malfind hits, RWX private memory, and hollowed images signal injection.",
            "User context: SYSTEM-level binaries running under a normal user (or vice versa) are anomalous.",
        ),
        suggested_tools=("volatility3", "strings"),
    ),
    Phase(
        id="persistence",
        name="Persistence Mechanisms",
        objective="Determine how the adversary survives a reboot.",
        heuristics=(
            "Registry Run/RunOnce keys pointing at temp, AppData, or unsigned binaries.",
            "Services whose ImagePath is a script, a temp path, or an unsigned executable.",
            "Scheduled tasks and WMI event subscriptions invoking encoded PowerShell.",
            "Startup-folder LNKs and userinit/Shell winlogon hijacks.",
            "Recently modified persistence keys whose timestamps cluster with the suspected intrusion.",
        ),
        suggested_tools=("regripper", "fls", "icat"),
    ),
    Phase(
        id="timeline",
        name="Super-Timeline",
        objective="Order the intrusion in time and expose timestamp tampering.",
        heuristics=(
            "Build a Plaso super-timeline; pivot tightly around the first suspicious artifact.",
            "Look for activity bursts: dropper write, execution, then outbound connection within seconds.",
            "Timestomping: a Birth time later than Modified/Accessed/Changed, or zeroed sub-second fields.",
            "Files dropped into Temp, Downloads, AppData, or ProgramData right before execution.",
            "Correlate file-create events with the persistence keys found in the prior phase.",
        ),
        suggested_tools=("log2timeline", "psort", "mactime", "fls"),
    ),
    Phase(
        id="network_exfil",
        name="Network & Exfiltration",
        objective="Identify C2 channels and data exfiltration.",
        heuristics=(
            "Listening or established sockets owned by non-network binaries (notepad, calc) signal injection.",
            "Beaconing: regular fixed-interval connections to a single external host.",
            "Carved URLs, emails, and PII features hint at staged or exfiltrated data.",
            "Connections to raw IPs, dynamic-DNS hosts, or known-bad infrastructure.",
            "Large outbound transfers or archive creation immediately before a connection.",
        ),
        suggested_tools=("volatility3", "tshark", "bulk_extractor"),
    ),
    Phase(
        id="lateral",
        name="Lateral Movement & Accounts",
        objective="Trace credential abuse and movement between hosts.",
        heuristics=(
            "Security log 4624/4625: type-3 (network) and type-10 (RDP) logons at odd hours.",
            "New local accounts (4720) or privilege grants (4672) near the intrusion window.",
            "Service installs (7045) and remote task creation indicate hands-on-keyboard movement.",
            "Cleared event logs (1102) are themselves an indicator of compromise.",
            "Pass-the-hash / overpass-the-hash patterns: NTLM logons for accounts that normally use Kerberos.",
        ),
        suggested_tools=("evtx_dump",),
    ),
    Phase(
        id="report",
        name="Synthesis & Reporting",
        objective=(
            "Synthesize findings into an incident-response narrative with IOCs, "
            "a MITRE ATT&CK mapping, and evidence hashes - no further tools."
        ),
        heuristics=(
            "Every claim must cite the artifact and the tool output that supports it.",
            "Separate confirmed findings from unproven hypotheses; state confidence explicitly.",
            "Map each behavior to a MITRE ATT&CK technique where one applies.",
            "Re-verify evidence integrity against the case-open baseline before closing.",
        ),
        suggested_tools=(),
    ),
)


# Index for O(1) lookup by id; phases are few but callers reference them by name.
PHASES_BY_ID: dict[str, Phase] = {phase.id: phase for phase in PHASES}


def phase_index(phase_id: str) -> int:
    """Return the ordinal of a phase, or -1 if unknown."""
    for index, phase in enumerate(PHASES):
        if phase.id == phase_id:
            return index
    return -1
