"""Backends that expose the Protocol SIFT toolchain to the agent.

Two implementations satisfy one ``SiftBackend`` protocol:

* ``ProtocolSiftBackend`` speaks MCP over stdio to the real Protocol SIFT server
  on a SANS SIFT Workstation. The ``mcp`` dependency is imported lazily so the
  rest of the package - and the entire ``--dry-run`` path - works with no MCP
  install and no workstation present.
* ``SimulatedSiftBackend`` replays a fixed, self-consistent intrusion scenario
  from canned fixtures. It needs no API key, no network, and no SIFT install,
  which makes the agent runnable, testable, and demoable offline while still
  exercising the full guardrail -> tool -> finding pipeline.

A tool result carries both human/LLM-readable ``output`` text and, for the
simulated backend, a tuple of structured ``Signal`` objects. The real backend
returns raw text only; interpreting it into findings is the planner's job.
"""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel

from .config import READONLY_TOOLS

Severity = Literal["info", "low", "medium", "high", "critical"]


class ToolSpec(BaseModel):
    name: str
    description: str


class Signal(BaseModel):
    """A structured forensic observation surfaced by a tool.

    Simulated results ship these so the offline scripted planner can produce
    real findings deterministically. Real MCP results leave them empty and the
    model extracts findings from ``ToolResult.output`` text instead.
    """

    title: str
    detail: str
    severity: Severity = "info"
    mitre: tuple[str, ...] = ()
    iocs: tuple[str, ...] = ()
    artifact: str | None = None


class ToolResult(BaseModel):
    tool: str
    ok: bool
    output: str
    error: str | None = None
    signals: tuple[Signal, ...] = ()


@runtime_checkable
class SiftBackend(Protocol):
    """Minimal async surface the agent needs from any tool provider."""

    name: str

    async def list_tools(self) -> tuple[ToolSpec, ...]: ...

    async def call_tool(self, name: str, args: dict) -> ToolResult: ...

    async def aclose(self) -> None: ...


def _allowlist_specs() -> tuple[ToolSpec, ...]:
    """Tool specs derived from the read-only catalog, in deterministic order."""
    return tuple(
        ToolSpec(name=name, description=desc)
        for name, desc in sorted(READONLY_TOOLS.items())
    )


# --------------------------------------------------------------------------- #
# Simulated backend
# --------------------------------------------------------------------------- #

# A single coherent intrusion the simulated tools all corroborate: a malicious
# binary masquerading as svchost.exe, launched from a user Temp path with the
# wrong parent, kept alive by a Run key, beaconing to an external host. Every
# fixture below points at the same story so findings cross-validate.
_SIM_IOC_HOST = "185.220.101.47"
_SIM_IOC_PATH = r"C:\Users\victim\AppData\Local\Temp\svchost.exe"
_SIM_IOC_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

_SIMULATED: dict[str, ToolResult] = {
    "sha256sum": ToolResult(
        tool="sha256sum",
        ok=True,
        output=(
            f"{_SIM_IOC_HASH}  /evidence/disk.raw\n"
            "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00  /evidence/memory.mem"
        ),
    ),
    "hashdeep": ToolResult(
        tool="hashdeep",
        ok=True,
        output="2 files hashed, 0 mismatches against baseline set.",
    ),
    "mmls": ToolResult(
        tool="mmls",
        ok=True,
        output=(
            "DOS Partition Table\n"
            "Units are in 512-byte sectors\n"
            "      Slot      Start        End          Length       Description\n"
            "002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)\n"
            "003:  000:001   0000206848   0083886079   0083679232   NTFS / exFAT (0x07)"
        ),
    ),
    "fsstat": ToolResult(
        tool="fsstat",
        ok=True,
        output="FILE SYSTEM INFORMATION\nFile System Type: NTFS\nVolume Serial Number: 8A7C-2F19",
    ),
    "volatility3": ToolResult(
        tool="volatility3",
        ok=True,
        output=(
            "PID    PPID   ImageFileName   Path\n"
            "4123   3344   svchost.exe     " + _SIM_IOC_PATH + "\n"
            "3344   3300   explorer.exe    C:\\Windows\\explorer.exe\n"
            "0772   0568   svchost.exe     C:\\Windows\\System32\\svchost.exe\n"
            "[malfind] PID 4123 svchost.exe: MZ header in RWX private memory at 0x1f0000\n"
            "[netscan] PID 4123 -> " + _SIM_IOC_HOST + ":443 ESTABLISHED"
        ),
        signals=(
            Signal(
                title="Imposter svchost.exe with wrong parent and path",
                detail=(
                    "PID 4123 svchost.exe is a child of explorer.exe (PPID 3344) and "
                    "runs from " + _SIM_IOC_PATH + ". Legitimate svchost descends from "
                    "services.exe and lives in System32."
                ),
                severity="critical",
                mitre=("T1036.005", "T1055"),
                iocs=(_SIM_IOC_PATH,),
                artifact="memory.mem",
            ),
            Signal(
                title="Injected code in PID 4123",
                detail="malfind found an MZ image in RWX private memory, consistent with process injection.",
                severity="high",
                mitre=("T1055",),
                artifact="memory.mem",
            ),
            Signal(
                title="C2 beacon from PID 4123",
                detail=f"netscan shows an established connection to {_SIM_IOC_HOST}:443 owned by the imposter process.",
                severity="critical",
                mitre=("T1071.001",),
                iocs=(f"{_SIM_IOC_HOST}:443",),
                artifact="memory.mem",
            ),
        ),
    ),
    "strings": ToolResult(
        tool="strings",
        ok=True,
        output=(
            f"http://{_SIM_IOC_HOST}/gate.php\n"
            "cmd.exe /c powershell -enc SQBFAFgA\n"
            "User-Agent: Mozilla/5.0 (compatible; beacon)"
        ),
    ),
    "regripper": ToolResult(
        tool="regripper",
        ok=True,
        output=(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "  Updater -> " + _SIM_IOC_PATH + "\n"
            "  LastWrite: 2026-05-20 02:14:07Z"
        ),
        signals=(
            Signal(
                title="Run-key persistence",
                detail=(
                    "HKLM Run value 'Updater' launches " + _SIM_IOC_PATH + " at logon; "
                    "LastWrite clusters with the intrusion window."
                ),
                severity="high",
                mitre=("T1547.001",),
                iocs=(_SIM_IOC_PATH,),
                artifact="disk.raw",
            ),
        ),
    ),
    "fls": ToolResult(
        tool="fls",
        ok=True,
        output=(
            "r/r 64207-128-1: Users/victim/AppData/Local/Temp/svchost.exe\n"
            "r/r 64207-128-1 (deleted): Users/victim/AppData/Local/Temp/dropper.tmp"
        ),
    ),
    "istat": ToolResult(
        tool="istat",
        ok=True,
        output="inode: 64207\nAllocated\nSize: 184320\nCreated:\t2026-05-20 02:13:55 (UTC)",
    ),
    "icat": ToolResult(
        tool="icat",
        ok=True,
        output="MZ\x90\x00... (PE binary content elided in simulation)",
    ),
    "log2timeline": ToolResult(
        tool="log2timeline",
        ok=True,
        output="Parsed 41822 events into plaso.dump.",
    ),
    "psort": ToolResult(
        tool="psort",
        ok=True,
        output=(
            "2026-05-20T02:13:55Z FILE  dropper.tmp written to Temp\n"
            "2026-05-20T02:14:01Z FILE  svchost.exe created in Temp\n"
            "2026-05-20T02:14:07Z REG   Run\\Updater set\n"
            "2026-05-20T02:14:09Z NET   outbound 185.220.101.47:443"
        ),
        signals=(
            Signal(
                title="Tight dropper-to-beacon timeline",
                detail=(
                    "Within 14 seconds: dropper write, payload create, persistence set, "
                    "and first C2 connection - a single automated infection chain."
                ),
                severity="high",
                mitre=("T1059.001",),
                artifact="disk.raw",
            ),
        ),
    ),
    "mactime": ToolResult(
        tool="mactime",
        ok=True,
        output="Mon May 20 2026 02:13:55  184320 .a.b  Users/victim/AppData/Local/Temp/svchost.exe",
    ),
    "bulk_extractor": ToolResult(
        tool="bulk_extractor",
        ok=True,
        output=(
            f"url.txt: http://{_SIM_IOC_HOST}/gate.php\n"
            "email.txt: exfil@mail.protonmail.com"
        ),
        signals=(
            Signal(
                title="Carved C2 URL and exfil address",
                detail=f"bulk_extractor recovered http://{_SIM_IOC_HOST}/gate.php and an external exfil mailbox.",
                severity="medium",
                mitre=("T1567",),
                iocs=(f"http://{_SIM_IOC_HOST}/gate.php", "exfil@mail.protonmail.com"),
                artifact="disk.raw",
            ),
        ),
    ),
    "tshark": ToolResult(
        tool="tshark",
        ok=True,
        output=f"1   0.000000  10.0.0.5 -> {_SIM_IOC_HOST}  TLSv1.2  Client Hello (SNI: update-cdn.top)",
    ),
    "evtx_dump": ToolResult(
        tool="evtx_dump",
        ok=True,
        output=(
            "EventID 4624 Type 10 (RemoteInteractive) Account: victim  Source: 10.0.0.9\n"
            "EventID 7045 Service installed: 'WinUpdaterSvc' ImagePath=" + _SIM_IOC_PATH
        ),
        signals=(
            Signal(
                title="RDP logon and rogue service install",
                detail=(
                    "A type-10 (RDP) logon for 'victim' precedes a 7045 service install "
                    "named 'WinUpdaterSvc' pointing at the imposter binary."
                ),
                severity="high",
                mitre=("T1021.001", "T1543.003"),
                iocs=("10.0.0.9",),
                artifact="disk.raw",
            ),
        ),
    ),
    "yara": ToolResult(
        tool="yara",
        ok=True,
        output=f"Cobalt_Strike_Beacon {_SIM_IOC_PATH}",
        signals=(
            Signal(
                title="YARA: Cobalt Strike beacon",
                detail="The Temp svchost.exe matches a Cobalt Strike beacon signature.",
                severity="critical",
                mitre=("T1071.001",),
                iocs=(_SIM_IOC_HASH,),
                artifact="disk.raw",
            ),
        ),
    ),
    "exiftool": ToolResult(
        tool="exiftool",
        ok=True,
        output="File Type: Win32 EXE\nLinker Version: 14.0\nTime Stamp: 2026:05:19 23:01:11Z",
    ),
}


class SimulatedSiftBackend:
    """Replays a fixed intrusion scenario with no external dependencies."""

    name = "simulated"

    async def list_tools(self) -> tuple[ToolSpec, ...]:
        return _allowlist_specs()

    async def call_tool(self, name: str, args: dict) -> ToolResult:
        canned = _SIMULATED.get(name)
        if canned is not None:
            return canned
        # Allowlisted but unscripted tool: return an empty-but-ok result so the
        # loop stays well-defined rather than raising.
        return ToolResult(
            tool=name,
            ok=True,
            output=f"[simulated] {name} produced no noteworthy artifacts.",
        )

    async def aclose(self) -> None:
        return None


# --------------------------------------------------------------------------- #
# Real Protocol SIFT backend (MCP over stdio)
# --------------------------------------------------------------------------- #


class ProtocolSiftBackend:
    """Talks to the real Protocol SIFT MCP server as a stdio subprocess.

    The ``mcp`` package is imported lazily inside ``_ensure_session`` so importing
    this module never requires the dependency; only an actual real run does.
    """

    name = "protocol-sift"

    def __init__(self, command: str, args: tuple[str, ...] = ()) -> None:
        self._command = command
        self._args = list(args)
        self._session = None  # mcp.ClientSession once connected
        self._stack = None  # contextlib.AsyncExitStack holding the streams

    async def _ensure_session(self):
        if self._session is not None:
            return self._session
        from contextlib import AsyncExitStack

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        self._stack = AsyncExitStack()
        params = StdioServerParameters(command=self._command, args=self._args)
        read, write = await self._stack.enter_async_context(stdio_client(params))
        session = await self._stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        self._session = session
        return session

    async def list_tools(self) -> tuple[ToolSpec, ...]:
        session = await self._ensure_session()
        listing = await session.list_tools()
        specs = [
            ToolSpec(name=tool.name, description=tool.description or "")
            for tool in listing.tools
        ]
        # Deterministic order for prompt-cache stability.
        specs.sort(key=lambda spec: spec.name)
        return tuple(specs)

    async def call_tool(self, name: str, args: dict) -> ToolResult:
        session = await self._ensure_session()
        try:
            response = await session.call_tool(name, args)
        except Exception as exc:  # surface transport/tool errors as a result
            return ToolResult(tool=name, ok=False, output="", error=str(exc))
        text = "\n".join(
            block.text
            for block in response.content
            if getattr(block, "type", None) == "text"
        )
        return ToolResult(
            tool=name,
            ok=not getattr(response, "isError", False),
            output=text,
            error=None,
        )

    async def aclose(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None
            self._session = None
