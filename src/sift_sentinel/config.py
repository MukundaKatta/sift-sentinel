"""Runtime configuration and the SIFT tool risk catalog.

The catalog is the source of truth for what the agent is allowed to run. It is
intentionally an allowlist of read-only forensic tools: the guardrail layer
(see guardrails.py) denies anything not listed here, so adding a tool is a
deliberate, reviewable act rather than something the model can do on its own.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()

DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_MAX_ITERATIONS = 40

# Read-only DFIR tools the agent may invoke. Each reads evidence and may write
# derived artifacts (timelines, carved files) only into the case workspace.
# Keeping the value as a short human description keeps this easy to audit.
READONLY_TOOLS: dict[str, str] = {
    # Memory forensics
    "volatility3": "Analyze a memory image (pslist, malfind, netscan, etc.).",
    # Timeline
    "log2timeline": "Build a Plaso super-timeline from a mounted image.",
    "psort": "Filter and render a Plaso storage file to a timeline.",
    "mactime": "Render a Sleuth Kit body file into a MAC timeline.",
    # Filesystem (Sleuth Kit, read-only)
    "mmls": "List the partition layout of a disk image.",
    "fsstat": "Show filesystem metadata for a volume.",
    "fls": "List file and directory names, including deleted entries.",
    "istat": "Show metadata for a specific inode.",
    "icat": "Stream the content of a file by inode (read-only).",
    # Carving / IOC discovery
    "bulk_extractor": "Carve emails, URLs, and PII features from an image.",
    "yara": "Scan evidence for known-bad signatures.",
    "strings": "Extract printable strings from a binary or image.",
    # Windows artifacts
    "regripper": "Parse Windows registry hives for persistence artifacts.",
    "evtx_dump": "Convert Windows .evtx event logs to readable records.",
    # Integrity / metadata (never mutate evidence)
    "sha256sum": "Hash a file for evidence-integrity verification.",
    "hashdeep": "Recursively hash a tree and audit against a known set.",
    "exiftool": "Read embedded metadata from a file (read-only).",
    # Network
    "tshark": "Read and filter a pcap capture (read-only).",
}

# Tools that are explicitly denied even if a model asks for them, with the
# reason surfaced back to the planner so it can choose a safe alternative.
DENIED_TOOLS: dict[str, str] = {
    "dd": "Can overwrite evidence or devices; use icat for read-only extraction.",
    "dcfldd": "Imaging tool that writes raw devices; out of scope for triage.",
    "mkfs": "Formats a filesystem; destructive.",
    "fdisk": "Mutates partition tables; destructive.",
    "rm": "Deletes files; destructive.",
    "mount": "Mounting read-write can change timestamps; the harness mounts read-only.",
    "chmod": "Mutates evidence metadata.",
    "chown": "Mutates evidence metadata.",
}


@dataclass(frozen=True)
class Settings:
    """Resolved runtime settings for a single agent run."""

    model: str = DEFAULT_MODEL
    max_iterations: int = DEFAULT_MAX_ITERATIONS
    mcp_command: str = "protocol-sift-mcp"
    api_key: str | None = None
    allowlist: frozenset[str] = field(default_factory=lambda: frozenset(READONLY_TOOLS))

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            model=os.environ.get("SIFT_SENTINEL_MODEL", DEFAULT_MODEL),
            max_iterations=int(
                os.environ.get("SIFT_SENTINEL_MAX_ITERATIONS", DEFAULT_MAX_ITERATIONS)
            ),
            mcp_command=os.environ.get("SIFT_SENTINEL_MCP_COMMAND", "protocol-sift-mcp"),
            api_key=os.environ.get("ANTHROPIC_API_KEY"),
            allowlist=frozenset(READONLY_TOOLS),
        )
