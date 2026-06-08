# sift-sentinel

An autonomous DFIR triage agent that drives **Protocol SIFT** (Claude Code + MCP + 200+ forensic tools on the SANS SIFT Workstation) through the SANS **Find Evil** methodology, behind **architectural guardrails** that the model cannot talk its way past, and that writes a complete, replayable **audit trail** of every decision.

Built for the FIND EVIL! challenge. The whole guarded loop runs offline with no API key and no VM, so you can verify it in one command.

```
  sift-sentinel  case DEMO-CASE
  backend=simulated  planner=scripted
  --------------------------------------------------------
  verdict        : COMPROMISED
  confidence     : 1.00 (confirmed)
  findings       : 7 distinct (10 recorded)
  phases done    : 7/7
  tool calls     : 17
  denied calls   : 0
  tokens (in/out): 0/0
```

## Architecture

![sift-sentinel architecture: a guarded plan-act-validate loop over the SANS Find Evil playbook. A planner proposes one tool call, the check_call guardrail enforces an allowlist, explicit-deny, and path jail, the backend runs it over MCP against the SIFT Workstation or a simulated stand-in, the verify_evidence guardrail re-checks a SHA-256 integrity ledger, and findings integrate into a revisable hypothesis. Every step writes a JSONL audit record, and the run emits an IR report, audit trail, state, and accuracy report.](docs/architecture.png)

The agent walks a fixed SANS Find Evil playbook. Every tool call the planner proposes passes a code-level guardrail (allowlist, explicit-deny, path jail) before the backend runs it; evidence integrity is re-verified against a case-open SHA-256 baseline after every call; and every transition is written to a replayable JSONL audit trail. The simulated backend runs the whole loop offline, so the architecture and the guardrails are verifiable with no API key and no VM.

## The 60-second proof

No API key, no SIFT VM, no network. This replays a fixed simulated intrusion through the scripted planner and prints both reports:

```bash
pip install -e .
python examples/run_offline.py
```

Or run the CLI and write the graded deliverables to disk:

```bash
PYTHONPATH=src python -m sift_sentinel \
  --ground-truth datasets/simulated-intrusion.groundtruth.json \
  --workspace ./sift-workspace
```

Run the tests (all offline and deterministic):

```bash
python -m pytest -q
```

A small subset of those checks also runs with **only the Python standard
library** -- no `pytest`, no `pydantic`, no install at all -- so the tool
catalog, the explicit-deny list, and the Find Evil playbook invariants stay
verifiable in a bare interpreter:

```bash
python -m unittest discover -s tests/unit
```

The repo ships two tiny synthetic evidence fixtures (`evidence/disk.raw`, `evidence/memory.mem`) so the offline run hashes them at case open and the IR report's chain-of-custody section shows real SHA-256 values. They are obvious placeholders, not real case data.

## Why this design

The rubric rewards **enforced architectural constraints** over prompt-based ones, and a **high-quality audit trail** over a black box. Most agent demos put "do not modify evidence" in a system prompt and hope. This does not trust the model at all.

Two ideas carry the project:

1. **The guardrail is code, not a prompt.** Every tool call the planner proposes is mediated by three independent deterministic checks before it can run, and evidence integrity is re-verified against a case-open hash baseline after every call. If the model asks for `dd`, it is denied. If it points a path at `/etc/passwd`, it is denied. The model has no way to override this.

2. **Every transition is auditable.** Plans, guarded denials, tool calls, integrity checks, findings, and hypothesis revisions are each written to a JSONL trail as they happen. The investigation can be replayed and graded line by line.

## How it works

The agent is a deterministic plan-act-validate state machine. It does **not** improvise from a blank prompt. It walks a fixed playbook that encodes the SANS Find Evil flow, and for each phase it asks a planner which read-only tools to run:

```
              plan ──▶ guardrail.check_call ──▶ backend.call_tool ──▶ guardrail.verify_evidence ──▶ interpret ──▶ integrate
               │            (allowlist /            (MCP or              (hash baseline             (findings)    (hypothesis +
               │             deny / jail)            simulated)           re-check)                                revision)
               └──────────────────────────────── audit.record at every step ────────────────────────────────────┘
```

The playbook ([`src/sift_sentinel/playbook.py`](src/sift_sentinel/playbook.py)) runs seven phases in a load-bearing order:

| # | Phase | What it hunts |
|---|-------|----------------|
| 1 | Acquisition & Triage | Hash baseline, partition/filesystem layout, image type |
| 2 | Memory & Process Anomalies | Wrong parent/path/count, imposter names, injected code (the heart of Find Evil) |
| 3 | Persistence Mechanisms | Run keys, rogue services, scheduled tasks, startup hijacks |
| 4 | Super-Timeline | Dropper-to-beacon bursts, timestomping, correlation with persistence |
| 5 | Network & Exfiltration | C2 beaconing, sockets on non-network binaries, carved URLs |
| 6 | Lateral Movement & Accounts | 4624/4625 logons, service installs, cleared logs, pass-the-hash |
| 7 | Synthesis & Reporting | IOCs, MITRE ATT&CK mapping, evidence hashes, final integrity gate |

The phase order and the per-phase suggested-tool order are fixed. That keeps the model's prompt prefix byte-stable across turns, which preserves the Anthropic prompt cache and makes runs reproducible. The Find Evil heuristics live as data in the playbook, not buried in a system prompt, so the scripted planner and the real Claude planner read from the same source of truth.

## The architectural guardrail

[`src/sift_sentinel/guardrails.py`](src/sift_sentinel/guardrails.py) is the policy enforcement point between the planner and the toolchain. Three checks, plus integrity:

1. **Allowlist.** Only the read-only forensic tools in [`config.READONLY_TOOLS`](src/sift_sentinel/config.py) (volatility3, log2timeline, regripper, tshark, sha256sum, and 13 others) may run. Anything not on the list is denied as `tool_not_allowlisted`. Adding a tool is a deliberate, reviewable code change, not something the model can do at runtime.
2. **Explicit deny.** Destructive tools (`dd`, `mkfs`, `rm`, `mount`, `chmod`, ...) are denied as `tool_explicitly_denied`, with the reason surfaced back to the planner so it can pick a safe alternative (for example `icat` for read-only extraction instead of `dd`).
3. **Path jail.** Every path-shaped argument, found by recursively walking the tool-call arguments, must resolve (after symlink and `~` expansion) inside the evidence or workspace roots. Anything else is denied as `path_outside_jail`, so the agent cannot read or write the host.
4. **Integrity ledger.** Evidence files are SHA-256 hashed at case open. After every tool call, and once more as a final gate before the report, the ledger re-verifies them. Any byte change or deletion is `evidence_hash_mismatch`. This is defense in depth: even if a tool somehow slipped past the allowlist, a mutation of evidence is caught.

Deny reasons are a closed `Literal` union (`DenyCode`), not free-form strings, so downstream branching, the audit log, and the tests stay exhaustive and stable.

## The audit trail

[`src/sift_sentinel/audit.py`](src/sift_sentinel/audit.py) writes one flushed JSONL record per step, so the trail survives a crash mid-run. Each record carries the phase, the action (`plan`, `tool_call`, `validation`, `revision`, `report`, `stop`), the tool and args, the guardrail verdict, a result summary, confidence, the standing hypothesis, and token usage.

The offline demo produces 37 records for a 7-phase run, including the two hypothesis **revisions** where the agent's belief crossed the confirmation threshold. A revision is a visible belief update, not a hidden one: when accumulated findings push compromise confidence past 0.70, the hypothesis flips from `open` to `confirmed` and that transition is logged.

## Self-scored accuracy

When you pass `--ground-truth`, the run scores itself against an analyst key ([`datasets/simulated-intrusion.groundtruth.json`](datasets/simulated-intrusion.groundtruth.json)) and writes a precision/recall/F1 report for IOCs and MITRE techniques:

```
- Verdict: expected `compromised`, got `compromised` (correct)

### Indicators of Compromise
- Precision: 1.00   Recall: 0.83   F1: 0.91
- Missed: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

### MITRE ATT&CK Techniques
- Precision: 1.00   Recall: 1.00   F1: 1.00
```

The ground-truth key intentionally includes one IOC (a payload hash) that the simulated tools do not surface, so the recall is honestly below 1.0 rather than a rigged perfect score.

## How it extends Protocol SIFT

Protocol SIFT ships Claude Code configured for DFIR: a `~/.claude/CLAUDE.md` orchestrator prompt, a `settings.json` permission allow/deny list, and skills for memory analysis, Plaso timelines, Sleuth Kit, Windows artifacts, and YARA. sift-sentinel sits on top of that baseline and turns it into a guarded, self-scoring agent loop:

- **`--backend protocol-sift`** ([`mcp_client.ProtocolSiftBackend`](src/sift_sentinel/mcp_client.py)) speaks MCP over stdio to the Protocol SIFT server, so the same forensic tools Protocol SIFT exposes are the ones the agent drives. `--backend simulated` is the offline stand-in used for the demo and tests.
- **`--planner claude`** ([`agent.ClaudePlanner`](src/sift_sentinel/agent.py)) drives the loop with a real model. Every SIFT command is exposed through a single stable `run_sift_tool` definition rather than one tool per command, which keeps the cached prompt prefix byte-identical across turns. `--planner scripted` walks the playbook deterministically with no API key.
- The allowlist mirrors the spirit of Protocol SIFT's permission model, but enforces it in code with a path jail and an evidence-integrity ledger that a prompt-level allow/deny list does not provide.

A live run, once the SIFT Workstation and MCP server are up:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export SIFT_SENTINEL_MCP_COMMAND=protocol-sift-mcp
sift-sentinel \
  --backend protocol-sift --planner claude \
  --case-id IR-2026-0042 \
  --evidence-root /cases/IR-2026-0042/evidence \
  --workspace   /cases/IR-2026-0042/work
```

## Deliverables each run writes

| File | What it is |
|------|------------|
| `analysis/forensic_audit.jsonl` | The full step-by-step audit trail |
| `reports/<case>-ir-report.md` | SOC-ready IR report: verdict, findings, IOC table, MITRE mapping, evidence hashes |
| `reports/<case>-state.json` | Raw case state for inspection or downstream tooling |
| `reports/<case>-accuracy.md` | Self-scored accuracy report (only with `--ground-truth`) |

## Configuration

Copy `.env.example` to `.env`. The agent reads:

| Variable | Default | Purpose |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | (none) | Required only for `--planner claude` |
| `SIFT_SENTINEL_MODEL` | `claude-sonnet-4-6` | Planner model |
| `SIFT_SENTINEL_MCP_COMMAND` | `protocol-sift-mcp` | How to launch the Protocol SIFT MCP server |
| `SIFT_SENTINEL_MAX_ITERATIONS` | `40` | Plan-act-validate budget before a forced stop |

## Layout

```
src/sift_sentinel/
  guardrails.py   allowlist + explicit-deny + path jail + evidence-hash ledger
  audit.py        flushed JSONL audit log + run summary
  playbook.py     the SANS Find Evil methodology as ordered phases + heuristics
  agent.py        plan-act-validate loop; scripted + Claude planners
  mcp_client.py   simulated backend and Protocol SIFT MCP backend
  config.py       read-only tool catalog, denied tools, settings
  accuracy.py     precision/recall/F1 against analyst ground truth
  report.py       IR report + accuracy report (pure functions of state)
  cli.py          argparse entrypoint
  py.typed        PEP 561 marker so consumers see the inline type hints
tests/            offline, deterministic pytest suite
  unit/           standard-library-only subset (python -m unittest)
datasets/         simulated-intrusion ground-truth key
evidence/         tiny synthetic disk.raw + memory.mem demo fixtures (not real evidence)
examples/         run_offline.py
```

## Status and what needs the real SIFT Workstation

Honest scope. What is done and verifiable right now, with no account or VM:

- The full guarded plan-act-validate loop, all four guardrail checks, the audit trail, the self-scoring, and all four deliverables run offline. `python -m pytest -q` is green; `python examples/run_offline.py` confirms the simulated compromise end to end.

What needs the real environment, and is therefore not yet demonstrated against live evidence:

- A **SANS SIFT Workstation** with **Protocol SIFT** installed and its MCP server reachable, to exercise `--backend protocol-sift` against the genuine 200+ tool catalog.
- **Real case evidence** (a memory image, a disk image, a pcap) to run a non-simulated investigation.
- The **demo video** of a live run, which depends on both of the above.

The simulated backend exists precisely so the architecture, the guardrails, and the audit quality can be proven without waiting on that environment. Swapping `--backend simulated` for `--backend protocol-sift` is the only change needed to point it at the real toolchain.

## License

MIT. See [`LICENSE`](LICENSE).
