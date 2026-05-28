# FIND EVIL! — submission copy (sift-sentinel)

Event: FIND EVIL! (Devpost) — autonomous cyber incident response, $22K.
Deadline 2026-06-15 23:45 EDT. Teams <=5, solo OK. Rules explicitly allow
OpenClaw / MCP / Claude Code / AutoGen / CrewAI / LangGraph.

Repo: https://github.com/MukundaKatta/sift-sentinel

## Tagline

    An autonomous DFIR triage agent that drives Protocol SIFT through the SANS
    Find Evil methodology behind code-enforced guardrails the model cannot talk
    its way past, and writes a replayable audit trail of every decision.

## Short description

    sift-sentinel is a guarded plan-act-validate agent for digital forensics
    and incident response. It walks the seven-phase SANS Find Evil flow, asking
    a planner (a real Claude model, or a deterministic scripted planner) which
    read-only forensic tools to run at each phase, and drives them over MCP on
    the SANS SIFT Workstation via Protocol SIFT. Every proposed tool call is
    mediated by three independent code checks plus an evidence-integrity ledger
    before it can run, and every transition is written to a JSONL audit trail.
    The whole guarded loop runs offline with no API key and no VM, so a judge
    can verify it in one command.

## Inspiration

    Most "autonomous IR" demos put "do not modify evidence" in a system prompt
    and hope the model complies. In real forensics that is malpractice: chain
    of custody has to be enforced, not requested. We wanted an agent that does
    not trust the model at all, where the safety properties are architectural
    and the entire investigation is auditable line by line.

## What it does

    It runs the SANS Find Evil methodology as a fixed seven-phase playbook:
    acquisition and triage, memory and process anomalies, persistence, super
    timeline, network and exfiltration, lateral movement and accounts, then
    synthesis and reporting. For each phase the planner proposes read-only
    tools (volatility3, log2timeline, regripper, tshark, sha256sum, and others).
    It produces a SOC-ready IR report with verdict, findings, an IOC table, a
    MITRE ATT&CK mapping, and evidence hashes, plus a self-scored
    precision/recall/F1 report when given an analyst ground-truth key.

## How we built it

    The agent is a deterministic plan-act-validate state machine, not a
    blank-prompt improviser. The Find Evil heuristics live as data in the
    playbook so the scripted planner and the real Claude planner read from one
    source of truth. Two ideas carry the project:

    1. The guardrail is code, not a prompt. guardrails.py is the policy
       enforcement point between planner and toolchain: an allowlist of
       read-only tools, an explicit deny list for destructive tools (dd, mkfs,
       rm, mount...), a path jail that resolves every path argument and rejects
       anything outside the evidence/workspace roots, and a SHA-256 evidence
       ledger re-verified after every call and as a final gate. Deny reasons
       are a closed Literal union, not free-form strings.

    2. Every transition is auditable. audit.py writes one flushed JSONL record
       per step (plan, tool_call, validation, revision, report, stop) so the
       trail survives a crash and the run can be replayed and graded.

    It extends Protocol SIFT: --backend protocol-sift speaks MCP over stdio to
    the Protocol SIFT server; --backend simulated is the offline stand-in for
    the demo and tests. Every SIFT command is exposed through one stable
    run_sift_tool definition, which keeps the cached prompt prefix byte-stable
    across turns and the runs reproducible.

## Challenges we ran into

    Making the guardrail genuinely unbypassable rather than advisory: path
    arguments hide in nested tool-call structures, so the jail walks arguments
    recursively and resolves symlinks and ~ before deciding. Keeping the prompt
    prefix byte-identical across turns (one stable tool definition, fixed phase
    order) so the prompt cache holds and runs stay reproducible. And scoring
    honestly: the ground-truth key intentionally includes one IOC the simulated
    tools do not surface, so recall is below 1.0 instead of a rigged perfect.

## Accomplishments we're proud of

    The entire guarded loop, all four guardrail checks, the audit trail, the
    self-scoring, and all four deliverables run offline and deterministically.
    32 tests pass with no API key or VM. The safety properties are provable by
    reading the code, not by trusting a prompt.

## What we learned

    For agentic IR, the value is in enforced constraints and audit quality, not
    in a clever prompt. If "don't touch the evidence" is a policy the model can
    override, it is not a control.

## What's next (needs the real environment)

    Honest scope. Done and verifiable now with no account or VM: the full loop,
    guardrails, audit, self-scoring, all deliverables, 32 green tests. Still to
    demonstrate against live data: a SANS SIFT Workstation with Protocol SIFT
    and its MCP server reachable, real case evidence (memory/disk/pcap), and the
    demo video of a live run. Swapping --backend simulated for
    --backend protocol-sift is the only change needed to point at the real
    toolchain.

## Tech tags

    python, dfir, incident-response, cybersecurity, forensics, sans-sift,
    protocol-sift, find-evil, mcp, model-context-protocol, claude, anthropic,
    agent, guardrails, audit-log, mitre-attack, mit

## Links

  - Repo: https://github.com/MukundaKatta/sift-sentinel
  - 60-second offline proof: `pip install -e . && python examples/run_offline.py`
  - Tests: `python -m pytest -q` (32, offline, deterministic)

## Submission requirement checklist

  - [x] Public repo, working code, offline-verifiable (32 tests green)
  - [x] Uses an allowed stack (Claude / MCP / Protocol SIFT)
  - [ ] Live run against SANS SIFT Workstation + Protocol SIFT — USER TODO (needs VM)
  - [ ] Real-evidence investigation — USER TODO (needs case data)
  - [ ] Demo video of a live run — USER TODO (depends on the two above)
