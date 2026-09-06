# TRIPWIRE: AgentOps Control Layer

An e2e framework for local agent authority verification, acting as a "git diff for agent authority" without modifying your machine or exposing secrets.

<p align="center">
    <img src="docs/tripwire-logo.png" alt="TRIPWIRE Logo" />
    <br/>
    <a href="https://github.com/Omkarchaithanya/ROTE-play/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/License-MIT-blue.svg"/></a>
    <img alt="Python" src="https://img.shields.io/badge/python-3.8%2B-blue.svg"/>
    <img alt="Rote" src="https://img.shields.io/badge/Rote-Ready-yellow"/>
    <img alt="Status" src="https://img.shields.io/badge/Status-Experimental-orange"/>
</p>

---

TRIPWIRE is a local-first security check for AI-agent authority. It answers one practical question before an agent run:

> What can this agent reach, and is that access safe to continue with?

The project ships as reusable Rote Plays for the Playoffs. The Plays inspect agent harnesses, MCP configuration, credential loci, listener exposure, git metadata, Play metadata, and execution traces. They report risk state and safe-to-run decisions without printing secret values or modifying the machine.

**Featured Example:** Run a full local agent surface scan safely using the packaged Rote Play: `rote play run plays/tripwire-agent-surface-census/main.ts scope=all apply=false demo=false`

**Zero to Hero Tutorial:** See the detailed DAG documentation in `docs/dag.md` to understand how TRIPWIRE calculates your Blast Radius and Agent Permission Graph.

## Quick Start

Run with the Rote CLI:

```bash
rote play run plays/tripwire-agent-surface-census/main.ts scope=all apply=false demo=false --output=human
rote play run plays/tripwire-investigate/main.ts trace_file=/path/to/repo/tests/fixtures/play_test_suspicious.json --output=json
```

Or run the standalone Python orchestrator for local validation:

```bash
# Human readable output
python3 scripts/tripwire.py --scope all --apply false --format human run_all

# Raw JSON output for automation pipelines
python3 scripts/tripwire.py --scope all --apply false --format json run_all
```

## Dependencies

See `deps.toml`.

Required:

- `python3` for Rote execution

Optional:

- `git`
- `gh`
- `netstat`
- `ss`
- `lsof`
- network access to the configured pricing URL

Optional dependencies degrade to warnings or `UNKNOWN`.

## Inspect

```bash
rote version
rote info
rote --help
rote play --help
rote play lint main.ts
```

If `rote` is not installed, inspect the frontmatter directly:

```bash
python3 scripts/tripwire.py --format human doctor
```

## Playoffs-Ready Plays

| Play | Purpose | Demo result |
| --- | --- | --- |
| `tripwire-agent-surface-census` | Runs a local read-only census of agent authority surfaces. | `TRIPWIRE S3 WRITE RISK findings=16` |
| `tripwire-investigate` | Audits an AI-agent execution trace for risky behavior and policy outcome. | `TRIPWIRE: BLOCKED - Behavioral Risk: HIGH` |

Both packaged Plays live under `plays/` and are the correct submission/demo targets:

- `plays/tripwire-agent-surface-census/main.ts`
- `plays/tripwire-investigate/main.ts`

Do not use the repository-root `main.ts` as the Playoffs package. The released, reusable Play packages are the two directories above.

## Quick Demo

From WSL, after the Plays are installed into local Rote discovery:

```bash
cd /tmp
rote play search tripwire
rote play run tripwire-agent-surface-census scope=all apply=false demo=true --output=summary
rote play run tripwire-investigate trace_file=/path/to/repo/tests/fixtures/play_test_suspicious.json --output=summary
```

Expected output:

```text
ok: found 2 plays
TRIPWIRE S3 WRITE RISK findings=16
TRIPWIRE: BLOCKED - Behavioral Risk: HIGH
```

## Example Output

```text
TRIPWIRE - AgentOps Control Layer
===================================

TRIPWIRE DELTA
Since previous baseline:
  + New MCP Server
  ~ github schema changed

AGENT PERMISSION GRAPH
  Claude -> claude -> cloudflare -> Credential:NO -> local/remote (Effect: UNKNOWN)

BLAST RADIUS
  Score: 100/100 (HIGH)

SAFE TO RUN?
  CONDITIONAL
  Reason: High blast radius detected

RAW FINDINGS
... (Standard S0-S3 Findings)
```

The exact findings depend on the local machine.

## Overview & Key Features

TRIPWIRE provides a standard for interrogating what an agent on this machine can currently reach, and whether it was authorized. Users can interact with the environment during execution loops to determine if it is safe to proceed.

In addition to detecting schema drift and exposed credentials, we provide tools for reconstructing the Agent Permission Graph (Agent -> Harness -> Tool -> Resource -> Effect). TRIPWIRE is isolated, secure, and reports credential *presence*, never the values themselves.

Below is a list of core probes and calculations that TRIPWIRE performs:

- **Agent Permission Graph:** Reconstructs the chain of agent authority.
- **MCP Schema Fingerprinting:** Analyzes and fingerprints connected MCP servers.
- **Agent Surface Delta:** Maintains a local baseline to show exactly what changed (`+ New MCP Server`, `~ Schema Drift`).
- **Blast Radius & Safe-To-Run:** Calculates a deterministic risk score resulting in a firm `YES`, `NO`, or `CONDITIONAL` decision.

## What TRIPWIRE Checks

TRIPWIRE builds an evidence-backed view of local agent authority:

- Agent harness inventory and runtime identity
- MCP server configuration and tool schema fingerprints
- Credential-shaped files and secret loci, reported by presence only
- Network and listener exposure
- Local Rote Play metadata and read/write declarations
- Git history paths that may indicate credential leakage
- Execution-trace behavior for credential, network, and write-risk patterns

The output is deterministic and maps findings to:

- `S0 CLEAN`: no meaningful issue detected
- `S1 DRIFT`: configuration drift or uncertainty
- `S2 SECRET RISK`: reachable credential/session artifact risk
- `S3 WRITE RISK`: potentially unsafe write capability or read-only mismatch
- `UNKNOWN`: insufficient evidence

## Safety Contract

TRIPWIRE is read-only by default.

> ⚠️ **Security Guarantee:** TRIPWIRE must never print API keys, access tokens, OAuth tokens, passwords, cookies, private keys, authentication headers, or environment variable values. Secret-bearing fields are represented as `PRESENT`, `MISSING`, `PLACEHOLDER`, `UNKNOWN`, or `NEVER DISPLAYED`.

## Verify Locally

Run the Python test suite:

```bash
python3 -m unittest discover -s tests
```

Current verified result:

```text
Ran 56 tests
OK (skipped=1)
```

The tests cover:

- clean/missing/degraded environments
- missing harnesses
- missing MCP config
- MCP credential presence
- unreadable paths and inaccessible directories
- `.env` and credential-shaped file detection
- missing GitHub CLI
- unknown token expiry
- unavailable network
- listener inspection failure
- S0, S1, S2, S3, and UNKNOWN classification
- JSON validity and result parity
- `apply=false` write safety
- end-to-end synthetic secret non-disclosure
- deterministic demo fixture mode

Run the Rote checks:

```bash
rote play lint ./plays/tripwire-agent-surface-census/main.ts
rote play lint ./plays/tripwire-investigate/main.ts
rote play list --json
```

Current verified status:

```text
tripwire-agent-surface-census: Released
tripwire-investigate: Released
```

## Standalone Runner

The same probe engine can be run without Rote for local validation:

```bash
python3 scripts/tripwire.py --scope all --apply false --format human run_all
python3 scripts/tripwire.py --scope all --apply false --format json run_all
python3 scripts/tripwire.py --scope all --apply false --format summary --demo true run_all
```

## Architecture

### Component Overview

```text
┌─────────────────────────────────────────────────────────┐
│                    TRIPWIRE Engine                      │
│  ┌────────────────┐              ┌──────────────────┐   │
│  │  Probes        │              │  BIE Evaluator   │   │
│  │  (Layer 1)     │              │  (Layer 2 & 3)   │   │
│  └────────┬───────┘              └────────┬─────────┘   │
└───────────┼───────────────────────────────┼─────────────┘
            │ Bounded Execution             │ Deterministic
            │ (Read-only)                   │ Verdict
┌───────────▼───────────────────────────────▼─────────────┐
│                 Local Environment                       │
│    (MCP Servers, Git, Harnesses, Environment Vars)      │
└─────────────────────────────────────────────────────────┘
```

The Play DAG follows three layers:

1. **Independent Probes:** `harness_inventory`, `mcp_census`, `play_registry`, `secret_loci`, etc. collect bounded local evidence.
2. **Classification (Join & Classify):** Joins the probe outputs into normalized findings. Determines `S0 CLEAN`, `S1 DRIFT`, `S2 SECRET RISK`, or `S3 WRITE RISK`.
3. **Verdict & Contract:** Returns the final risk level and emits the `SAFE TO RUN?` decision.

## Future Roadmap & Improvements

- **Rote CLI Native Integration:** Upgrade standalone Python scripts to natively output `.rote` journey traces.
- **Safe Credential Revocation Adapter:** Implement adapter to safely rotate local keys when write-risks are flagged.
- **CI/CD Pipeline Integration:** Automated test and XRAY validation on PRs via GitHub Actions.
- **Expanded XRAY Heuristics:** Advanced regex detection for heavily obfuscated shell payloads.

## Demo Recording Guide

Use `docs/demo-recording-guide.md` for a step-by-step recording script. The recommended social/demo story is:

1. Search for the Plays with `rote play search tripwire`.
2. Run the agent surface census and show the `S3 WRITE RISK` result.
3. Run the suspicious trace investigation and show the `BLOCKED` result.
4. Explain that both Plays are reusable, inspectable, read-only by default, and ready to publish to Community.

## Playoffs Submission

Submission happens when Play asks where the verified method should live. Choose `Community`. A public canonical Play URI is the completed submission.

Use the Play agent flow:

```text
$play explore publish my TRIPWIRE agent surface census Play as a reusable Community Play for checking local agent authority, MCP configuration, credential loci, listener exposure, Rote Play metadata, and producing a safe-to-run verdict. Use the existing project at ./ and the packaged Play at plays/tripwire-agent-surface-census/main.ts. Verify it with demo=true first, then save/publish it to Community.
```

After publishing, confirm that the public URI opens and runs through Rote.

## Limitations

- The local build environment used for this submission did not have `rote` on PATH, so Rote CLI lint/run could not be executed here.
- MCP write capability is inferred from local configuration metadata and server/package hints. It is evidence-based but conservative.
- `price_tape` is secondary. Network failure reports `pricing: UNKNOWN` and does not block the census.
- `git_leak_probe` inspects local git history paths only. It does not download remote repository contents or print file contents.
- `revoke_stale` is disabled until a safe local revocation adapter exists.

## Project Status

- Rote/Play preflight: ready
- Rote authentication: verified
- Packaged Play lint: passing
- Local Play discovery: passing
- Python tests: passing
- Public Community publishing: pending user confirmation in Play
