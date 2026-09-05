# TRIPWIRE - AgentOps Control Layer

TRIPWIRE answers one local question:

> What can an agent on this machine currently reach, and did anyone authorize it?

It is a local-first Rote Play that acts as a "git diff for agent authority". It performs a read-only Agent Surface Census, building an Agent Permission Graph, calculating Blast Radius, detecting schema drift, and returning a Safe-To-Run decision without printing secrets or modifying the machine.

## Problem

Modern coding agents can reach local config files, MCP servers, CLIs, browser helpers, git history, and credential-bearing state. That surface changes quickly and is hard to inspect as a human. Tool poisoning or leaked credentials can have catastrophic effects.

## What It Discovers

TRIPWIRE provides:

## Future Roadmap & Improvements
- **Rote CLI Native Integration:** Upgrade standalone Python scripts to natively output `.rote` journey traces and schedule them using Rote cron once supported.
- **Safe Credential Revocation Adapter:** Implement the adapter to safely rotate local keys when `TRIPWIRE` flags write-risks.
- **CI/CD Pipeline Integration:** Integrated GitHub Actions workflow for automated test and XRAY validation on PRs.
- **Expanded XRAY Heuristics:** Advanced regex detection for heavily obfuscated shell payloads and encodes.

- **Agent Permission Graph:** Reconstructs the chain from Agent -> Harness -> Tool (MCP) -> Resource -> Effect.
- **MCP Schema Fingerprinting:** Analyzes connected MCP servers, issues a `tools/list` RPC, and cryptographically fingerprints the schema.
- **Agent Surface Delta:** Maintains a local baseline (`.tripwire_baseline.json`) to show exactly what changed (e.g. `+ New MCP Server`, `~ Schema Drift`) since yesterday.
- **Blast Radius & Safe-To-Run:** Calculates a deterministic risk score based on tool exposure, reachability, and credential presence, resulting in a firm `YES`, `NO`, or `CONDITIONAL` decision.
- **Granular Probes:** 
  - agent harness & OS/Git identity
  - filesystem and network reachability
  - credential loci (MCP config, `.env`, `.pem` files)
  - GitHub CLI availability and SSH key age metadata

It records expected absence as data. Missing CLIs, missing config, missing network, unreadable directories, and permission-limited listener inspection produce `missing`, `unknown`, `skipped`, or warnings.

## Security Guarantees

TRIPWIRE reports credential presence, not credential values.

It must never print:

- API keys
- access tokens
- OAuth tokens
- passwords
- cookies
- private keys
- authentication headers
- environment variable values
- MCP secret values

Secret-bearing fields are represented as `PRESENT`, `MISSING`, `PLACEHOLDER`, `UNKNOWN`, or `NEVER DISPLAYED`.

The probe engine uses bounded paths. It does not recursively scan the whole filesystem. It does not upload credentials. It does not delete or modify local configuration.

## Classification

Every finding maps to:

- `S0 CLEAN`: no meaningful issue detected
- `S1 DRIFT`: configuration, stale state, or uncertainty without direct secret exposure or unguarded writes
- `S2 SECRET RISK`: evidence that a credential/session artifact exists in a reachable or risky location
- `S3 WRITE RISK`: evidence of potentially unguarded write capability or a read-only/write mismatch
- `UNKNOWN`: insufficient evidence

The overall severity is the highest known severity. `UNKNOWN` is not escalated to S2 or S3.

## Finding Schema

Each finding has stable fields:

- `id`
- `probe`
- `surface`
- `asset`
- `status`
- `severity`
- `message`
- `evidence`
- `credential_state`
- `write_capability`
- `confidence`
- `remediation`
- `details`

This keeps human, summary, and JSON output tied to the same underlying findings.

## Parameters

Rote parameters:

- `scope=all|harness|mcp|plays|secrets`
- `apply=false|true`
- `format=human|json|summary`
- `demo=false|true`

Defaults:

- `scope=all`
- `apply=false`
- `format=human`
- `demo=false`

`demo=true` uses deterministic fixtures under `tests/fixtures/demo` instead of the real local home/workspace. Normal runs ignore `tests/fixtures`.

## Read/Write Behavior

`apply=false` is the safe default.

The DAG declares an optional `revoke_stale` stage, but this implementation keeps it disabled. It reports whether `apply=true` was requested and does not revoke credentials, delete files, or modify configuration.

## DAG

Layer 1 independent probes:

- `harness_inventory`
- `mcp_census`
- `play_registry`
- `secret_loci`
- `token_ttl`
- `listen_surface`
- `price_tape`
- `git_leak_probe`

Layer 2 join:

- `classify`

Layer 3 verdict/write contract:

- `verdict`
- `revoke_stale` disabled

See `docs/dag.md` for the inspectable DAG explanation and value edges.

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

## Run With Rote

```bash
rote play run main.ts scope=all apply=false demo=false --output=human
rote play run main.ts scope=all apply=false demo=false --output=json
rote play run main.ts scope=all apply=false demo=true --output=human
```

## Run Without Rote

The standalone runner executes the same probe/join/verdict sequence for local validation:

```bash
python3 scripts/tripwire.py --scope all --apply false --format human run_all
python3 scripts/tripwire.py --scope all --apply false --format json run_all
python3 scripts/tripwire.py --scope all --apply false --format human --demo true run_all
```

On Windows, if `python3` is not available but another Python executable is, use that executable for standalone validation. Keep `python3` in `main.ts` unless the target Rote environment requires a different command.

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

## Testing

```bash
python3 -m unittest discover -s tests
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

## Limitations

- The local build environment used for this submission did not have `rote` on PATH, so Rote CLI lint/run could not be executed here.
- MCP write capability is inferred from local configuration metadata and server/package hints. It is evidence-based but conservative.
- `price_tape` is secondary. Network failure reports `pricing: UNKNOWN` and does not block the census.
- `git_leak_probe` inspects local git history paths only. It does not download remote repository contents or print file contents.
- `revoke_stale` is disabled until a safe local revocation adapter exists.
