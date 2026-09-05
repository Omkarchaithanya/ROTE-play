# TRIPWIRE DAG

TRIPWIRE is structured as independent local probes, a deterministic classifier, and a final verdict renderer.

## Layer 1: Independent Probes

These steps do not depend on each other:

- `harness_inventory`
- `mcp_census`
- `play_registry`
- `secret_loci`
- `token_ttl`
- `listen_surface`
- `price_tape`
- `git_leak_probe`

Each probe emits one JSON payload:

```json
{
  "ok": true,
  "probe": "probe_name",
  "warnings": [],
  "findings": []
}
```

Expected absence is represented as data, not failure. Missing harnesses, missing CLI tools, missing MCP config, blocked directories, and network failures produce `missing`, `unknown`, `skipped`, or warning findings.

## Layer 2: Classification Join

`classify` depends on all Layer 1 probes and receives their stdout JSON via Rote value edges:

```text
@harness_inventory{$.stdout.text}
@mcp_census{$.stdout.text}
@play_registry{$.stdout.text}
@secret_loci{$.stdout.text}
@token_ttl{$.stdout.text}
@listen_surface{$.stdout.text}
@price_tape{$.stdout.text}
@git_leak_probe{$.stdout.text}
```

The classifier computes:

- `S0 CLEAN`
- `S1 DRIFT`
- `S2 SECRET RISK`
- `S3 WRITE RISK`
- `UNKNOWN`

The overall severity is the highest known severity. `UNKNOWN` does not escalate to S2 or S3.

## Layer 3: Verdict And Write Contract

`verdict` depends on `classify` and emits canonical JSON containing:

- all normalized findings
- counts
- warnings
- provenance
- write contract

`revoke_stale` depends on `verdict`, but it is disabled by implementation. It reports the requested `apply` value and does not revoke, delete, or modify anything.

## Failure Attribution

Each probe is a separate Rote step with its own timeout. A failure or degraded result is attributable to that step. Unrelated Layer 1 probes can still complete when another optional surface is missing.

## Normalized Finding Schema

Each finding includes:

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

Credential values are never included. Secret-bearing details are represented as `PRESENT`, `MISSING`, `PLACEHOLDER`, `UNKNOWN`, or `NEVER DISPLAYED`.
