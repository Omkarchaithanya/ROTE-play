# TRIPWIRE INVESTIGATE

## What it does

The TRIPWIRE Investigate Play analyzes an AI-agent execution trace and produces an evidence-backed security policy decision. It evaluates behavioral sequences, semantic capability invocation, schema drift, and authority escalation to determine the potential security risk of the agent's actions.

## Input

The input is a JSON execution trace (`trace_file`) containing the sequence of tools the agent invoked, their arguments, and other relevant contextual data.

You can execute the Play with a minimal valid invocation:

```bash
rote play run /mnt/c/Users/omkar/mobi/plays/tripwire-investigate/main.ts trace_file=/absolute/path/to/trace.json
```

To output raw JSON instead of the human-formatted report, use the native Rote flag:

```bash
rote play run /mnt/c/Users/omkar/mobi/plays/tripwire-investigate/main.ts trace_file=/absolute/path/to/trace.json --output=json
```

## Output

The Play outputs a deterministically calculated security policy tier:

* **SAFE**: No policy-triggering behavioral threat was detected under the available evidence. *Important*: SAFE does not mean "guaranteed mathematically secure". It means that the observed actions conform to baseline expectations or heuristics without exhibiting high-confidence malicious traits.
* **REVIEW**: The execution exhibits medium-risk indicators, such as the use of unknown capability semantics or isolated sensitive credential access. A human operator should inspect this execution before allowing further action.
* **BLOCKED**: The execution exhibits critical security violations (e.g., exfiltration chains, unauthorized semantic external writes). The execution is deemed malicious or unsafe and must be stopped.

## Risk

The Play calculates behavioral security threats across three levels:

* **LOW**: Actions align with legitimate workflow expansions or baseline behavior.
* **MEDIUM**: Ambiguous or potentially risky actions that cannot be deterministically verified as benign.
* **HIGH**: Sequences or capabilities strongly associated with malicious intent or privilege misuse.

**Risk vs. Blast Radius**:
* **Risk** represents the *behavioral and security threat* inferred from the dynamic execution trace (e.g., did the agent try to exfiltrate data?).
* **Blast Radius** represents the *potential impact* derived from static authority and reachable resources (e.g., how much damage could the agent do if compromised, regardless of what it actually did?).

## Authority

**Authority** measures the delta between the approved static MCP capabilities (the baseline) and the capabilities discovered currently on disk.

When Authority is **UNKNOWN**, it means that there is no approved baseline available for comparison (i.e., static authority data is unavailable). If the trace is otherwise benign but capability semantics are unavailable, the Play returns REVIEW rather than guessing.

## Schema / Schema Drift

**Schema** refers to the JSON-RPC tool definitions provided by the agent's Model Context Protocol (MCP) servers. 

**Schema Drift** occurs when the cryptographic hash of the canonicalized MCP tool schemas changes compared to the approved baseline. This indicates that the API surface available to the agent has been altered (e.g., a tool was added, removed, or modified).

## Evidence

**Evidence** represents concrete, atomic observations generated from trace events or static probes that support the final decision.

Examples of Evidence include:
* Schema unchanged / Schema changed
* Sensitive credential access
* Write semantics verified
* Suspicious capability chain: credential read -> network request

## Behavioral Investigation

The Behavioral Investigation Engine (BIE) processes the trace through a strict, deterministic pipeline:

1. **Observation**: Trace events are parsed and enriched with semantic metadata.
2. **Behavioral Fingerprint**: Capabilities (reads, writes, network, credentials) and sequences are tracked.
3. **Hypotheses**: Standard threat model narratives (e.g., "Suspicious privilege misuse") are instantiated.
4. **Evidence & Safe Probes**: Probes gather static and dynamic evidence which deterministically adjust the confidence of each hypothesis.
5. **Deterministic Policy**: The highest-confidence hypothesis and specific behavioral anomalies drive a fixed risk calculation, producing the final policy decision (SAFE, REVIEW, or BLOCKED).

*Note: The BIE uses deterministic logic, semantic mapping, and sequence heuristics. It is NOT an LLM making autonomous, non-deterministic security decisions.*

## Example 1 — Benign

A legitimate read-only workflow.

**Trace**: `read_file` -> `read_database` -> `analyze` -> `generate_report`
**Expected Output without a semantic baseline**:
```
Result: REVIEW
Behavioral Finding: Unknown capability semantics require review
Policy: REVIEW
```

## Example 2 — Suspicious Chain

An agent reads a credential, makes a network request, and writes to an external service.

**Trace**: `credential_read` -> `network_request` -> `external_write`
**Expected Output**:
```
Result: BLOCKED
Behavioral Finding: Critical exfiltration/injection chain
Policy: BLOCKED
Reason: Suspicious privilege misuse or injection
```

## Example 3 — Semantic Authority

An agent invokes a tool named `harmless_info`, but the tool has `EXTERNAL_WRITE` semantics. TRIPWIRE evaluates the authority semantics rather than trusting the tool name.

**Trace**: `harmless_info` (Semantic: `EXTERNAL_WRITE`)
**Expected Output**:
```
Result: BLOCKED
Behavioral Finding: External write capability detected
Policy: BLOCKED
Reason: Suspicious privilege misuse or injection
```

## Read-only Guarantee

The TRIPWIRE Investigate Play strictly **analyzes** the supplied trace. It does not execute the traced agent actions, nor does it interact with live external services described in the trace. It is a read-only investigation tool.

## Limitations

* **Static Information Dependency**: Static Authority and Blast Radius metrics may be UNKNOWN if the Play is executed without a previously established `.tripwire_approved.json` baseline.
* **Trace-Based Analysis**: The Play analyzes supplied JSON execution traces after the fact or during a dry-run phase; it does not control or intercept an agent's live execution inline.
* **Evidence Boundaries**: Decisions are strictly bound by the available evidence and semantic mappings. If a tool's semantic effect is truly UNKNOWN, the Play falls back to REVIEW rather than guessing.
