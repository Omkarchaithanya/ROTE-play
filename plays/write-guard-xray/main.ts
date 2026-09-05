/** @rote-frontmatter
name: write-guard-xray
version: 0.1.0
description: Inspect a Rote Play source/URI and report whether declared write capabilities match represented step behavior.
metadata:
  status: draft
  execution_model: steps_with_presentation
  flow_type: inspect_analyze_verdict
  read_only_default: true
  writes: none
  safety: This Play never executes the inspected Play and never modifies local files, credentials, or configuration.
parameters:
- name: play_uri
  param_type: string
  required: true
  description: Local path, owner/name, or https Play URI to inspect.
  example: ./main.ts
- name: format
  param_type: string
  required: false
  default: human
  description: Output representation.
  example: human
  valid_values: [human, json]
steps:
  metadata_probe:
    type: process.exec
    timeout_ms: 30000
    argv: [python3, plays/write-guard-xray/write_guard_xray.py, --format, json, metadata_probe, $play_uri]
  capability_probe:
    type: process.exec
    timeout_ms: 15000
    depends_on: [metadata_probe]
    argv:
    - python3
    - plays/write-guard-xray/write_guard_xray.py
    - --format
    - json
    - capability_probe
    - --metadata-json
    - '@metadata_probe{$.stdout.text}'
  step_tool_probe:
    type: process.exec
    timeout_ms: 15000
    depends_on: [capability_probe]
    argv:
    - python3
    - plays/write-guard-xray/write_guard_xray.py
    - --format
    - json
    - step_tool_probe
    - --capability-json
    - '@capability_probe{$.stdout.text}'
  write_analysis:
    type: process.exec
    timeout_ms: 15000
    depends_on: [step_tool_probe]
    argv:
    - python3
    - plays/write-guard-xray/write_guard_xray.py
    - --format
    - json
    - write_analysis
    - --steps-json
    - '@step_tool_probe{$.stdout.text}'
  verdict:
    type: process.exec
    timeout_ms: 15000
    depends_on: [write_analysis]
    argv:
    - python3
    - plays/write-guard-xray/write_guard_xray.py
    - --format
    - json
    - verdict
    - $play_uri
    - --analysis-json
    - '@write_analysis{$.stdout.text}'
representations:
  human: complete - target, declaration, observed capabilities, findings, classification, verdict.
  json: canonical - stable findings, metadata, step observations, safety, provenance.
*/

const { FlowOutput, loadPresentationContext, stepName } = await import("__ROTE_PRESENTATION_SDK__");

const out = new FlowOutput();
const ctx = await loadPresentationContext();
const verdictStep = ctx.step(stepName("verdict"));
const verdictText = verdictStep?.outcome?.output?.body?.stdout?.text ?? "";

function parseJson(text: string): any {
  try {
    return JSON.parse(text);
  } catch {
    return {
      ok: false,
      overall: "UNKNOWN",
      overall_label: "UNKNOWN",
      verdict: "INSPECTION INCOMPLETE",
      findings: [],
      warnings: ["verdict step produced no parseable JSON"],
    };
  }
}

const result = parseJson(verdictText);
const human = [
  "WRITE-GUARD-XRAY",
  "",
  `Target: ${result.target ?? "UNKNOWN"}`,
  `Play: ${result.metadata?.name ?? "UNKNOWN"}`,
  `Version: ${result.metadata?.version ?? "UNKNOWN"}`,
  "",
  "Declared",
  `  writes: ${result.declared?.write_capability ?? "UNKNOWN"}`,
  `  guard: ${result.declared?.guard ?? "UNKNOWN"}`,
  "",
  "Observed",
  `  write-capable steps: ${(result.steps ?? []).filter((step: any) => step.observed === "WRITE_CAPABLE").length}`,
  `  unguarded: ${(result.steps ?? []).filter((step: any) => step.guarded === "MISSING").length}`,
  "",
  "Classification",
  `  ${result.overall ?? "UNKNOWN"} - ${result.overall_label ?? "UNKNOWN"}`,
  "",
  "Verdict",
  `  ${result.verdict ?? "INSPECTION INCOMPLETE"}`,
].join("\n");

out.human(human);
out.summary(`WRITE-GUARD-XRAY ${result.overall ?? "UNKNOWN"} ${result.overall_label ?? "UNKNOWN"} findings=${(result.findings ?? []).length}`);
out.result(result);
