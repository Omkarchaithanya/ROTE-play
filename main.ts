/**
 * @rote-frontmatter
 * ---
 * name: tripwire-agent-surface-census
 * version: 0.1.0
 * description: Local-first, read-only census of agent harness reach, MCP configuration, credential loci, listeners, and Rote Play metadata.
 * provenance:
 *   author: local
 *   workspace: tripwire-agent-surface-census
 * metadata:
 *   requires_sessions: false
 *   rote_version: 1.0
 *   status: draft
 *   execution_model: steps_with_presentation
 *   flow_type: parallel
 *   read_only_default: true
 *   write_contract: revoke_stale is declared but disabled unless apply=true and a safe revocation adapter exists.
 * parameters:
 * - name: scope
 *   param_type: string
 *   required: false
 *   default: all
 *   example: all
 *   valid_values: [all, harness, mcp, plays, secrets]
 * - name: apply
 *   param_type: boolean
 *   required: false
 *   default: 'false'
 *   example: 'false'
 * - name: format
 *   param_type: string
 *   required: false
 *   default: human
 *   example: human
 *   valid_values: [human, json, summary]
 * - name: demo
 *   param_type: boolean
 *   required: false
 *   default: 'false'
 *   example: 'false'
 * steps:
 *   harness_inventory:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, scripts/tripwire.py, --scope, $scope, --apply, $apply, --format, json, --demo, $demo, harness_inventory]
 *   mcp_census:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, scripts/tripwire.py, --scope, $scope, --apply, $apply, --format, json, --demo, $demo, mcp_census]
 *   play_registry:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, scripts/tripwire.py, --scope, $scope, --apply, $apply, --format, json, --demo, $demo, play_registry]
 *   secret_loci:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, scripts/tripwire.py, --scope, $scope, --apply, $apply, --format, json, --demo, $demo, secret_loci]
 *   token_ttl:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, scripts/tripwire.py, --scope, $scope, --apply, $apply, --format, json, --demo, $demo, token_ttl]
 *   listen_surface:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, scripts/tripwire.py, --scope, $scope, --apply, $apply, --format, json, --demo, $demo, listen_surface]
 *   price_tape:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv: [python3, scripts/tripwire.py, --scope, $scope, --apply, $apply, --format, json, --demo, $demo, price_tape]
 *   git_leak_probe:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, scripts/tripwire.py, --scope, $scope, --apply, $apply, --format, json, --demo, $demo, git_leak_probe]
 *   classify:
 *     type: process.exec
 *     timeout_ms: 15000
 *     depends_on:
 *     - harness_inventory
 *     - mcp_census
 *     - play_registry
 *     - secret_loci
 *     - token_ttl
 *     - listen_surface
 *     - price_tape
 *     - git_leak_probe
 *     argv:
 *     - python3
 *     - scripts/tripwire.py
 *     - --scope
 *     - $scope
 *     - --apply
 *     - $apply
 *     - --format
 *     - json
 *     - --demo
 *     - $demo
 *     - classify
 *     - '@harness_inventory{$.stdout.text}'
 *     - '@mcp_census{$.stdout.text}'
 *     - '@play_registry{$.stdout.text}'
 *     - '@secret_loci{$.stdout.text}'
 *     - '@token_ttl{$.stdout.text}'
 *     - '@listen_surface{$.stdout.text}'
 *     - '@price_tape{$.stdout.text}'
 *     - '@git_leak_probe{$.stdout.text}'
 *   verdict:
 *     type: process.exec
 *     timeout_ms: 15000
 *     depends_on: [classify]
 *     argv:
 *     - python3
 *     - scripts/tripwire.py
 *     - --scope
 *     - $scope
 *     - --apply
 *     - $apply
 *     - --format
 *     - json
 *     - --demo
 *     - $demo
 *     - verdict
 *     - '@classify{$.stdout.text}'
 *   revoke_stale:
 *     type: process.exec
 *     timeout_ms: 5000
 *     depends_on: [verdict]
 *     argv:
 *     - python3
 *     - -c
 *     - "import json, sys; apply=str(sys.argv[1]).lower() == 'true'; print(json.dumps({'ok': True, 'probe': 'revoke_stale', 'status': 'disabled', 'apply_requested': apply, 'message': 'revoke_stale is intentionally disabled until a safe local revocation adapter is available'}))"
 *     - $apply
 * representations:
 *   human: complete - ledger, warnings, classification, and write contract from verdict.
 *   json: canonical - same findings plus provenance and write contract.
 *   summary: intentionally lossy - overall severity and finding count only.
 * ---
 */

const { FlowOutput, loadPresentationContext, stepName } = await import("__ROTE_PRESENTATION_SDK__");

const out = new FlowOutput();
const ctx = await loadPresentationContext();

function parseJsonStep(text: string, name: string): any {
  try {
    return JSON.parse(text);
  } catch {
    return {
      ok: false,
      name,
      warnings: [`${name} produced no parseable JSON`],
      findings: [],
      overall: "UNKNOWN",
      overall_label: "UNKNOWN",
    };
  }
}

const verdictStep = ctx.step(stepName("verdict"));
const verdictText = verdictStep?.outcome?.output?.body?.stdout?.text ?? "";
const verdict = parseJsonStep(verdictText, "verdict");
const humanText = typeof verdict === "object" && verdict.findings
  ? [
      "TRIPWIRE - Agent Surface Census",
      "",
      `Overall: ${verdict.overall ?? "UNKNOWN"} ${verdict.overall_label ?? "UNKNOWN"}`,
      `Findings: ${(verdict.findings ?? []).length}`,
      `Warnings: ${(verdict.warnings ?? []).length}`,
      "",
      "Write contract",
      `  apply requested: ${verdict.write_contract?.apply_requested ?? false}`,
      `  revoke_stale: ${verdict.write_contract?.revoke_stale ?? "DISABLED"}`,
    ].join("\n")
  : String(verdict);

out.human(humanText);
out.summary(`TRIPWIRE ${verdict.overall ?? "UNKNOWN"} ${verdict.overall_label ?? "UNKNOWN"} findings=${(verdict.findings ?? []).length}`);
out.result({
  ...verdict,
  representations: {
    human: "complete - concise ledger plus write contract",
    json: "canonical - all findings, warnings, provenance, and write contract",
    summary: "intentionally lossy - verdict and count only",
  },
});
