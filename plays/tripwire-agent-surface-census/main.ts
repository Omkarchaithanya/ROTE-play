/**
 * @rote-frontmatter
 * ---
 * name: tripwire-agent-surface-census
 * description: Local-first, read-only census of agent harness reach, MCP configuration, credential loci, listeners, and Rote Play metadata.
 * provenance:
 *   author: local
 *   workspace: tripwire-agent-surface-census
 * metadata:
 *   version: 0.1.0
 *   requires_sessions: false
 *   rote_version: 0.80.0
 *   status: released
 *   execution_model: steps_with_presentation
 *   flow_type: parallel
 *   format: typescript
 *   discoverability:
 *     tags:
 *     - security
 *     - agent-operations
 *     - mcp
 *     - tripwire
 *     - census
 *     - effect-read-only
 *   read_only_default: true
 *   write_contract: revoke_stale is declared but disabled unless apply=true and a safe revocation adapter exists.
 * presentation_fixtures:
 *   agent_identity: resources/presentation-fixtures/empty/fixture.yaml
 *   harness_inventory: resources/presentation-fixtures/empty/fixture.yaml
 *   mcp_census: resources/presentation-fixtures/empty/fixture.yaml
 *   play_registry: resources/presentation-fixtures/empty/fixture.yaml
 *   secret_loci: resources/presentation-fixtures/empty/fixture.yaml
 *   token_ttl: resources/presentation-fixtures/empty/fixture.yaml
 *   listen_surface: resources/presentation-fixtures/empty/fixture.yaml
 *   price_tape: resources/presentation-fixtures/price_tape/fixture.yaml
 *   git_leak_probe: resources/presentation-fixtures/empty/fixture.yaml
 *   filesystem_reachability: resources/presentation-fixtures/empty/fixture.yaml
 *   network_surface: resources/presentation-fixtures/empty/fixture.yaml
 *   classify: resources/presentation-fixtures/classify/fixture.yaml
 *   verdict: resources/presentation-fixtures/verdict/fixture.yaml
 *   revoke_stale: resources/presentation-fixtures/revoke_stale/fixture.yaml
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
 * - name: demo
 *   param_type: boolean
 *   required: false
 *   default: 'false'
 *   example: 'false'
 * steps:
 *   agent_identity:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, '@resource{tripwire.py}', --scope, $scope, --apply, $apply, --format, json, --demo, $demo, agent_identity]
 *   harness_inventory:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, '@resource{tripwire.py}', --scope, $scope, --apply, $apply, --format, json, --demo, $demo, harness_inventory]
 *   mcp_census:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, '@resource{tripwire.py}', --scope, $scope, --apply, $apply, --format, json, --demo, $demo, mcp_census]
 *   play_registry:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, '@resource{tripwire.py}', --scope, $scope, --apply, $apply, --format, json, --demo, $demo, play_registry]
 *   secret_loci:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, '@resource{tripwire.py}', --scope, $scope, --apply, $apply, --format, json, --demo, $demo, secret_loci]
 *   token_ttl:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, '@resource{tripwire.py}', --scope, $scope, --apply, $apply, --format, json, --demo, $demo, token_ttl]
 *   listen_surface:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, '@resource{tripwire.py}', --scope, $scope, --apply, $apply, --format, json, --demo, $demo, listen_surface]
 *   price_tape:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv: [python3, '@resource{tripwire.py}', --scope, $scope, --apply, $apply, --format, json, --demo, $demo, price_tape]
 *   git_leak_probe:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, '@resource{tripwire.py}', --scope, $scope, --apply, $apply, --format, json, --demo, $demo, git_leak_probe]
 *   filesystem_reachability:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, '@resource{tripwire.py}', --scope, $scope, --apply, $apply, --format, json, --demo, $demo, filesystem_reachability]
 *   network_surface:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv: [python3, '@resource{tripwire.py}', --scope, $scope, --apply, $apply, --format, json, --demo, $demo, network_surface]
 *   classify:
 *     type: process.exec
 *     timeout_ms: 15000
 *     depends_on:
 *     - agent_identity
 *     - harness_inventory
 *     - mcp_census
 *     - play_registry
 *     - secret_loci
 *     - token_ttl
 *     - listen_surface
 *     - price_tape
 *     - git_leak_probe
 *     - filesystem_reachability
 *     - network_surface
 *     argv:
 *     - python3
 *     - '@resource{tripwire.py}'
 *     - --scope
 *     - $scope
 *     - --apply
 *     - $apply
 *     - --format
 *     - json
 *     - --demo
 *     - $demo
 *     - classify
 *     - '@agent_identity{$.stdout.text}'
 *     - '@harness_inventory{$.stdout.text}'
 *     - '@mcp_census{$.stdout.text}'
 *     - '@play_registry{$.stdout.text}'
 *     - '@secret_loci{$.stdout.text}'
 *     - '@token_ttl{$.stdout.text}'
 *     - '@listen_surface{$.stdout.text}'
 *     - '@price_tape{$.stdout.text}'
 *     - '@git_leak_probe{$.stdout.text}'
 *     - '@filesystem_reachability{$.stdout.text}'
 *     - '@network_surface{$.stdout.text}'
 *   verdict:
 *     type: process.exec
 *     timeout_ms: 15000
 *     depends_on: [classify]
 *     argv:
 *     - python3
 *     - '@resource{tripwire.py}'
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
 *     - '@resource{revoke_stale.py}'
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
