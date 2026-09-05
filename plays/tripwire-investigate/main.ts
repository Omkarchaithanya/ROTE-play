/** 
 * @rote-frontmatter
 * ---
 * name: tripwire-investigate
 * description: "Audit an AI-agent execution trace for authority drift, schema drift, behavioral anomalies, credential/network escalation, and security risk, then produce an evidence-backed deterministic policy outcome."
 * source: "https://github.com/Omkarchaithanya/ROTE-play"
 * metadata:
 *   version: "0.1.0"
 *   rote_version: "0.78.0"
 *   execution_model: "steps_with_presentation"
 *   flow_type: "sequential"
 *   requires_sessions: false
 *   status: "draft"
 *   read_only_default: true
 *   contract:
 *     atomic: true
 *     composable: false
 *     input:
 *       type: "file"
 *     output:
 *       format: "json"
 *       destination: "stdout"
 * presentation_fixtures:
 *   investigate: resources/presentation-fixtures/investigate/fixture.yaml
 * parameters:
 *   - name: trace_file
 *     required: true
 *     description: "Path to the JSON execution trace of the agent"
 * steps:
 *   investigate:
 *     type: process.exec
 *     timeout_ms: 30000
 *     argv:
 *       - python3
 *       - "-X"
 *       - "bie=@resource{bie.py}"
 *       - "@resource{tripwire.py}"
 *       - "--format"
 *       - "json"
 *       - "investigate"
 *       - "$trace_file"
 * ---
 */

const { FlowOutput, loadPresentationContext, stepName } = await import("__ROTE_PRESENTATION_SDK__");

const out = new FlowOutput();
const ctx = await loadPresentationContext();

const investigateStep = ctx.step(stepName("investigate"));
const outputText = investigateStep?.outcome?.output?.body?.stdout?.text;

let resultData;
if (!outputText || outputText.trim() === "") {
  resultData = {
    target: 'unknown-agent',
    policy_decision: "BLOCKED",
    risk: "HIGH",
    finding: "Missing or invalid output from investigator engine"
  };
} else {
  try {
    resultData = JSON.parse(outputText);
  } catch (e) {
    resultData = { 
      target: 'unknown-agent',
      policy_decision: "BLOCKED", 
      risk: "HIGH", 
      finding: "Parse error from python engine" 
    };
  }
}

// Construct Human Format matching Phase 5/16 requirements
const target = resultData.target || 'unknown-agent';
const decision = resultData.policy_decision || 'BLOCKED';
const finding = resultData.finding || 'Investigation failed';
const anomalies = (resultData.anomalies || []).length > 0 
  ? resultData.anomalies.join("\n") 
  : "No specific anomalies detected";

let humanLines = [
  "TRIPWIRE SECURITY REVIEW\n",
  "Target:",
  `${target}\n`,
  "Result:",
  `${decision}\n`,
  "Detected:",
  `${resultData.changes || 'No changes detected'}\n`,
  "Behavioral Finding:",
  `${anomalies}\n`,
  "Authority:",
  `${resultData.auth_delta === 'UNKNOWN' ? 'UNKNOWN \u2014 no approved baseline available' : (resultData.auth_delta || 'UNKNOWN')}\n`,
  "Schema:",
  `${resultData.schema_drifts || 'No schema drift'}\n`,
  "Evidence:"
];

for (const e of (resultData.evidence || [])) {
  humanLines.push(`- ${e.id}: ${e.obs}`);
}
humanLines.push("");

const blastLevel = resultData.blast_level || 'UNKNOWN';
const blastScore = resultData.blast_score || 0;
humanLines.push("Static Blast Radius:");
if (blastLevel === 'UNKNOWN') {
  humanLines.push(`UNKNOWN \u2014 static authority data unavailable\n`);
} else {
  humanLines.push(`Score: ${blastScore}/100 (${blastLevel})\n`);
}

humanLines.push("Policy:");
humanLines.push(`${decision}\n`);

humanLines.push("Reason:");
if (decision === 'SAFE' && blastLevel === 'UNKNOWN' && resultData.auth_delta === 'UNKNOWN') {
  humanLines.push(`No behavioral violation detected; static authority/blast-radius assessment unavailable.\n`);
} else {
  humanLines.push(`${finding}\n`);
}

const humanText = humanLines.join("\n");

out.human(humanText);
out.summary(`TRIPWIRE: ${decision} - Behavioral Risk: ${resultData.risk}`);
out.result(resultData);

