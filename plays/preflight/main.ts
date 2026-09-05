/** 
 * @rote-frontmatter
 * ---
 * name: 'PREFLIGHT'
 * description: 'Run all AgentOps preflight checks.'
 * metadata:
 *   rote_version: 1.0
 *   requires_sessions: false
 *   status: draft
 *   execution_model: steps_with_presentation
 *   flow_type: sequential
 * parameters:
 *   - name: format
 *     param_type: string
 *     default: 'human'
 *   - name: demo
 *     param_type: string
 *     default: 'false'
 *   - name: xray_target
 *     param_type: string
 *     default: ''
 * steps:
 *   inspect:
 *     type: process.exec
 *     argv:
 *       - python3
 *       - "@resource{preflight.py}"
 *       - "--format"
 *       - "$format"
 *       - "--demo"
 *       - "$demo"
 *       - "--xray-target"
 *       - "$xray_target"
 * ---
 */

const { FlowOutput } = await import("__ROTE_PRESENTATION_SDK__");
const out = new FlowOutput();
out.human("preflight running...");
out.summary("preflight running...");
out.result({ "status": "ok" });
