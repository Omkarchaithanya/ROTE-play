/** 
 * @rote-frontmatter
 * ---
 * name: 'TRIBAL-FIVE'
 * description: 'Answer five tribal knowledge questions for this repo.'
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
 * steps:
 *   inspect:
 *     type: process.exec
 *     argv:
 *       - python3
 *       - "@resource{tribal_five.py}"
 *       - "--format"
 *       - "$format"
 * ---
 */

const { FlowOutput } = await import("__ROTE_PRESENTATION_SDK__");
const out = new FlowOutput();
out.human("tribal-five running...");
out.summary("tribal-five running...");
out.result({ "status": "ok" });
