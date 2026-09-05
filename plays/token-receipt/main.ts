/** 
 * @rote-frontmatter
 * ---
 * name: 'TOKEN-RECEIPT'
 * description: 'Reconstruct agent spend for the week.'
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
 *       - "@resource{token_receipt.py}"
 *       - "--format"
 *       - "$format"
 * ---
 */

const { FlowOutput } = await import("__ROTE_PRESENTATION_SDK__");
const out = new FlowOutput();
out.human("token-receipt running...");
out.summary("token-receipt running...");
out.result({ "status": "ok" });
