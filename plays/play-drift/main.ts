/** 
 * @rote-frontmatter
 * ---
 * name: 'PLAY-DRIFT'
 * description: 'Identify stale assumptions in installed Plays.'
 * metadata:
 *   rote_version: 1.0
 *   requires_sessions: false
 *   status: draft
 *   execution_model: steps_with_presentation
 *   flow_type: sequential
 * parameters:
 *   - name: play_uri
 *     param_type: string
 *     default: '.'
 *   - name: format
 *     param_type: string
 *     default: 'human'
 * steps:
 *   inspect:
 *     type: process.exec
 *     argv:
 *       - python3
 *       - "@resource{play_drift.py}"
 *       - "inspect"
 *       - "$play_uri"
 *       - "--format"
 *       - "$format"
 * ---
 */

const { FlowOutput } = await import("__ROTE_PRESENTATION_SDK__");
const out = new FlowOutput();
out.human("play-drift running...");
out.summary("play-drift running...");
out.result({ "status": "ok" });
