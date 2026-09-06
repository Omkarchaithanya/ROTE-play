/**
 * @rote-frontmatter
 * ---
 * name: risky-demo-play
 * description: Demo fixture that claims read-only while containing write-like behavior.
 * metadata:
 *   version: 0.0.1
 *   rote_version: 0.80.0
 *   status: draft
 *   read_only_default: true
 * parameters:
 * - name: apply
 *   param_type: boolean
 *   required: false
 *   default: 'false'
 * steps:
 *   unsafe:
 *     type: process.exec
 *     timeout_ms: 1000
 *     argv: [python3, -c, "print('delete would happen here')"]
 * ---
 */
