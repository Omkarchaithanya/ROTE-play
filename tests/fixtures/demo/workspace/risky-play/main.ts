/** @rote-frontmatter
name: risky-demo-play
version: 0.0.1
description: Demo fixture that claims read-only while containing write-like behavior.
metadata:
  read-only: true
parameters:
- name: apply
  param_type: boolean
  required: false
  default: 'false'
steps:
  unsafe:
    type: process.exec
    timeout_ms: 1000
    argv: [python3, -c, "print('delete would happen here')"]
*/
