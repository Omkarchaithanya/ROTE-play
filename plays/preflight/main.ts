/** @rote-frontmatter
name: 'PREFLIGHT'
description: 'Run all AgentOps preflight checks.'
parameters:
  - name: format
    default: 'human'
  - name: demo
    default: 'false'
  - name: xray_target
    default: ''
steps:
  inspect:
    command: 'python preflight.py --format {{format}} {{demo ? "--demo" : ""}} {{xray_target ? "--xray-target " + xray_target : ""}}'
*/
