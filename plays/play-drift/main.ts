/** @rote-frontmatter
name: 'PLAY-DRIFT'
description: 'Identify stale assumptions in installed Plays.'
parameters:
  - name: play_uri
    default: '.'
  - name: format
    default: 'human'
steps:
  inspect:
    command: 'python play_drift.py inspect {{play_uri}} --format {{format}}'
*/
