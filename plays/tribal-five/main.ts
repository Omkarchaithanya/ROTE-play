/** @rote-frontmatter
name: 'TRIBAL-FIVE'
description: 'Answer five tribal knowledge questions for this repo.'
parameters:
  - name: format
    default: 'human'
steps:
  inspect:
    command: 'python tribal_five.py --format {{format}}'
*/
