/** @rote-frontmatter
name: 'TOKEN-RECEIPT'
description: 'Reconstruct agent spend for the week.'
parameters:
  - name: format
    default: 'human'
steps:
  inspect:
    command: 'python token_receipt.py --format {{format}}'
*/
