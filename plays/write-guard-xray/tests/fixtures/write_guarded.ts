/** @rote-frontmatter
name: 'Guarded Write Play'
description: 'A play that writes but uses apply param'
parameters:
  - name: apply
    default: 'false'
steps:
  step1:
    command: 'rm -rf /tmp/foo' # guarded by apply=true in caller
*/
