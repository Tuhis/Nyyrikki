#!/usr/bin/env bash
# Every third-party action is pinned to a commit SHA, and every workflow
# defaults its token to contents: read (docs/01 D18, G5).
set -euo pipefail
status=0
for f in .github/workflows/*.yml; do
  while IFS= read -r line; do
    ref=${line#*uses:}; ref=${ref%%#*}; ref=$(echo "$ref" | tr -d ' "'"'"'')
    case $ref in ./*) continue ;; esac
    if ! [[ $ref =~ @[0-9a-f]{40}$ ]]; then echo "$f: action not pinned to a SHA: $ref"; status=1; fi
  done < <(grep -E '^\s*-?\s*uses:' "$f")
  if ! awk '/^permissions:/{p=1;next} p&&/^[^ ]/{exit} p&&/contents: read/{ok=1} END{exit !ok}' "$f"; then
    echo "$f: no top-level 'permissions: contents: read'"; status=1
  fi
  if awk '/^permissions:/{p=1;next} p&&/^[^ ]/{exit} p&&/: write/{bad=1} END{exit !bad}' "$f"; then
    echo "$f: top-level permissions grant write"; status=1
  fi
done
exit $status
