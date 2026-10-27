#!/usr/bin/env bash
# Every third-party action is pinned to a commit SHA, in workflows and in
# composite actions, and every workflow defaults its token to
# contents: read (docs/01 D18, G5).
set -euo pipefail
shopt -s nullglob
status=0

workflows=(.github/workflows/*.yml .github/workflows/*.yaml)
actions=()
while IFS= read -r f; do actions+=("$f"); done < <(find .github/actions \( -name 'action.yml' -o -name 'action.yaml' \) 2>/dev/null | sort)

for f in "${workflows[@]}" ${actions[@]+"${actions[@]}"}; do
  while IFS= read -r line; do
    ref=${line#*uses:}; ref=${ref%%#*}; ref=$(echo "$ref" | tr -d ' "'"'"'')
    case $ref in ./*) continue ;; esac
    if ! [[ $ref =~ @[0-9a-f]{40}$ ]]; then echo "$f: action not pinned to a SHA: $ref"; status=1; fi
  done < <(grep -E '^\s*-?\s*uses:' "$f" || true)
done

# The top-level permissions block: comment lines are skipped (a column-0
# comment must not end the block, and "# contents: read" must not count),
# and trailing comments are stripped.
perms='/^[[:space:]]*(#.*)?$/{next} {sub(/[[:space:]]+#.*/,"")} /^permissions:/{p=1;next} p&&/^[^ ]/{exit}'
for f in "${workflows[@]}"; do
  if ! awk "$perms"' p&&/^[[:space:]]+contents:[[:space:]]*read[[:space:]]*$/{ok=1} END{exit !ok}' "$f"; then
    echo "$f: no top-level 'permissions: contents: read'"; status=1
  fi
  # Fail closed: every line of the block must grant read or none; any
  # other value (write, a quoted "write", an alias) is reported.
  if awk "$perms"' p&&!/^[[:space:]]+[a-z-]+:[[:space:]]*(read|none)[[:space:]]*$/{bad=1} END{exit !bad}' "$f"; then
    echo "$f: top-level permissions grant more than read"; status=1
  fi
done
exit $status
