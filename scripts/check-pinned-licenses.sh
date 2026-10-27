#!/usr/bin/env bash
# Checks that every hand-reviewed module is still at the reviewed version
# with the reviewed LICENSE file (docs/01 D14). A version bump needs a new
# review and a new pin.
set -euo pipefail
cd "$(dirname "$0")/.."
status=0
while read -r modver sum _; do
  [[ -z $modver || $modver == \#* ]] && continue
  mod=${modver%@*}; want=${modver#*@}
  have=$(go list -m -f '{{.Version}}' "$mod")
  if [ "$have" != "$want" ]; then echo "$mod is $have, but $want was reviewed; review it and update scripts/pinned-licenses"; status=1; continue; fi
  dir=$(go list -m -f '{{.Dir}}' "$mod")
  got=$(sha256sum "$dir/LICENSE" | cut -d' ' -f1)
  if [ "$got" != "$sum" ]; then echo "$mod LICENSE changed ($got); review it"; status=1; fi
done < scripts/pinned-licenses
exit $status
