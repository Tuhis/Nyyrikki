#!/usr/bin/env bash
# Every gate must fail on its planted violation (docs/01 §5.6). A gate that
# passes its canary checks nothing, and this script fails.
set -uo pipefail
cd "$(dirname "$0")/.."
status=0
for c in fmt vet staticcheck tidy test vuln licenses secret chart pinning; do
  gate=$c; [ "$c" = secret ] && gate=secrets
  dir=test/canaries/$c
  if [ "$c" = chart ] && [ ! -d deploy/chart/nyyrikki ]; then echo "skip: no chart yet"; continue; fi
  if [ "$c" = chart ] || [ "$c" = pinning ]; then
    # These gates read fixed paths; run them on a copy with the canary in place.
    tmp=$(mktemp -d); cp -r . "$tmp/repo"; cp -r "$dir/." "$tmp/repo/"; dir=$tmp/repo
  fi
  if scripts/gates.sh "$gate" "$dir" >/dev/null 2>&1; then
    echo "FAIL: gate $gate passed its canary $c"; status=1
  else
    echo "ok: gate $gate fails on its canary"
  fi
done
exit $status
