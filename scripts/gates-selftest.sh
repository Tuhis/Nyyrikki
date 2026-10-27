#!/usr/bin/env bash
# Every gate must fail on its planted violation (docs/01 §5.6). A gate that
# passes its canary checks nothing, and this script fails. A gate that
# fails for any other reason (a crash, a missing tool, a download error)
# hasn't shown that it checks anything either, so each canary's own
# finding must appear in the gate's output.
set -uo pipefail
cd "$(dirname "$0")/.."

# canary  gate  marker-regex (the planted finding, as the tool reports it)
canaries=(
  "fmt|fmt|(^|/)bad\.go$"
  "vet|vet|format %d has arg .* of wrong type"
  "staticcheck|staticcheck|SA4017"
  "tidy|tidy|^-require github\.com/oklog/ulid"
  "test|test|planted failure"
  "vuln|vuln|GO-2022-1059"
  "licenses|licenses|Not allowed license 'GPL-3\.0' found for library 'example\.com/gpl'"
  "secret|secrets|nyyrikki-elevation-handle"
  "secret|secrets|nyyrikki-stream-ticket"
  "secret|secrets|github-pat"
  "chart|chart|Deployment canary is invalid"
  "pinning|pinning|not pinned to a SHA"
  "pinning|pinning|canary-write\.yml: top-level permissions grant write"
  "pinning|pinning|canary-nodefault\.yml: no top-level 'permissions: contents: read'"
)

status=0
tmps=()
trap 'rm -rf "${tmps[@]}"' EXIT
for entry in "${canaries[@]}"; do
  IFS='|' read -r c gate marker <<<"$entry"
  dir=test/canaries/$c
  if [ "$c" = chart ] && [ ! -d deploy/chart/nyyrikki ]; then echo "skip: no chart yet"; continue; fi
  case $c in
    chart|pinning|secret)
      # These gates read the repository's own paths and config (the chart,
      # the workflows, .gitleaks.toml); run them on a copy with the canary
      # dropped in, outside any allowlisted path.
      # The copy holds only tracked files, so a stray local file can't
      # satisfy a marker.
      tmp=$(mktemp -d); tmps+=("$tmp"); mkdir "$tmp/repo"
      git ls-files -z | xargs -0 cp --parents -t "$tmp/repo"
      cp -r "$dir/." "$tmp/repo/"; dir=$tmp/repo ;;
  esac
  out=$(scripts/gates.sh "$gate" "$dir" 2>&1); rc=$?
  if [ $rc -eq 0 ]; then
    echo "FAIL: gate $gate passed its canary $c"; status=1
  elif ! grep -Eq -- "$marker" <<<"$out"; then
    echo "FAIL: gate $gate failed on canary $c (exit $rc) without reporting /$marker/: it may be broken"
    echo "$out" | tail -5 | sed 's/^/    /'
    status=1
  else
    echo "ok: gate $gate catches /$marker/ in canary $c"
  fi
done
exit $status
